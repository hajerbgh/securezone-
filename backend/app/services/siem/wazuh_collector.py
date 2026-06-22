"""
WazuhCollector — Collecte des alertes depuis l'API REST Wazuh.

Rôle dans le SIEM :
  Wazuh Manager surveille tous les agents installés sur le réseau
  (serveurs Linux, postes Windows, firewalls). Il génère des alertes
  quand il détecte quelque chose d'anormal dans les logs.

  Ce collecteur interroge l'API Wazuh toutes les N secondes,
  récupère les nouvelles alertes, et les transmet au pipeline SIEM.

Flux :
  Agents réseau → Wazuh Manager → WazuhCollector → pipeline SIEM

API Wazuh utilisée :
  GET /security/user/authenticate  → obtenir un JWT Wazuh
  GET /alerts                      → lire les alertes paginées
  GET /agents                      → état des agents connectés
"""

import asyncio
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from typing import Optional
import httpx

logger = logging.getLogger(__name__)


@dataclass
class RawAlert:
    """
    Une alerte brute telle que retournée par Wazuh.
    Pas encore normalisée — contient les données Wazuh telles quelles.
    """
    wazuh_id: str                    # ID unique Wazuh
    timestamp: datetime
    agent_id: str                    # ID de l'agent Wazuh sur la machine
    agent_name: str                  # Nom de la machine
    agent_ip: str                    # IP de la machine source
    rule_id: str                     # ID de la règle Wazuh déclenchée
    rule_description: str            # Description lisible de la règle
    rule_level: int                  # Niveau de sévérité Wazuh (1-15)
    rule_groups: list[str]           # Catégories : ["authentication", "sshd"]
    full_log: str                    # Log brut complet
    data: dict = field(default_factory=dict)  # Données structurées additionnelles
    location: str = ""               # Fichier source du log (ex: /var/log/auth.log)
    decoder_name: str = ""           # Décodeur utilisé par Wazuh


@dataclass
class AgentStatus:
    """État d'un agent Wazuh sur une machine."""
    agent_id: str
    name: str
    ip: str
    status: str          # "active" | "disconnected" | "never_connected"
    last_keep_alive: Optional[datetime]
    os_name: str
    os_version: str
    version: str         # Version de l'agent Wazuh


class WazuhCollector:
    """
    Client pour l'API REST Wazuh Manager.

    Authentification : JWT renouvelé automatiquement toutes les 15 min.
    Pagination : récupère les alertes par lots de 500.
    Déduplication : garde trace du dernier timestamp traité.

    Usage :
        collector = WazuhCollector(base_url="https://wazuh-manager:55000")
        async for alert in collector.poll_alerts():
            await pipeline.process(alert)
    """

    def __init__(
        self,
        base_url: str = "https://localhost:55000",
        username: str = "wazuh-wui",
        password: str = "",
        poll_interval_seconds: int = 30,
    ):
        self.base_url = base_url.rstrip("/")
        self.username = username
        self.password = password
        self.poll_interval = poll_interval_seconds

        self._token: Optional[str] = None
        self._token_expires: Optional[datetime] = None
        self._last_alert_timestamp: Optional[datetime] = None
        self._available: Optional[bool] = None

    # ─────────────────────────────────────────────
    # Polling principal
    # ─────────────────────────────────────────────

    async def poll_alerts(self, since: Optional[datetime] = None):
        """
        Générateur asynchrone — yield les nouvelles alertes en continu.

        Usage :
            async for alert in collector.poll_alerts():
                await process(alert)

        En mode simulation (Wazuh non disponible), génère des alertes
        fictives réalistes pour permettre le développement et les tests.
        """
        self._last_alert_timestamp = since or (
            datetime.now(timezone.utc) - timedelta(hours=1)
        )

        while True:
            try:
                if not await self._check_available():
                    alerts = self._mock_alerts()
                else:
                    alerts = await self._fetch_new_alerts()

                for alert in alerts:
                    yield alert
                    # Mettre à jour le curseur de temps
                    if alert.timestamp > (self._last_alert_timestamp or datetime.min.replace(tzinfo=timezone.utc)):
                        self._last_alert_timestamp = alert.timestamp

            except Exception as e:
                logger.error(f"WazuhCollector erreur polling : {e}")

            await asyncio.sleep(self.poll_interval)

    async def fetch_once(self) -> list[RawAlert]:
        """
        Récupère les alertes disponibles une seule fois (sans boucle).
        Utilisé par le SIEMEngine pour l'ingestion à la demande.
        """
        if not await self._check_available():
            return self._mock_alerts()
        return await self._fetch_new_alerts()

    # ─────────────────────────────────────────────
    # Agents
    # ─────────────────────────────────────────────

    async def get_agents(self) -> list[AgentStatus]:
        """
        Retourne l'état de tous les agents Wazuh connectés.
        Utilisé pour synchroniser l'inventaire des assets.
        """
        if not await self._check_available():
            return self._mock_agents()

        try:
            token = await self._get_token()
            async with httpx.AsyncClient(verify=False, timeout=15) as client:
                resp = await client.get(
                    f"{self.base_url}/agents",
                    headers={"Authorization": f"Bearer {token}"},
                    params={"limit": 500, "select": "id,name,ip,status,lastKeepAlive,os,version"},
                )
                resp.raise_for_status()
                agents_data = resp.json().get("data", {}).get("affected_items", [])

            return [self._parse_agent(a) for a in agents_data]

        except Exception as e:
            logger.error(f"Erreur get_agents : {e}")
            return []

    # ─────────────────────────────────────────────
    # Authentification JWT Wazuh
    # ─────────────────────────────────────────────

    async def _get_token(self) -> str:
        """
        Obtient ou renouvelle le JWT Wazuh.
        Le token expire toutes les 15 minutes — on le renouvelle
        5 minutes avant l'expiration pour éviter les interruptions.
        """
        now = datetime.now(timezone.utc)
        if self._token and self._token_expires and now < self._token_expires:
            return self._token

        async with httpx.AsyncClient(verify=False, timeout=10) as client:
            resp = await client.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
            )
            resp.raise_for_status()
            self._token = resp.json()["data"]["token"]
            # Token valide 15 min — on renouvelle à 10 min
            self._token_expires = now + timedelta(minutes=10)
            logger.debug("Token Wazuh renouvelé")
            return self._token

    # ─────────────────────────────────────────────
    # Récupération des alertes
    # ─────────────────────────────────────────────

    async def _fetch_new_alerts(self) -> list[RawAlert]:
        """
        Récupère les alertes Wazuh depuis le dernier timestamp traité.
        Pagine automatiquement si plus de 500 alertes.
        """
        token = await self._get_token()
        alerts = []
        offset = 0
        limit = 500

        # Formater le timestamp pour l'API Wazuh
        since_str = self._last_alert_timestamp.strftime("%Y-%m-%dT%H:%M:%S") if self._last_alert_timestamp else None

        while True:
            params = {
                "limit":  limit,
                "offset": offset,
                "sort":   "+timestamp",
            }
            if since_str:
                params["q"] = f"timestamp>{since_str}"

            async with httpx.AsyncClient(verify=False, timeout=30) as client:
                resp = await client.get(
                    f"{self.base_url}/alerts",
                    headers={"Authorization": f"Bearer {token}"},
                    params=params,
                )
                resp.raise_for_status()

            data = resp.json().get("data", {})
            items = data.get("affected_items", [])
            total = data.get("total_affected_items", 0)

            for item in items:
                alert = self._parse_alert(item)
                if alert:
                    alerts.append(alert)

            offset += limit
            if offset >= total:
                break

        if alerts:
            logger.info(f"WazuhCollector : {len(alerts)} nouvelles alertes récupérées")

        return alerts

    # ─────────────────────────────────────────────
    # Parsing
    # ─────────────────────────────────────────────

    def _parse_alert(self, raw: dict) -> Optional[RawAlert]:
        """Parse une alerte Wazuh brute en RawAlert structuré."""
        try:
            agent = raw.get("agent", {})
            rule = raw.get("rule", {})

            # Parser le timestamp Wazuh (format ISO 8601)
            ts_str = raw.get("timestamp", "")
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
            except Exception:
                ts = datetime.now(timezone.utc)

            return RawAlert(
                wazuh_id=raw.get("id", ""),
                timestamp=ts,
                agent_id=agent.get("id", "000"),
                agent_name=agent.get("name", "unknown"),
                agent_ip=agent.get("ip", ""),
                rule_id=str(rule.get("id", "")),
                rule_description=rule.get("description", ""),
                rule_level=int(rule.get("level", 0)),
                rule_groups=rule.get("groups", []),
                full_log=raw.get("full_log", ""),
                data=raw.get("data", {}),
                location=raw.get("location", ""),
                decoder_name=raw.get("decoder", {}).get("name", ""),
            )
        except Exception as e:
            logger.warning(f"Impossible de parser l'alerte Wazuh : {e}")
            return None

    def _parse_agent(self, raw: dict) -> AgentStatus:
        """Parse les données d'un agent Wazuh."""
        lka = raw.get("lastKeepAlive")
        try:
            last_keep_alive = datetime.fromisoformat(lka.replace("Z", "+00:00")) if lka else None
        except Exception:
            last_keep_alive = None

        os_info = raw.get("os", {})
        return AgentStatus(
            agent_id=str(raw.get("id", "")),
            name=raw.get("name", ""),
            ip=raw.get("ip", ""),
            status=raw.get("status", "unknown"),
            last_keep_alive=last_keep_alive,
            os_name=os_info.get("name", ""),
            os_version=os_info.get("version", ""),
            version=raw.get("version", ""),
        )

    # ─────────────────────────────────────────────
    # Disponibilité
    # ─────────────────────────────────────────────

    async def _check_available(self) -> bool:
        """Vérifie si Wazuh Manager est accessible."""
        if self._available is not None:
            return self._available
        try:
            async with httpx.AsyncClient(verify=False, timeout=5) as client:
                r = await client.get(f"{self.base_url}/")
                self._available = r.status_code < 500
        except Exception:
            self._available = False
            logger.warning("Wazuh Manager inaccessible — mode simulation SIEM activé")
        return self._available

    # ─────────────────────────────────────────────
    # Simulation (développement sans Wazuh)
    # ─────────────────────────────────────────────

    def _mock_alerts(self) -> list[RawAlert]:
        """
        Alertes simulées réalistes pour le développement.
        Couvre les principaux cas d'usage : brute force SSH,
        scan de ports, connexion suspecte, modification fichier système.
        """
        now = datetime.now(timezone.utc)
        return [
            RawAlert(
                wazuh_id="mock-001",
                timestamp=now,
                agent_id="001",
                agent_name="srv-paie.internal",
                agent_ip="10.0.0.10",
                rule_id="5763",
                rule_description="SSHD brute force trying to get access to the system",
                rule_level=10,
                rule_groups=["authentication_failures", "sshd"],
                full_log="sshd[1234]: Failed password for root from 192.168.99.50 port 54321 ssh2",
                data={"srcip": "192.168.99.50", "dstport": "22"},
                location="/var/log/auth.log",
            ),
            RawAlert(
                wazuh_id="mock-002",
                timestamp=now,
                agent_id="002",
                agent_name="firewall-01",
                agent_ip="10.0.0.1",
                rule_id="40111",
                rule_description="Multiple port scans from same source",
                rule_level=8,
                rule_groups=["network", "scan"],
                full_log="kernel: [UFW BLOCK] IN=eth0 SRC=185.220.101.5 DST=10.0.0.1 DPT=3389",
                data={"srcip": "185.220.101.5", "dstport": "3389"},
                location="kernel",
            ),
            RawAlert(
                wazuh_id="mock-003",
                timestamp=now,
                agent_id="001",
                agent_name="srv-paie.internal",
                agent_ip="10.0.0.10",
                rule_id="550",
                rule_description="Integrity checksum changed",
                rule_level=7,
                rule_groups=["ossec", "syscheck"],
                full_log="File '/etc/passwd' modified. MD5 changed.",
                data={"file": "/etc/passwd"},
                location="syscheck",
            ),
        ]

    def _mock_agents(self) -> list[AgentStatus]:
        return [
            AgentStatus("001", "srv-paie.internal",    "10.0.0.10", "active",       datetime.now(timezone.utc), "Ubuntu", "22.04", "4.8.0"),
            AgentStatus("002", "firewall-01",           "10.0.0.1",  "active",       datetime.now(timezone.utc), "Linux",  "5.15",  "4.8.0"),
            AgentStatus("003", "workstation-hajer",     "10.0.0.50", "active",       datetime.now(timezone.utc), "Windows","11",     "4.8.0"),
            AgentStatus("004", "srv-backup",            "10.0.0.30", "disconnected", None,                       "Ubuntu", "20.04", "4.7.0"),
        ]
