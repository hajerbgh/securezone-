"""
LogNormalizer — Normalisation et enrichissement des alertes Wazuh.

Rôle dans le SIEM :
  Les alertes Wazuh arrivent dans un format propriétaire avec des
  rule_id et des rule_groups spécifiques à Wazuh.

  Ce module les transforme en NormalizedEvent — un format unifié
  indépendant de la source — et les enrichit avec :
    - La catégorie d'alerte SecureZone (brute_force, port_scan, etc.)
    - La technique MITRE ATT&CK correspondante (T1110, T1046, etc.)
    - La sévérité normalisée (info/low/medium/high/critical)
    - Le score de risque initial (0.0 – 10.0)

Mapping Wazuh rule_level → sévérité :
  1-3  : info
  4-6  : low
  7-9  : medium
  10-12: high
  13-15: critical
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.services.siem.wazuh_collector import RawAlert
from app.models.alert import AlertCategory, AlertSeverity

logger = logging.getLogger(__name__)


@dataclass
class NormalizedEvent:
    """
    Événement de sécurité normalisé, prêt pour la corrélation et le stockage.
    Format unique indépendant de la source (Wazuh, Filebeat, API externe).
    """
    # Identité
    source_id: str               # ID original dans la source (Wazuh ID)
    source_system: str           # "wazuh" | "filebeat" | "api"
    timestamp: datetime

    # Localisation
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    hostname: str
    agent_id: str

    # Classification
    category: AlertCategory
    severity: AlertSeverity
    title: str
    description: str
    risk_score: float            # 0.0 – 10.0

    # MITRE ATT&CK
    mitre_technique_id: str      # ex: "T1110"
    mitre_technique_name: str    # ex: "Brute Force"
    mitre_tactic: str            # ex: "Credential Access"

    # Données brutes
    raw_log: str
    raw_data: dict = field(default_factory=dict)

    # Tags pour la corrélation
    correlation_tags: list[str] = field(default_factory=list)


# ══════════════════════════════════════════════════════════════════
# Tables de mapping Wazuh → SecureZone
# ══════════════════════════════════════════════════════════════════

# Mapping rule_groups Wazuh → catégorie SecureZone + MITRE
GROUPS_TO_CATEGORY = {
    # Authentification
    "authentication_failures":  (AlertCategory.BRUTE_FORCE,    "T1110", "Brute Force",              "Credential Access"),
    "authentication_success":   (AlertCategory.CREDENTIAL_ACCESS,"T1078","Valid Accounts",           "Defense Evasion"),
    "brute_force":              (AlertCategory.BRUTE_FORCE,    "T1110", "Brute Force",              "Credential Access"),

    # Réseau
    "scan":                     (AlertCategory.PORT_SCAN,       "T1046", "Network Service Discovery","Discovery"),
    "network":                  (AlertCategory.PORT_SCAN,       "T1046", "Network Service Discovery","Discovery"),
    "firewall":                 (AlertCategory.PORT_SCAN,       "T1046", "Network Service Discovery","Discovery"),

    # Exploitation Web
    "web":                      (AlertCategory.SQL_INJECTION,   "T1190", "Exploit Public-Facing App","Initial Access"),
    "web_appsec":               (AlertCategory.SQL_INJECTION,   "T1190", "Exploit Public-Facing App","Initial Access"),
    "attack":                   (AlertCategory.COMMAND_EXEC,    "T1059", "Command and Scripting",   "Execution"),

    # Intégrité système (syscheck = surveillance des fichiers)
    "syscheck":                 (AlertCategory.LATERAL_MOVEMENT,"T1078", "Valid Accounts",          "Defense Evasion"),
    "ossec":                    (AlertCategory.ANOMALY,         "T1036", "Masquerading",            "Defense Evasion"),

    # Exfiltration
    "data_exfiltration":        (AlertCategory.EXFILTRATION,    "T1041", "Exfiltration Over C2",   "Exfiltration"),

    # Windows specifique
    "windows":                  (AlertCategory.LATERAL_MOVEMENT,"T1021", "Remote Services",        "Lateral Movement"),
    "win_evt":                  (AlertCategory.CREDENTIAL_ACCESS,"T1003","OS Credential Dumping",  "Credential Access"),

    # Divers
    "vulnerability-detector":   (AlertCategory.VULNERABILITY,   "T1190", "Exploit Public-Facing App","Initial Access"),
}

# Mapping rule_id Wazuh spécifiques (prioritaire sur les groups)
RULE_ID_TO_CATEGORY = {
    # SSH
    "5763": (AlertCategory.BRUTE_FORCE,    "T1110", "Brute Force",              "Credential Access"),
    "5764": (AlertCategory.BRUTE_FORCE,    "T1110", "Brute Force",              "Credential Access"),
    "5710": (AlertCategory.BRUTE_FORCE,    "T1110", "Brute Force",              "Credential Access"),

    # Scan de ports
    "40111": (AlertCategory.PORT_SCAN,     "T1046", "Network Service Discovery","Discovery"),
    "40112": (AlertCategory.PORT_SCAN,     "T1046", "Network Service Discovery","Discovery"),

    # Modification fichiers critiques
    "550":  (AlertCategory.LATERAL_MOVEMENT,"T1078","Valid Accounts",           "Defense Evasion"),
    "554":  (AlertCategory.LATERAL_MOVEMENT,"T1078","Valid Accounts",           "Defense Evasion"),

    # Exécution commandes suspectes
    "87901": (AlertCategory.COMMAND_EXEC,  "T1059", "Command and Scripting",   "Execution"),
    "87902": (AlertCategory.COMMAND_EXEC,  "T1059", "Command and Scripting",   "Execution"),
}

# Mapping rule_level Wazuh → sévérité SecureZone
def _level_to_severity(level: int) -> AlertSeverity:
    if level >= 13: return AlertSeverity.CRITICAL
    if level >= 10: return AlertSeverity.HIGH
    if level >= 7:  return AlertSeverity.MEDIUM
    if level >= 4:  return AlertSeverity.LOW
    return AlertSeverity.INFO

# Score de risque initial par sévérité
SEVERITY_BASE_SCORE = {
    AlertSeverity.CRITICAL: 9.0,
    AlertSeverity.HIGH:     7.0,
    AlertSeverity.MEDIUM:   5.0,
    AlertSeverity.LOW:      3.0,
    AlertSeverity.INFO:     1.0,
}


class LogNormalizer:
    """
    Transforme les RawAlert Wazuh en NormalizedEvent.

    Le normalizer est sans état — chaque appel est indépendant.
    On peut l'appeler en parallèle sur plusieurs alertes.

    Usage :
        normalizer = LogNormalizer()
        event = normalizer.normalize(raw_alert)
        if event:
            await correlator.process(event)
    """

    def normalize(self, alert: RawAlert) -> Optional[NormalizedEvent]:
        """
        Normalise une alerte Wazuh en NormalizedEvent.
        Retourne None si l'alerte est trop peu significative (level < 3).
        """
        # Ignorer les alertes de bas niveau (informatives seulement)
        if alert.rule_level < 3:
            return None

        # Déterminer la catégorie et le mapping MITRE
        category, mitre_id, mitre_name, mitre_tactic = self._classify(alert)

        # Sévérité depuis le niveau Wazuh
        severity = _level_to_severity(alert.rule_level)

        # Score de risque de base — sera affiné par le CorrelationEngine
        risk_score = SEVERITY_BASE_SCORE[severity]

        # Extraire les IPs depuis les données structurées Wazuh
        src_ip = (
            alert.data.get("srcip") or
            alert.data.get("src_ip") or
            alert.data.get("source_ip") or
            self._extract_ip_from_log(alert.full_log, "src")
        )
        dst_ip = (
            alert.data.get("dstip") or
            alert.data.get("dst_ip") or
            alert.agent_ip or None
        )

        # Extraire les ports
        src_port = self._parse_port(alert.data.get("srcport") or alert.data.get("sport"))
        dst_port = self._parse_port(
            alert.data.get("dstport") or
            alert.data.get("dport") or
            alert.data.get("dst_port")
        )

        # Construire le titre lisible
        title = self._build_title(alert, category)

        # Tags de corrélation — permettent de regrouper les événements liés
        tags = self._build_correlation_tags(alert, src_ip, category)

        return NormalizedEvent(
            source_id=alert.wazuh_id,
            source_system="wazuh",
            timestamp=alert.timestamp,
            source_ip=src_ip,
            destination_ip=dst_ip,
            source_port=src_port,
            destination_port=dst_port,
            hostname=alert.agent_name,
            agent_id=alert.agent_id,
            category=category,
            severity=severity,
            title=title,
            description=alert.rule_description,
            risk_score=risk_score,
            mitre_technique_id=mitre_id,
            mitre_technique_name=mitre_name,
            mitre_tactic=mitre_tactic,
            raw_log=alert.full_log,
            raw_data={
                "rule_id":     alert.rule_id,
                "rule_level":  alert.rule_level,
                "rule_groups": alert.rule_groups,
                "agent_id":    alert.agent_id,
                "location":    alert.location,
                "decoder":     alert.decoder_name,
                **alert.data,
            },
            correlation_tags=tags,
        )

    def normalize_batch(self, alerts: list[RawAlert]) -> list[NormalizedEvent]:
        """Normalise une liste d'alertes, ignore les None."""
        events = []
        for alert in alerts:
            event = self.normalize(alert)
            if event:
                events.append(event)
        logger.debug(f"Normalisés : {len(events)}/{len(alerts)} alertes")
        return events

    # ─────────────────────────────────────────────
    # Classification
    # ─────────────────────────────────────────────

    def _classify(self, alert: RawAlert) -> tuple:
        """
        Détermine la catégorie et le mapping MITRE.

        Priorité :
          1. rule_id spécifique (le plus précis)
          2. premier groupe Wazuh reconnu
          3. fallback sur ANOMALY
        """
        # 1. Chercher par rule_id
        if alert.rule_id in RULE_ID_TO_CATEGORY:
            return RULE_ID_TO_CATEGORY[alert.rule_id]

        # 2. Chercher dans les groupes
        for group in alert.rule_groups:
            group_lower = group.lower()
            for key, mapping in GROUPS_TO_CATEGORY.items():
                if key in group_lower:
                    return mapping

        # 3. Fallback
        return (AlertCategory.ANOMALY, "T1036", "Masquerading", "Defense Evasion")

    # ─────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────

    def _build_title(self, alert: RawAlert, category: AlertCategory) -> str:
        """Construit un titre lisible pour l'alerte."""
        prefix_map = {
            AlertCategory.BRUTE_FORCE:      "Brute Force",
            AlertCategory.PORT_SCAN:        "Scan réseau",
            AlertCategory.SQL_INJECTION:    "Tentative injection",
            AlertCategory.COMMAND_EXEC:     "Exécution suspecte",
            AlertCategory.CREDENTIAL_ACCESS:"Accès credentials",
            AlertCategory.LATERAL_MOVEMENT: "Mouvement latéral",
            AlertCategory.EXFILTRATION:     "Exfiltration",
            AlertCategory.ANOMALY:          "Anomalie",
            AlertCategory.VULNERABILITY:    "Vulnérabilité",
        }
        prefix = prefix_map.get(category, "Alerte")
        # Tronquer la description Wazuh si trop longue
        desc = alert.rule_description[:80] if alert.rule_description else ""
        return f"{prefix} — {desc}" if desc else f"{prefix} détecté sur {alert.agent_name}"

    def _build_correlation_tags(
        self,
        alert: RawAlert,
        src_ip: Optional[str],
        category: AlertCategory,
    ) -> list[str]:
        """
        Construit les tags de corrélation.

        Ces tags permettent au CorrelationEngine de regrouper
        les événements liés. Exemple : tous les événements avec
        le tag "src:192.168.99.50" proviennent de la même IP.
        """
        tags = [f"category:{category.value}"]
        if src_ip:
            tags.append(f"src:{src_ip}")
        if alert.agent_id:
            tags.append(f"agent:{alert.agent_id}")
        if alert.agent_ip:
            tags.append(f"target:{alert.agent_ip}")
        # Tag par groupe de règle principal
        if alert.rule_groups:
            tags.append(f"rule_group:{alert.rule_groups[0]}")
        return tags

    def _extract_ip_from_log(self, log: str, direction: str = "src") -> Optional[str]:
        """Extrait une IP depuis le log brut via regex simple."""
        import re
        pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        ips = re.findall(pattern, log)
        # Filtrer les IPs locales évidentes (127.x.x.x)
        valid = [ip for ip in ips if not ip.startswith("127.")]
        if not valid:
            return None
        # Pour la source, prendre la première IP non-locale
        return valid[0] if direction == "src" else valid[-1]

    def _parse_port(self, value) -> Optional[int]:
        """Parse un port depuis une valeur potentiellement string."""
        if value is None:
            return None
        try:
            port = int(str(value))
            return port if 1 <= port <= 65535 else None
        except (ValueError, TypeError):
            return None
