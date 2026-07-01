"""
NmapScanner — Découverte de ports et services via python-nmap.

Rôle dans SecureZone :
  - Identifie les hôtes actifs sur une plage IP
  - Détecte les ports ouverts et les services qui tournent dessus
  - Enrichit l'inventaire Asset avec ces informations
  - Fournit les données de base pour OpenVAS (quoi scanner en détail)
"""

import asyncio
import logging
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class PortInfo:
    """Un port ouvert détecté sur un hôte."""
    port: int
    protocol: str          # "tcp" | "udp"
    state: str             # "open" | "filtered" | "closed"
    service: str           # "ssh" | "http" | "rdp" | ...
    version: str = ""      # ex: "OpenSSH 8.9"
    product: str = ""      # ex: "OpenSSH"
    extra_info: str = ""


@dataclass
class HostScanResult:
    """Résultat complet du scan d'un hôte."""
    ip_address: str
    hostname: str = ""
    status: str = "down"               # "up" | "down"
    os_name: str = ""
    os_accuracy: int = 0
    mac_address: str = ""
    open_ports: list[PortInfo] = field(default_factory=list)
    scan_duration_seconds: float = 0.0

    @property
    def is_alive(self) -> bool:
        return self.status == "up"

    def to_dict(self) -> dict:
        return {
            "ip_address": self.ip_address,
            "hostname": self.hostname,
            "status": self.status,
            "os_name": self.os_name,
            "mac_address": self.mac_address,
            "open_ports": [
                {
                    "port": p.port,
                    "protocol": p.protocol,
                    "state": p.state,
                    "service": p.service,
                    "version": p.version,
                    "product": p.product,
                }
                for p in self.open_ports
            ],
        }


class NmapScanner:
    """
    Wrapper autour de python-nmap pour SecureZone.

    Modes de scan disponibles :
      - discovery  : ping sweep rapide — quels hôtes sont en ligne ?
      - ports      : scan des ports les plus communs (top 1000)
      - full       : scan complet ports + détection OS + versions services
      - stealth    : scan SYN furtif (nécessite root)

    Usage :
        scanner = NmapScanner()
        results = await scanner.scan_range("10.0.1.0/24", mode="ports")
        for host in results:
            print(host.ip_address, [p.port for p in host.open_ports])
    """

    # Arguments nmap par mode de scan
    # Sur Windows : SYN scan (-sS) et détection OS (-O) nécessitent des droits admin
    # → on utilise TCP connect (-sT) qui fonctionne sans privilèges élevés
    _IS_WINDOWS = __import__("platform").system() == "Windows"

    @classmethod
    def _build_scan_modes(cls) -> dict[str, str]:
        if cls._IS_WINDOWS:
            return {
                "discovery": "-sn -T4",
                "ports":     "-sT -T4 --top-ports 1000",   # TCP connect, pas de SYN
                "full":      "-sT -sV -T4 --top-ports 1000",  # Versions, sans OS detect
                "stealth":   "-sT -T2 --top-ports 1000",
                "udp":       "-sU -T4 --top-ports 100",
            }
        return {
            "discovery": "-sn -T4",
            "ports":     "-sS -T4 --top-ports 1000",
            "full":      "-sS -sV -O -T4 -p-",
            "stealth":   "-sS -T2 --top-ports 1000",
            "udp":       "-sU -T4 --top-ports 100",
        }

    SCAN_MODES: dict[str, str] = {}  # initialisé dans __init__

    def __init__(self):
        self.SCAN_MODES = self._build_scan_modes()
        self._check_nmap_available()

    def _check_nmap_available(self):
        """Vérifie que nmap est installé sur le système."""
        import shutil
        if shutil.which("nmap"):
            logger.info(f"nmap détecté ({'Windows' if self._IS_WINDOWS else 'Linux/Mac'})")
        else:
            logger.warning("nmap introuvable dans le PATH — les scans seront simulés")

    async def scan_range(
        self,
        ip_range: str,
        mode: str = "ports",
        exclude_ips: list[str] | None = None,
        port_range: str | None = None,
        extra_args: str = "",
        timeout_seconds: int = 600,
    ) -> list[HostScanResult]:
        """
        Lance un scan nmap sur une plage IP de manière asynchrone.

        Args:
            ip_range: Plage CIDR ou IP unique. Ex: "10.0.0.0/24", "192.168.1.1"
            mode: Mode de scan (voir SCAN_MODES)
            exclude_ips: IPs/subnets à exclure. Ex: ["192.168.1.5", "10.0.0.1"]
            port_range: Ports ciblés. Ex: "22,80,443" ou "1-1000" (None = comportement du mode)
            extra_args: Arguments nmap supplémentaires
            timeout_seconds: Timeout max du scan

        Returns:
            Liste de HostScanResult pour chaque hôte découvert
        """
        if mode not in self.SCAN_MODES:
            raise ValueError(f"Mode inconnu '{mode}'. Valeurs possibles : {list(self.SCAN_MODES)}")

        nmap_args = self.SCAN_MODES[mode]

        # Remplacer le port range par défaut si spécifié
        if port_range:
            import re
            nmap_args = re.sub(r'-p[^\s]*\s*|-p-', '', nmap_args).strip()
            nmap_args += f" -p {port_range}"

        # Exclusions d'IPs
        if exclude_ips:
            exclude_str = ",".join(exclude_ips)
            nmap_args += f" --exclude {exclude_str}"

        if extra_args:
            nmap_args += f" {extra_args}"

        logger.info(
            f"Démarrage scan nmap | range={ip_range} | mode={mode}"
            + (f" | exclude={exclude_ips}" if exclude_ips else "")
            + (f" | ports={port_range}" if port_range else "")
        )

        try:
            results = await asyncio.wait_for(
                self._run_nmap(ip_range, nmap_args),
                timeout=timeout_seconds,
            )
            logger.info(f"Scan terminé | {len(results)} hôtes analysés")
            return results

        except asyncio.TimeoutError:
            logger.error(f"Timeout scan nmap après {timeout_seconds}s sur {ip_range}")
            raise
        except Exception as e:
            logger.error(f"Erreur scan nmap : {e}")
            raise

    async def _run_nmap(self, ip_range: str, args: str) -> list[HostScanResult]:
        """Exécute nmap dans un thread pool pour ne pas bloquer l'event loop."""
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, self._sync_scan, ip_range, args)

    def _sync_scan(self, ip_range: str, args: str) -> list[HostScanResult]:
        """Scan synchrone nmap — exécuté dans un thread séparé."""
        try:
            import nmap as nmap_lib
        except ImportError:
            logger.warning("python-nmap non installé — retour de données simulées")
            return self._mock_scan(ip_range)

        nm = nmap_lib.PortScanner()

        try:
            import time
            start = time.time()
            nm.scan(hosts=ip_range, arguments=args)
            duration = time.time() - start
        except nmap_lib.PortScannerError as e:
            logger.warning(f"nmap indisponible ({e}) — retour de données simulées")
            return self._mock_scan(ip_range)

        results = []
        for ip in nm.all_hosts():
            host_data = nm[ip]
            result = HostScanResult(
                ip_address=ip,
                hostname=host_data.hostname() or "",
                status=host_data.state(),
                scan_duration_seconds=duration / max(len(nm.all_hosts()), 1),
            )

            # Détection OS (disponible en mode full)
            if "osmatch" in host_data and host_data["osmatch"]:
                best_match = host_data["osmatch"][0]
                result.os_name = best_match.get("name", "")
                result.os_accuracy = int(best_match.get("accuracy", 0))

            # Adresse MAC
            if "mac" in host_data.get("addresses", {}):
                result.mac_address = host_data["addresses"]["mac"]

            # Ports ouverts
            for proto in host_data.all_protocols():
                for port in host_data[proto].keys():
                    port_data = host_data[proto][port]
                    if port_data["state"] in ("open", "filtered"):
                        result.open_ports.append(PortInfo(
                            port=port,
                            protocol=proto,
                            state=port_data["state"],
                            service=port_data.get("name", ""),
                            version=port_data.get("version", ""),
                            product=port_data.get("product", ""),
                            extra_info=port_data.get("extrainfo", ""),
                        ))

            results.append(result)

        return results

    def _mock_scan(self, ip_range: str) -> list[HostScanResult]:
        """
        Données simulées quand nmap n'est pas disponible.
        Utilise l'IP saisie comme adresse de l'hôte simulé (Metasploitable2).
        """
        import re
        # Extraire la première IP de la plage (10.0.0.1/24 → 10.0.0.1, ou IP brute)
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", ip_range.strip())
        target_ip = ip_match.group(1) if ip_match else "192.168.56.101"

        logger.info(f"Mode simulation — hôte fictif basé sur {target_ip}")
        return [
            HostScanResult(
                ip_address=target_ip,
                hostname="metasploitable.local",
                status="up",
                os_name="Linux 2.6 (Ubuntu 8.04)",
                open_ports=[
                    PortInfo(21,   "tcp", "open", "ftp",            "2.3.4", "vsftpd"),
                    PortInfo(22,   "tcp", "open", "ssh",            "4.7p1", "OpenSSH"),
                    PortInfo(23,   "tcp", "open", "telnet",         "",      "Linux telnetd"),
                    PortInfo(25,   "tcp", "open", "smtp",           "2.8.19","Postfix smtpd"),
                    PortInfo(80,   "tcp", "open", "http",           "",      "Apache httpd 2.2.8"),
                    PortInfo(139,  "tcp", "open", "netbios-ssn",    "",      "Samba smbd 3.X"),
                    PortInfo(445,  "tcp", "open", "microsoft-ds",   "",      "Samba smbd 3.0.20"),
                    PortInfo(3306, "tcp", "open", "mysql",          "5.0.51","MySQL"),
                    PortInfo(5432, "tcp", "open", "postgresql",     "8.3.0", "PostgreSQL"),
                    PortInfo(6667, "tcp", "open", "irc",            "",      "UnrealIRCd"),
                    PortInfo(8009, "tcp", "open", "ajp13",          "",      "Apache Jserv"),
                    PortInfo(8180, "tcp", "open", "http",           "",      "Apache Tomcat/Coyote"),
                ],
            ),
        ]

    async def scan_single(self, ip: str, mode: str = "ports") -> Optional[HostScanResult]:
        """Scan d'un seul hôte. Retourne None si hôte injoignable."""
        results = await self.scan_range(ip, mode=mode)
        return results[0] if results else None
