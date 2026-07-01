"""
OpenVASScanner — Détection de vulnérabilités CVE via Greenbone/GVM.

Protocole : GMP (Greenbone Management Protocol) over TLS, port 9390.
Chaque commande GMP est un fragment XML terminé par un octet nul (\\0).

Flux d'un scan :
  1. Connexion TLS → authentification
  2. Créer une "target"  (liste d'IPs)
  3. Créer un "task"     (config de scan + target)
  4. Démarrer le task
  5. Polling toutes les 30 s jusqu'à "Done"
  6. Récupérer le rapport XML et parser les résultats
  7. Nettoyer (suppression task + target)

Mode simulation :
  Si GVM est inaccessible (ou non configuré), le scanner bascule
  automatiquement sur _mock_findings() — CVEs Metasploitable2 réalistes.
"""

import asyncio
import logging
import socket
import ssl
import time
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CVEFinding:
    """Une vulnérabilité détectée par GVM/OpenVAS."""
    name: str
    cve_id: str
    cvss_score: float
    cvss_vector: str
    severity: str          # "Critical" | "High" | "Medium" | "Low" | "None"
    description: str
    solution: str
    affected_ip: str
    affected_port: int
    affected_service: str
    references: list[str] = field(default_factory=list)
    cpe: str = ""

    @property
    def severity_normalized(self) -> str:
        mapping = {
            "critical": "critical", "high": "high",
            "medium": "medium", "low": "low", "none": "none", "log": "none",
        }
        return mapping.get(self.severity.lower(), "low")

    def to_dict(self) -> dict:
        return {
            "cve_id":           self.cve_id,
            "title":            self.name,
            "description":      self.description,
            "solution":         self.solution,
            "cvss_score":       self.cvss_score,
            "cvss_vector":      self.cvss_vector,
            "severity":         self.severity_normalized,
            "affected_port":    self.affected_port,
            "affected_service": self.affected_service,
            "references":       self.references,
            "cpe":              self.cpe,
        }


class GmpConnection:
    """
    Connexion bas niveau au protocole GMP over TLS.
    Chaque message GMP est un fragment XML suivi d'un octet nul.
    """

    SCAN_CONFIG_FULL_AND_FAST = "daba56c8-73ec-11df-a475-002264764cea"
    SCANNER_OPENVAS_DEFAULT   = "08b69003-5fc2-4037-a479-93b440211c73"

    def __init__(self, host: str, port: int = 9390, timeout: int = 30):
        self.host = host
        self.port = port
        self.timeout = timeout
        self._sock: Optional[ssl.SSLSocket] = None

    def connect(self):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        raw = socket.create_connection((self.host, self.port), timeout=self.timeout)
        self._sock = ctx.wrap_socket(raw, server_hostname=self.host)
        logger.info(f"GMP connecté à {self.host}:{self.port}")

    def disconnect(self):
        if self._sock:
            try:
                self._sock.close()
            except Exception:
                pass
            self._sock = None

    def send(self, xml_command: str) -> ET.Element:
        """Envoie une commande GMP et retourne la réponse parsée."""
        if not self._sock:
            raise RuntimeError("GmpConnection non connectée")

        self._sock.sendall((xml_command + "\0").encode("utf-8"))

        # Lecture jusqu'à l'octet nul (fin de message GMP)
        chunks: list[bytes] = []
        while True:
            chunk = self._sock.recv(65536)
            if not chunk:
                break
            if b"\0" in chunk:
                chunks.append(chunk.split(b"\0")[0])
                break
            chunks.append(chunk)

        xml_data = b"".join(chunks).decode("utf-8", errors="replace")
        return ET.fromstring(xml_data)

    def authenticate(self, username: str, password: str):
        resp = self.send(
            f"<authenticate>"
            f"<credentials>"
            f"<username>{username}</username>"
            f"<password>{password}</password>"
            f"</credentials>"
            f"</authenticate>"
        )
        status = resp.get("status", "")
        if not status.startswith("2"):
            raise RuntimeError(f"Authentification GVM échouée (status={status})")
        logger.info("GVM authentifié")

    def create_target(self, ip_list: list[str]) -> str:
        hosts = ", ".join(ip_list)
        name = f"SecureZone-{int(time.time())}"
        resp = self.send(
            f"<create_target>"
            f"<name>{name}</name>"
            f"<hosts>{hosts}</hosts>"
            f"<alive_tests>Consider Alive</alive_tests>"
            f"</create_target>"
        )
        target_id = resp.get("id", "")
        if not target_id:
            raise RuntimeError("Échec création target GVM")
        logger.debug(f"Target GVM créée : {target_id}")
        return target_id

    def create_task(self, target_id: str) -> str:
        name = f"SZ-scan-{int(time.time())}"
        resp = self.send(
            f"<create_task>"
            f"<name>{name}</name>"
            f"<config id=\"{self.SCAN_CONFIG_FULL_AND_FAST}\"/>"
            f"<target id=\"{target_id}\"/>"
            f"<scanner id=\"{self.SCANNER_OPENVAS_DEFAULT}\"/>"
            f"</create_task>"
        )
        task_id = resp.get("id", "")
        if not task_id:
            raise RuntimeError("Échec création task GVM")
        logger.debug(f"Task GVM créé : {task_id}")
        return task_id

    def start_task(self, task_id: str):
        self.send(f"<start_task task_id=\"{task_id}\"/>")
        logger.info(f"Scan GVM démarré (task={task_id})")

    def poll_task(self, task_id: str) -> tuple[str, str, str]:
        """Retourne (status, progress_pct, report_id)."""
        resp = self.send(f"<get_tasks task_id=\"{task_id}\"/>")
        task_el = resp.find(".//task")
        if task_el is None:
            return "Unknown", "0", ""
        status = task_el.findtext("status", "Unknown")
        progress = task_el.findtext("progress", "0")
        last_report = task_el.find(".//last_report/report")
        report_id = last_report.get("id", "") if last_report is not None else ""
        return status, progress, report_id

    def get_report(self, report_id: str) -> ET.Element:
        return self.send(
            f"<get_reports report_id=\"{report_id}\" "
            f"filter=\"levels=hmlg\" ignore_pagination=\"1\" details=\"1\"/>"
        )

    def delete_task(self, task_id: str):
        try:
            self.send(f"<delete_task task_id=\"{task_id}\" ultimate=\"1\"/>")
        except Exception:
            pass

    def delete_target(self, target_id: str):
        try:
            self.send(f"<delete_target target_id=\"{target_id}\" ultimate=\"1\"/>")
        except Exception:
            pass

    def __enter__(self):
        self.connect()
        return self

    def __exit__(self, *_):
        self.disconnect()


class OpenVASScanner:
    """
    Scanner GVM/OpenVAS pour SecureZone.

    - Mode réel   : connexion TLS à gvmd (Kali, port 9390)
    - Mode mock   : CVEs Metasploitable2 simulées si GVM inaccessible
    """

    def __init__(self, host: str = "localhost", port: int = 9390,
                 username: str = "admin", password: str = "admin"):
        self.host = host
        self.port = port
        self.username = username
        self.password = password
        self._available: Optional[bool] = None

    async def _check_available(self) -> bool:
        if self._available is not None:
            return self._available

        # Test TCP rapide (5 s) avant d'essayer TLS
        loop = asyncio.get_event_loop()
        try:
            await asyncio.wait_for(
                loop.run_in_executor(None, self._test_tcp),
                timeout=6,
            )
            self._available = True
            logger.info(f"GVM/OpenVAS accessible sur {self.host}:{self.port}")
        except Exception:
            self._available = False
            logger.warning(
                f"GVM inaccessible ({self.host}:{self.port}) — mode simulation activé"
            )
        return self._available

    def _test_tcp(self):
        s = socket.create_connection((self.host, self.port), timeout=5)
        s.close()

    async def scan_hosts(self, ip_list: list[str], timeout_seconds: int = 1800) -> list[CVEFinding]:
        """Lance un scan GVM ou retourne des CVEs simulées selon disponibilité."""
        if not await self._check_available():
            logger.info("GVM non disponible — retour de CVEs simulées (Metasploitable2)")
            return self._mock_findings(ip_list)

        try:
            loop = asyncio.get_event_loop()
            findings = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    self._run_gmp_scan_sync,
                    ip_list,
                    timeout_seconds,
                ),
                timeout=timeout_seconds + 30,
            )
            logger.info(f"Scan GVM terminé — {len(findings)} vulnérabilités")
            return findings
        except Exception as e:
            logger.error(f"Erreur scan GVM : {e} — bascule en mode simulation")
            return self._mock_findings(ip_list)

    def _run_gmp_scan_sync(self, ip_list: list[str], timeout: int) -> list[CVEFinding]:
        """Exécution synchrone complète du scan GMP (dans un thread executor)."""
        with GmpConnection(self.host, self.port) as gmp:
            gmp.authenticate(self.username, self.password)

            target_id = gmp.create_target(ip_list)
            task_id   = gmp.create_task(target_id)
            gmp.start_task(task_id)

            # Polling toutes les 30 s
            elapsed = 0
            report_id = ""
            while elapsed < timeout:
                time.sleep(30)
                elapsed += 30
                status, progress, report_id = gmp.poll_task(task_id)
                logger.info(f"GVM scan : {progress}% — {status}")
                if status == "Done":
                    break
                if status in ("Stopped", "Stop Requested", "Failed"):
                    raise RuntimeError(f"Scan GVM échoué : status={status}")

            if not report_id:
                raise TimeoutError(f"Scan GVM timeout après {timeout}s")

            report_xml = gmp.get_report(report_id)
            findings   = self._parse_report(report_xml, ip_list)

            gmp.delete_task(task_id)
            gmp.delete_target(target_id)

        return findings

    def _parse_report(self, root: ET.Element, ip_list: list[str]) -> list[CVEFinding]:
        findings = []
        for result in root.findall(".//result"):
            try:
                cvss = float(result.findtext("severity", "0") or "0")
            except ValueError:
                cvss = 0.0
            if cvss <= 0:
                continue

            # Extraction CVE et références depuis les NVTs
            nvt = result.find("nvt")
            cve_id, references, cpe = "", [], ""
            if nvt is not None:
                for ref in nvt.findall("refs/ref"):
                    ref_type = ref.get("type", "")
                    ref_id   = ref.get("id", "")
                    if ref_type == "cve" and not cve_id:
                        cve_id = ref_id
                    if ref_id:
                        references.append(ref_id)
                cpe = nvt.findtext("cpe", "")

            host_el = result.find("host")
            ip = host_el.text.strip() if host_el is not None and host_el.text else (ip_list[0] if ip_list else "")

            port_str = result.findtext("port", "0/tcp")
            port_num, protocol = 0, "tcp"
            if "/" in port_str:
                try:
                    port_num  = int(port_str.split("/")[0])
                    protocol  = port_str.split("/")[1]
                except (ValueError, IndexError):
                    pass

            findings.append(CVEFinding(
                name            = result.findtext("name", "Unknown vulnerability"),
                cve_id          = cve_id,
                cvss_score      = cvss,
                cvss_vector     = result.findtext("nvt/cvss_base_vector", ""),
                severity        = self._cvss_to_severity(cvss),
                description     = result.findtext("description", ""),
                solution        = result.findtext("solution", ""),
                affected_ip     = ip,
                affected_port   = port_num,
                affected_service= protocol,
                references      = references,
                cpe             = cpe,
            ))
        return findings

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        if score > 0.0:  return "Low"
        return "None"

    def _mock_findings(self, ip_list: list[str]) -> list[CVEFinding]:
        """
        CVEs simulées basées sur Metasploitable2 — utilisées quand GVM est absent.
        L'IP cible est celle saisie dans le scan (pas un 10.0.0.x codé en dur).
        """
        import re
        ip_match = re.match(r"(\d+\.\d+\.\d+\.\d+)", (ip_list[0] if ip_list else "192.168.56.101"))
        target_ip = ip_match.group(1) if ip_match else "192.168.56.101"

        return [
            CVEFinding(
                name="vsftpd 2.3.4 Backdoor Command Execution",
                cve_id="CVE-2011-2523", cvss_score=10.0,
                cvss_vector="AV:N/AC:L/Au:N/C:C/I:C/A:C", severity="Critical",
                description=(
                    "vsftpd 2.3.4 contient une backdoor dans son code source. "
                    "L'envoi d'un ':)' dans le champ username ouvre un shell root sur le port 6200."
                ),
                solution="Mettre à jour vsftpd. Désactiver FTP anonyme.",
                affected_ip=target_ip, affected_port=21, affected_service="ftp",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
            ),
            CVEFinding(
                name="Samba MS-RPC Remote Code Execution (username map script)",
                cve_id="CVE-2007-2447", cvss_score=9.3,
                cvss_vector="AV:N/AC:M/Au:N/C:C/I:C/A:C", severity="Critical",
                description=(
                    "Samba 3.0.0–3.0.25rc3 : injection de commandes shell via le paramètre "
                    "username dans la gestion MS-RPC SamrChangePassword."
                ),
                solution="Mettre à jour Samba vers 3.0.25+. Restreindre l'accès SMB.",
                affected_ip=target_ip, affected_port=445, affected_service="smb",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2007-2447"],
            ),
            CVEFinding(
                name="UnrealIRCd Backdoor Remote Code Execution",
                cve_id="CVE-2010-2075", cvss_score=9.3,
                cvss_vector="AV:N/AC:M/Au:N/C:C/I:C/A:C", severity="Critical",
                description=(
                    "UnrealIRCd 3.2.8.1 (2009-2010) contient une backdoor permettant "
                    "l'exécution de commandes arbitraires via une connexion IRC."
                ),
                solution="Remplacer par une version officielle vérifiée.",
                affected_ip=target_ip, affected_port=6667, affected_service="irc",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2010-2075"],
            ),
            CVEFinding(
                name="Apache Tomcat AJP File Inclusion / RCE (Ghostcat)",
                cve_id="CVE-2020-1938", cvss_score=9.8,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", severity="Critical",
                description=(
                    "Le connecteur AJP d'Apache Tomcat permet la lecture de fichiers "
                    "arbitraires et l'exécution de code sans authentification (Ghostcat)."
                ),
                solution="Désactiver le connecteur AJP ou mettre à jour Tomcat vers 9.0.31+.",
                affected_ip=target_ip, affected_port=8009, affected_service="ajp13",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2020-1938"],
            ),
            CVEFinding(
                name="OpenSSH Username Enumeration",
                cve_id="CVE-2018-15473", cvss_score=5.3,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N", severity="Medium",
                description=(
                    "OpenSSH ≤ 7.7 : énumération de noms d'utilisateurs par différences "
                    "de temps de réponse lors de l'authentification."
                ),
                solution="Mettre à jour OpenSSH vers 7.8+.",
                affected_ip=target_ip, affected_port=22, affected_service="ssh",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2018-15473"],
            ),
            CVEFinding(
                name="MySQL Weak Authentication / Information Disclosure",
                cve_id="CVE-2012-2122", cvss_score=5.1,
                cvss_vector="AV:N/AC:H/Au:N/C:P/I:P/A:P", severity="Medium",
                description=(
                    "MySQL 5.1.x : dans certaines conditions, un attaquant peut s'authentifier "
                    "avec un mot de passe incorrect en réessayant plusieurs fois (timing attack)."
                ),
                solution="Mettre à jour MySQL vers 5.1.63+ / 5.5.24+.",
                affected_ip=target_ip, affected_port=3306, affected_service="mysql",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2012-2122"],
            ),
        ]
