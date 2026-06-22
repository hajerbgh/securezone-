"""
OpenVASScanner — Détection de vulnérabilités CVE via Greenbone/OpenVAS.

Rôle dans SecureZone :
  - Après le scan Nmap (on sait quels ports sont ouverts),
    OpenVAS teste chaque service contre sa base de 80 000+ CVEs
  - Retourne des vulnérabilités avec CVSS score, description, solution
  - Ces vulnérabilités sont stockées dans la table `vulnerabilities`

Architecture OpenVAS :
  GVM (Greenbone Vulnerability Manager) expose une API XML appelée GMP
  (Greenbone Management Protocol). On l'interroge via HTTP/HTTPS.

  Flux :
    1. Créer une "target" (liste d'IPs à scanner)
    2. Créer un "task" (lier une config de scan à une target)
    3. Démarrer le task
    4. Polling jusqu'à completion
    5. Récupérer le "report" avec les vulnérabilités trouvées
"""

import asyncio
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass, field
from typing import Optional
import httpx

logger = logging.getLogger(__name__)


@dataclass
class CVEFinding:
    """Une vulnérabilité détectée par OpenVAS."""
    name: str
    cve_id: str                    # "CVE-2024-1234" ou "" si pas de CVE
    cvss_score: float              # 0.0 – 10.0
    cvss_vector: str
    severity: str                  # "Critical" | "High" | "Medium" | "Low" | "None"
    description: str
    solution: str
    affected_ip: str
    affected_port: int
    affected_service: str
    references: list[str] = field(default_factory=list)
    cpe: str = ""                  # Common Platform Enumeration

    @property
    def severity_normalized(self) -> str:
        """Normalise la sévérité pour correspondre à VulnSeverity enum."""
        mapping = {
            "critical": "critical",
            "high":     "high",
            "medium":   "medium",
            "low":      "low",
            "none":     "none",
            "log":      "none",
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


class OpenVASScanner:
    """
    Client HTTP pour l'API GMP d'OpenVAS/Greenbone.

    En environnement de développement sans OpenVAS installé,
    le scanner bascule automatiquement en mode simulation (_mock).

    Usage :
        scanner = OpenVASScanner(base_url="http://openvas:9390")
        findings = await scanner.scan_hosts(["10.0.0.10", "10.0.0.20"])
        for f in findings:
            print(f.cve_id, f.cvss_score, f.affected_ip)
    """

    # Config de scan OpenVAS (Full and Fast)
    SCAN_CONFIG_ID = "daba56c8-73ec-11df-a475-002264764cea"
    # Scanner ID (OpenVAS Default)
    SCANNER_ID = "08b69003-5fc2-4037-a479-93b440211c73"

    def __init__(self, base_url: str = "http://localhost:9390"):
        self.base_url = base_url.rstrip("/")
        self._available: Optional[bool] = None

    async def _check_available(self) -> bool:
        """Teste si OpenVAS est accessible."""
        if self._available is not None:
            return self._available
        try:
            async with httpx.AsyncClient(timeout=5) as client:
                r = await client.get(f"{self.base_url}/gmp")
                self._available = r.status_code < 500
        except Exception:
            self._available = False
            logger.warning("OpenVAS inaccessible — mode simulation activé")
        return self._available

    async def scan_hosts(
        self,
        ip_list: list[str],
        timeout_seconds: int = 1800,   # 30 min max
    ) -> list[CVEFinding]:
        """
        Lance un scan OpenVAS sur une liste d'IPs.

        Le scan OpenVAS est lourd (plusieurs minutes). On crée un task,
        on poll toutes les 30s jusqu'à completion, puis on récupère le rapport.
        """
        if not await self._check_available():
            logger.info("OpenVAS non disponible — retour de CVEs simulées")
            return self._mock_findings(ip_list)

        try:
            target_id = await self._create_target(ip_list)
            task_id = await self._create_task(target_id)
            report_id = await self._start_and_wait(task_id, timeout_seconds)
            findings = await self._get_report(report_id)

            # Nettoyage
            await self._delete_task(task_id)
            await self._delete_target(target_id)

            logger.info(f"Scan OpenVAS terminé — {len(findings)} vulnérabilités trouvées")
            return findings

        except Exception as e:
            logger.error(f"Erreur scan OpenVAS : {e}")
            raise

    async def _gmp_request(self, xml_command: str) -> ET.Element:
        """Envoie une commande GMP (XML) à l'API OpenVAS."""
        async with httpx.AsyncClient(verify=False, timeout=30) as client:
            response = await client.post(
                f"{self.base_url}/gmp",
                content=xml_command,
                headers={"Content-Type": "application/xml"},
            )
            response.raise_for_status()
            return ET.fromstring(response.text)

    async def _create_target(self, ip_list: list[str]) -> str:
        """Crée une 'target' OpenVAS (liste d'hôtes à scanner)."""
        hosts = ", ".join(ip_list)
        xml = f"""
        <create_target>
          <name>SecureZone-scan-{asyncio.get_event_loop().time():.0f}</name>
          <hosts>{hosts}</hosts>
          <alive_tests>Consider Alive</alive_tests>
        </create_target>
        """
        root = await self._gmp_request(xml)
        target_id = root.get("id")
        logger.debug(f"Target OpenVAS créée : {target_id}")
        return target_id

    async def _create_task(self, target_id: str) -> str:
        """Crée un task OpenVAS en liant la target et la config de scan."""
        xml = f"""
        <create_task>
          <name>SecureZone-task</name>
          <config id="{self.SCAN_CONFIG_ID}"/>
          <target id="{target_id}"/>
          <scanner id="{self.SCANNER_ID}"/>
        </create_task>
        """
        root = await self._gmp_request(xml)
        task_id = root.get("id")
        logger.debug(f"Task OpenVAS créé : {task_id}")
        return task_id

    async def _start_and_wait(self, task_id: str, timeout: int) -> str:
        """Démarre le task et poll jusqu'à completion. Retourne le report_id."""
        # Démarrer le task
        await self._gmp_request(f'<start_task task_id="{task_id}"/>')
        logger.info(f"Scan OpenVAS démarré (task={task_id})")

        # Polling toutes les 30 secondes
        elapsed = 0
        poll_interval = 30
        while elapsed < timeout:
            await asyncio.sleep(poll_interval)
            elapsed += poll_interval

            status_xml = await self._gmp_request(
                f'<get_tasks task_id="{task_id}"/>'
            )
            task_el = status_xml.find(".//task")
            if task_el is None:
                continue

            status = task_el.findtext("status", "")
            progress = task_el.findtext("progress", "0")
            logger.info(f"OpenVAS progress: {progress}% — status: {status}")

            if status == "Done":
                # Récupérer l'ID du dernier rapport
                last_report = task_el.find(".//last_report/report")
                if last_report is not None:
                    return last_report.get("id", "")
                break

            if status in ("Stopped", "Stop Requested", "Failed"):
                raise RuntimeError(f"Scan OpenVAS échoué — status: {status}")

        raise asyncio.TimeoutError(f"Scan OpenVAS timeout après {timeout}s")

    async def _get_report(self, report_id: str) -> list[CVEFinding]:
        """Récupère et parse le rapport de vulnérabilités."""
        xml = f'<get_reports report_id="{report_id}" filter="levels=hmlg"/>'
        root = await self._gmp_request(xml)
        findings = []

        for result in root.findall(".//result"):
            # Ignorer les résultats sans sévérité réelle
            severity_str = result.findtext("severity", "0.0")
            try:
                cvss = float(severity_str)
            except ValueError:
                cvss = 0.0

            if cvss <= 0:
                continue

            # Extraction du CVE depuis les NVTs
            nvt = result.find("nvt")
            cve_id = ""
            references = []
            cpe = ""
            if nvt is not None:
                for ref in nvt.findall("refs/ref"):
                    ref_type = ref.get("type", "")
                    ref_id = ref.get("id", "")
                    if ref_type == "cve":
                        cve_id = ref_id
                    references.append(ref_id)
                cpe = nvt.findtext("solution/cpe", "")

            host_el = result.find("host")
            ip = host_el.text.strip() if host_el is not None else ""
            port_str = result.findtext("port", "0/tcp")
            port_num = 0
            protocol = "tcp"
            if "/" in port_str:
                parts = port_str.split("/")
                try:
                    port_num = int(parts[0])
                    protocol = parts[1]
                except (ValueError, IndexError):
                    pass

            findings.append(CVEFinding(
                name=result.findtext("name", "Unknown vulnerability"),
                cve_id=cve_id,
                cvss_score=cvss,
                cvss_vector=result.findtext("threat", ""),
                severity=self._cvss_to_severity(cvss),
                description=result.findtext("description", ""),
                solution=result.findtext("solution", ""),
                affected_ip=ip,
                affected_port=port_num,
                affected_service=protocol,
                references=references,
                cpe=cpe,
            ))

        return findings

    async def _delete_task(self, task_id: str):
        try:
            await self._gmp_request(f'<delete_task task_id="{task_id}" ultimate="1"/>')
        except Exception:
            pass

    async def _delete_target(self, target_id: str):
        try:
            await self._gmp_request(f'<delete_target target_id="{target_id}" ultimate="1"/>')
        except Exception:
            pass

    @staticmethod
    def _cvss_to_severity(score: float) -> str:
        if score >= 9.0: return "Critical"
        if score >= 7.0: return "High"
        if score >= 4.0: return "Medium"
        if score > 0.0:  return "Low"
        return "None"

    def _mock_findings(self, ip_list: list[str]) -> list[CVEFinding]:
        """CVEs simulées pour le développement sans OpenVAS."""
        mock_data = [
            CVEFinding(
                name="MS-RDP Remote Code Execution",
                cve_id="CVE-2019-0708",
                cvss_score=9.8,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                severity="Critical",
                description="BlueKeep — vulnérabilité critique RDP permettant l'exécution de code à distance sans authentification.",
                solution="Appliquer le patch MS19-0708 de Microsoft. Désactiver RDP si non nécessaire.",
                affected_ip=ip_list[0] if ip_list else "10.0.0.10",
                affected_port=3389,
                affected_service="ms-wbt-server",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
            ),
            CVEFinding(
                name="OpenSSH Authentication Bypass",
                cve_id="CVE-2023-38408",
                cvss_score=7.5,
                cvss_vector="AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                severity="High",
                description="Vulnérabilité dans ssh-agent permettant l'exécution de code arbitraire via un socket UNIX malveillant.",
                solution="Mettre à jour OpenSSH vers la version 9.3p2 ou supérieure.",
                affected_ip=ip_list[0] if ip_list else "10.0.0.1",
                affected_port=22,
                affected_service="ssh",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-38408"],
            ),
            CVEFinding(
                name="PostgreSQL Privilege Escalation",
                cve_id="CVE-2023-2454",
                cvss_score=6.5,
                cvss_vector="AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N",
                severity="Medium",
                description="Un utilisateur avec CREATE SCHEMA peut contourner les restrictions pg_catalog.",
                solution="Mettre à jour PostgreSQL vers 15.3, 14.8, 13.11 ou 12.15.",
                affected_ip=ip_list[-1] if ip_list else "10.0.0.20",
                affected_port=5432,
                affected_service="postgresql",
                references=["https://nvd.nist.gov/vuln/detail/CVE-2023-2454"],
            ),
        ]
        # Associer les IPs disponibles
        for i, finding in enumerate(mock_data):
            if i < len(ip_list):
                finding.affected_ip = ip_list[i]
        return mock_data
