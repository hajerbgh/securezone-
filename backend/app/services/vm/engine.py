"""
VMEngine — Orchestrateur du Vulnerability Management Engine.

Rôle dans SecureZone :
  - Coordonne Nmap + OpenVAS en pipeline
  - Persiste les résultats dans PostgreSQL (tables assets + vulnerabilities)
  - Met à jour les scores de risque des assets
  - Notifie le RSSI pour les vulnérabilités critiques

Pipeline d'un scan :
  1. ScanJob créé en DB (status=running)
  2. Nmap découvre les hôtes et ports ouverts  →  met à jour les assets
  3. OpenVAS analyse les services détectés      →  crée les CVEFindings
  4. Persiste les vulnérabilités en DB
  5. Calcule les risk_score des assets impactés
  6. Met à jour ScanJob (status=completed)
"""

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset, AssetStatus, AssetType
from app.models.vulnerability import Vulnerability, ScanJob, VulnSeverity, VulnStatus
from app.services.vm.nmap_scanner import NmapScanner, HostScanResult
from app.services.vm.openvas_scanner import OpenVASScanner, CVEFinding
from app.core.config import settings

logger = logging.getLogger(__name__)

# Poids CVSS → risk_score de l'asset (0–10)
SEVERITY_WEIGHTS = {
    "critical": 4.0,
    "high":     2.5,
    "medium":   1.0,
    "low":      0.3,
    "none":     0.0,
}


class VMEngine:
    """
    Orchestrateur principal du VM Engine.

    Usage (depuis un endpoint ou le scheduler) :
        engine = VMEngine(db_session)
        await engine.run_scan(scan_job_id=42)
    """

    def __init__(self, db: AsyncSession):
        self.db = db
        self.nmap = NmapScanner(nmap_path=settings.NMAP_PATH)
        self.openvas = OpenVASScanner(base_url=settings.OPENVAS_URL)

    # ─────────────────────────────────────────────
    # Point d'entrée principal
    # ─────────────────────────────────────────────

    async def run_scan(self, scan_job_id: int) -> dict:
        """
        Exécute un scan complet (Nmap + OpenVAS) pour un ScanJob donné.
        Met à jour le ScanJob et les assets/vulnérabilités en DB.
        """
        scan_job = await self._get_scan_job(scan_job_id)
        if not scan_job:
            raise ValueError(f"ScanJob #{scan_job_id} introuvable")

        # Marquer le scan comme en cours
        await self._update_job_status(scan_job, "running", progress=0)
        logger.info(f"VM Engine démarré — ScanJob #{scan_job_id} | ranges={scan_job.ip_ranges}")

        try:
            all_findings: list[CVEFinding] = []
            total_assets = 0

            # Traiter chaque plage IP
            for ip_range in scan_job.ip_ranges:
                # Phase 1 : Nmap — découverte des hôtes
                logger.info(f"Phase 1 — Nmap sur {ip_range}")
                hosts = await self.nmap.scan_range(ip_range, mode="full")
                alive_hosts = [h for h in hosts if h.is_alive]
                logger.info(f"  → {len(alive_hosts)}/{len(hosts)} hôtes actifs")

                # Phase 2 : Mise à jour des assets en DB
                for host in alive_hosts:
                    await self._upsert_asset(host)
                total_assets += len(alive_hosts)

                # Progrès : 50% après Nmap
                await self._update_job_status(scan_job, "running", progress=50)

                # Phase 3 : OpenVAS — détection CVEs
                if alive_hosts:
                    ip_list = [h.ip_address for h in alive_hosts]
                    logger.info(f"Phase 2 — OpenVAS sur {len(ip_list)} hôtes")
                    findings = await self.openvas.scan_hosts(ip_list)
                    all_findings.extend(findings)
                    logger.info(f"  → {len(findings)} vulnérabilités détectées")

            # Phase 4 : Persistance des vulnérabilités
            vulns_saved = await self._persist_vulnerabilities(all_findings, scan_job_id)

            # Phase 5 : Recalcul des risk scores
            await self._recalculate_risk_scores()

            # Finalisation du ScanJob
            await self._update_job_status(
                scan_job, "completed", progress=100,
                assets_scanned=total_assets,
                vulnerabilities_found=vulns_saved,
            )

            summary = {
                "scan_job_id":         scan_job_id,
                "status":              "completed",
                "assets_scanned":      total_assets,
                "vulnerabilities_found": vulns_saved,
                "critical_count":      sum(1 for f in all_findings if f.severity_normalized == "critical"),
                "high_count":          sum(1 for f in all_findings if f.severity_normalized == "high"),
            }
            logger.info(f"VM Engine terminé : {summary}")
            return summary

        except Exception as e:
            logger.error(f"VM Engine erreur sur ScanJob #{scan_job_id} : {e}")
            await self._update_job_status(scan_job, "failed", error_message=str(e))
            raise

    # ─────────────────────────────────────────────
    # Gestion des assets
    # ─────────────────────────────────────────────

    async def _upsert_asset(self, host: HostScanResult) -> Asset:
        """
        Crée ou met à jour un Asset en DB à partir d'un résultat Nmap.
        "Upsert" = Update if exists, Insert if not.
        """
        result = await self.db.execute(
            select(Asset).where(Asset.ip_address == host.ip_address)
        )
        asset = result.scalar_one_or_none()

        if not asset:
            # Création d'un nouvel asset découvert par le scan
            asset = Asset(
                ip_address=host.ip_address,
                hostname=host.hostname or None,
                asset_type=AssetType.UNKNOWN,
            )
            self.db.add(asset)
            logger.info(f"Nouvel asset découvert : {host.ip_address}")

        # Mise à jour des informations
        asset.status = AssetStatus.ONLINE if host.is_alive else AssetStatus.OFFLINE
        asset.last_seen = datetime.now(timezone.utc)

        if host.os_name:
            asset.os_name = host.os_name

        if host.mac_address:
            asset.mac_address = host.mac_address

        if host.hostname and not asset.hostname:
            asset.hostname = host.hostname

        # Mise à jour des ports ouverts (format JSON)
        asset.open_ports = [
            {
                "port":     p.port,
                "protocol": p.protocol,
                "state":    p.state,
                "service":  p.service,
                "version":  p.version,
            }
            for p in host.open_ports
        ]

        await self.db.flush()
        return asset

    # ─────────────────────────────────────────────
    # Persistance des vulnérabilités
    # ─────────────────────────────────────────────

    async def _persist_vulnerabilities(
        self,
        findings: list[CVEFinding],
        scan_job_id: int,
    ) -> int:
        """
        Sauvegarde les CVEFindings dans la table vulnerabilities.
        Évite les doublons : si CVE + asset_id + port déjà existant → on update.
        Retourne le nombre de nouvelles vulnérabilités créées.
        """
        saved = 0

        for finding in findings:
            # Trouver l'asset correspondant
            asset_result = await self.db.execute(
                select(Asset).where(Asset.ip_address == finding.affected_ip)
            )
            asset = asset_result.scalar_one_or_none()
            if not asset:
                logger.warning(f"Asset {finding.affected_ip} introuvable pour CVE {finding.cve_id}")
                continue

            # Vérifier si cette vuln existe déjà pour cet asset
            existing_result = await self.db.execute(
                select(Vulnerability).where(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.cve_id == (finding.cve_id or None),
                    Vulnerability.affected_port == finding.affected_port,
                )
            )
            existing = existing_result.scalar_one_or_none()

            if existing:
                # Update : re-détectée lors de ce scan
                existing.cvss_score = finding.cvss_score
                existing.scan_id = scan_job_id
                existing.status = VulnStatus.OPEN  # Re-ouvrir si était "patched"
                logger.debug(f"Vuln re-détectée : {finding.cve_id} sur {finding.affected_ip}")
            else:
                # Nouvelle vulnérabilité
                severity_map = {
                    "critical": VulnSeverity.CRITICAL,
                    "high":     VulnSeverity.HIGH,
                    "medium":   VulnSeverity.MEDIUM,
                    "low":      VulnSeverity.LOW,
                    "none":     VulnSeverity.NONE,
                }
                vuln = Vulnerability(
                    cve_id=finding.cve_id or None,
                    title=finding.name,
                    description=finding.description,
                    solution=finding.solution,
                    cvss_score=finding.cvss_score,
                    cvss_vector=finding.cvss_vector,
                    severity=severity_map.get(finding.severity_normalized, VulnSeverity.LOW),
                    asset_id=asset.id,
                    affected_port=finding.affected_port,
                    affected_service=finding.affected_service,
                    status=VulnStatus.OPEN,
                    scan_id=scan_job_id,
                    scanner_name="openvas",
                    references=finding.references,
                    cpe=finding.cpe,
                )
                self.db.add(vuln)
                saved += 1

        await self.db.flush()
        return saved

    # ─────────────────────────────────────────────
    # Calcul des risk scores
    # ─────────────────────────────────────────────

    async def _recalculate_risk_scores(self):
        """
        Recalcule le risk_score de chaque asset selon ses vulnérabilités ouvertes.

        Formule :
          risk_score = min(10, Σ (poids_sévérité × cvss_score / 10))

        Un asset avec une CVE critique (9.8) aura un score ≈ 3.9
        Un asset avec 5 CVEs high (7.5 chacune) aura un score ≈ 9.4 (plafonné à 10)
        """
        assets_result = await self.db.execute(select(Asset))
        assets = assets_result.scalars().all()

        for asset in assets:
            vulns_result = await self.db.execute(
                select(Vulnerability).where(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.status == VulnStatus.OPEN,
                )
            )
            vulns = vulns_result.scalars().all()

            if not vulns:
                asset.risk_score = 0.0
                continue

            score = sum(
                SEVERITY_WEIGHTS.get(v.severity.value, 0) * (v.cvss_score or 5.0) / 10.0
                for v in vulns
            )
            asset.risk_score = min(10.0, round(score, 1))

        await self.db.flush()
        logger.debug(f"Risk scores recalculés pour {len(assets)} assets")

    # ─────────────────────────────────────────────
    # Helpers ScanJob
    # ─────────────────────────────────────────────

    async def _get_scan_job(self, scan_job_id: int) -> ScanJob | None:
        result = await self.db.execute(
            select(ScanJob).where(ScanJob.id == scan_job_id)
        )
        return result.scalar_one_or_none()

    async def _update_job_status(
        self,
        job: ScanJob,
        status: str,
        progress: int = 0,
        assets_scanned: int = 0,
        vulnerabilities_found: int = 0,
        error_message: str | None = None,
    ):
        job.status = status
        job.progress_percent = progress
        if assets_scanned:
            job.assets_scanned = assets_scanned
        if vulnerabilities_found:
            job.vulnerabilities_found = vulnerabilities_found
        if error_message:
            job.error_message = error_message
        if status == "running" and not job.started_at:
            job.started_at = datetime.now(timezone.utc)
        if status in ("completed", "failed"):
            job.completed_at = datetime.now(timezone.utc)
        await self.db.flush()
