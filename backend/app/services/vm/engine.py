"""
VMEngine — Orchestrateur du Vulnerability Management Engine.

Pipeline d'un scan :
  1. ScanJob créé en DB (status=running)
  2. Nmap découvre les hôtes et ports ouverts  →  met à jour les assets
  3. OpenVAS analyse les services détectés      →  crée les CVEFindings
  4. Persiste les vulnérabilités en DB
  5. Génère des alertes SIEM pour les CVE critical/high nouvelles
  6. Calcule les risk_score des assets (pondérés par leur criticité métier)
  7. Met à jour ScanJob (status=completed)

Formule risk_score :
  risk = min(10, Σ (severity_weight × cvss/10)) × criticality_multiplier
  Exemple : serveur critique (×2) avec CVE-9.8 → score ≈ 7.8
"""

import logging
from datetime import datetime, timezone

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.asset import Asset, AssetStatus, AssetType, AssetCriticality
from app.models.vulnerability import Vulnerability, ScanJob, VulnSeverity, VulnStatus
from app.models.alert import Alert, AlertSeverity, AlertCategory, AlertStatus
from app.services.vm.nmap_scanner import NmapScanner, HostScanResult
from app.services.vm.openvas_scanner import OpenVASScanner, CVEFinding
from app.core.config import settings

logger = logging.getLogger(__name__)

# Poids CVSS pour le calcul risk_score de l'asset
SEVERITY_WEIGHTS = {
    "critical": 4.0,
    "high":     2.5,
    "medium":   1.0,
    "low":      0.3,
    "none":     0.0,
}

# Multiplicateur selon la criticité métier de l'asset
CRITICALITY_MULTIPLIERS = {
    "critical": 2.0,   # Serveur de prod, AD, base de données critique
    "high":     1.5,   # Serveur applicatif important
    "medium":   1.0,   # Poste de travail standard
    "low":      0.5,   # Imprimante, IoT non critique
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
        self.nmap = NmapScanner()
        self.openvas = OpenVASScanner(
            host=settings.GVM_HOST,
            port=settings.GVM_PORT,
            username=settings.GVM_USERNAME,
            password=settings.GVM_PASSWORD,
        )

    # ─────────────────────────────────────────────
    # Point d'entrée principal
    # ─────────────────────────────────────────────

    async def run_scan(self, scan_job_id: int) -> dict:
        """
        Exécute un scan complet selon scanner_type du ScanJob :
          - "nmap"    → découverte uniquement (ports, OS, services)
          - "openvas" → scan rapide Nmap + détection CVE OpenVAS
          - "full"    → Nmap complet + OpenVAS (recommandé)
        """
        scan_job = await self._get_scan_job(scan_job_id)
        if not scan_job:
            raise ValueError(f"ScanJob #{scan_job_id} introuvable")

        await self._update_job_status(scan_job, "running", progress=0)
        logger.info(
            f"VM Engine démarré — ScanJob #{scan_job_id} | "
            f"type={scan_job.scanner_type} | ranges={scan_job.ip_ranges}"
            + (f" | exclude={scan_job.exclude_ips}" if scan_job.exclude_ips else "")
        )

        try:
            all_findings: list[CVEFinding] = []
            new_findings: list[CVEFinding] = []   # Uniquement les nouvelles (pas les re-détections)
            total_assets = 0

            exclude_ips = scan_job.exclude_ips or []
            port_range = scan_job.port_range or None

            for ip_range in scan_job.ip_ranges:
                # ── Phase 1 : Nmap ──────────────────────────────────
                # Toujours exécuté sauf si scanner_type == "openvas" seul
                # (dans ce cas : discovery rapide pour créer les assets)
                nmap_mode = "full" if scan_job.scanner_type == "full" else "discovery"
                logger.info(f"Phase 1 — Nmap [{nmap_mode}] sur {ip_range}")

                hosts = await self.nmap.scan_range(
                    ip_range,
                    mode=nmap_mode,
                    exclude_ips=exclude_ips or None,
                    port_range=port_range,
                )
                alive_hosts = [h for h in hosts if h.is_alive]
                logger.info(f"  → {len(alive_hosts)}/{len(hosts)} hôtes actifs")

                for host in alive_hosts:
                    await self._upsert_asset(host)
                total_assets += len(alive_hosts)

                await self._update_job_status(scan_job, "running", progress=40)

                # ── Phase 2 : OpenVAS ────────────────────────────────
                # Exécuté si scanner_type est "openvas" ou "full"
                if scan_job.scanner_type in ("openvas", "full") and alive_hosts:
                    ip_list = [h.ip_address for h in alive_hosts]
                    logger.info(f"Phase 2 — OpenVAS sur {len(ip_list)} hôtes")
                    findings = await self.openvas.scan_hosts(ip_list)
                    all_findings.extend(findings)
                    logger.info(f"  → {len(findings)} vulnérabilités détectées")

            await self._update_job_status(scan_job, "running", progress=75)

            # ── Phase 3 : Persistance vulnérabilités ──────────────
            vulns_saved, new_findings = await self._persist_vulnerabilities(
                all_findings, scan_job_id
            )

            # ── Phase 4 : Alertes SIEM pour CVE critiques/high nouvelles ──
            if new_findings:
                await self._generate_vuln_alerts(new_findings, scan_job_id)

            # ── Phase 5 : Recalcul risk scores (avec criticité asset) ─
            await self._recalculate_risk_scores()

            await self._update_job_status(
                scan_job, "completed", progress=100,
                assets_scanned=total_assets,
                vulnerabilities_found=vulns_saved,
            )

            summary = {
                "scan_job_id":           scan_job_id,
                "status":                "completed",
                "scanner_type":          scan_job.scanner_type,
                "assets_scanned":        total_assets,
                "vulnerabilities_found": vulns_saved,
                "critical_count":        sum(1 for f in all_findings if f.severity_normalized == "critical"),
                "high_count":            sum(1 for f in all_findings if f.severity_normalized == "high"),
                "alerts_generated":      sum(1 for f in new_findings if f.severity_normalized in ("critical", "high")),
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
        """Crée ou met à jour un Asset en DB à partir d'un résultat Nmap."""
        result = await self.db.execute(
            select(Asset).where(Asset.ip_address == host.ip_address)
        )
        asset = result.scalar_one_or_none()

        if not asset:
            asset = Asset(
                ip_address=host.ip_address,
                hostname=host.hostname or None,
                asset_type=AssetType.UNKNOWN,
                criticality=AssetCriticality.MEDIUM,
            )
            self.db.add(asset)
            logger.info(f"Nouvel asset découvert : {host.ip_address}")

        asset.status = AssetStatus.ONLINE if host.is_alive else AssetStatus.OFFLINE
        asset.last_seen = datetime.now(timezone.utc)

        if host.os_name:
            asset.os_name = host.os_name
        if host.mac_address:
            asset.mac_address = host.mac_address
        if host.hostname and not asset.hostname:
            asset.hostname = host.hostname

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
    ) -> tuple[int, list[CVEFinding]]:
        """
        Sauvegarde les CVEFindings dans la table vulnerabilities.
        - Si CVE + asset + port déjà existant → update (last_seen, cvss)
        - Sinon → insert (new)
        Retourne (nb nouvelles créées, liste des nouvelles findings).
        """
        saved = 0
        new_findings: list[CVEFinding] = []
        now = datetime.now(timezone.utc)

        severity_map = {
            "critical": VulnSeverity.CRITICAL,
            "high":     VulnSeverity.HIGH,
            "medium":   VulnSeverity.MEDIUM,
            "low":      VulnSeverity.LOW,
            "none":     VulnSeverity.NONE,
        }

        for finding in findings:
            asset_result = await self.db.execute(
                select(Asset).where(Asset.ip_address == finding.affected_ip)
            )
            asset = asset_result.scalar_one_or_none()
            if not asset:
                logger.warning(
                    f"Asset {finding.affected_ip} introuvable pour CVE {finding.cve_id}"
                )
                continue

            existing_result = await self.db.execute(
                select(Vulnerability).where(
                    Vulnerability.asset_id == asset.id,
                    Vulnerability.cve_id == (finding.cve_id or None),
                    Vulnerability.affected_port == finding.affected_port,
                )
            )
            existing = existing_result.scalar_one_or_none()

            if existing:
                # Re-détection : mettre à jour sans changer first_seen
                existing.cvss_score = finding.cvss_score
                existing.cvss_vector = finding.cvss_vector
                existing.scan_id = scan_job_id
                existing.last_seen = now
                existing.status = VulnStatus.OPEN   # Ré-ouvrir si patché entre-temps
                logger.debug(
                    f"Vuln re-détectée : {finding.cve_id} sur {finding.affected_ip}"
                )
            else:
                # Nouvelle vulnérabilité
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
                    first_seen=now,
                    last_seen=now,
                )
                self.db.add(vuln)
                new_findings.append(finding)
                saved += 1

        await self.db.flush()
        return saved, new_findings

    # ─────────────────────────────────────────────
    # Alertes SIEM pour vulnérabilités critiques
    # ─────────────────────────────────────────────

    async def _generate_vuln_alerts(
        self,
        new_findings: list[CVEFinding],
        scan_job_id: int,
    ):
        """
        Génère des alertes SIEM pour chaque nouvelle CVE critical ou high.
        Corrélation VM Engine → SIEM Engine.
        """
        now = datetime.now(timezone.utc)

        for finding in new_findings:
            if finding.severity_normalized not in ("critical", "high"):
                continue

            asset_result = await self.db.execute(
                select(Asset).where(Asset.ip_address == finding.affected_ip)
            )
            asset = asset_result.scalar_one_or_none()

            sev = (
                AlertSeverity.CRITICAL
                if finding.severity_normalized == "critical"
                else AlertSeverity.HIGH
            )

            cve_label = f"[{finding.cve_id}] " if finding.cve_id else ""
            alert = Alert(
                title=f"[VM] {finding.severity_normalized.upper()} — {cve_label}{finding.name}",
                description=(
                    f"CVSS: {finding.cvss_score} | Port: {finding.affected_port}/{finding.affected_service}\n"
                    f"{(finding.description or '')[:600]}\n\n"
                    f"Solution: {(finding.solution or 'Voir références')[:300]}"
                ),
                severity=sev,
                category=AlertCategory.VULNERABILITY,
                status=AlertStatus.OPEN,
                destination_ip=finding.affected_ip,
                destination_port=finding.affected_port,
                asset_id=asset.id if asset else None,
                risk_score=finding.cvss_score,
                first_seen=now,
                last_seen=now,
                raw_log={
                    "cve_id":      finding.cve_id,
                    "cvss_score":  finding.cvss_score,
                    "cvss_vector": finding.cvss_vector,
                    "solution":    finding.solution,
                    "references":  finding.references,
                    "scan_job_id": scan_job_id,
                },
            )
            self.db.add(alert)
            logger.info(
                f"Alerte SIEM générée : {finding.cve_id or finding.name} "
                f"[{finding.severity_normalized}] sur {finding.affected_ip}"
            )

        await self.db.flush()

    # ─────────────────────────────────────────────
    # Calcul des risk scores (avec criticité asset)
    # ─────────────────────────────────────────────

    async def _recalculate_risk_scores(self):
        """
        Recalcule le risk_score de chaque asset selon ses vulnérabilités ouvertes
        et sa criticité métier.

        Formule :
          base  = Σ (severity_weight × cvss_score / 10)
          score = min(10, base × criticality_multiplier)

        Exemples :
          Serveur critique (×2) + CVE 9.8 → score = min(10, 3.9×2) = 7.8
          5× CVE high 7.5 sur asset medium → score = min(10, 9.4×1.0) = 9.4
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

            base_score = sum(
                SEVERITY_WEIGHTS.get(v.severity.value, 0) * (v.cvss_score or 5.0) / 10.0
                for v in vulns
            )

            criticality = (asset.criticality.value if hasattr(asset.criticality, "value") else asset.criticality) or "medium"
            multiplier = CRITICALITY_MULTIPLIERS.get(criticality, 1.0)

            asset.risk_score = min(10.0, round(base_score * multiplier, 1))

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
