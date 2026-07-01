from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from sqlalchemy.orm import selectinload

from app.db.session import get_db
from app.models.asset import Asset, AssetType, AssetStatus
from app.models.vulnerability import Vulnerability, VulnStatus, VulnSeverity
from app.schemas.scan import (
    VulnerabilityRead,
    VulnerabilityUpdate,
    VulnerabilityStats,
    VulnerabilityImport,
    VulnerabilityImportResult,
)
from app.api.deps import get_current_user, require_analyst
from app.models.user import User

router = APIRouter(tags=["Vulnérabilités (VM Engine)"])


@router.get("/", response_model=List[VulnerabilityRead])
async def list_vulnerabilities(
    severity: Optional[VulnSeverity] = Query(None),
    status: Optional[VulnStatus] = Query(None),
    asset_id: Optional[int] = Query(None),
    cve_id: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Liste les vulnérabilités avec filtres.
    Triées par CVSS score décroissant — les plus critiques en premier.
    """
    query = (
        select(Vulnerability)
        .options(selectinload(Vulnerability.asset))
    )
    if severity:
        query = query.where(Vulnerability.severity == severity)
    if status:
        query = query.where(Vulnerability.status == status)
    if asset_id:
        query = query.where(Vulnerability.asset_id == asset_id)
    if cve_id:
        query = query.where(Vulnerability.cve_id.ilike(f"%{cve_id}%"))
    query = query.order_by(Vulnerability.cvss_score.desc().nullslast()).offset(skip).limit(limit)
    result = await db.execute(query)
    vulns = result.scalars().all()

    # Injecter asset_ip et asset_hostname dans chaque objet avant sérialisation
    response = []
    for v in vulns:
        data = {
            **{c.key: getattr(v, c.key) for c in v.__table__.columns},
            "asset_ip":       v.asset.ip_address if v.asset else None,
            "asset_hostname": v.asset.hostname if v.asset else None,
        }
        response.append(VulnerabilityRead.model_validate(data))
    return response


@router.get("/stats", response_model=VulnerabilityStats)
async def vulnerability_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Statistiques globales des vulnérabilités — pour le dashboard."""
    total = await db.scalar(select(func.count(Vulnerability.id))) or 0
    open_count = await db.scalar(
        select(func.count(Vulnerability.id)).where(Vulnerability.status == VulnStatus.OPEN)
    ) or 0

    stats: dict = {"total": total, "open": open_count}
    for sev in ("critical", "high", "medium", "low"):
        count = await db.scalar(
            select(func.count(Vulnerability.id)).where(Vulnerability.severity == sev)
        )
        stats[sev] = count or 0

    # Top 5 CVE par score CVSS
    top_result = await db.execute(
        select(Vulnerability.cvss_score, Vulnerability.cve_id, Asset.ip_address)
        .join(Asset, Vulnerability.asset_id == Asset.id)
        .where(Vulnerability.status == VulnStatus.OPEN)
        .order_by(Vulnerability.cvss_score.desc().nullslast())
        .limit(5)
    )
    top_cvss = [
        {"cve_id": row[1], "cvss_score": row[0], "asset_ip": row[2]}
        for row in top_result
    ]

    # Top 10 assets avec le plus de vulnérabilités ouvertes
    by_asset_result = await db.execute(
        select(
            Asset.ip_address,
            Asset.hostname,
            func.count(Vulnerability.id).label("vuln_count"),
        )
        .join(Vulnerability, Vulnerability.asset_id == Asset.id)
        .where(Vulnerability.status == VulnStatus.OPEN)
        .group_by(Asset.id, Asset.ip_address, Asset.hostname)
        .order_by(func.count(Vulnerability.id).desc())
        .limit(10)
    )
    by_asset = [
        {
            "ip":         row[0],
            "hostname":   row[1],
            "vuln_count": row[2],
        }
        for row in by_asset_result
    ]

    return VulnerabilityStats(by_asset=by_asset, top_cvss=top_cvss, **stats)


@router.get("/{vuln_id}", response_model=VulnerabilityRead)
async def get_vulnerability(
    vuln_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnérabilité introuvable")
    return vuln


@router.patch("/{vuln_id}", response_model=VulnerabilityRead)
async def update_vulnerability(
    vuln_id: int,
    payload: VulnerabilityUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Met à jour le statut d'une vulnérabilité.
    Workflow : OPEN → IN_REMEDIATION → PATCHED (ou ACCEPTED_RISK / FALSE_POSITIVE).
    """
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnérabilité introuvable")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(vuln, field, value)

    if payload.status == VulnStatus.PATCHED:
        vuln.remediated_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(vuln)
    return vuln


@router.post("/import", response_model=VulnerabilityImportResult, status_code=201)
async def import_vulnerabilities(
    payload: List[VulnerabilityImport],
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Import en masse depuis un scanner externe (OpenVAS, Nessus, Qualys…).
    Crée l'asset automatiquement s'il n'existe pas encore.
    Déduplique sur (asset_id, cve_id, affected_port).
    """
    saved = 0
    skipped = 0
    now = datetime.now(timezone.utc)

    for item in payload:
        # Résoudre ou créer l'asset
        result = await db.execute(
            select(Asset).where(Asset.ip_address == item.affected_ip)
        )
        asset = result.scalar_one_or_none()

        if not asset:
            asset = Asset(
                ip_address=item.affected_ip,
                hostname=item.affected_ip,
                asset_type=AssetType.UNKNOWN,
                status=AssetStatus.ONLINE,
            )
            db.add(asset)
            await db.flush()

        # Déduplication
        existing_result = await db.execute(
            select(Vulnerability).where(
                Vulnerability.asset_id == asset.id,
                Vulnerability.cve_id == (item.cve_id or None),
                Vulnerability.affected_port == item.affected_port,
            )
        )
        if existing_result.scalar_one_or_none():
            skipped += 1
            continue

        vuln = Vulnerability(
            cve_id=item.cve_id or None,
            title=item.title,
            description=item.description,
            solution=item.solution,
            cvss_score=item.cvss_score,
            severity=item.severity,
            asset_id=asset.id,
            affected_port=item.affected_port,
            affected_service=item.affected_service,
            status=VulnStatus.OPEN,
            scanner_name="import",
            references=item.references,
            first_seen=now,
            last_seen=now,
        )
        db.add(vuln)
        saved += 1

    await db.commit()
    return VulnerabilityImportResult(
        imported=saved,
        skipped=skipped,
        total_received=len(payload),
    )
