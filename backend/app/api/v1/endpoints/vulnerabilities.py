from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from app.db.session import get_db
from app.models.vulnerability import Vulnerability, VulnStatus, VulnSeverity
from app.models.asset import Asset
from app.schemas.scan import VulnerabilityRead, VulnerabilityUpdate, VulnerabilityStats
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
    Par défaut triées par CVSS score décroissant (les plus critiques en premier).
    """
    query = select(Vulnerability)
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
    return result.scalars().all()


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

    stats = {"total": total, "open": open_count}
    for sev in ["critical", "high", "medium", "low"]:
        count = await db.scalar(
            select(func.count(Vulnerability.id)).where(Vulnerability.severity == sev)
        )
        stats[sev] = count or 0

    # Top 5 assets les plus vulnérables
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

    return VulnerabilityStats(by_asset={}, top_cvss=top_cvss, **stats)


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
    Ex: passer de OPEN → IN_REMEDIATION après assignation, puis → PATCHED après correction.
    """
    result = await db.execute(select(Vulnerability).where(Vulnerability.id == vuln_id))
    vuln = result.scalar_one_or_none()
    if not vuln:
        raise HTTPException(status_code=404, detail="Vulnérabilité introuvable")

    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(vuln, field, value)

    if payload.status == VulnStatus.PATCHED:
        from datetime import datetime, timezone
        vuln.remediated_at = datetime.now(timezone.utc)

    await db.flush()
    await db.refresh(vuln)
    return vuln
