"""
Endpoints /compliance — Gestion de la conformité.

Routes :
  GET    /compliance/dashboard            → KPIs du dashboard
  POST   /compliance/evaluate             → Lancer une évaluation complète
  GET    /compliance/policies             → Lister les politiques
  POST   /compliance/policies             → Créer une politique
  GET    /compliance/policies/{id}        → Détail d'une politique
  PATCH  /compliance/policies/{id}        → Modifier une politique
  DELETE /compliance/policies/{id}        → Supprimer une politique
  GET    /compliance/checks               → Lister les checks
  GET    /compliance/checks/asset/{id}    → Checks d'un asset
  POST   /compliance/checks/{id}/exception → Accorder une exception
  POST   /compliance/reports/generate     → Générer un rapport PDF
  GET    /compliance/reports              → Lister les rapports
  GET    /compliance/reports/{id}/download → Télécharger un rapport PDF
"""

import logging
import os
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from fastapi.responses import FileResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db.session import get_db
from app.models.compliance import (
    HardeningPolicy, ComplianceCheck, ComplianceReport,
    ComplianceStatus, PolicyFramework
)
from app.models.asset import Asset
from app.schemas.compliance import (
    PolicyCreate, PolicyRead, PolicyUpdate,
    ComplianceCheckRead, ExceptionCreate,
    ReportGenerateRequest, ReportRead,
    ComplianceDashboard, EvaluationResult,
)
from app.api.deps import get_current_user, require_analyst, require_admin
from app.models.user import User
from app.services.compliance.engine import ComplianceEngine
from app.services.compliance.pdf_report import PDFReportGenerator

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Compliance Engine"])

REPORTS_DIR = "/app/reports"


# ── Dashboard ─────────────────────────────────────────────────────

@router.get("/dashboard", response_model=ComplianceDashboard)
async def compliance_dashboard(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """KPIs Compliance pour le tableau de bord principal."""
    engine = ComplianceEngine(db)
    stats = await engine.get_dashboard_stats()
    return stats


# ── Évaluation ────────────────────────────────────────────────────

@router.post("/evaluate", response_model=EvaluationResult)
async def run_evaluation(
    framework: Optional[PolicyFramework] = Query(None),
    department: Optional[str] = Query(None),
    background_tasks: BackgroundTasks = None,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_analyst),
):
    """
    Lance une évaluation complète de conformité.

    Évalue toutes les policies actives sur tous les assets
    (ou le sous-ensemble filtré) et recalcule les scores.

    En production, les évaluations s'exécutent automatiquement
    après chaque scan VM (ScanJob completed).
    """
    engine = ComplianceEngine(db)
    result = await engine.run_full_evaluation(framework=framework, department=department)
    await db.commit()
    return result


# ── Policies ──────────────────────────────────────────────────────

@router.get("/policies", response_model=List[PolicyRead])
async def list_policies(
    framework: Optional[PolicyFramework] = Query(None),
    active_only: bool = Query(True),
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Liste les politiques de durcissement avec filtres optionnels."""
    query = select(HardeningPolicy)
    if active_only:
        query = query.where(HardeningPolicy.is_active == True)
    if framework:
        query = query.where(HardeningPolicy.framework == framework)
    query = query.offset(skip).limit(limit).order_by(HardeningPolicy.framework, HardeningPolicy.name)
    result = await db.execute(query)
    return result.scalars().all()


@router.post("/policies", response_model=PolicyRead)
async def create_policy(
    payload: PolicyCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Crée une nouvelle politique de durcissement.

    Exemples de règles :
    - port_closed : {"port": 3389, "protocol": "tcp"}  → RDP doit être fermé
    - patch_applied : {"cve_id": "CVE-2019-0708"}       → BlueKeep doit être patché
    - os_version : {"forbidden_patterns": ["2008", "XP"]} → OS EOL interdits
    - vuln_score_max : {"max_score": 7.0}               → Risk score max 7.0
    """
    policy = HardeningPolicy(
        **payload.model_dump(),
        created_by_id=current_user.id,
    )
    db.add(policy)
    await db.flush()
    await db.refresh(policy)
    return policy


@router.get("/policies/{policy_id}", response_model=PolicyRead)
async def get_policy(
    policy_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(select(HardeningPolicy).where(HardeningPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Politique introuvable")
    return policy


@router.patch("/policies/{policy_id}", response_model=PolicyRead)
async def update_policy(
    policy_id: int,
    payload: PolicyUpdate,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_analyst),
):
    result = await db.execute(select(HardeningPolicy).where(HardeningPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Politique introuvable")
    for field, value in payload.model_dump(exclude_unset=True).items():
        setattr(policy, field, value)
    await db.flush()
    await db.refresh(policy)
    return policy


@router.delete("/policies/{policy_id}", dependencies=[Depends(require_admin)])
async def delete_policy(policy_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(HardeningPolicy).where(HardeningPolicy.id == policy_id))
    policy = result.scalar_one_or_none()
    if not policy:
        raise HTTPException(status_code=404, detail="Politique introuvable")
    await db.delete(policy)
    return {"message": "Politique supprimée"}


# ── Checks ────────────────────────────────────────────────────────

@router.get("/checks", response_model=List[ComplianceCheckRead])
async def list_checks(
    status: Optional[ComplianceStatus] = Query(None),
    asset_id: Optional[int] = Query(None),
    policy_id: Optional[int] = Query(None),
    skip: int = 0,
    limit: int = 100,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Liste les résultats de vérification.
    Filtre par status=non_compliant pour voir toutes les non-conformités.
    """
    query = select(ComplianceCheck)
    if status:
        query = query.where(ComplianceCheck.status == status)
    if asset_id:
        query = query.where(ComplianceCheck.asset_id == asset_id)
    if policy_id:
        query = query.where(ComplianceCheck.policy_id == policy_id)
    query = query.offset(skip).limit(limit).order_by(ComplianceCheck.checked_at.desc().nullslast())
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/checks/asset/{asset_id}", response_model=List[ComplianceCheckRead])
async def get_asset_checks(
    asset_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Tous les checks de conformité pour un asset donné."""
    result = await db.execute(
        select(ComplianceCheck)
        .where(ComplianceCheck.asset_id == asset_id)
        .order_by(ComplianceCheck.status)
    )
    return result.scalars().all()


@router.post("/checks/{check_id}/exception")
async def grant_exception(
    check_id: int,
    payload: ExceptionCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_admin),
):
    """
    Accorde une exception sur une non-conformité.

    Une exception autorisée compte comme COMPLIANT dans le score,
    mais reste visible dans les rapports pour les auditeurs.
    Réservé aux admins — traçabilité obligatoire.
    """
    result = await db.execute(select(ComplianceCheck).where(ComplianceCheck.id == check_id))
    check = result.scalar_one_or_none()
    if not check:
        raise HTTPException(status_code=404, detail="Check introuvable")

    check.exception_granted = True
    check.exception_reason = payload.reason
    check.exception_granted_by_id = current_user.id
    check.exception_expires_at = payload.expires_at
    check.status = ComplianceStatus.COMPLIANT

    await db.flush()
    return {"message": "Exception accordée", "check_id": check_id}


# ── Rapports PDF ──────────────────────────────────────────────────

@router.post("/reports/generate", response_model=ReportRead)
async def generate_report(
    payload: ReportGenerateRequest,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """
    Génère un rapport de conformité PDF.

    Collecte les données actuelles en DB, génère le PDF
    via ReportLab et retourne les métadonnées du rapport.
    """
    # Collecter les données
    report_data = await _build_report_data(db, payload)

    # Générer le PDF
    gen = PDFReportGenerator()
    pdf_bytes = gen.generate(report_data)

    # Sauvegarder le fichier
    os.makedirs(REPORTS_DIR, exist_ok=True)
    filename = f"compliance_{payload.framework.value}_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.pdf"
    filepath = os.path.join(REPORTS_DIR, filename)
    with open(filepath, "wb") as f:
        f.write(pdf_bytes)

    # Créer l'entrée en DB
    report = ComplianceReport(
        title=payload.title,
        framework=payload.framework,
        scope_departments=payload.scope_departments,
        overall_score=report_data["overall_score"],
        scores_by_department=report_data["scores_by_department"],
        total_checks=report_data["total_checks"],
        compliant_count=report_data["compliant_count"],
        non_compliant_count=report_data["non_compliant_count"],
        pdf_path=filepath,
        generated_by_id=current_user.id,
    )
    db.add(report)
    await db.flush()
    await db.refresh(report)
    return report


@router.get("/reports", response_model=List[ReportRead])
async def list_reports(
    skip: int = 0,
    limit: int = 20,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    result = await db.execute(
        select(ComplianceReport)
        .order_by(ComplianceReport.created_at.desc())
        .offset(skip).limit(limit)
    )
    return result.scalars().all()


@router.get("/reports/{report_id}/download")
async def download_report(
    report_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Télécharge un rapport PDF généré."""
    result = await db.execute(select(ComplianceReport).where(ComplianceReport.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Rapport introuvable")
    if not report.pdf_path or not os.path.exists(report.pdf_path):
        raise HTTPException(status_code=404, detail="Fichier PDF introuvable")
    return FileResponse(
        report.pdf_path,
        media_type="application/pdf",
        filename=os.path.basename(report.pdf_path),
    )


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

async def _build_report_data(db: AsyncSession, payload: ReportGenerateRequest) -> dict:
    """Collecte toutes les données nécessaires pour le rapport."""

    # Scores par département
    query = select(Asset.department, func.avg(Asset.compliance_score))
    if payload.scope_departments:
        query = query.where(Asset.department.in_(payload.scope_departments))
    query = query.group_by(Asset.department)
    dept_result = await db.execute(query)
    scores_by_dept = {
        dept or "Non assigné": round(score or 0, 1)
        for dept, score in dept_result
    }

    # Score global
    overall_score = round(
        sum(scores_by_dept.values()) / max(len(scores_by_dept), 1), 1
    )

    # Totaux checks
    total_checks = await db.scalar(select(func.count(ComplianceCheck.id))) or 0
    compliant = await db.scalar(
        select(func.count(ComplianceCheck.id)).where(
            ComplianceCheck.status == ComplianceStatus.COMPLIANT
        )
    ) or 0
    non_compliant = await db.scalar(
        select(func.count(ComplianceCheck.id)).where(
            ComplianceCheck.status == ComplianceStatus.NON_COMPLIANT
        )
    ) or 0

    # Détail non-conformités (pour l'annexe)
    nc_result = await db.execute(
        select(
            ComplianceCheck.details,
            Asset.ip_address,
            HardeningPolicy.name,
            HardeningPolicy.severity,
        )
        .join(Asset, ComplianceCheck.asset_id == Asset.id)
        .join(HardeningPolicy, ComplianceCheck.policy_id == HardeningPolicy.id)
        .where(ComplianceCheck.status == ComplianceStatus.NON_COMPLIANT)
        .order_by(HardeningPolicy.severity.desc())
        .limit(100)
    )
    nc_checks = [
        {
            "detail":      row[0] or "",
            "asset_ip":    row[1],
            "policy_name": row[2],
            "severity":    row[3].value if row[3] else "",
        }
        for row in nc_result
    ]

    # Top violations
    viol_result = await db.execute(
        select(
            HardeningPolicy.name,
            HardeningPolicy.framework,
            func.count(ComplianceCheck.id).label("violations"),
        )
        .join(ComplianceCheck, ComplianceCheck.policy_id == HardeningPolicy.id)
        .where(ComplianceCheck.status == ComplianceStatus.NON_COMPLIANT)
        .group_by(HardeningPolicy.id, HardeningPolicy.name, HardeningPolicy.framework)
        .order_by(func.count(ComplianceCheck.id).desc())
        .limit(5)
    )
    top_violations = [
        {"policy": r[0], "framework": r[1].value if r[1] else "", "violations": r[2]}
        for r in viol_result
    ]

    total_assets = await db.scalar(select(func.count(Asset.id))) or 0

    return {
        "title":                 payload.title,
        "framework":             payload.framework.value,
        "scope":                 ", ".join(payload.scope_departments) or "Tout le parc",
        "overall_score":         overall_score,
        "scores_by_department":  scores_by_dept,
        "total_assets":          total_assets,
        "total_checks":          total_checks,
        "compliant_count":       compliant,
        "non_compliant_count":   non_compliant,
        "non_compliant_checks":  nc_checks,
        "top_violated_policies": top_violations,
    }
