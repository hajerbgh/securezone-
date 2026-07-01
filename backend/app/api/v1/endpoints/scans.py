"""
Endpoints /scans — Gestion des scans de vulnérabilités.

Routes disponibles :
  POST   /scans/           → Créer un scan (immédiat ou planifié)
  GET    /scans/           → Lister tous les scans
  GET    /scans/scheduled  → Lister les scans planifiés actifs
  GET    /scans/{id}       → Détail d'un scan
  POST   /scans/{id}/run   → Déclencher immédiatement un scan existant
  DELETE /scans/{id}       → Supprimer un scan planifié
"""

import asyncio
import logging
from typing import List, Optional
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.db.session import get_db
from app.models.vulnerability import ScanJob
from app.models.user import User
from app.schemas.scan import ScanJobCreate, ScanJobRead, ScanJobSummary
from app.api.deps import get_current_user, require_analyst
from app.services.vm.scheduler import scan_scheduler

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Scans (VM Engine)"])


@router.post("/", response_model=ScanJobRead)
async def create_scan(
    payload: ScanJobCreate,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Crée un scan de vulnérabilités.

    - **is_scheduled=False** → scan lancé immédiatement en arrière-plan
    - **is_scheduled=True**  → scan planifié selon cron_expression

    Exemples de cron_expression :
      "0 2 * * *"    → chaque nuit à 2h00
      "0 */6 * * *"  → toutes les 6 heures
      "0 8 * * 1"    → chaque lundi à 8h00
    """
    job = ScanJob(
        name=payload.name,
        ip_ranges=payload.ip_ranges,
        exclude_ips=payload.exclude_ips,
        port_range=payload.port_range,
        scanner_type=payload.scanner_type,
        is_scheduled=payload.is_scheduled,
        cron_expression=payload.cron_expression,
        status="pending",
        created_by_id=current_user.id,
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    if payload.is_scheduled:
        # Enregistrer dans le scheduler APScheduler
        await scan_scheduler.schedule_job(job)
        logger.info(f"Scan planifié créé : #{job.id} | cron={payload.cron_expression}")
    else:
        # Lancer immédiatement en arrière-plan
        background_tasks.add_task(_run_scan_background, job.id)
        logger.info(f"Scan immédiat lancé en arrière-plan : #{job.id}")

    return job


@router.get("/", response_model=List[ScanJobSummary])
async def list_scans(
    status: Optional[str] = Query(None, description="Filtrer par status: pending|running|completed|failed"),
    scheduled_only: bool = Query(False),
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Liste tous les scans, du plus récent au plus ancien."""
    query = select(ScanJob)
    if status:
        query = query.where(ScanJob.status == status)
    if scheduled_only:
        query = query.where(ScanJob.is_scheduled == True)
    query = query.order_by(ScanJob.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    return result.scalars().all()


@router.get("/scheduled")
async def get_scheduled_jobs(_: User = Depends(get_current_user)):
    """
    Retourne les scans planifiés actifs dans APScheduler
    avec leur prochaine date d'exécution.
    """
    return {
        "scheduled_jobs": scan_scheduler.get_scheduled_jobs(),
        "count": len(scan_scheduler.get_scheduled_jobs()),
    }


@router.get("/{scan_id}", response_model=ScanJobRead)
async def get_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Détail complet d'un scan avec progression et résultats."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan introuvable")
    return job


@router.post("/{scan_id}/run")
async def trigger_scan(
    scan_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_analyst),
):
    """
    Déclenche immédiatement un scan existant (planifié ou non).
    Utile pour lancer un scan nocturne manuellement depuis le dashboard.
    """
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan introuvable")

    if job.status == "running":
        raise HTTPException(status_code=409, detail="Ce scan est déjà en cours d'exécution")

    background_tasks.add_task(_run_scan_background, scan_id)
    return {"message": f"Scan #{scan_id} déclenché", "scan_id": scan_id}


@router.delete("/{scan_id}", dependencies=[Depends(require_analyst)])
async def delete_scan(
    scan_id: int,
    db: AsyncSession = Depends(get_db),
):
    """
    Supprime un scan planifié et le retire du scheduler.
    Ne peut pas supprimer un scan en cours d'exécution.
    """
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan introuvable")

    if job.status == "running":
        raise HTTPException(status_code=409, detail="Impossible de supprimer un scan en cours")

    # Retirer du scheduler si planifié
    if job.is_scheduled:
        await scan_scheduler.unschedule_job(scan_id)

    await db.delete(job)
    return {"message": f"Scan #{scan_id} supprimé"}


@router.post("/from-alert/{alert_id}", response_model=ScanJobRead)
async def trigger_scan_from_alert(
    alert_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """
    Corrélation SIEM → VM Engine.

    Déclenche un scan de vulnérabilités ciblé sur l'IP d'une alerte SIEM.
    Utile quand le SIEM détecte une activité suspecte sur un hôte :
    on vérifie immédiatement si des CVEs exploitables sont présentes.

    L'IP utilisée est : destination_ip si disponible, sinon source_ip.
    """
    from app.models.alert import Alert
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte SIEM introuvable")

    ip = alert.destination_ip or alert.source_ip
    if not ip:
        raise HTTPException(
            status_code=422,
            detail="L'alerte n'a pas d'IP cible — impossible de lancer un scan"
        )

    job = ScanJob(
        name=f"Scan auto [Alerte #{alert_id}] — {ip}",
        ip_ranges=[ip],
        exclude_ips=[],
        scanner_type="full",
        is_scheduled=False,
        status="pending",
        created_by_id=current_user.id,
    )
    db.add(job)
    await db.flush()
    await db.refresh(job)

    background_tasks.add_task(_run_scan_background, job.id)
    logger.info(
        f"Scan de corrélation déclenché — Alerte #{alert_id} → IP {ip} | ScanJob #{job.id}"
    )
    return job


# ─────────────────────────────────────────────
# Tâche de fond — exécution du VM Engine
# ─────────────────────────────────────────────

async def _run_scan_background(scan_job_id: int):
    """
    Lance le VMEngine dans un contexte DB indépendant.
    Exécuté via BackgroundTasks FastAPI (hors cycle de vie de la requête HTTP).
    """
    from app.db.session import AsyncSessionLocal
    from app.services.vm.engine import VMEngine

    logger.info(f"Background task démarrée pour ScanJob #{scan_job_id}")
    async with AsyncSessionLocal() as db:
        try:
            engine = VMEngine(db)
            summary = await engine.run_scan(scan_job_id)
            await db.commit()
            logger.info(f"Background scan terminé : {summary}")
        except Exception as e:
            # Rollback les données partielles mais persister le status "failed"
            # dans une session séparée (le rollback annulerait le status sinon)
            try:
                async with AsyncSessionLocal() as fail_db:
                    from sqlalchemy import select as _select
                    result = await fail_db.execute(
                        _select(ScanJob).where(ScanJob.id == scan_job_id)
                    )
                    job = result.scalar_one_or_none()
                    if job:
                        job.status = "failed"
                        job.error_message = str(e)[:500]
                        await fail_db.commit()
            except Exception:
                pass
            logger.error(f"Background scan #{scan_job_id} échoué : {e}")
