"""
Endpoints /incidents — Gestion des incidents de sécurité (IR Engine).

Routes :
  GET    /incidents/                    → Liste des incidents
  POST   /incidents/                    → Créer un incident manuellement
  GET    /incidents/stats               → Métriques MTTD/MTTR
  GET    /incidents/{id}                → Détail complet d'un incident
  PATCH  /incidents/{id}/status         → Changer le statut
  POST   /incidents/{id}/note           → Ajouter une note analyste
  POST   /incidents/{id}/run-playbook   → Attacher et démarrer un playbook
  POST   /incidents/actions/{id}/approve  → Approuver une action manuelle
  POST   /incidents/actions/{id}/execute  → Exécuter une action approuvée
  POST   /incidents/from-alert/{alert_id} → Créer depuis une alerte SIEM
"""

import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from pydantic import BaseModel
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, require_analyst
from app.db.session import get_db
from app.models.alert import Alert
from app.models.incident import (
    Incident, IncidentSeverity, IncidentStatus,
    Playbook, PlaybookAction, PlaybookActionStatus,
)
from app.models.user import User

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Incidents (IR Engine)"])


# ─────────────────────────────────────────────
# Schemas
# ─────────────────────────────────────────────

class IncidentCreate(BaseModel):
    title: str
    description: Optional[str] = None
    severity: IncidentSeverity
    source_alert_ids: List[int] = []
    ioc_list: List[str] = []
    playbook_id: Optional[int] = None


class StatusUpdate(BaseModel):
    status: IncidentStatus
    note: Optional[str] = None


class NoteCreate(BaseModel):
    note: str


# ─────────────────────────────────────────────
# Incidents CRUD
# ─────────────────────────────────────────────

@router.get("/stats")
async def get_incident_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Métriques globales : total, ouverts, critiques, MTTD, MTTR."""
    from app.services.ir.engine import IREngine
    engine = IREngine(db)
    return await engine.get_stats()


@router.get("/", response_model=List[dict])
async def list_incidents(
    status: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Liste tous les incidents, du plus récent au plus ancien."""
    query = select(Incident)
    if status:
        query = query.where(Incident.status == status)
    if severity:
        query = query.where(Incident.severity == severity)
    query = query.order_by(Incident.created_at.desc()).offset(skip).limit(limit)
    result = await db.execute(query)
    incidents = result.scalars().all()
    return [_serialize_incident(i) for i in incidents]


@router.post("/", response_model=dict, status_code=201)
async def create_incident(
    payload: IncidentCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Crée un incident manuellement (sans alerte source)."""
    incident = Incident(
        title=payload.title,
        description=payload.description,
        severity=payload.severity,
        status=IncidentStatus.NEW,
        source_alert_ids=payload.source_alert_ids,
        ioc_list=payload.ioc_list,
        risk_score=0.0,
        detected_at=datetime.now(timezone.utc),
        assigned_to_id=current_user.id,
    )
    db.add(incident)
    await db.flush()
    await db.refresh(incident)

    # Attacher un playbook si fourni
    if payload.playbook_id:
        pb_result = await db.execute(
            select(Playbook).where(Playbook.id == payload.playbook_id)
        )
        pb = pb_result.scalar_one_or_none()
        if pb:
            incident.playbook_id = pb.id
            from app.services.ir.engine import IREngine
            engine = IREngine(db)
            await engine._instantiate_playbook(incident, pb)

    await db.commit()
    await db.refresh(incident)
    return _serialize_incident(incident)


@router.get("/{incident_id}", response_model=dict)
async def get_incident(
    incident_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Détail complet d'un incident avec ses actions de playbook."""
    incident = await _get_or_404(db, incident_id)
    return await _serialize_full(db, incident)


@router.patch("/{incident_id}/status")
async def update_status(
    incident_id: int,
    payload: StatusUpdate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Change le statut d'un incident et met à jour les timestamps."""
    incident = await _get_or_404(db, incident_id)
    old_status = incident.status
    incident.status = payload.status
    now = datetime.now(timezone.utc)

    # Timestamps automatiques
    if payload.status == IncidentStatus.CONTAINMENT and not incident.contained_at:
        incident.contained_at = now
    elif payload.status == IncidentStatus.RECOVERY and not incident.resolved_at:
        incident.resolved_at = now
        if incident.detected_at:
            delta = now - incident.detected_at
            incident.mttr_minutes = int(delta.total_seconds() / 60)
    elif payload.status == IncidentStatus.CLOSED and not incident.closed_at:
        incident.closed_at = now

    # Ajouter la note dans la description si fournie
    if payload.note:
        ts = now.strftime("%Y-%m-%d %H:%M")
        annotation = f"\n\n[{ts}] {current_user.username}: {payload.note}"
        incident.description = (incident.description or "") + annotation

    await db.commit()
    return {
        "incident_id": incident_id,
        "old_status": old_status,
        "new_status": payload.status,
    }


@router.post("/{incident_id}/note")
async def add_note(
    incident_id: int,
    payload: NoteCreate,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Ajoute une note d'analyste dans la description de l'incident."""
    incident = await _get_or_404(db, incident_id)
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M")
    incident.description = (incident.description or "") + f"\n\n[{ts}] {current_user.username}: {payload.note}"
    await db.commit()
    return {"ok": True}


@router.post("/{incident_id}/run-playbook/{playbook_id}")
async def attach_playbook(
    incident_id: int,
    playbook_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_analyst),
):
    """Attache un playbook à un incident et démarre les actions auto."""
    incident = await _get_or_404(db, incident_id)

    pb_result = await db.execute(select(Playbook).where(Playbook.id == playbook_id))
    pb = pb_result.scalar_one_or_none()
    if not pb:
        raise HTTPException(status_code=404, detail="Playbook introuvable")

    from app.services.ir.engine import IREngine
    engine = IREngine(db)
    incident.playbook_id = pb.id
    await engine._instantiate_playbook(incident, pb)
    await db.commit()

    background_tasks.add_task(_run_auto_actions_bg, incident_id)
    return {"message": f"Playbook '{pb.name}' attaché, actions auto démarrées."}


# ─────────────────────────────────────────────
# Playbook Actions
# ─────────────────────────────────────────────

@router.post("/actions/{action_id}/approve")
async def approve_action(
    action_id: int,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(require_analyst),
):
    """Approuve une action manuelle (passe de PENDING à APPROVED)."""
    action = await _get_action_or_404(db, action_id)

    if action.status != PlaybookActionStatus.PENDING:
        raise HTTPException(
            status_code=409,
            detail=f"Action dans l'état '{action.status}' — ne peut pas être approuvée."
        )
    if not action.requires_approval:
        raise HTTPException(status_code=400, detail="Cette action ne nécessite pas d'approbation.")

    action.status = PlaybookActionStatus.APPROVED
    action.approved_by_id = current_user.id
    action.approved_at = datetime.now(timezone.utc)
    await db.commit()
    return {"ok": True, "action_id": action_id, "status": "approved"}


@router.post("/actions/{action_id}/execute")
async def execute_action(
    action_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_analyst),
):
    """
    Exécute une action SOAR.
    - Actions auto (requires_approval=False) : exécution directe
    - Actions manuelles : doivent être APPROVED avant
    """
    action = await _get_action_or_404(db, action_id)

    if action.status == PlaybookActionStatus.DONE:
        raise HTTPException(status_code=409, detail="Action déjà exécutée.")
    if action.status == PlaybookActionStatus.EXECUTING:
        raise HTTPException(status_code=409, detail="Action en cours d'exécution.")
    if action.requires_approval and action.status != PlaybookActionStatus.APPROVED:
        raise HTTPException(
            status_code=403,
            detail="Cette action nécessite une approbation avant exécution."
        )

    action.status = PlaybookActionStatus.EXECUTING
    await db.commit()

    background_tasks.add_task(_execute_action_bg, action_id)
    return {"ok": True, "action_id": action_id, "status": "executing"}


@router.post("/actions/{action_id}/skip")
async def skip_action(
    action_id: int,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_analyst),
):
    """Marque une action comme ignorée (SKIPPED)."""
    action = await _get_action_or_404(db, action_id)
    action.status = PlaybookActionStatus.SKIPPED
    await db.commit()
    return {"ok": True}


# ─────────────────────────────────────────────
# Création depuis une alerte
# ─────────────────────────────────────────────

@router.post("/from-alert/{alert_id}", response_model=dict, status_code=201)
async def create_from_alert(
    alert_id: int,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_analyst),
):
    """Crée un incident manuellement depuis une alerte SIEM existante."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte introuvable")

    from app.services.ir.engine import IREngine
    engine = IREngine(db)
    incident = await engine.auto_create_from_alert(alert)
    if not incident:
        raise HTTPException(
            status_code=409,
            detail="Un incident existe déjà pour cette alerte, ou la sévérité est insuffisante."
        )

    await db.commit()
    background_tasks.add_task(_run_auto_actions_bg, incident.id)
    return _serialize_incident(incident)


# ─────────────────────────────────────────────
# Playbooks
# ─────────────────────────────────────────────

@router.get("/playbooks/list")
async def list_playbooks(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Liste tous les playbooks disponibles."""
    result = await db.execute(select(Playbook).where(Playbook.is_active == True))
    playbooks = result.scalars().all()
    return [
        {
            "id": pb.id,
            "name": pb.name,
            "description": pb.description,
            "trigger_category": pb.trigger_category,
            "steps_count": len(pb.steps),
            "mitre_techniques": pb.mitre_techniques,
        }
        for pb in playbooks
    ]


# ─────────────────────────────────────────────
# Tâches de fond
# ─────────────────────────────────────────────

async def _run_auto_actions_bg(incident_id: int):
    """Exécute les actions auto d'un incident dans une session indépendante."""
    from app.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        try:
            result = await db.execute(select(Incident).where(Incident.id == incident_id))
            incident = result.scalar_one_or_none()
            if not incident:
                return

            from app.services.ir.engine import IREngine
            engine = IREngine(db)
            await engine.execute_auto_actions(incident)
            await db.commit()
            logger.info(f"Actions auto exécutées pour incident #{incident_id}")
        except Exception as e:
            logger.error(f"Erreur actions auto incident #{incident_id}: {e}")


async def _execute_action_bg(action_id: int):
    """Exécute une action SOAR spécifique en background."""
    from app.db.session import AsyncSessionLocal

    async with AsyncSessionLocal() as db:
        try:
            act_result = await db.execute(
                select(PlaybookAction).where(PlaybookAction.id == action_id)
            )
            action = act_result.scalar_one_or_none()
            if not action:
                return

            inc_result = await db.execute(
                select(Incident).where(Incident.id == action.incident_id)
            )
            incident = inc_result.scalar_one_or_none()
            if not incident:
                return

            # Charger l'alerte source si disponible
            alert = None
            if incident.source_alert_ids:
                al_result = await db.execute(
                    select(Alert).where(Alert.id == incident.source_alert_ids[0])
                )
                alert = al_result.scalar_one_or_none()

            from app.services.ir.soar import SOARExecutor
            executor = SOARExecutor(db)
            result_text = await executor.execute(action, incident, alert)

            action.status = PlaybookActionStatus.DONE
            action.executed_at = datetime.now(timezone.utc)
            action.execution_result = result_text
            await db.commit()
            logger.info(f"Action #{action_id} '{action.title}' exécutée.")
        except Exception as e:
            async with AsyncSessionLocal() as err_db:
                act_r = await err_db.execute(
                    select(PlaybookAction).where(PlaybookAction.id == action_id)
                )
                act = act_r.scalar_one_or_none()
                if act:
                    act.status = PlaybookActionStatus.FAILED
                    act.execution_result = str(e)
                    await err_db.commit()
            logger.error(f"Erreur action #{action_id}: {e}")


# ─────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────

async def _get_or_404(db: AsyncSession, incident_id: int) -> Incident:
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    incident = result.scalar_one_or_none()
    if not incident:
        raise HTTPException(status_code=404, detail="Incident introuvable")
    return incident


async def _get_action_or_404(db: AsyncSession, action_id: int) -> PlaybookAction:
    result = await db.execute(select(PlaybookAction).where(PlaybookAction.id == action_id))
    action = result.scalar_one_or_none()
    if not action:
        raise HTTPException(status_code=404, detail="Action introuvable")
    return action


def _serialize_incident(i: Incident) -> dict:
    return {
        "id": i.id,
        "title": i.title,
        "description": i.description,
        "severity": i.severity,
        "status": i.status,
        "risk_score": i.risk_score,
        "source_alert_ids": i.source_alert_ids or [],
        "ioc_list": i.ioc_list or [],
        "playbook_id": i.playbook_id,
        "assigned_to_id": i.assigned_to_id,
        "detected_at": i.detected_at.isoformat() if i.detected_at else None,
        "contained_at": i.contained_at.isoformat() if i.contained_at else None,
        "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
        "closed_at": i.closed_at.isoformat() if i.closed_at else None,
        "mttd_minutes": i.mttd_minutes,
        "mttr_minutes": i.mttr_minutes,
        "root_cause": i.root_cause,
        "lessons_learned": i.lessons_learned,
        "created_at": i.created_at.isoformat() if i.created_at else None,
    }


async def _serialize_full(db: AsyncSession, i: Incident) -> dict:
    data = _serialize_incident(i)

    # Actions du playbook
    actions_result = await db.execute(
        select(PlaybookAction)
        .where(PlaybookAction.incident_id == i.id)
        .order_by(PlaybookAction.step_order)
    )
    actions = actions_result.scalars().all()
    data["playbook_actions"] = [
        {
            "id": a.id,
            "step_order": a.step_order,
            "title": a.title,
            "action_type": a.action_type,
            "description": a.description,
            "requires_approval": bool(a.requires_approval),
            "status": a.status,
            "approved_at": a.approved_at.isoformat() if a.approved_at else None,
            "executed_at": a.executed_at.isoformat() if a.executed_at else None,
            "execution_result": a.execution_result,
        }
        for a in actions
    ]

    # Playbook info
    if i.playbook_id:
        pb_result = await db.execute(select(Playbook).where(Playbook.id == i.playbook_id))
        pb = pb_result.scalar_one_or_none()
        if pb:
            data["playbook_name"] = pb.name
            data["mitre_techniques"] = pb.mitre_techniques

    return data
