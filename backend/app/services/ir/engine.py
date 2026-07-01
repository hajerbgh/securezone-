"""
IREngine — Moteur de réponse aux incidents (Incident Response).

Rôle dans SecureZone :
  1. Reçoit une alerte SIEM critique/haute et crée automatiquement un Incident
  2. Sélectionne le playbook adapté selon la catégorie de l'alerte
  3. Instancie les PlaybookActions (étapes de réponse)
  4. Auto-exécute les étapes ne nécessitant pas d'approbation humaine

Cycle de vie d'un incident :
  NEW → ASSIGNED → INVESTIGATING → CONTAINMENT → ERADICATION → RECOVERY → CLOSED
"""

import logging
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.alert import Alert, AlertSeverity
from app.models.incident import (
    Incident, IncidentSeverity, IncidentStatus,
    Playbook, PlaybookAction, PlaybookActionStatus,
)

logger = logging.getLogger(__name__)

# Sévérités d'alerte qui déclenchent automatiquement un incident
AUTO_TRIGGER_SEVERITIES = {AlertSeverity.CRITICAL, AlertSeverity.HIGH}


class IREngine:
    """
    Orchestrateur du module Incident Response.

    Usage :
        engine = IREngine(db)
        incident = await engine.auto_create_from_alert(alert)
    """

    def __init__(self, db: AsyncSession):
        self.db = db

    # ─────────────────────────────────────────────
    # Création automatique depuis une alerte
    # ─────────────────────────────────────────────

    async def auto_create_from_alert(self, alert: Alert) -> Optional[Incident]:
        """
        Crée un incident à partir d'une alerte SIEM.

        Ne crée pas de doublon si un incident ouvert existe déjà
        pour la même alerte.
        """
        if alert.severity not in AUTO_TRIGGER_SEVERITIES:
            return None

        # Vérifier qu'on n'a pas déjà un incident pour cette alerte
        if await self._incident_exists_for_alert(alert.id):
            logger.debug(f"Incident déjà existant pour l'alerte #{alert.id}")
            return None

        # Créer l'incident
        incident = Incident(
            title=f"[AUTO] {alert.title}",
            description=(
                f"Incident créé automatiquement depuis l'alerte SIEM #{alert.id}.\n\n"
                f"Catégorie : {alert.category}\n"
                f"Source IP : {alert.source_ip or '?'} → {alert.destination_ip or '?'}\n"
                f"Description : {alert.description or '—'}"
            ),
            severity=self._map_severity(alert.severity),
            status=IncidentStatus.NEW,
            source_alert_ids=[alert.id],
            risk_score=alert.risk_score or 0.0,
            detected_at=alert.created_at or datetime.now(timezone.utc),
            ioc_list=[ip for ip in [alert.source_ip, alert.destination_ip] if ip],
        )
        self.db.add(incident)
        await self.db.flush()
        await self.db.refresh(incident)

        # Sélectionner et attacher le playbook
        playbook = await self._select_playbook(alert)
        if playbook:
            incident.playbook_id = playbook.id
            await self._instantiate_playbook(incident, playbook)
            logger.info(f"Playbook '{playbook.name}' attaché à l'incident #{incident.id}")

        logger.info(
            f"Incident #{incident.id} créé automatiquement "
            f"[{incident.severity}] depuis l'alerte #{alert.id}"
        )
        return incident

    # ─────────────────────────────────────────────
    # Sélection du playbook
    # ─────────────────────────────────────────────

    async def _select_playbook(self, alert: Alert) -> Optional[Playbook]:
        """Trouve le playbook le mieux adapté à la catégorie de l'alerte."""
        # 1. Playbook spécifique à la catégorie
        result = await self.db.execute(
            select(Playbook).where(
                Playbook.trigger_category == alert.category.value,
                Playbook.is_active == True,
            ).limit(1)
        )
        pb = result.scalar_one_or_none()
        if pb:
            return pb

        # 2. Playbook générique "high_severity"
        result = await self.db.execute(
            select(Playbook).where(
                Playbook.trigger_category == "generic_high",
                Playbook.is_active == True,
            ).limit(1)
        )
        return result.scalar_one_or_none()

    async def _instantiate_playbook(self, incident: Incident, playbook: Playbook):
        """Crée les PlaybookAction depuis les étapes JSON du playbook."""
        for step in playbook.steps:
            action = PlaybookAction(
                incident_id=incident.id,
                step_order=step["order"],
                title=step["title"],
                action_type=step["action_type"],
                description=step.get("description", ""),
                requires_approval=step.get("requires_approval", True),
                status=PlaybookActionStatus.PENDING,
            )
            self.db.add(action)

        await self.db.flush()

    # ─────────────────────────────────────────────
    # Exécution des actions auto (sans approbation)
    # ─────────────────────────────────────────────

    async def execute_auto_actions(self, incident: Incident, alert: Optional[Alert] = None):
        """
        Exécute immédiatement les actions marquées requires_approval=False.
        Appelé après la création de l'incident et ses actions.
        """
        from app.services.ir.soar import SOARExecutor
        from datetime import datetime, timezone

        executor = SOARExecutor(self.db)

        result = await self.db.execute(
            select(PlaybookAction).where(
                PlaybookAction.incident_id == incident.id,
                PlaybookAction.requires_approval == False,
                PlaybookAction.status == PlaybookActionStatus.PENDING,
            ).order_by(PlaybookAction.step_order)
        )
        auto_actions = result.scalars().all()

        for action in auto_actions:
            action.status = PlaybookActionStatus.EXECUTING
            await self.db.flush()

            result_text = await executor.execute(action, incident, alert)

            action.status = PlaybookActionStatus.DONE
            action.executed_at = datetime.now(timezone.utc)
            action.execution_result = result_text
            await self.db.flush()

            logger.info(f"Action auto '{action.title}' exécutée pour incident #{incident.id}")

    # ─────────────────────────────────────────────
    # Stats MTTD / MTTR
    # ─────────────────────────────────────────────

    async def get_stats(self) -> dict:
        """Calcule les métriques MTTD et MTTR depuis les incidents clôturés."""
        from sqlalchemy import func

        total = await self.db.scalar(select(func.count(Incident.id))) or 0
        open_count = await self.db.scalar(
            select(func.count(Incident.id)).where(
                Incident.status != IncidentStatus.CLOSED
            )
        ) or 0
        critical = await self.db.scalar(
            select(func.count(Incident.id)).where(
                Incident.severity == IncidentSeverity.CRITICAL,
                Incident.status != IncidentStatus.CLOSED,
            )
        ) or 0

        # MTTD moyen (en minutes)
        mttd_avg = await self.db.scalar(
            select(func.avg(Incident.mttd_minutes)).where(
                Incident.mttd_minutes.isnot(None)
            )
        )
        # MTTR moyen
        mttr_avg = await self.db.scalar(
            select(func.avg(Incident.mttr_minutes)).where(
                Incident.mttr_minutes.isnot(None)
            )
        )

        return {
            "total": total,
            "open": open_count,
            "critical_open": critical,
            "mttd_minutes": round(mttd_avg, 1) if mttd_avg else None,
            "mttr_minutes": round(mttr_avg, 1) if mttr_avg else None,
        }

    # ─────────────────────────────────────────────
    # Helpers
    # ─────────────────────────────────────────────

    async def _incident_exists_for_alert(self, alert_id: int) -> bool:
        from sqlalchemy.dialects.postgresql import JSONB

        result = await self.db.execute(
            select(Incident.id).where(
                Incident.source_alert_ids.cast(JSONB).contains([alert_id])
            ).limit(1)
        )
        return result.scalar_one_or_none() is not None

    @staticmethod
    def _map_severity(alert_sev: AlertSeverity) -> IncidentSeverity:
        mapping = {
            AlertSeverity.CRITICAL: IncidentSeverity.CRITICAL,
            AlertSeverity.HIGH: IncidentSeverity.HIGH,
            AlertSeverity.MEDIUM: IncidentSeverity.MEDIUM,
            AlertSeverity.LOW: IncidentSeverity.LOW,
            AlertSeverity.INFO: IncidentSeverity.LOW,
        }
        return mapping.get(alert_sev, IncidentSeverity.MEDIUM)
