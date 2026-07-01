"""
ScanScheduler — Planificateur de scans automatiques via APScheduler.

Rôle dans SecureZone :
  - Exécute automatiquement les ScanJobs marqués is_scheduled=True
  - Supporte les expressions cron ("0 2 * * *" = chaque nuit à 2h00)
  - S'intègre au lifespan FastAPI (démarrage/arrêt propre)
  - Persiste les jobs dans PostgreSQL (redémarrage sans perte)

Exemple de use case (doc projet) :
  "À 2h00 du matin, le scheduler déclenche un scan de toute la plage 10.0.0.0/16"
  → ScanJob avec cron_expression="0 2 * * *" et ip_ranges=["10.0.0.0/16"]

Architecture :
  APScheduler tourne dans le même processus FastAPI.
  Chaque job planifié crée un nouveau ScanJob en DB puis appelle VMEngine.
"""

import logging
from datetime import datetime, timezone

from apscheduler.schedulers.asyncio import AsyncIOScheduler
from apscheduler.triggers.cron import CronTrigger
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select

from app.models.vulnerability import ScanJob
from app.db.session import AsyncSessionLocal
from app.core.config import settings

logger = logging.getLogger(__name__)


class ScanScheduler:
    """
    Gestionnaire du planificateur de scans SecureZone.

    Cycle de vie :
        scheduler = ScanScheduler()
        await scheduler.start()          # Au démarrage FastAPI
        await scheduler.reload_jobs()    # Charge les jobs depuis la DB
        await scheduler.stop()           # À l'arrêt FastAPI

    Quand un ScanJob est créé/modifié via l'API :
        await scheduler.schedule_job(scan_job)    # Ajouter
        await scheduler.unschedule_job(job_id)    # Retirer
    """

    def __init__(self):
        self._scheduler = AsyncIOScheduler(
            timezone=settings.SCAN_SCHEDULER_TIMEZONE
        )
        self._running = False

    async def start(self):
        """Démarre le scheduler. Appelé dans le lifespan FastAPI."""
        if not self._running:
            self._scheduler.start()
            self._running = True
            logger.info(f"ScanScheduler démarré (timezone={settings.SCAN_SCHEDULER_TIMEZONE})")
            # Charger les jobs existants depuis la DB
            await self.reload_jobs()

    async def stop(self):
        """Arrête proprement le scheduler."""
        if self._running:
            self._scheduler.shutdown(wait=False)
            self._running = False
            logger.info("ScanScheduler arrêté")

    async def reload_jobs(self):
        """
        Charge tous les ScanJobs planifiés depuis la DB et les enregistre.
        Appelé au démarrage et après modification d'un job.
        """
        async with AsyncSessionLocal() as db:
            result = await db.execute(
                select(ScanJob).where(
                    ScanJob.is_scheduled == True,
                    ScanJob.cron_expression.isnot(None),
                )
            )
            jobs = result.scalars().all()

        # Retirer tous les jobs existants avant de recharger
        for job in self._scheduler.get_jobs():
            if job.id.startswith("scan_job_"):
                job.remove()

        for job in jobs:
            self._register_cron_job(job)

        logger.info(f"Scheduler : {len(jobs)} scan(s) planifié(s) chargé(s)")

    def _register_cron_job(self, scan_job: ScanJob):
        """Enregistre un ScanJob dans APScheduler via son expression cron."""
        job_id = f"scan_job_{scan_job.id}"

        try:
            trigger = CronTrigger.from_crontab(
                scan_job.cron_expression,
                timezone=settings.SCAN_SCHEDULER_TIMEZONE,
            )
            self._scheduler.add_job(
                func=self._execute_scheduled_scan,
                trigger=trigger,
                id=job_id,
                args=[
                    scan_job.id,
                    scan_job.ip_ranges,
                    scan_job.scanner_type,
                    scan_job.exclude_ips or [],
                    scan_job.port_range,
                ],
                name=scan_job.name or f"Scan planifié #{scan_job.id}",
                replace_existing=True,
                misfire_grace_time=3600,  # Tolérance 1h si le serveur était down
            )
            logger.info(
                f"Job planifié enregistré : {job_id} | "
                f"cron={scan_job.cron_expression} | "
                f"ranges={scan_job.ip_ranges}"
            )
        except Exception as e:
            logger.error(f"Erreur enregistrement job {job_id} : {e}")

    async def schedule_job(self, scan_job: ScanJob):
        """Planifie un nouveau ScanJob (appelé depuis l'endpoint API)."""
        if not scan_job.is_scheduled or not scan_job.cron_expression:
            return
        self._register_cron_job(scan_job)

    async def unschedule_job(self, scan_job_id: int):
        """Retire un ScanJob du scheduler."""
        job_id = f"scan_job_{scan_job_id}"
        try:
            self._scheduler.remove_job(job_id)
            logger.info(f"Job {job_id} retiré du scheduler")
        except Exception:
            pass  # Job inexistant — pas d'erreur

    def get_scheduled_jobs(self) -> list[dict]:
        """Retourne la liste des jobs planifiés avec leur prochaine exécution."""
        jobs = []
        for job in self._scheduler.get_jobs():
            if job.id.startswith("scan_job_"):
                jobs.append({
                    "job_id":   job.id,
                    "name":     job.name,
                    "next_run": job.next_run_time.isoformat() if job.next_run_time else None,
                    "trigger":  str(job.trigger),
                })
        return jobs

    async def trigger_now(self, scan_job_id: int):
        """Déclenche immédiatement un scan planifié (hors schedule)."""
        job_id = f"scan_job_{scan_job_id}"
        job = self._scheduler.get_job(job_id)
        if job:
            self._scheduler.modify_job(job_id, next_run_time=datetime.now(timezone.utc))
            logger.info(f"Scan {job_id} déclenché manuellement")
        else:
            raise ValueError(f"Job {job_id} introuvable dans le scheduler")

    # ─────────────────────────────────────────────
    # Exécution d'un scan planifié
    # ─────────────────────────────────────────────

    async def _execute_scheduled_scan(
        self,
        template_job_id: int,
        ip_ranges: list[str],
        scanner_type: str,
        exclude_ips: list[str] | None = None,
        port_range: str | None = None,
    ):
        """
        Callback APScheduler — exécuté automatiquement selon le cron.

        Crée un nouveau ScanJob "enfant" pour cette exécution,
        puis lance le VMEngine dessus.
        """
        logger.info(
            f"Scheduler déclenche le scan planifié #{template_job_id} "
            f"| ranges={ip_ranges}"
            + (f" | exclude={exclude_ips}" if exclude_ips else "")
        )

        # Ouvrir une session DB dédiée à ce job
        async with AsyncSessionLocal() as db:
            try:
                # Créer un ScanJob pour cette exécution spécifique
                execution_job = ScanJob(
                    name=f"Scan automatique - {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M')}",
                    ip_ranges=ip_ranges,
                    exclude_ips=exclude_ips or [],
                    port_range=port_range,
                    scanner_type=scanner_type,
                    is_scheduled=False,  # C'est une exécution, pas un template
                    status="pending",
                )
                db.add(execution_job)
                await db.flush()

                # Lancer le VM Engine
                from app.services.vm.engine import VMEngine
                engine = VMEngine(db)
                summary = await engine.run_scan(execution_job.id)

                await db.commit()
                logger.info(f"Scan planifié terminé : {summary}")

            except Exception as e:
                await db.rollback()
                logger.error(f"Erreur scan planifié #{template_job_id} : {e}")


# Instance globale partagée (singleton)
scan_scheduler = ScanScheduler()
