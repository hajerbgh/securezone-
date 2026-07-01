"""
SIEMEngine — Orchestrateur principal du SIEM.

Pipeline complet :
  1. WazuhCollector  → récupère les alertes Wazuh brutes
  2. LogNormalizer   → normalise + enrichit MITRE ATT&CK
  3. AnomalyDetector → score ML (Isolation Forest)
  4. CorrelationEngine → détecte les patterns multi-événements
  5. Persistance DB  → enregistre dans la table alerts
  6. Elasticsearch   → indexe pour la recherche full-text

Le SIEMEngine tourne en arrière-plan dans le lifespan FastAPI.
Il peut aussi être déclenché manuellement via l'endpoint /siem/ingest.
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import Optional

from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, and_

from app.models.alert import Alert, AlertStatus
from app.models.asset import Asset
from app.services.siem.wazuh_collector import WazuhCollector, RawAlert
from app.services.siem.normalizer import LogNormalizer, NormalizedEvent
from app.services.siem.correlator import CorrelationEngine, CorrelatedAlert
from app.services.siem.anomaly_detector import AnomalyDetector
from app.core.config import settings

logger = logging.getLogger(__name__)


class SIEMEngine:
    def __init__(self):
        self.collector = WazuhCollector(
            base_url=settings.WAZUH_MANAGER_URL,
            username=settings.WAZUH_API_USER,
            password=settings.WAZUH_API_PASSWORD,
        )
        self.normalizer = LogNormalizer()
        self.correlator = CorrelationEngine()
        self.anomaly_detector = AnomalyDetector()
        self._running = False

    # ─────────────────────────────────────────────
    # Ingestion principale
    # ─────────────────────────────────────────────

    async def ingest_once(self, db: AsyncSession) -> dict:
        raw_alerts = await self.collector.fetch_once()
        if not raw_alerts:
            return {"status": "ok", "collected": 0, "saved": 0}
        return await self._process_alerts(raw_alerts, db)

    async def ingest_raw(self, raw_logs: list[dict], db: AsyncSession) -> dict:
        raw_alerts = []
        for log in raw_logs:
            from app.services.siem.wazuh_collector import RawAlert
            alert = RawAlert(
                wazuh_id=log.get("id", f"ext-{datetime.now(timezone.utc).timestamp()}"),
                timestamp=datetime.now(timezone.utc),
                agent_id=log.get("agent_id", "external"),
                agent_name=log.get("hostname", "external"),
                agent_ip=log.get("source_ip", ""),
                rule_id=log.get("rule_id", "0"),
                rule_description=log.get("description", "External log"),
                rule_level=int(log.get("level", 5)),
                rule_groups=log.get("groups", []),
                full_log=log.get("message", ""),
                data=log.get("data", {}),
            )
            raw_alerts.append(alert)
        return await self._process_alerts(raw_alerts, db)

    # ─────────────────────────────────────────────
    # Pipeline de traitement
    # ─────────────────────────────────────────────

    async def _process_alerts(self, raw_alerts: list[RawAlert], db: AsyncSession) -> dict:
        stats = {
            "collected": len(raw_alerts),
            "normalized": 0,
            "anomalies_detected": 0,
            "correlated_alerts": 0,
            "simple_alerts": 0,
            "saved": 0,
        }

        # 2. Normaliser
        events = self.normalizer.normalize_batch(raw_alerts)
        stats["normalized"] = len(events)
        if not events:
            return stats

        # 3. Scorer les anomalies ML
        anomaly_events = []
        for event in events:
            self.anomaly_detector.add_to_buffer(event)
            result = self.anomaly_detector.score(event)
            if result.is_anomaly:
                event.risk_score = result.adjusted_risk_score
                event.description += f" [ML: {result.reason}]"
                anomaly_events.append(event)
                stats["anomalies_detected"] += 1

        # 4. Corrélation
        correlated, uncorrelated = self.correlator.process_batch(events)
        stats["correlated_alerts"] = len(correlated)
        stats["simple_alerts"] = len(uncorrelated)

        # 5. Persister
        saved = 0
        new_alerts: list[Alert] = []

        for ca in correlated:
            alert = await self._save_correlated_alert(ca, db)
            if alert:
                saved += 1
                new_alerts.append(alert)

        for event in uncorrelated:
            if event.severity.value in ("high", "critical") or event in anomaly_events:
                alert = await self._save_simple_alert(event, db)
                if alert:
                    saved += 1
                    new_alerts.append(alert)

        await db.flush()
        stats["saved"] = saved

        # 6. Auto-créer des incidents pour les alertes critiques/hautes (IR Engine)
        if new_alerts:
            from app.services.ir.engine import IREngine
            from app.models.alert import AlertSeverity
            ir_engine = IREngine(db)
            for alert in new_alerts:
                if alert.severity in (AlertSeverity.CRITICAL, AlertSeverity.HIGH):
                    try:
                        incident = await ir_engine.auto_create_from_alert(alert)
                        if incident:
                            await ir_engine.execute_auto_actions(incident, alert)
                    except Exception as ir_err:
                        logger.warning(f"IR auto-create échoué pour alerte #{alert.id}: {ir_err}")

        await db.flush()

        # 7. Ré-entraîner si nécessaire
        self.anomaly_detector.retrain_if_needed()

        logger.info(f"SIEM ingest : {stats}")
        return stats

    # ─────────────────────────────────────────────
    # Persistance
    # ─────────────────────────────────────────────

    async def _save_correlated_alert(
        self, ca: CorrelatedAlert, db: AsyncSession
    ) -> Optional[Alert]:
        """Enregistre une alerte corrélée — avec déduplication sur 5 minutes."""
        recent_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        existing = await db.execute(
            select(Alert).where(
                and_(
                    Alert.source_ip == ca.source_ip,
                    Alert.title == ca.title,
                    Alert.created_at >= recent_cutoff,
                )
            ).limit(1)
        )
        if existing.scalars().first():
            return None  # Doublon

        asset_id = await self._find_asset_id(ca.destination_ip, db)
        alert = Alert(
            title=ca.title,
            description=ca.description,
            severity=ca.severity,
            category=ca.category,
            status=AlertStatus.OPEN,
            source_ip=ca.source_ip,
            destination_ip=ca.destination_ip,
            destination_port=ca.destination_port,
            asset_id=asset_id,
            mitre_technique_id=ca.mitre_technique_id,
            mitre_technique_name=ca.mitre_technique_name,
            risk_score=ca.risk_score,
            event_count=ca.event_count,
            first_seen=ca.first_seen,
            last_seen=ca.last_seen,
            correlated_alert_ids=[],
            raw_log=ca.raw_data,
        )
        db.add(alert)
        return alert

    async def _save_simple_alert(
        self, event: NormalizedEvent, db: AsyncSession
    ) -> Optional[Alert]:
        """Enregistre une alerte simple — avec déduplication sur 5 minutes."""
        recent_cutoff = datetime.now(timezone.utc) - timedelta(minutes=5)
        existing = await db.execute(
            select(Alert).where(
                and_(
                    Alert.source_ip == event.source_ip,
                    Alert.mitre_technique_id == event.mitre_technique_id,
                    Alert.created_at >= recent_cutoff,
                )
            ).limit(1)
        )
        if existing.scalars().first():
            return None  # Doublon

        asset_id = await self._find_asset_id(event.destination_ip, db)
        alert = Alert(
            title=event.title,
            description=event.description,
            severity=event.severity,
            category=event.category,
            status=AlertStatus.OPEN,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            destination_port=event.destination_port,
            asset_id=asset_id,
            mitre_technique_id=event.mitre_technique_id,
            mitre_technique_name=event.mitre_technique_name,
            risk_score=event.risk_score,
            event_count=1,
            first_seen=event.timestamp,
            last_seen=event.timestamp,
            correlated_alert_ids=[],
            raw_log={"source_id": event.source_id, **event.raw_data},
        )
        db.add(alert)
        return alert

    async def _find_asset_id(self, ip: Optional[str], db: AsyncSession) -> Optional[int]:
        if not ip:
            return None
        result = await db.execute(
            select(Asset.id).where(Asset.ip_address == ip)
        )
        row = result.first()
        return row[0] if row else None

    def get_engine_status(self) -> dict:
        return {
            "running":     self._running,
            "correlator":  self.correlator.get_stats(),
            "ml_detector": self.anomaly_detector.get_stats(),
        }


# Instance globale partagée
siem_engine = SIEMEngine()