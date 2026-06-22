"""
Endpoints /siem — SIEM Engine API.

Routes :
  GET  /siem/dashboard         → KPIs temps réel
  POST /siem/ingest            → Ingérer des logs externes
  POST /siem/collect           → Déclencher la collecte Wazuh manuellement
  GET  /siem/status            → État du moteur SIEM
  GET  /siem/agents            → État des agents Wazuh
  GET  /siem/alerts/search     → Recherche full-text dans les alertes
  GET  /siem/mitre/summary     → Résumé des techniques MITRE détectées
"""

import logging
from datetime import datetime, timezone, timedelta
from typing import List, Optional

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, desc

from app.db.session import get_db
from app.models.alert import Alert, AlertStatus, AlertSeverity, AlertCategory
from app.schemas.siem import IngestRequest, IngestResult, SIEMDashboard, AlertSearchRequest
from app.schemas.alert import AlertRead
from app.api.deps import get_current_user, require_analyst
from app.models.user import User
from app.services.siem.engine import siem_engine

logger = logging.getLogger(__name__)
router = APIRouter(tags=["SIEM Engine"])


# ── Dashboard ─────────────────────────────────────────────────────

@router.get("/dashboard", response_model=SIEMDashboard)
async def siem_dashboard(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """KPIs SIEM temps réel pour le tableau de bord principal."""
    total = await db.scalar(select(func.count(Alert.id))) or 0
    open_count = await db.scalar(
        select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
    ) or 0
    critical = await db.scalar(
        select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.CRITICAL)
    ) or 0
    high = await db.scalar(
        select(func.count(Alert.id)).where(Alert.severity == AlertSeverity.HIGH)
    ) or 0

    # Alertes dernières 24h
    since_24h = datetime.now(timezone.utc) - timedelta(hours=24)
    last_24h = await db.scalar(
        select(func.count(Alert.id)).where(Alert.created_at >= since_24h)
    ) or 0

    # Top 5 IPs sources
    src_result = await db.execute(
        select(Alert.source_ip, func.count(Alert.id).label("count"))
        .where(Alert.source_ip.isnot(None))
        .group_by(Alert.source_ip)
        .order_by(desc("count"))
        .limit(5)
    )
    top_sources = [{"ip": row[0], "count": row[1]} for row in src_result]

    # Top catégories
    cat_result = await db.execute(
        select(Alert.category, func.count(Alert.id).label("count"))
        .group_by(Alert.category)
        .order_by(desc("count"))
        .limit(6)
    )
    top_categories = [{"category": row[0].value, "count": row[1]} for row in cat_result]

    return SIEMDashboard(
        total_alerts=total,
        open_alerts=open_count,
        critical_count=critical,
        high_count=high,
        alerts_last_24h=last_24h,
        top_sources=top_sources,
        top_categories=top_categories,
        engine_status=siem_engine.get_engine_status(),
    )


# ── Collecte et ingestion ─────────────────────────────────────────

@router.post("/collect", response_model=IngestResult)
async def trigger_collection(
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_analyst),
):
    """
    Déclenche immédiatement la collecte Wazuh.
    Normalement automatique, mais utile pour forcer une collecte
    depuis le dashboard.
    """
    result = await siem_engine.ingest_once(db)
    await db.commit()
    return result


@router.post("/ingest", response_model=IngestResult)
async def ingest_external_logs(
    payload: IngestRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(require_analyst),
):
    """
    Ingère des logs depuis une source externe (firewall, EDR, autre SIEM).

    Format attendu pour chaque log :
    {
        "id": "unique-id",
        "hostname": "srv-web",
        "source_ip": "1.2.3.4",
        "level": 8,
        "description": "Port scan detected",
        "groups": ["scan", "network"],
        "message": "raw log line here",
        "data": {}
    }
    """
    if not payload.logs:
        raise HTTPException(status_code=400, detail="Liste de logs vide")

    result = await siem_engine.ingest_raw(payload.logs, db)
    await db.commit()
    return result


# ── État du moteur ────────────────────────────────────────────────

@router.get("/status")
async def siem_status(_: User = Depends(get_current_user)):
    """État de santé du SIEM Engine (corrélateur, ML, collecteur)."""
    return siem_engine.get_engine_status()


@router.get("/agents")
async def get_wazuh_agents(_: User = Depends(get_current_user)):
    """
    Liste les agents Wazuh et leur état de connexion.
    Utile pour vérifier quelles machines sont surveillées.
    """
    agents = await siem_engine.collector.get_agents()
    return {
        "agents": [
            {
                "id":            a.agent_id,
                "name":          a.name,
                "ip":            a.ip,
                "status":        a.status,
                "os":            f"{a.os_name} {a.os_version}".strip(),
                "last_keepalive": a.last_keep_alive.isoformat() if a.last_keep_alive else None,
                "version":       a.version,
            }
            for a in agents
        ],
        "total": len(agents),
        "active": sum(1 for a in agents if a.status == "active"),
    }


# ── Recherche ─────────────────────────────────────────────────────

@router.post("/alerts/search", response_model=List[AlertRead])
async def search_alerts(
    payload: AlertSearchRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Recherche d'alertes avec filtres multiples.
    Recherche textuelle dans title + description.
    """
    query = select(Alert)

    if payload.query:
        search = f"%{payload.query}%"
        query = query.where(
            Alert.title.ilike(search) | Alert.description.ilike(search)
        )
    if payload.severity:
        query = query.where(Alert.severity == payload.severity)
    if payload.category:
        query = query.where(Alert.category == payload.category)
    if payload.from_date:
        query = query.where(Alert.created_at >= payload.from_date)
    if payload.to_date:
        query = query.where(Alert.created_at <= payload.to_date)

    query = query.order_by(Alert.created_at.desc()).limit(payload.limit)
    result = await db.execute(query)
    return result.scalars().all()


# ── MITRE ATT&CK ──────────────────────────────────────────────────

@router.get("/mitre/summary")
async def mitre_summary(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Résumé des techniques MITRE ATT&CK détectées sur le parc.
    Permet à l'analyste de voir quelles tactiques sont utilisées.
    """
    result = await db.execute(
        select(
            Alert.mitre_technique_id,
            Alert.mitre_technique_name,
            func.count(Alert.id).label("count"),
            func.max(Alert.risk_score).label("max_risk"),
        )
        .where(Alert.mitre_technique_id.isnot(None))
        .group_by(Alert.mitre_technique_id, Alert.mitre_technique_name)
        .order_by(desc("count"))
        .limit(20)
    )
    techniques = [
        {
            "technique_id":   row[0],
            "technique_name": row[1],
            "alert_count":    row[2],
            "max_risk_score": round(row[3] or 0, 1),
        }
        for row in result
    ]
    return {"techniques": techniques, "total_unique": len(techniques)}
