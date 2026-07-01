from typing import List, Optional
from fastapi import APIRouter, Depends, Header, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func

from app.db.session import get_db
from app.models.alert import Alert, AlertCategory, AlertStatus, AlertSeverity
from app.schemas.alert import AlertRead
from app.api.deps import get_current_user
from app.models.user import User
from app.core.config import settings
from app.services.siem.phishing import (
    PhishingDetectionEngine, analyze_url, analyze_email,
)

router = APIRouter(tags=["Phishing"])
_engine = PhishingDetectionEngine()


# ── Schémas ──────────────────────────────────────────────────────

class URLRequest(BaseModel):
    url: str
    source_ip: Optional[str] = None
    user: Optional[str] = None
    create_alert: bool = True


class EmailRequest(BaseModel):
    sender: str
    subject: str = ""
    spf_result: str = "none"
    dmarc_result: str = "none"
    body_urls: list[str] = []
    reply_to: Optional[str] = None
    recipient: Optional[str] = None
    source_ip: Optional[str] = None
    create_alert: bool = True


class PhishingStats(BaseModel):
    total: int
    open: int
    high_risk: int
    critical: int


# ── Endpoints ────────────────────────────────────────────────────

@router.post("/analyze/url")
async def analyze_url_ep(
    req: URLRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Analyse heuristique d'une URL. Si create_alert=true et score ≥ 31, crée une alerte SIEM."""
    score_obj = analyze_url(req.url)
    result = {
        "score": score_obj.score,
        "severity": score_obj.severity,
        "indicators": score_obj.indicators,
        "details": score_obj.details,
        "is_phishing": score_obj.is_phishing,
        "alert_created": False,
    }

    if req.create_alert and score_obj.score >= 31:
        extra = await _engine.process(
            event_type="url",
            db=db,
            source_ip=req.source_ip,
            url=req.url,
            user=req.user,
        )
        result["alert_created"] = extra.get("alert_created", False)
        result["alert_id"] = extra.get("alert_id")

    return result


@router.post("/analyze/email")
async def analyze_email_ep(
    req: EmailRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Analyse heuristique d'un email. Si create_alert=true et score ≥ 31, crée une alerte SIEM."""
    score_obj = analyze_email(
        sender=req.sender,
        subject=req.subject,
        spf_result=req.spf_result,
        dmarc_result=req.dmarc_result,
        body_urls=req.body_urls,
        reply_to=req.reply_to,
    )
    result = {
        "score": score_obj.score,
        "severity": score_obj.severity,
        "indicators": score_obj.indicators,
        "details": score_obj.details,
        "is_phishing": score_obj.is_phishing,
        "alert_created": False,
    }

    if req.create_alert and score_obj.score >= 31:
        extra = await _engine.process(
            event_type="email",
            db=db,
            source_ip=req.source_ip,
            sender=req.sender,
            subject=req.subject,
            spf_result=req.spf_result,
            dmarc_result=req.dmarc_result,
            body_urls=req.body_urls,
            reply_to=req.reply_to,
            recipient=req.recipient,
        )
        result["alert_created"] = extra.get("alert_created", False)
        result["alert_id"] = extra.get("alert_id")

    return result


@router.get("/alerts", response_model=List[AlertRead])
async def list_phishing_alerts(
    skip: int = 0,
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """Alertes SIEM de catégorie phishing."""
    result = await db.execute(
        select(Alert)
        .where(Alert.category == AlertCategory.PHISHING)
        .order_by(Alert.created_at.desc())
        .offset(skip)
        .limit(limit)
    )
    return result.scalars().all()


@router.get("/stats", response_model=PhishingStats)
async def phishing_stats(
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    total = await db.scalar(
        select(func.count(Alert.id)).where(Alert.category == AlertCategory.PHISHING)
    ) or 0
    open_count = await db.scalar(
        select(func.count(Alert.id)).where(
            Alert.category == AlertCategory.PHISHING,
            Alert.status == AlertStatus.OPEN,
        )
    ) or 0
    high_risk = await db.scalar(
        select(func.count(Alert.id)).where(
            Alert.category == AlertCategory.PHISHING,
            Alert.severity.in_([AlertSeverity.HIGH, AlertSeverity.CRITICAL]),
        )
    ) or 0
    critical = await db.scalar(
        select(func.count(Alert.id)).where(
            Alert.category == AlertCategory.PHISHING,
            Alert.severity == AlertSeverity.CRITICAL,
        )
    ) or 0

    return PhishingStats(total=total, open=open_count, high_risk=high_risk, critical=critical)


# ── Ingestion automatique (Wazuh / Squid / Email GW) ─────────────
# Authentification par clé API — pas de JWT — pour les systèmes automatisés

class IngestEvent(BaseModel):
    type: str                        # "url" | "email"
    source_ip: Optional[str] = None
    user: Optional[str] = None
    # URL
    url: Optional[str] = None
    # Email
    sender: Optional[str] = None
    subject: Optional[str] = None
    spf_result: str = "none"
    dmarc_result: str = "none"
    body_urls: list[str] = []
    reply_to: Optional[str] = None
    recipient: Optional[str] = None
    # Metadata
    log_source: Optional[str] = None  # "squid" | "wazuh" | "postfix" | "exchange"
    raw_log: Optional[dict] = None


class IngestBatch(BaseModel):
    events: List[IngestEvent]


def _verify_api_key(x_api_key: Optional[str] = Header(default=None)):
    if x_api_key != settings.INGEST_API_KEY:
        raise HTTPException(status_code=403, detail="Clé API invalide")


@router.post("/ingest", summary="Ingestion automatique (Wazuh/Squid/Email GW)")
async def ingest_events(
    batch: IngestBatch,
    db: AsyncSession = Depends(get_db),
    _key: None = Depends(_verify_api_key),
):
    """
    Endpoint d'ingestion automatique pour systèmes externes.
    Authentifié par clé API (header X-Api-Key) — pas de JWT.

    Sources supportées :
      - Wazuh active-response script
      - Squid proxy (via squid_phishing_hook.py)
      - Postfix/email gateway milter
      - Scripts de log shipping
    """
    results = []
    for ev in batch.events:
        out = await _engine.process(
            event_type=ev.type,
            db=db,
            source_ip=ev.source_ip,
            user=ev.user,
            url=ev.url,
            sender=ev.sender,
            subject=ev.subject or "",
            spf_result=ev.spf_result,
            dmarc_result=ev.dmarc_result,
            body_urls=ev.body_urls,
            reply_to=ev.reply_to,
            recipient=ev.recipient,
            raw_log={**(ev.raw_log or {}), "log_source": ev.log_source},
        )
        results.append({
            "type": ev.type,
            "target": ev.url or ev.sender,
            "score": out.get("score", 0),
            "severity": out.get("severity", "low"),
            "alert_created": out.get("alert_created", False),
            "alert_id": out.get("alert_id"),
        })

    created = sum(1 for r in results if r["alert_created"])
    return {
        "processed": len(results),
        "alerts_created": created,
        "results": results,
    }
