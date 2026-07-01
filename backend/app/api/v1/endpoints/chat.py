"""
Endpoints /chat — Chatbot SIEM alimenté par Groq API.

Le chatbot reçoit un contexte temps réel de la posture de sécurité
(alertes, vulnérabilités, conformité) injecté dans le system prompt.

Route :
  POST /chat/message  → envoie un message, reçoit une réponse IA
"""

import logging
from typing import List, Optional

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user
from app.core.config import settings
from app.db.session import get_db
from app.models.alert import Alert, AlertCategory, AlertSeverity, AlertStatus
from app.models.asset import Asset
from app.models.compliance import ComplianceCheck, ComplianceStatus
from app.models.user import User
from app.models.vulnerability import Vulnerability, VulnStatus

logger = logging.getLogger(__name__)
router = APIRouter(tags=["Chatbot"])

GROQ_URL = "https://api.groq.com/openai/v1/chat/completions"
GROQ_MODEL = "llama-3.1-8b-instant"


class ChatMessage(BaseModel):
    role: str  # "user" | "assistant"
    content: str


class ChatRequest(BaseModel):
    message: str
    history: List[ChatMessage] = []


class ChatResponse(BaseModel):
    reply: str
    context_tokens: Optional[int] = None


async def _build_siem_context(db: AsyncSession) -> str:
    """Construit un résumé de la posture de sécurité en temps réel."""

    # Compte alertes par sévérité
    alert_counts = {}
    for sev in AlertSeverity:
        cnt = await db.scalar(
            select(func.count(Alert.id)).where(
                Alert.severity == sev,
                Alert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING]),
            )
        ) or 0
        alert_counts[sev.value] = cnt

    total_open_alerts = sum(alert_counts.values())

    # 5 alertes critiques/high récentes
    recent_result = await db.execute(
        select(Alert.title, Alert.severity, Alert.category, Alert.source_ip, Alert.destination_ip)
        .where(
            Alert.severity.in_([AlertSeverity.CRITICAL, AlertSeverity.HIGH]),
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING]),
        )
        .order_by(Alert.created_at.desc())
        .limit(5)
    )
    recent_alerts = recent_result.all()

    # Vulnérabilités ouvertes
    open_vulns = await db.scalar(
        select(func.count(Vulnerability.id)).where(Vulnerability.status == VulnStatus.OPEN)
    ) or 0
    crit_vulns = await db.scalar(
        select(func.count(Vulnerability.id)).where(
            Vulnerability.status == VulnStatus.OPEN,
            Vulnerability.severity == "critical",
        )
    ) or 0

    # Assets
    total_assets = await db.scalar(select(func.count(Asset.id))) or 0
    avg_compliance = await db.scalar(select(func.avg(Asset.compliance_score))) or 0.0

    # Non-conformités
    non_compliant_checks = await db.scalar(
        select(func.count(ComplianceCheck.id)).where(
            ComplianceCheck.status == ComplianceStatus.NON_COMPLIANT
        )
    ) or 0

    # Phishing récent (dernières détections)
    phishing_count = await db.scalar(
        select(func.count(Alert.id)).where(
            Alert.category == AlertCategory.PHISHING,
            Alert.status.in_([AlertStatus.OPEN, AlertStatus.INVESTIGATING]),
        )
    ) or 0

    lines = [
        "=== CONTEXTE SIEM SECUREZONE (temps réel) ===",
        f"Date/heure de la requête : {__import__('datetime').datetime.utcnow().strftime('%Y-%m-%d %H:%M UTC')}",
        "",
        "--- ALERTES OUVERTES ---",
        f"Total alertes ouvertes/en investigation : {total_open_alerts}",
        f"  · Critiques : {alert_counts.get('critical', 0)}",
        f"  · Élevées   : {alert_counts.get('high', 0)}",
        f"  · Moyennes  : {alert_counts.get('medium', 0)}",
        f"  · Faibles   : {alert_counts.get('low', 0)}",
        f"Détections phishing actives : {phishing_count}",
    ]

    if recent_alerts:
        lines.append("")
        lines.append("--- ALERTES CRITIQUES/ÉLEVÉES RÉCENTES ---")
        for title, sev, cat, src_ip, dst_ip in recent_alerts:
            ips = f"{src_ip or '?'} → {dst_ip or '?'}"
            lines.append(f"  [{sev.upper()} | {cat}] {title} ({ips})")

    lines += [
        "",
        "--- VULNÉRABILITÉS ---",
        f"Vulnérabilités ouvertes : {open_vulns} (dont {crit_vulns} critiques)",
        "",
        "--- CONFORMITÉ ---",
        f"Score de conformité global : {round(avg_compliance, 1)}%",
        f"Non-conformités actives : {non_compliant_checks}",
        "",
        "--- PARC D'ASSETS ---",
        f"Total assets surveillés : {total_assets}",
        "=== FIN DU CONTEXTE ===",
    ]

    return "\n".join(lines)


SYSTEM_PROMPT_TEMPLATE = """Tu es SecureBot, l'assistant IA du SIEM SecureZone.
Tu aides les analystes SOC et les ingénieurs en sécurité à comprendre la posture de sécurité de leur entreprise.

Règles importantes :
- Réponds toujours en français, de manière concise et professionnelle.
- Base-toi sur le contexte SIEM fourni ci-dessous pour répondre aux questions.
- Si une information n'est pas dans le contexte, dis-le clairement.
- Ne génère jamais de faux positifs ou de données inventées.
- Pour les alertes critiques, recommande toujours une action immédiate.
- Utilise un langage adapté aux professionnels de la sécurité (SOC, CISO).

{context}
"""


@router.post("/message", response_model=ChatResponse)
async def chat_message(
    payload: ChatRequest,
    db: AsyncSession = Depends(get_db),
    _: User = Depends(get_current_user),
):
    """
    Envoie un message au chatbot SIEM.

    Le chatbot reçoit automatiquement le contexte temps réel de la posture
    de sécurité (alertes, vulnérabilités, conformité, assets).
    """
    if not settings.GROQ_API_KEY:
        raise HTTPException(
            status_code=503,
            detail="GROQ_API_KEY non configuré. Ajoutez-le dans le fichier .env.",
        )

    # Construire le contexte SIEM
    siem_context = await _build_siem_context(db)
    system_prompt = SYSTEM_PROMPT_TEMPLATE.format(context=siem_context)

    # Construire l'historique de messages
    messages = [{"role": "system", "content": system_prompt}]
    for msg in payload.history[-10:]:  # Garder les 10 derniers messages
        messages.append({"role": msg.role, "content": msg.content})
    messages.append({"role": "user", "content": payload.message})

    # Appeler l'API Groq
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            response = await client.post(
                GROQ_URL,
                headers={
                    "Authorization": f"Bearer {settings.GROQ_API_KEY}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": GROQ_MODEL,
                    "messages": messages,
                    "max_tokens": 1024,
                    "temperature": 0.3,
                },
            )
            response.raise_for_status()
    except httpx.HTTPStatusError as e:
        logger.error(f"Groq API error {e.response.status_code}: {e.response.text}")
        raise HTTPException(
            status_code=502,
            detail=f"Erreur Groq API : {e.response.status_code}",
        )
    except httpx.TimeoutException:
        raise HTTPException(status_code=504, detail="Timeout Groq API")

    data = response.json()
    reply = data["choices"][0]["message"]["content"]
    usage = data.get("usage", {})

    return ChatResponse(
        reply=reply,
        context_tokens=usage.get("total_tokens"),
    )
