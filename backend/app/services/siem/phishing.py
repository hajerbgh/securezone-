"""
PhishingDetectionEngine — Détection de phishing par heuristiques.

Score 0–100 :
  0–30   → Faible (informatif)
  31–60  → Moyen  (surveiller)
  61–85  → Élevé  (probable phishing)
  86–100 → Critique (phishing confirmé)

Techniques de détection :
  URLs  : IP brute, TLD suspect, URL shortener, entropie, typosquatting,
           sous-domaines multiples, mots-clés sensitifs
  Email : SPF/DMARC fail, domaine lookalike, urgence sujet, reply-to mismatch
"""

import re
import math
import logging
from dataclasses import dataclass, field
from typing import Optional
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# ── Listes de référence ──────────────────────────────────────────

KNOWN_BRANDS = [
    "paypal", "google", "microsoft", "apple", "amazon", "facebook",
    "netflix", "instagram", "twitter", "linkedin", "dropbox", "icloud",
    "outlook", "office365", "gmail", "yahoo", "ebay", "wellsfargo",
    "bankofamerica", "chase", "citibank", "hsbc", "bnpparibas",
    "societegenerale", "creditagricole", "labanquepostale", "caf", "impots",
]

SUSPICIOUS_TLDS = {
    ".tk", ".ml", ".ga", ".cf", ".gq",
    ".xyz", ".top", ".click", ".work", ".loan", ".win", ".bid",
    ".download", ".review", ".science", ".party",
}

URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "ow.ly", "goo.gl",
    "is.gd", "buff.ly", "adf.ly", "bl.ink", "rb.gy",
    "shorturl.at", "cutt.ly", "tiny.cc",
}

URGENCY_KEYWORDS = [
    "urgent", "immediate", "action required", "verify", "suspend",
    "expire", "limited", "warning", "alert", "confirm", "update",
    "unusual", "suspicious", "locked", "disabled", "activate",
    "vérif", "suspendu", "action immédiate", "sécurité",
    "mot de passe", "connexion inhabituelle", "compte bloqué",
]

SENSITIVE_PATH_KEYWORDS = [
    "login", "signin", "password", "passwd", "credential",
    "account", "banking", "secure", "verify", "update",
    "wallet", "payment", "invoice", "billing", "auth",
]


# ── Score result ─────────────────────────────────────────────────

@dataclass
class PhishingScore:
    score: float
    severity: str
    indicators: list[str] = field(default_factory=list)
    details: dict = field(default_factory=dict)

    @property
    def is_phishing(self) -> bool:
        return self.score >= 61

    @classmethod
    def build(cls, raw: float, indicators: list[str], details: dict) -> "PhishingScore":
        capped = min(100.0, round(raw, 1))
        severity = (
            "critical" if capped >= 86 else
            "high"     if capped >= 61 else
            "medium"   if capped >= 31 else
            "low"
        )
        return cls(score=capped, severity=severity, indicators=indicators, details=details)


# ── Utilitaires ──────────────────────────────────────────────────

def _entropy(s: str) -> float:
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    n = len(s)
    return -sum((f / n) * math.log2(f / n) for f in freq.values())


def _extract_domain(value: str) -> str:
    if "@" in value:
        return value.split("@")[-1].lower().strip()
    try:
        parsed = urlparse(value if "://" in value else "http://" + value)
        host = parsed.netloc or parsed.path
        return host.lower().split(":")[0]
    except Exception:
        return value.lower()


def _is_ip(host: str) -> bool:
    return bool(re.match(r"^\d{1,3}(\.\d{1,3}){3}$", host))


def _levenshtein(a: str, b: str) -> int:
    if abs(len(a) - len(b)) > 3:
        return 99
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        row = [i + 1]
        for j, cb in enumerate(b):
            row.append(min(dp[j + 1] + 1, row[-1] + 1, dp[j] + (0 if ca == cb else 1)))
        dp = row
    return dp[-1]


def _typosquatting(host: str) -> tuple[int, list[str]]:
    apex = host.split(".")[-2] if "." in host else host
    for brand in KNOWN_BRANDS:
        if brand in host and not host.endswith(brand + ".com"):
            return 25, [f"brand_in_subdomain:{brand}"]
        if _levenshtein(apex, brand) <= 2 and apex != brand and len(brand) > 4:
            return 35, [f"typosquatting:{brand}≈{apex}"]
        normalized = apex.replace("1", "l").replace("0", "o").replace("3", "e").replace("@", "a")
        if normalized == brand and apex != brand:
            return 40, [f"homoglyph:{brand}"]
    return 0, []


# ── Analyse URL ──────────────────────────────────────────────────

def analyze_url(url: str) -> PhishingScore:
    score = 0.0
    indicators: list[str] = []
    details: dict = {"url": url}

    try:
        parsed = urlparse(url if "://" in url else "http://" + url)
        host = parsed.netloc.lower().split(":")[0]
        path = (parsed.path + "?" + parsed.query).lower()
        scheme = parsed.scheme
    except Exception:
        host = _extract_domain(url)
        path = url.lower()
        scheme = "unknown"

    details.update({"host": host, "scheme": scheme})

    if _is_ip(host):
        score += 40
        indicators.append("ip_as_host")

    if host in URL_SHORTENERS:
        score += 25
        indicators.append("url_shortener")

    for tld in SUSPICIOUS_TLDS:
        if host.endswith(tld):
            score += 20
            indicators.append(f"suspicious_tld:{tld}")
            break

    ts, ts_ind = _typosquatting(host)
    score += ts
    indicators.extend(ts_ind)

    apex = host.split(".")[-2] if "." in host else host
    ent = _entropy(apex)
    details["domain_entropy"] = round(ent, 2)
    if ent > 3.8 and not ts_ind:
        score += 15
        indicators.append(f"high_entropy:{ent:.1f}")

    if len(url) > 200:
        score += 10
        indicators.append(f"long_url:{len(url)}")

    hits = [kw for kw in SENSITIVE_PATH_KEYWORDS if kw in path]
    if hits:
        score += min(15, len(hits) * 5)
        indicators.append(f"sensitive_path:{','.join(hits[:3])}")

    if len(host.split(".")) >= 4:
        score += 15
        indicators.append(f"many_subdomains:{len(host.split('.'))}")

    if scheme == "http" and any(kw in path for kw in ["login", "signin", "secure", "account"]):
        score += 10
        indicators.append("http_sensitive_page")

    return PhishingScore.build(score, indicators, details)


# ── Analyse Email ────────────────────────────────────────────────

def analyze_email(
    sender: str,
    subject: str = "",
    spf_result: str = "none",
    dmarc_result: str = "none",
    body_urls: Optional[list[str]] = None,
    reply_to: Optional[str] = None,
) -> PhishingScore:
    score = 0.0
    indicators: list[str] = []
    domain = _extract_domain(sender)
    details: dict = {"sender": sender, "sender_domain": domain, "subject": subject}

    if spf_result in ("fail", "softfail"):
        pts = 20 if spf_result == "fail" else 10
        score += pts
        indicators.append(f"spf_{spf_result}")

    if dmarc_result == "fail":
        score += 25
        indicators.append("dmarc_fail")

    ts, ts_ind = _typosquatting(domain)
    score += ts
    indicators.extend(ts_ind)

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            score += 15
            indicators.append(f"sender_suspicious_tld:{tld}")
            break

    urgency_hits = [kw for kw in URGENCY_KEYWORDS if kw in subject.lower()]
    if urgency_hits:
        score += min(20, len(urgency_hits) * 7)
        indicators.append(f"urgency_keywords:{','.join(urgency_hits[:2])}")

    if reply_to and _extract_domain(reply_to) != domain:
        score += 20
        indicators.append(f"reply_to_mismatch:{_extract_domain(reply_to)}")

    if body_urls:
        url_scores = [analyze_url(u).score for u in body_urls[:10]]
        max_score = max(url_scores, default=0.0)
        if max_score > 30:
            score += max_score * 0.5
            indicators.append(f"malicious_url_in_body:{max_score:.0f}")
            details["worst_url_score"] = max_score

    return PhishingScore.build(score, indicators, details)


# ── Engine principal ─────────────────────────────────────────────

class PhishingDetectionEngine:
    """Analyse les événements phishing et génère des alertes SIEM (score ≥ 31)."""

    async def process(
        self,
        event_type: str,
        db,
        source_ip: Optional[str] = None,
        # Email
        sender: Optional[str] = None,
        subject: str = "",
        spf_result: str = "none",
        dmarc_result: str = "none",
        body_urls: Optional[list[str]] = None,
        reply_to: Optional[str] = None,
        recipient: Optional[str] = None,
        # URL
        url: Optional[str] = None,
        user: Optional[str] = None,
        raw_log: Optional[dict] = None,
    ) -> dict:
        from datetime import datetime, timezone
        from app.models.alert import Alert, AlertSeverity, AlertCategory, AlertStatus

        SEV_MAP = {
            "low": AlertSeverity.LOW,
            "medium": AlertSeverity.MEDIUM,
            "high": AlertSeverity.HIGH,
            "critical": AlertSeverity.CRITICAL,
        }

        if event_type == "email" and sender:
            result = analyze_email(sender, subject, spf_result, dmarc_result, body_urls, reply_to)
            title = f"[Phishing] Email suspect — {sender}"
            description = (
                f"Expéditeur : {sender}\n"
                f"Destinataire : {recipient or '—'}\n"
                f"Sujet : {subject or '—'}\n"
                f"SPF : {spf_result} | DMARC : {dmarc_result}\n"
                f"Score phishing : {result.score:.0f}/100\n"
                f"Indicateurs : {', '.join(result.indicators) or 'Aucun'}"
            )
        elif event_type == "url" and url:
            result = analyze_url(url)
            title = f"[Phishing] URL suspecte — {url[:80]}"
            description = (
                f"URL : {url}\n"
                f"Hôte : {result.details.get('host', '—')}\n"
                f"Score phishing : {result.score:.0f}/100\n"
                f"Indicateurs : {', '.join(result.indicators) or 'Aucun'}"
            )
        else:
            return {"score": 0, "severity": "low", "alert_created": False}

        out = {
            "score": result.score,
            "severity": result.severity,
            "indicators": result.indicators,
            "details": result.details,
            "is_phishing": result.is_phishing,
            "alert_created": False,
        }

        if result.score >= 31:
            now = datetime.now(timezone.utc)
            alert = Alert(
                title=title,
                description=description,
                severity=SEV_MAP.get(result.severity, AlertSeverity.MEDIUM),
                category=AlertCategory.PHISHING,
                status=AlertStatus.OPEN,
                source_ip=source_ip,
                risk_score=round(result.score / 10, 1),
                first_seen=now,
                last_seen=now,
                mitre_technique_id="T1566",
                mitre_technique_name="Phishing",
                raw_log={
                    **(raw_log or {}),
                    "phishing_score": result.score,
                    "indicators": result.indicators,
                    "details": result.details,
                    "event_type": event_type,
                    "user": user,
                },
            )
            db.add(alert)
            await db.flush()
            out["alert_created"] = True
            out["alert_id"] = alert.id
            logger.info(f"Alerte phishing [score={result.score:.0f}] {title[:60]}")

        return out
