from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from app.models.alert import AlertSeverity, AlertStatus, AlertCategory


class IngestRequest(BaseModel):
    """Corps de la requête POST /siem/ingest pour les sources externes."""
    logs: List[Dict[str, Any]]
    source: str = "external"     # "firewall" | "edr" | "external"


class IngestResult(BaseModel):
    collected: int
    normalized: int
    anomalies_detected: int
    correlated_alerts: int
    simple_alerts: int
    saved: int


class SIEMDashboard(BaseModel):
    """KPIs temps réel pour le dashboard SIEM."""
    total_alerts: int
    open_alerts: int
    critical_count: int
    high_count: int
    alerts_last_24h: int
    top_sources: List[Dict[str, Any]]    # [{ip, count}]
    top_categories: List[Dict[str, Any]] # [{category, count}]
    engine_status: Dict[str, Any]


class AlertSearchRequest(BaseModel):
    """Recherche full-text dans les alertes."""
    query: str
    severity: Optional[AlertSeverity] = None
    category: Optional[AlertCategory] = None
    from_date: Optional[datetime] = None
    to_date: Optional[datetime] = None
    limit: int = 50
