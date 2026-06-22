from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from app.models.alert import AlertSeverity, AlertStatus, AlertCategory


class AlertRead(BaseModel):
    id: int
    title: str
    description: Optional[str]
    severity: AlertSeverity
    category: AlertCategory
    status: AlertStatus
    source_ip: Optional[str]
    destination_ip: Optional[str]
    source_port: Optional[int]
    destination_port: Optional[int]
    asset_id: Optional[int]
    mitre_technique_id: Optional[str]
    mitre_technique_name: Optional[str]
    risk_score: float
    event_count: int
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
    correlated_alert_ids: List[int]
    created_at: datetime

    class Config:
        from_attributes = True


class AlertUpdate(BaseModel):
    status: Optional[AlertStatus] = None
    assigned_to_id: Optional[int] = None
    resolution_note: Optional[str] = None


class AlertStats(BaseModel):
    total: int
    open: int
    critical: int
    high: int
    medium: int
    low: int
    by_category: Dict[str, int]
