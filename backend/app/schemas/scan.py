from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, validator
from app.models.vulnerability import VulnSeverity, VulnStatus


# ── Vulnerabilities ──────────────────────────────────────────

class VulnerabilityRead(BaseModel):
    id: int
    cve_id: Optional[str]
    title: str
    description: Optional[str]
    solution: Optional[str]
    cvss_score: Optional[float]
    severity: VulnSeverity
    status: VulnStatus
    asset_id: int
    affected_port: Optional[int]
    affected_service: Optional[str]
    scanner_name: Optional[str]
    references: List[str]
    remediation_note: Optional[str]
    deadline: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class VulnerabilityUpdate(BaseModel):
    status: Optional[VulnStatus] = None
    assigned_to_id: Optional[int] = None
    remediation_note: Optional[str] = None
    deadline: Optional[datetime] = None


class VulnerabilityStats(BaseModel):
    total: int
    open: int
    critical: int
    high: int
    medium: int
    low: int
    by_asset: Dict[str, int]       # ip_address → count
    top_cvss: List[Dict[str, Any]] # [{cve_id, cvss_score, asset_ip}]


# ── ScanJobs ─────────────────────────────────────────────────

class ScanJobCreate(BaseModel):
    name: Optional[str] = None
    ip_ranges: List[str]
    scanner_type: str = "full"     # "nmap" | "openvas" | "full"
    is_scheduled: bool = False
    cron_expression: Optional[str] = None  # "0 2 * * *"

    @validator("cron_expression")
    def validate_cron(cls, v, values):
        if values.get("is_scheduled") and not v:
            raise ValueError("cron_expression requis quand is_scheduled=True")
        if v:
            # Validation basique : 5 champs cron
            parts = v.strip().split()
            if len(parts) != 5:
                raise ValueError("Expression cron invalide (format: 'min heure jour mois jour_semaine')")
        return v

    @validator("scanner_type")
    def validate_scanner(cls, v):
        if v not in ("nmap", "openvas", "full"):
            raise ValueError("scanner_type doit être 'nmap', 'openvas' ou 'full'")
        return v

    @validator("ip_ranges")
    def validate_ip_ranges(cls, v):
        if not v:
            raise ValueError("Au moins une plage IP requise")
        return v


class ScanJobRead(BaseModel):
    id: int
    name: Optional[str]
    ip_ranges: List[str]
    scanner_type: str
    is_scheduled: bool
    cron_expression: Optional[str]
    status: str
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    progress_percent: int
    assets_scanned: int
    vulnerabilities_found: int
    error_message: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


class ScanJobSummary(BaseModel):
    id: int
    name: Optional[str]
    ip_ranges: List[str]
    scanner_type: str
    status: str
    progress_percent: int
    vulnerabilities_found: int
    created_at: datetime

    class Config:
        from_attributes = True
