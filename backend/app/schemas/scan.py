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
    cvss_vector: Optional[str]
    severity: VulnSeverity
    status: VulnStatus
    asset_id: int
    asset_ip: Optional[str] = None        # Injecté depuis la relation Asset
    asset_hostname: Optional[str] = None  # Injecté depuis la relation Asset
    affected_port: Optional[int]
    affected_service: Optional[str]
    scanner_name: Optional[str]
    references: List[str]
    cpe: Optional[str]
    remediation_note: Optional[str]
    assigned_to_id: Optional[int]
    deadline: Optional[datetime]
    remediated_at: Optional[datetime]
    scan_id: Optional[int]
    first_seen: Optional[datetime]
    last_seen: Optional[datetime]
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
    # Top 10 assets avec le plus de vulnérabilités ouvertes
    by_asset: List[Dict[str, Any]]
    # Top 5 CVE par score CVSS
    top_cvss: List[Dict[str, Any]]


# ── Import externe (OpenVAS, Nessus, etc.) ───────────────────

class VulnerabilityImport(BaseModel):
    affected_ip: str
    cve_id: Optional[str] = None
    title: str
    description: Optional[str] = None
    solution: Optional[str] = None
    cvss_score: float = 0.0
    severity: VulnSeverity = VulnSeverity.LOW
    affected_port: int = 0
    affected_service: Optional[str] = None
    references: List[str] = []


class VulnerabilityImportResult(BaseModel):
    imported: int
    skipped: int
    total_received: int


# ── ScanJobs ─────────────────────────────────────────────────

class ScanJobCreate(BaseModel):
    name: Optional[str] = None
    ip_ranges: List[str]
    exclude_ips: List[str] = []
    port_range: Optional[str] = None   # "22,80,443" ou "1-1000" (None = tous les ports)
    scanner_type: str = "full"
    is_scheduled: bool = False
    cron_expression: Optional[str] = None

    @validator("cron_expression")
    def validate_cron(cls, v, values):
        if values.get("is_scheduled") and not v:
            raise ValueError("cron_expression requis quand is_scheduled=True")
        if v:
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

    @validator("port_range")
    def validate_port_range(cls, v):
        if v is None:
            return v
        # Accepter "22,80,443" ou "1-1000" ou "1-65535"
        import re
        if not re.match(r'^[\d,\-]+$', v):
            raise ValueError("port_range invalide — format attendu : '22,80,443' ou '1-1000'")
        return v


class ScanJobRead(BaseModel):
    id: int
    name: Optional[str]
    ip_ranges: List[str]
    exclude_ips: List[str]
    port_range: Optional[str]
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
