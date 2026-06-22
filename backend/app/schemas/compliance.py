from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, validator
from app.models.compliance import PolicyFramework, PolicySeverity, ComplianceStatus


# ── Hardening Policies ────────────────────────────────────────────

class PolicyCreate(BaseModel):
    name: str
    description: Optional[str] = None
    framework: PolicyFramework = PolicyFramework.CUSTOM
    control_id: Optional[str] = None
    severity: PolicySeverity = PolicySeverity.MEDIUM
    rule_type: str
    rule_config: Dict[str, Any]
    applies_to_tags: List[str] = []
    applies_to_asset_types: List[str] = []
    applies_to_departments: List[str] = []
    is_active: bool = True

    @validator("rule_type")
    def validate_rule_type(cls, v):
        valid = {
            "port_closed", "port_open", "os_version",
            "service_disabled", "patch_applied",
            "vuln_score_max", "tag_required", "field_value",
        }
        if v not in valid:
            raise ValueError(f"rule_type invalide. Valeurs: {sorted(valid)}")
        return v

    @validator("rule_config")
    def validate_rule_config(cls, v, values):
        rule_type = values.get("rule_type", "")
        # Vérifications basiques par type
        if rule_type in ("port_closed", "port_open") and "port" not in v:
            raise ValueError("rule_config doit contenir 'port' pour ce type de règle")
        if rule_type == "patch_applied" and "cve_id" not in v:
            raise ValueError("rule_config doit contenir 'cve_id' pour patch_applied")
        return v


class PolicyUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    severity: Optional[PolicySeverity] = None
    is_active: Optional[bool] = None
    applies_to_tags: Optional[List[str]] = None
    applies_to_asset_types: Optional[List[str]] = None
    applies_to_departments: Optional[List[str]] = None


class PolicyRead(BaseModel):
    id: int
    name: str
    description: Optional[str]
    framework: PolicyFramework
    control_id: Optional[str]
    severity: PolicySeverity
    rule_type: str
    rule_config: Dict[str, Any]
    applies_to_tags: List[str]
    applies_to_asset_types: List[str]
    applies_to_departments: List[str]
    is_active: bool
    created_at: datetime

    class Config:
        from_attributes = True


# ── Compliance Checks ─────────────────────────────────────────────

class ComplianceCheckRead(BaseModel):
    id: int
    policy_id: int
    asset_id: int
    status: ComplianceStatus
    checked_at: Optional[datetime]
    actual_value: Optional[Any]
    expected_value: Optional[Any]
    details: Optional[str]
    exception_granted: bool
    exception_reason: Optional[str]
    exception_expires_at: Optional[datetime]

    class Config:
        from_attributes = True


class ExceptionCreate(BaseModel):
    reason: str
    expires_at: Optional[datetime] = None


# ── Compliance Reports ─────────────────────────────────────────────

class ReportGenerateRequest(BaseModel):
    title: str
    framework: PolicyFramework
    scope_departments: List[str] = []   # [] = tout le parc


class ReportRead(BaseModel):
    id: int
    title: str
    framework: PolicyFramework
    overall_score: float
    total_checks: int
    compliant_count: int
    non_compliant_count: int
    scores_by_department: Dict[str, float]
    pdf_path: Optional[str]
    created_at: datetime

    class Config:
        from_attributes = True


# ── Dashboard Stats ───────────────────────────────────────────────

class ComplianceDashboard(BaseModel):
    global_score: float
    non_compliant_assets: int
    checks_by_status: Dict[str, int]
    top_violated_policies: List[Dict[str, Any]]


class EvaluationResult(BaseModel):
    status: str
    assets_evaluated: int
    policies_applied: Optional[int] = None
    total_checks: Optional[int] = None
    scores: Optional[Dict[str, Any]] = None
