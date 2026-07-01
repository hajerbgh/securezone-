from datetime import datetime
from typing import Any, Dict, List, Optional
from pydantic import BaseModel
from app.models.asset import AssetType, AssetStatus, AssetCriticality


class AssetBase(BaseModel):
    hostname: Optional[str] = None
    ip_address: str
    mac_address: Optional[str] = None
    asset_type: AssetType = AssetType.UNKNOWN
    criticality: AssetCriticality = AssetCriticality.MEDIUM
    department: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    tags: List[str] = []
    is_whitelisted: bool = False
    whitelist_reason: Optional[str] = None


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    hostname: Optional[str] = None
    asset_type: Optional[AssetType] = None
    criticality: Optional[AssetCriticality] = None
    department: Optional[str] = None
    location: Optional[str] = None
    owner: Optional[str] = None
    tags: Optional[List[str]] = None
    is_whitelisted: Optional[bool] = None
    whitelist_reason: Optional[str] = None


class AssetRead(AssetBase):
    id: int
    status: AssetStatus
    criticality: AssetCriticality
    os_name: Optional[str]
    os_version: Optional[str]
    compliance_score: float
    risk_score: float
    wazuh_agent_id: Optional[str]
    last_seen: Optional[datetime]
    open_ports: List[Dict[str, Any]]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


class AssetSummary(BaseModel):
    id: int
    hostname: Optional[str]
    ip_address: str
    asset_type: AssetType
    criticality: AssetCriticality
    status: AssetStatus
    compliance_score: float
    risk_score: float
    department: Optional[str]

    class Config:
        from_attributes = True
