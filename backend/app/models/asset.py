import enum
from sqlalchemy import Boolean, Column, Enum, Float, Integer, String, Text, JSON, DateTime
from app.db.session import Base
from app.models.base import TimestampMixin


class AssetType(str, enum.Enum):
    SERVER = "server"
    WORKSTATION = "workstation"
    FIREWALL = "firewall"
    SWITCH = "switch"
    ROUTER = "router"
    PRINTER = "printer"
    IOT = "iot"
    UNKNOWN = "unknown"


class AssetStatus(str, enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    UNREACHABLE = "unreachable"
    MAINTENANCE = "maintenance"
    UNKNOWN = "unknown"


class AssetCriticality(str, enum.Enum):
    """
    Niveau de criticité métier de l'asset.
    Utilisé pour pondérer le risk_score :
      critical × 2.0 | high × 1.5 | medium × 1.0 | low × 0.5
    Ex : serveur de paie → CRITICAL ; imprimante → LOW
    """
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id = Column(Integer, primary_key=True, index=True)
    hostname = Column(String(255), index=True, nullable=True)
    ip_address = Column(String(45), unique=True, index=True, nullable=False)  # IPv4 ou IPv6
    mac_address = Column(String(17), nullable=True)

    # Classification
    asset_type = Column(Enum(AssetType), default=AssetType.UNKNOWN, nullable=False)
    status = Column(Enum(AssetStatus), default=AssetStatus.UNKNOWN, nullable=False)
    # String plutôt qu'Enum natif PostgreSQL pour éviter les problèmes de casse
    criticality = Column(String(20), default="medium", nullable=False, index=True)
    os_name = Column(String(255), nullable=True)
    os_version = Column(String(100), nullable=True)

    # Organisation
    department = Column(String(100), nullable=True, index=True)
    location = Column(String(255), nullable=True)
    owner = Column(String(255), nullable=True)
    tags = Column(JSON, default=list)  # ["production", "critical", "pci-dss"]

    # Scores
    compliance_score = Column(Float, default=0.0)   # 0.0 à 100.0
    risk_score = Column(Float, default=0.0)          # 0.0 à 10.0

    # Whitelisting (évite les faux positifs sur l'IR Engine)
    is_whitelisted = Column(Boolean, default=False)
    whitelist_reason = Column(Text, nullable=True)

    # Wazuh
    wazuh_agent_id = Column(String(50), nullable=True, unique=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)

    # Métadonnées enrichies
    open_ports = Column(JSON, default=list)      # [{"port": 443, "service": "https", "version": "..."}]
    software_inventory = Column(JSON, default=list)

    def __repr__(self):
        return f"<Asset {self.ip_address} ({self.hostname or 'unknown'}) [{self.criticality}]>"
