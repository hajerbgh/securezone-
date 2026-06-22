import enum
from sqlalchemy import Boolean, Column, Enum, Float, ForeignKey, Integer, String, Text, JSON, DateTime
from sqlalchemy.orm import relationship
from app.db.session import Base
from app.models.base import TimestampMixin


class AlertSeverity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class AlertStatus(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    RESOLVED = "resolved"
    FALSE_POSITIVE = "false_positive"
    SUPPRESSED = "suppressed"


class AlertCategory(str, enum.Enum):
    BRUTE_FORCE = "brute_force"
    PORT_SCAN = "port_scan"
    SQL_INJECTION = "sql_injection"
    COMMAND_EXEC = "command_exec"
    CREDENTIAL_ACCESS = "credential_access"
    LATERAL_MOVEMENT = "lateral_movement"
    EXFILTRATION = "exfiltration"
    ANOMALY = "anomaly"           # Détection ML (Isolation Forest)
    COMPLIANCE = "compliance"
    VULNERABILITY = "vulnerability"
    OTHER = "other"


class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)

    # Classification
    severity = Column(Enum(AlertSeverity), default=AlertSeverity.MEDIUM, nullable=False, index=True)
    category = Column(Enum(AlertCategory), default=AlertCategory.OTHER, nullable=False, index=True)
    status = Column(Enum(AlertStatus), default=AlertStatus.OPEN, nullable=False, index=True)

    # Source
    source_ip = Column(String(45), nullable=True, index=True)
    destination_ip = Column(String(45), nullable=True)
    source_port = Column(Integer, nullable=True)
    destination_port = Column(Integer, nullable=True)

    # Asset lié
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="SET NULL"), nullable=True)
    asset = relationship("Asset", backref="alerts")

    # MITRE ATT&CK
    mitre_technique_id = Column(String(20), nullable=True)    # ex: T1110
    mitre_technique_name = Column(String(255), nullable=True) # ex: Brute Force

    # Score de risque calculé
    risk_score = Column(Float, default=0.0)

    # Données brutes de l'événement
    raw_log = Column(JSON, nullable=True)
    event_count = Column(Integer, default=1)  # Nb d'événements agrégés
    first_seen = Column(DateTime(timezone=True), nullable=True)
    last_seen = Column(DateTime(timezone=True), nullable=True)

    # Gestion
    assigned_to_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_to = relationship("User", foreign_keys=[assigned_to_id])
    resolved_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    resolved_by = relationship("User", foreign_keys=[resolved_by_id])
    resolution_note = Column(Text, nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)

    # Corrélation
    correlated_alert_ids = Column(JSON, default=list)  # IDs des alertes liées

    def __repr__(self):
        return f"<Alert [{self.severity}] {self.title[:50]}>"
