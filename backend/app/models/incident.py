import enum
from sqlalchemy import Column, DateTime, Enum, Float, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base
from app.models.base import TimestampMixin


class IncidentSeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class IncidentStatus(str, enum.Enum):
    NEW = "new"
    ASSIGNED = "assigned"
    INVESTIGATING = "investigating"
    CONTAINMENT = "containment"
    ERADICATION = "eradication"
    RECOVERY = "recovery"
    CLOSED = "closed"


class PlaybookActionStatus(str, enum.Enum):
    PENDING = "pending"
    APPROVED = "approved"        # Validation humaine requise
    EXECUTING = "executing"
    DONE = "done"
    SKIPPED = "skipped"
    FAILED = "failed"


class Incident(Base, TimestampMixin):
    """Ticket d'incident de sécurité (créé depuis une alerte ou manuellement)."""
    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)

    severity = Column(Enum(IncidentSeverity), nullable=False, index=True)
    status = Column(Enum(IncidentStatus), default=IncidentStatus.NEW, nullable=False, index=True)

    # Alerte(s) source
    source_alert_ids = Column(JSON, default=list)

    # Score de risque calculé par l'IR Engine
    risk_score = Column(Float, default=0.0)

    # Assignation
    assigned_to_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    assigned_to = relationship("User", foreign_keys=[assigned_to_id])

    # Timeline
    detected_at = Column(DateTime(timezone=True), nullable=True)
    contained_at = Column(DateTime(timezone=True), nullable=True)
    resolved_at = Column(DateTime(timezone=True), nullable=True)
    closed_at = Column(DateTime(timezone=True), nullable=True)

    # MTTD / MTTR calculés
    mttd_minutes = Column(Integer, nullable=True)   # Mean Time To Detect
    mttr_minutes = Column(Integer, nullable=True)   # Mean Time To Respond

    # Résumé post-incident
    root_cause = Column(Text, nullable=True)
    lessons_learned = Column(Text, nullable=True)
    ioc_list = Column(JSON, default=list)   # Indicators of Compromise

    # Playbook sélectionné
    playbook_id = Column(Integer, ForeignKey("playbooks.id", ondelete="SET NULL"), nullable=True)
    playbook = relationship("Playbook")
    playbook_actions = relationship("PlaybookAction", backref="incident", cascade="all, delete-orphan")

    def __repr__(self):
        return f"<Incident #{self.id} [{self.severity}] {self.status}>"


class Playbook(Base, TimestampMixin):
    """Playbook de réponse aux incidents (modèles réutilisables)."""
    __tablename__ = "playbooks"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Déclencheur automatique
    trigger_category = Column(String(50), nullable=True)    # Correspond à AlertCategory
    trigger_severity_min = Column(String(20), nullable=True)

    # Étapes du playbook (ordonné)
    steps = Column(JSON, nullable=False)
    # Format:
    # [
    #   {
    #     "order": 1,
    #     "title": "Bloquer l'IP source",
    #     "action_type": "network_block",
    #     "description": "Ajouter la règle de blocage sur le firewall",
    #     "requires_approval": true,
    #     "params": {"target": "source_ip"}
    #   },
    #   ...
    # ]

    is_active = Column(Integer, default=True)
    mitre_techniques = Column(JSON, default=list)   # ["T1110", "T1046"]

    def __repr__(self):
        return f"<Playbook {self.name}>"


class PlaybookAction(Base, TimestampMixin):
    """Instance d'une action du playbook pour un incident donné."""
    __tablename__ = "playbook_actions"

    id = Column(Integer, primary_key=True, index=True)
    incident_id = Column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False)

    step_order = Column(Integer, nullable=False)
    title = Column(String(255), nullable=False)
    action_type = Column(String(50), nullable=False)
    description = Column(Text, nullable=True)
    requires_approval = Column(Integer, default=True)

    status = Column(Enum(PlaybookActionStatus), default=PlaybookActionStatus.PENDING, nullable=False)

    # Exécution
    approved_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    approved_by = relationship("User", foreign_keys=[approved_by_id])
    approved_at = Column(DateTime(timezone=True), nullable=True)
    executed_at = Column(DateTime(timezone=True), nullable=True)
    execution_result = Column(Text, nullable=True)

    def __repr__(self):
        return f"<PlaybookAction step={self.step_order} [{self.status}]>"
