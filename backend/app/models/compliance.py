import enum
from sqlalchemy import Boolean, Column, DateTime, Enum, Float, ForeignKey, Integer, String, Text, JSON
from sqlalchemy.orm import relationship
from app.db.session import Base
from app.models.base import TimestampMixin


class PolicyFramework(str, enum.Enum):
    ISO_27001 = "iso_27001"
    DORA = "dora"
    CIS = "cis"
    CUSTOM = "custom"


class PolicySeverity(str, enum.Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ComplianceStatus(str, enum.Enum):
    COMPLIANT = "compliant"
    NON_COMPLIANT = "non_compliant"
    PARTIALLY_COMPLIANT = "partially_compliant"
    NOT_APPLICABLE = "not_applicable"
    NOT_CHECKED = "not_checked"


class HardeningPolicy(Base, TimestampMixin):
    """Politique de hardening définie par l'équipe sécurité."""
    __tablename__ = "hardening_policies"

    id = Column(Integer, primary_key=True, index=True)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)

    # Cadre réglementaire
    framework = Column(Enum(PolicyFramework), default=PolicyFramework.CUSTOM, nullable=False)
    control_id = Column(String(50), nullable=True)     # ex: "ISO-27001-A.12.6.1"

    # Règle
    severity = Column(Enum(PolicySeverity), default=PolicySeverity.MEDIUM, nullable=False)
    rule_type = Column(String(50), nullable=False)     # "port_closed" | "patch_applied" | "service_disabled" | "config_value"
    rule_config = Column(JSON, nullable=False)         # {"port": 3389, "protocol": "tcp"}

    # Scope d'application
    applies_to_tags = Column(JSON, default=list)       # [] = tous les assets
    applies_to_asset_types = Column(JSON, default=list)
    applies_to_departments = Column(JSON, default=list)

    is_active = Column(Boolean, default=True)
    created_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    created_by = relationship("User")

    def __repr__(self):
        return f"<Policy {self.name} [{self.framework}]>"


class ComplianceCheck(Base, TimestampMixin):
    """Résultat d'une vérification de politique sur un asset."""
    __tablename__ = "compliance_checks"

    id = Column(Integer, primary_key=True, index=True)

    # Relation policy <-> asset
    policy_id = Column(Integer, ForeignKey("hardening_policies.id", ondelete="CASCADE"), nullable=False)
    policy = relationship("HardeningPolicy", backref="checks")
    asset_id = Column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False)
    asset = relationship("Asset", backref="compliance_checks")

    # Résultat
    status = Column(Enum(ComplianceStatus), default=ComplianceStatus.NOT_CHECKED, nullable=False, index=True)
    checked_at = Column(DateTime(timezone=True), nullable=True)
    actual_value = Column(JSON, nullable=True)      # Valeur constatée
    expected_value = Column(JSON, nullable=True)    # Valeur attendue par la policy
    details = Column(Text, nullable=True)           # Explication de la non-conformité

    # Exception accordée
    exception_granted = Column(Boolean, default=False)
    exception_reason = Column(Text, nullable=True)
    exception_granted_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    exception_granted_by = relationship("User")
    exception_expires_at = Column(DateTime(timezone=True), nullable=True)

    def __repr__(self):
        return f"<ComplianceCheck policy={self.policy_id} asset={self.asset_id} [{self.status}]>"


class ComplianceReport(Base, TimestampMixin):
    """Rapport de conformité généré (PDF)."""
    __tablename__ = "compliance_reports"

    id = Column(Integer, primary_key=True, index=True)
    title = Column(String(255), nullable=False)
    framework = Column(Enum(PolicyFramework), nullable=False)
    scope_departments = Column(JSON, default=list)   # [] = tout l'entreprise

    # Scores calculés
    overall_score = Column(Float, default=0.0)       # 0.0 - 100.0
    scores_by_department = Column(JSON, default=dict)
    scores_by_control = Column(JSON, default=dict)

    # Statistiques
    total_checks = Column(Integer, default=0)
    compliant_count = Column(Integer, default=0)
    non_compliant_count = Column(Integer, default=0)

    # Fichier PDF généré
    pdf_path = Column(String(500), nullable=True)
    generated_by_id = Column(Integer, ForeignKey("users.id", ondelete="SET NULL"), nullable=True)
    generated_by = relationship("User")

    def __repr__(self):
        return f"<ComplianceReport {self.title} score={self.overall_score:.1f}%>"
