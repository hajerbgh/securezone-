import enum
from sqlalchemy import Boolean, Column, Enum, Integer, String, Text
from app.db.session import Base
from app.models.base import TimestampMixin


class UserRole(str, enum.Enum):
    ADMIN = "admin"           # Accès total
    ANALYST = "analyst"       # Lecture + gestion incidents
    VIEWER = "viewer"         # Lecture seule
    AUDITOR = "auditor"       # Accès rapports uniquement


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    username = Column(String(100), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    role = Column(Enum(UserRole), default=UserRole.ANALYST, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    is_superuser = Column(Boolean, default=False, nullable=False)

    # Préférences
    department = Column(String(100), nullable=True)
    phone = Column(String(50), nullable=True)
    notes = Column(Text, nullable=True)

    def __repr__(self):
        return f"<User {self.username} ({self.role})>"
