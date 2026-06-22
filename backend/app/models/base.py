from sqlalchemy import Column, DateTime, Integer
from sqlalchemy.sql import func
from app.db.session import Base


class TimestampMixin:
    """Ajoute created_at et updated_at à tous les modèles."""
    created_at = Column(DateTime(timezone=True), server_default=func.now(), nullable=False)
    updated_at = Column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now(), nullable=False)
