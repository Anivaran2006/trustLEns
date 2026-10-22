"""
SQLAlchemy ORM models for TrustLens AI.
Stores scan audits, privacy-preserving snippets, ML risk predictions, and user feedback.
"""

import uuid
from datetime import datetime, timezone
from sqlalchemy import Column, String, Float, Boolean, DateTime, Text, ForeignKey
from sqlalchemy.orm import relationship
from app.db.session import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    email = Column(String(255), unique=True, index=True, nullable=False)
    full_name = Column(String(255), nullable=False)
    hashed_password = Column(String(255), nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)
    updated_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), onupdate=lambda: datetime.now(timezone.utc))

    # Relationships
    scans = relationship("ScanRecord", back_populates="user")
    sessions = relationship("UserSession", back_populates="user", cascade="all, delete-orphan")


class UserSession(Base):
    __tablename__ = "user_sessions"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="CASCADE"), nullable=False, index=True)
    session_token = Column(String(128), unique=True, index=True, nullable=False)
    csrf_token = Column(String(128), nullable=False)
    expires_at = Column(DateTime, nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), nullable=False)

    user = relationship("User", back_populates="sessions")


class ScanRecord(Base):
    __tablename__ = "scan_records"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc), index=True)
    
    # Optional association with registered user (None for guest scans)
    user_id = Column(String(36), ForeignKey("users.id", ondelete="SET NULL"), nullable=True, index=True)

    # Privacy: store SHA-256 hash of original message, plus a redacted, truncated preview
    message_hash = Column(String(64), index=True, nullable=False)
    message_preview = Column(String(256), nullable=False)
    
    # Model classification outcomes
    classification = Column(String(16), nullable=False)  # "HAM" or "SPAM"
    is_suspicious = Column(Boolean, nullable=False)
    risk_score = Column(Float, nullable=False)           # 0.0 to 1.0
    risk_level = Column(String(16), nullable=False)      # "LOW", "MEDIUM", "HIGH"
    model_version = Column(String(32), nullable=False)
    model_name = Column(String(64), nullable=False)
    
    # Serialized JSON blobs for indicators and investigation explanation
    indicators_json = Column(Text, nullable=False, default="{}")
    explanation_json = Column(Text, nullable=False, default="{}")

    # Associated relationships
    user = relationship("User", back_populates="scans")
    feedbacks = relationship("UserFeedback", back_populates="scan", cascade="all, delete-orphan")


class UserFeedback(Base):
    __tablename__ = "user_feedbacks"

    id = Column(String(36), primary_key=True, default=generate_uuid, index=True)
    scan_id = Column(String(36), ForeignKey("scan_records.id", ondelete="CASCADE"), nullable=False, index=True)
    created_at = Column(DateTime, default=lambda: datetime.now(timezone.utc))
    
    is_helpful = Column(Boolean, nullable=True)
    user_label = Column(String(16), nullable=True)  # "ham", "spam", "unsure"
    user_notes = Column(Text, nullable=True)

    scan = relationship("ScanRecord", back_populates="feedbacks")

