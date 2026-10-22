"""
Repository layer for TrustLens AI database interactions.
Decouples business logic from SQLAlchemy ORM, facilitating smooth migration
between SQLite and PostgreSQL.
"""

import json
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import desc, func

from app.db.models import ScanRecord, UserFeedback, User, UserSession
from app.core.security import hash_text, redact_sensitive_data

class ScanRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_scan(
        self,
        raw_text: str,
        classification: str,
        is_suspicious: bool,
        risk_score: float,
        risk_level: str,
        model_version: str,
        model_name: str,
        indicators: Dict[str, Any],
        explanation: Dict[str, Any],
        user_id: Optional[str] = None
    ) -> ScanRecord:
        """Stores a new investigation record with privacy protections and optional user link."""
        redacted = redact_sensitive_data(raw_text)
        preview = (redacted[:140] + "...") if len(redacted) > 140 else redacted
        msg_hash = hash_text(raw_text)
        norm_risk = risk_level.upper() if risk_level else ("HIGH" if risk_score >= 0.65 else ("MEDIUM" if risk_score >= 0.35 else "LOW"))

        scan = ScanRecord(
            message_hash=msg_hash,
            message_preview=preview,
            classification=classification,
            is_suspicious=is_suspicious,
            risk_score=risk_score,
            risk_level=norm_risk,
            model_version=model_version,
            model_name=model_name,
            indicators_json=json.dumps(indicators),
            explanation_json=json.dumps(explanation),
            user_id=user_id,
            created_at=datetime.now(timezone.utc)
        )
        self.db.add(scan)
        self.db.commit()
        self.db.refresh(scan)
        return scan

    def get_by_id(self, scan_id: str) -> Optional[ScanRecord]:
        return self.db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()

    def list_scans(
        self,
        skip: int = 0,
        limit: int = 50,
        risk_level: Optional[str] = None,
        search_query: Optional[str] = None,
        only_guest: bool = True
    ) -> Tuple[List[ScanRecord], int]:
        """
        Lists scan history with optional filtering and pagination.
        By default (only_guest=True), displays guest scans (user_id is NULL)
        to protect authenticated user scans from public discovery.
        """
        query = self.db.query(ScanRecord)

        if only_guest:
            query = query.filter(ScanRecord.user_id.is_(None))

        if risk_level and risk_level.upper() in ["LOW", "MEDIUM", "HIGH"]:
            if risk_level.upper() == "HIGH":
                query = query.filter(func.upper(ScanRecord.risk_level).in_(["HIGH", "CRITICAL"]))
            else:
                query = query.filter(func.upper(ScanRecord.risk_level) == risk_level.upper())

        if search_query and search_query.strip():
            term = f"%{search_query.strip()}%"
            query = query.filter(ScanRecord.message_preview.ilike(term))

        total_count = query.count()
        records = query.order_by(desc(ScanRecord.created_at)).offset(skip).limit(limit).all()
        return records, total_count

    def list_user_scans(
        self,
        user_id: str,
        skip: int = 0,
        limit: int = 50,
        risk_level: Optional[str] = None,
        search_query: Optional[str] = None
    ) -> Tuple[List[ScanRecord], int]:
        """Lists personal scan history strictly isolated to the specified user."""
        query = self.db.query(ScanRecord).filter(ScanRecord.user_id == user_id)

        if risk_level and risk_level.upper() in ["LOW", "MEDIUM", "HIGH"]:
            if risk_level.upper() == "HIGH":
                query = query.filter(func.upper(ScanRecord.risk_level).in_(["HIGH", "CRITICAL"]))
            else:
                query = query.filter(func.upper(ScanRecord.risk_level) == risk_level.upper())

        if search_query and search_query.strip():
            term = f"%{search_query.strip()}%"
            query = query.filter(ScanRecord.message_preview.ilike(term))

        total_count = query.count()
        records = query.order_by(desc(ScanRecord.created_at)).offset(skip).limit(limit).all()
        return records, total_count

    def get_user_scan(self, user_id: str, scan_id: str) -> Optional[ScanRecord]:
        """Fetches a specific scan record if and only if it belongs to user_id."""
        return self.db.query(ScanRecord).filter(
            ScanRecord.id == scan_id,
            ScanRecord.user_id == user_id
        ).first()

    def delete_by_id(self, scan_id: str, allow_user_owned: bool = False) -> bool:
        """Deletes a guest scan, or user-owned scan if explicitly allowed."""
        scan = self.get_by_id(scan_id)
        if not scan:
            return False
        if scan.user_id is not None and not allow_user_owned:
            return False
        self.db.delete(scan)
        self.db.commit()
        return True

    def delete_user_scan(self, user_id: str, scan_id: str) -> bool:
        """Deletes a personal scan belonging strictly to user_id."""
        scan = self.get_user_scan(user_id, scan_id)
        if not scan:
            return False
        self.db.delete(scan)
        self.db.commit()
        return True

    def clear_all(self, user_id: Optional[str] = None) -> int:
        """
        Clears scan history.
        If user_id is provided, deletes all scans belonging to that user.
        If user_id is None, deletes only guest/anonymous scans (user_id is NULL).
        """
        query = self.db.query(ScanRecord)
        if user_id is not None:
            query = query.filter(ScanRecord.user_id == user_id)
        else:
            query = query.filter(ScanRecord.user_id.is_(None))

        count = query.delete(synchronize_session=False)
        self.db.commit()
        return count

    def get_aggregated_metrics(self, user_id: Optional[str] = None) -> Dict[str, Any]:
        """Calculates live scan statistics across investigations (user-isolated if user_id provided)."""
        base_query = self.db.query(ScanRecord)
        if user_id is not None:
            base_query = base_query.filter(ScanRecord.user_id == user_id)

        total = base_query.count()
        if total == 0:
            return {
                "total_scans": 0,
                "suspicious_scans": 0,
                "legitimate_scans": 0,
                "average_risk_score": 0.0,
                "risk_distribution": {"LOW": 0, "MEDIUM": 0, "HIGH": 0}
            }

        suspicious_count = base_query.filter(ScanRecord.is_suspicious == True).count()
        legit_count = total - suspicious_count

        avg_query = self.db.query(func.avg(ScanRecord.risk_score))
        if user_id is not None:
            avg_query = avg_query.filter(ScanRecord.user_id == user_id)
        avg_score = avg_query.scalar() or 0.0

        low_count = base_query.filter(func.upper(ScanRecord.risk_level) == "LOW").count()
        med_count = base_query.filter(func.upper(ScanRecord.risk_level) == "MEDIUM").count()
        high_count = base_query.filter(func.upper(ScanRecord.risk_level).in_(["HIGH", "CRITICAL"])).count()

        unaccounted = total - (low_count + med_count + high_count)
        if unaccounted > 0:
            high_count += unaccounted

        return {
            "total_scans": total,
            "suspicious_scans": suspicious_count,
            "legitimate_scans": legit_count,
            "average_risk_score": round(float(avg_score), 4),
            "risk_distribution": {
                "LOW": low_count,
                "MEDIUM": med_count,
                "HIGH": high_count
            }
        }


class FeedbackRepository:
    def __init__(self, db: Session):
        self.db = db

    def submit_feedback(
        self,
        scan_id: str,
        is_helpful: Optional[bool] = None,
        user_label: Optional[str] = None,
        user_notes: Optional[str] = None
    ) -> Optional[UserFeedback]:
        scan = self.db.query(ScanRecord).filter(ScanRecord.id == scan_id).first()
        if not scan:
            return None

        feedback = UserFeedback(
            scan_id=scan_id,
            is_helpful=is_helpful,
            user_label=user_label.lower() if user_label else None,
            user_notes=user_notes,
            created_at=datetime.now(timezone.utc)
        )
        self.db.add(feedback)
        self.db.commit()
        self.db.refresh(feedback)
        return feedback


class UserRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_user(self, full_name: str, email: str, hashed_password: str) -> User:
        """Creates a new registered user with normalized email."""
        user = User(
            full_name=full_name.strip(),
            email=email.strip().lower(),
            hashed_password=hashed_password,
            is_active=True,
            created_at=datetime.now(timezone.utc)
        )
        self.db.add(user)
        self.db.commit()
        self.db.refresh(user)
        return user

    def get_by_email(self, email: str) -> Optional[User]:
        """Case-insensitive user lookup by email."""
        if not email:
            return None
        norm_email = email.strip().lower()
        return self.db.query(User).filter(func.lower(User.email) == norm_email).first()

    def get_by_id(self, user_id: str) -> Optional[User]:
        return self.db.query(User).filter(User.id == user_id).first()

    def count_user_scans(self, user_id: str) -> int:
        return self.db.query(ScanRecord).filter(ScanRecord.user_id == user_id).count()


class SessionRepository:
    def __init__(self, db: Session):
        self.db = db

    def create_session(
        self,
        user_id: str,
        session_token: str,
        csrf_token: str,
        expires_at: datetime
    ) -> UserSession:
        user_session = UserSession(
            user_id=user_id,
            session_token=session_token,
            csrf_token=csrf_token,
            expires_at=expires_at,
            created_at=datetime.now(timezone.utc)
        )
        self.db.add(user_session)
        self.db.commit()
        self.db.refresh(user_session)
        return user_session

    def get_session(self, session_token: str) -> Optional[UserSession]:
        return self.db.query(UserSession).filter(UserSession.session_token == session_token).first()

    def delete_session(self, session_token: str) -> bool:
        session_record = self.get_session(session_token)
        if not session_record:
            return False
        self.db.delete(session_record)
        self.db.commit()
        return True

    def delete_all_for_user(self, user_id: str) -> int:
        count = self.db.query(UserSession).filter(UserSession.user_id == user_id).delete()
        self.db.commit()
        return count
