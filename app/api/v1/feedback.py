"""
User feedback endpoint for TrustLens AI.
Stores user evaluations safely separated from verified ground-truth training datasets.
"""

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import User, ScanRecord
from app.db.repository import FeedbackRepository
from app.core.auth import get_current_user
from app.api.schemas import FeedbackRequest, FeedbackResponse

router = APIRouter()

@router.post(
    "/feedback",
    response_model=FeedbackResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Submit user feedback on an investigation result"
)
def submit_feedback(
    payload: FeedbackRequest,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    scan = db.query(ScanRecord).filter(ScanRecord.id == payload.scan_id).first()
    if not scan:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record {payload.scan_id} not found."
        )
    if scan.user_id is not None and scan.user_id != current_user.id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied: Cannot submit feedback on another user's investigation."
        )

    repo = FeedbackRepository(db)
    feedback = repo.submit_feedback(
        scan_id=payload.scan_id,
        is_helpful=payload.is_helpful,
        user_label=payload.user_label,
        user_notes=payload.user_notes
    )

    if not feedback:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan record {payload.scan_id} not found."
        )

    return FeedbackResponse(
        id=feedback.id,
        scan_id=feedback.scan_id,
        status="recorded",
        message="User feedback successfully logged. Maintained separately from verified ground-truth datasets."
    )
