"""
History management endpoints for TrustLens AI.
Supports paginated listings, search, detail retrieval, single record deletion, and bulk wipe.
Ensures strict privacy isolation between guest demo history and authenticated personal history.
"""

import json
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import User
from app.db.repository import ScanRepository
from app.core.auth import get_current_user
from app.api.schemas import ScanHistoryResponse, ScanSummaryItem, ScanDetailResponse

router = APIRouter()

@router.get(
    "/history",
    response_model=ScanHistoryResponse,
    summary="List past message investigations with privacy isolation and optional filtering"
)
def get_scan_history(
    skip: int = Query(0, ge=0, description="Offset index for pagination"),
    limit: int = Query(50, ge=1, le=100, description="Max items to retrieve"),
    risk_level: Optional[str] = Query(None, description="Filter by risk category: LOW, MEDIUM, HIGH"),
    search: Optional[str] = Query(None, description="Search term for message preview"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = ScanRepository(db)
    records, total = repo.list_user_scans(
        user_id=current_user.id,
        skip=skip,
        limit=limit,
        risk_level=risk_level,
        search_query=search
    )

    items = [
        ScanSummaryItem(
            id=r.id,
            created_at=r.created_at,
            message_preview=r.message_preview,
            classification=r.classification,
            is_suspicious=r.is_suspicious,
            risk_score=r.risk_score,
            risk_level=r.risk_level,
            model_version=r.model_version
        )
        for r in records
    ]

    return ScanHistoryResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=items
    )

@router.get(
    "/history/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Retrieve full audit details for a specific investigation"
)
def get_scan_detail(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = ScanRepository(db)
    record = repo.get_user_scan(user_id=current_user.id, scan_id=scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found or access restricted."
        )

    indicators = json.loads(record.indicators_json) if record.indicators_json else {}
    investigation = json.loads(record.explanation_json) if record.explanation_json else {}

    return ScanDetailResponse(
        id=record.id,
        created_at=record.created_at,
        message_preview=record.message_preview,
        classification=record.classification,
        is_suspicious=record.is_suspicious,
        risk_score=record.risk_score,
        risk_level=record.risk_level,
        model_version=record.model_version,
        model_name=record.model_name,
        observable_indicators=indicators,
        investigation=investigation
    )

@router.delete(
    "/history/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a specific scan record from persistent storage"
)
def delete_scan_record(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = ScanRepository(db)
    success = repo.delete_user_scan(user_id=current_user.id, scan_id=scan_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found or access restricted."
        )

    return {"status": "deleted", "scan_id": scan_id}

@router.delete(
    "/history",
    status_code=status.HTTP_200_OK,
    summary="Clear persistent scan history (Privacy wipe)"
)
def clear_all_history(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = ScanRepository(db)
    count = repo.clear_all(user_id=current_user.id)
    return {"status": "cleared", "records_removed": count}

