"""
Authentication and User Account endpoints for TrustLens AI.
Handles registration, login, logout, session verification, and personal scan isolation.
"""

from datetime import datetime, timezone, timedelta
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, Response, status, Query
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.security import limiter
from app.core.auth import (
    hash_password,
    verify_password,
    validate_password_complexity,
    validate_email_format,
    generate_tokens,
    set_auth_cookies,
    clear_auth_cookies,
    extract_session_token,
    get_current_user,
    get_optional_current_user
)
from app.db.session import get_db
from app.db.models import User, UserSession
from app.db.repository import UserRepository, SessionRepository, ScanRepository
from app.api.schemas import (
    UserRegisterRequest,
    UserLoginRequest,
    UserResponse,
    UserSessionResponse,
    MyScansResponse,
    ScanSummaryItem,
    ScanDetailResponse
)

router = APIRouter(prefix="/auth")

# Pre-computed dummy hash to mitigate timing-based user enumeration
_DUMMY_HASH = "$argon2id$v=19$m=19456,t=2,p=1$7vMvZP3T0n5gWl0bV2tF8A$5jKqL0lX7r8Q2m3k6V4s1a"

@router.post(
    "/register",
    response_model=UserSessionResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a new user account and establish session"
)
def register_user(
    payload: UserRegisterRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    # 1. Validate full name
    name = payload.full_name.strip()
    if len(name) < 2:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Full name must be at least 2 characters long."
        )

    # 2. Validate email format
    email = payload.email.strip().lower()
    if not validate_email_format(email):
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Please provide a valid email address."
        )

    # 3. Check password matching
    if payload.password != payload.confirm_password:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Passwords do not match. Please re-enter your password."
        )

    # 4. Check password complexity
    is_valid, msg = validate_password_complexity(payload.password)
    if not is_valid:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=msg
        )

    # 5. Check duplicate email
    user_repo = UserRepository(db)
    existing = user_repo.get_by_email(email)
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="An account with this email address already exists. Please sign in instead."
        )

    # 6. Hash password with Argon2
    hashed = hash_password(payload.password)

    # 7. Create user
    user = user_repo.create_user(full_name=name, email=email, hashed_password=hashed)

    # 8. Create session
    session_token, csrf_token = generate_tokens()
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.SESSION_MAX_AGE_DAYS)
    
    session_repo = SessionRepository(db)
    session_repo.create_session(
        user_id=user.id,
        session_token=session_token,
        csrf_token=csrf_token,
        expires_at=expires_at
    )

    # 9. Set HttpOnly and CSRF cookies
    set_auth_cookies(response, session_token, csrf_token)

    return UserSessionResponse(
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            created_at=user.created_at,
            total_scans=0
        ),
        csrf_token=csrf_token,
        message="Account created successfully."
    )


@router.post(
    "/login",
    response_model=UserSessionResponse,
    status_code=status.HTTP_200_OK,
    summary="Authenticate user and issue session"
)
@limiter.limit(settings.LOGIN_RATE_LIMIT)
def login_user(
    payload: UserLoginRequest,
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    email = payload.email.strip().lower()
    user_repo = UserRepository(db)
    user = user_repo.get_by_email(email)

    # Constant-time mitigation against timing enumeration
    if not user:
        verify_password(payload.password, _DUMMY_HASH)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid email or password."
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This account has been deactivated."
        )

    # Create session
    session_token, csrf_token = generate_tokens()
    expires_at = datetime.now(timezone.utc) + timedelta(days=settings.SESSION_MAX_AGE_DAYS)
    
    session_repo = SessionRepository(db)
    session_repo.create_session(
        user_id=user.id,
        session_token=session_token,
        csrf_token=csrf_token,
        expires_at=expires_at
    )

    # Set cookies
    set_auth_cookies(response, session_token, csrf_token)

    total_scans = user_repo.count_user_scans(user.id)

    return UserSessionResponse(
        user=UserResponse(
            id=user.id,
            email=user.email,
            full_name=user.full_name,
            created_at=user.created_at,
            total_scans=total_scans
        ),
        csrf_token=csrf_token,
        message="Signed in successfully."
    )


@router.post(
    "/logout",
    status_code=status.HTTP_200_OK,
    summary="Terminate active session and clear cookies"
)
def logout_user(
    request: Request,
    response: Response,
    db: Session = Depends(get_db)
):
    token = extract_session_token(request)
    if token:
        session_repo = SessionRepository(db)
        session_repo.delete_session(token)

    clear_auth_cookies(response)
    return {"status": "logged_out", "message": "Signed out successfully."}


@router.get(
    "/me",
    response_model=UserSessionResponse,
    summary="Retrieve current authenticated user and session metadata"
)
def get_current_user_profile(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    token = extract_session_token(request)
    csrf_token = ""
    if token:
        session_repo = SessionRepository(db)
        s = session_repo.get_session(token)
        if s:
            csrf_token = s.csrf_token

    user_repo = UserRepository(db)
    total_scans = user_repo.count_user_scans(current_user.id)

    return UserSessionResponse(
        user=UserResponse(
            id=current_user.id,
            email=current_user.email,
            full_name=current_user.full_name,
            created_at=current_user.created_at,
            total_scans=total_scans
        ),
        csrf_token=csrf_token,
        message="Active session verified."
    )


@router.get(
    "/my-scans",
    response_model=MyScansResponse,
    summary="List investigations performed by the current authenticated user"
)
def get_my_scans(
    skip: int = Query(0, ge=0),
    limit: int = Query(50, ge=1, le=100),
    risk_level: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
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

    return MyScansResponse(
        total=total,
        skip=skip,
        limit=limit,
        items=items
    )


@router.get(
    "/my-scans/{scan_id}",
    response_model=ScanDetailResponse,
    summary="Retrieve detail of a personal scan"
)
def get_my_scan_detail(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = ScanRepository(db)
    record = repo.get_user_scan(user_id=current_user.id, scan_id=scan_id)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found or does not belong to your account."
        )

    import json
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
    "/my-scans/{scan_id}",
    status_code=status.HTTP_200_OK,
    summary="Delete a personal scan from account history"
)
def delete_my_scan(
    scan_id: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = ScanRepository(db)
    success = repo.delete_user_scan(user_id=current_user.id, scan_id=scan_id)
    if not success:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Scan record not found or does not belong to your account."
        )
    return {"status": "deleted", "scan_id": scan_id}


@router.delete(
    "/my-scans",
    status_code=status.HTTP_200_OK,
    summary="Clear all personal scans for the authenticated account"
)
def clear_my_scans(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    repo = ScanRepository(db)
    count = repo.clear_all(user_id=current_user.id)
    return {"status": "cleared", "records_removed": count}
