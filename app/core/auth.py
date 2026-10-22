"""
Authentication, Argon2 password hashing, session tokens, and FastAPI security dependencies for TrustLens AI.
"""

import re
import secrets
from datetime import datetime, timezone, timedelta
from typing import Optional, Tuple
from argon2 import PasswordHasher
from argon2.exceptions import VerifyMismatchError, VerificationError, InvalidHashError
from fastapi import Request, Response, HTTPException, status, Depends
from sqlalchemy.orm import Session

from app.core.config import settings
from app.db.session import get_db
from app.db.models import User, UserSession

# Configure Argon2id password hasher with secure parameters
_hasher = PasswordHasher(
    time_cost=2,
    memory_cost=19456,  # 19 MiB
    parallelism=1,
    hash_len=32
)

def hash_password(password: str) -> str:
    """Securely hashes a plaintext password using Argon2id."""
    return _hasher.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifies a plaintext password against an Argon2id hash."""
    if not plain_password or not hashed_password:
        return False
    try:
        return _hasher.verify(hashed_password, plain_password)
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        return False

def validate_password_complexity(password: str) -> Tuple[bool, str]:
    """
    Validates password strength:
    - Minimum 8 characters
    - At least one letter
    - At least one digit or special character
    """
    if len(password) < 8:
        return False, "Password must be at least 8 characters long."
    if len(password) > 128:
        return False, "Password cannot exceed 128 characters."
    if not re.search(r"[a-zA-Z]", password):
        return False, "Password must contain at least one letter."
    if not re.search(r"[\d\W_]", password):
        return False, "Password must contain at least one number or special character."
    return True, ""

def validate_email_format(email: str) -> bool:
    """Validates basic RFC-compliant email structure."""
    if not email or len(email) > 255:
        return False
    email_regex = r"^[^@\s]+@[^@\s]+\.[^@\s]+$"
    return bool(re.match(email_regex, email.strip()))

def generate_tokens() -> Tuple[str, str]:
    """Generates high-entropy session and CSRF tokens."""
    session_token = secrets.token_urlsafe(32)
    csrf_token = secrets.token_urlsafe(32)
    return session_token, csrf_token

def set_auth_cookies(response: Response, session_token: str, csrf_token: str, max_age_days: Optional[int] = None) -> None:
    """
    Sets secure HttpOnly session cookie and accessible CSRF cookie for double-submit verification.
    """
    max_days = max_age_days or settings.SESSION_MAX_AGE_DAYS
    max_age_seconds = max_days * 24 * 60 * 60

    # 1. HttpOnly Session Cookie (inaccessible to JavaScript)
    response.set_cookie(
        key=settings.SESSION_COOKIE_NAME,
        value=session_token,
        max_age=max_age_seconds,
        httponly=True,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE,
        path="/"
    )

    # 2. Double-Submit CSRF Cookie (readable by frontend JavaScript to pass in X-CSRF-Token header)
    response.set_cookie(
        key=settings.CSRF_COOKIE_NAME,
        value=csrf_token,
        max_age=max_age_seconds,
        httponly=False,
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE,
        path="/"
    )

def clear_auth_cookies(response: Response) -> None:
    """Clears authentication cookies upon logout."""
    response.delete_cookie(
        key=settings.SESSION_COOKIE_NAME,
        path="/",
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE
    )
    response.delete_cookie(
        key=settings.CSRF_COOKIE_NAME,
        path="/",
        samesite=settings.COOKIE_SAMESITE,
        secure=settings.COOKIE_SECURE
    )

def extract_session_token(request: Request) -> Optional[str]:
    """Extracts session token from HttpOnly cookie or Authorization: Bearer header."""
    # 1. Cookie check
    cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if cookie_token:
        return cookie_token

    # 2. Bearer header fallback
    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token:
            return token

    return None

def get_optional_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> Optional[User]:
    """
    FastAPI dependency: Returns User if valid active session exists, else None.
    Crucial for guest mode: Does NOT raise 401.
    """
    token = extract_session_token(request)
    if not token:
        return None

    now = datetime.now(timezone.utc)
    session_record = db.query(UserSession).filter(
        UserSession.session_token == token
    ).first()

    if not session_record:
        return None

    # Check expiration (ensure naive/utc comparison safe)
    expires = session_record.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < now:
        db.delete(session_record)
        db.commit()
        return None

    user = db.query(User).filter(User.id == session_record.user_id, User.is_active == True).first()
    return user

def get_current_user(
    request: Request,
    db: Session = Depends(get_db)
) -> User:
    """
    FastAPI dependency: Enforces authenticated session.
    Also validates CSRF token for unsafe HTTP methods when session is cookie-based.
    """
    token = extract_session_token(request)
    if not token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required. Please sign in to access this feature."
        )

    now = datetime.now(timezone.utc)
    session_record = db.query(UserSession).filter(
        UserSession.session_token == token
    ).first()

    if not session_record:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired or is invalid. Please sign in again."
        )

    expires = session_record.expires_at
    if expires.tzinfo is None:
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < now:
        db.delete(session_record)
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has expired. Please sign in again."
        )

    user = db.query(User).filter(User.id == session_record.user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User account is deactivated or no longer exists."
        )

    # CSRF Check: if request came with session cookie (not pure Bearer header) on mutating methods
    cookie_token = request.cookies.get(settings.SESSION_COOKIE_NAME)
    if cookie_token and request.method in ("POST", "PUT", "DELETE", "PATCH"):
        csrf_header = request.headers.get("X-CSRF-Token")
        if not csrf_header or not secrets.compare_digest(csrf_header, session_record.csrf_token):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Security check failed: Invalid or missing CSRF verification token."
            )

    return user
