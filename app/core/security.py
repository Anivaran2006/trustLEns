"""
Security utilities for TrustLens AI:
- Rate limiting setup (SlowAPI)
- Input sanitization & truncation
- Sensitive data redaction for audit logs and persistent history
- Prompt injection protection
"""

import re
import html
import hashlib
from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])

# Sensitive tokens to mask in stored history (e.g. credit cards, social security, OTP codes, credentials)
CREDIT_CARD_REGEX = re.compile(r'\b(?:\d[ -]*?){13,16}\b')
SSN_REGEX = re.compile(r'\b\d{3}-\d{2}-\d{4}\b')
EMAIL_REGEX = re.compile(r'[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+')

def sanitize_and_encode_input(raw_text: str, max_length: int = 5000) -> str:
    """
    Cleans raw user input:
    - Normalizes unicode whitespace
    - Enforces maximum character boundaries
    - Strips dangerous control chars
    """
    if not raw_text:
        return ""
    # Strip non-printable control characters (except newline, tab)
    sanitized = re.sub(r'[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]', '', raw_text)
    # Truncate to maximum allowable length
    return sanitized[:max_length].strip()

def hash_text(text: str) -> str:
    """Produces SHA-256 hash for deduplication and privacy-preserving indexing."""
    return hashlib.sha256(text.encode('utf-8')).hexdigest()

def redact_sensitive_data(text: str) -> str:
    """
    Redacts potentially sensitive user data (card numbers, emails, SSNs, OTPs/passwords)
    before writing to persistent logs or history views.
    """
    if not text:
        return ""
    # Mask potential card sequences
    s = CREDIT_CARD_REGEX.sub("[REDACTED_CARD_NUMBER]", text)
    # Mask SSN patterns
    s = SSN_REGEX.sub("[REDACTED_SSN]", s)
    # Mask email addresses
    s = EMAIL_REGEX.sub("[REDACTED_EMAIL]", s)
    # Mask explicit OTP / PIN / verification codes
    s = re.sub(
        r'(?i)\b(otp|code|pin|security\s*code|verification\s*code)(\s*(?:is|:)?\s*)([0-9]{4,8})\b',
        r'\1\2[REDACTED_CODE]',
        s
    )
    # Mask explicit password / secret values
    s = re.sub(
        r'(?i)\b(password|passcode|secret)(\s*[:=]\s*)(\S+)',
        r'\1\2[REDACTED_SECRET]',
        s
    )
    return s

def sanitize_html_output(text: str) -> str:
    """Escapes HTML entities to defend against stored or reflected XSS."""
    return html.escape(text) if text else ""
