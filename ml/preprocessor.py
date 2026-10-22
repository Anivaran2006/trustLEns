"""
Text Preprocessing and Security Feature Extraction for TrustLens AI.
Preserves vital security signals (URLs, phone numbers, currency symbols, urgent punctuation)
while normalizing noisy text without data leakage.
"""

import re
from typing import Dict, Any, List
from sklearn.base import BaseEstimator, TransformerMixin

# Regular expressions for security indicators
URL_PATTERN = re.compile(
    r'(?:https?:\/\/|www\.)[^\s/$.?#].[^\s]*|'
    r'[a-zA-Z0-9.-]+\.(?:com|org|net|io|co|uk|us|biz|info|xyz|me|top|online|click|link|app|ru|cn)\b[^\s]*',
    re.IGNORECASE
)
PHONE_PATTERN = re.compile(
    r'(?:\+?\d{1,3}[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}|\b\d{5,7}\b|\b0\d{10}\b'
)
CURRENCY_PATTERN = re.compile(
    r'[$£€¥₹]\s*\d+(?:[.,]\d+)?|\b\d+(?:[.,]\d+)?\s*(?:pounds|dollars|euros|gbp|usd|inr|cash|bucks)\b',
    re.IGNORECASE
)
URGENCY_KEYWORDS = [
    "urgent", "immediately", "immediate", "alert", "action required", "warning",
    "expire", "expiring", "suspended", "suspension", "locked", "compromised",
    "limited time", "final notice", "deadline", "act now", "critical", "freeze"
]
ACTION_KEYWORDS = [
    "verify", "claim", "winner", "won", "prize", "congratulations", "login",
    "click", "call", "update", "confirm", "otp", "pin", "password", "security code",
    "refund", "unauthorized", "wire transfer", "gift card", "crypto", "bitcoin"
]

def clean_security_text(text: str) -> str:
    """
    Transforms raw message into security-tokenized text.
    Replaces raw URLs with __URL__, phones with __PHONE__, currency with __CURRENCY__,
    while preserving token frequency and security signals.
    """
    if not isinstance(text, str) or not text.strip():
        return ""

    s = text

    # Replace URLs with explicit token
    s = URL_PATTERN.sub(" __URL__ ", s)

    # Replace currency amounts with explicit token
    s = CURRENCY_PATTERN.sub(" __CURRENCY__ ", s)

    # Replace phone numbers and shortcodes with explicit token
    s = PHONE_PATTERN.sub(" __PHONE__ ", s)

    # Preserve excessive punctuation cues by condensing them into distinct tokens
    s = re.sub(r'!{2,}', ' __MULTI_EXCLAMATION__ ', s)
    s = re.sub(r'\?{2,}', ' __MULTI_QUESTION__ ', s)

    # Convert to lowercase for NLP vectorization
    s = s.lower()

    # Clean superfluous non-alphanumeric characters while keeping underscores for tokens
    s = re.sub(r'[^a-z0-9_\s]', ' ', s)

    # Collapse repeated whitespace
    s = re.sub(r'\s+', ' ', s).strip()

    return s


def extract_security_indicators(text: str) -> Dict[str, Any]:
    """
    Extracts observable threat indicators from a message.
    Used by the AI investigation layer to provide evidence-based analysis.
    """
    if not isinstance(text, str):
        text = ""

    urls = URL_PATTERN.findall(text)
    phones = PHONE_PATTERN.findall(text)
    currencies = CURRENCY_PATTERN.findall(text)

    text_lower = text.lower()
    found_urgency = [kw for kw in URGENCY_KEYWORDS if kw in text_lower]
    found_actions = [kw for kw in ACTION_KEYWORDS if kw in text_lower]

    caps_count = sum(1 for c in text if c.isupper())
    total_letters = sum(1 for c in text if c.isalpha())
    caps_ratio = (caps_count / total_letters) if total_letters > 0 else 0.0

    has_multi_excl = bool(re.search(r'!{2,}', text))
    has_multi_quest = bool(re.search(r'\?{2,}', text))

    return {
        "urls_detected": urls,
        "phones_detected": phones,
        "currencies_detected": currencies,
        "urgency_cues": found_urgency,
        "action_cues": found_actions,
        "all_caps_ratio": round(caps_ratio, 3),
        "excessive_punctuation": has_multi_excl or has_multi_quest,
        "char_length": len(text),
        "word_count": len(text.split())
    }


class SecurityTextPreprocessor(BaseEstimator, TransformerMixin):
    """
    Scikit-learn compatible transformer for text cleaning.
    Ensures safe pickling and clean pipeline integration.
    """
    def __init__(self):
        pass

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        if hasattr(X, "tolist"):
            X = X.tolist()
        return [clean_security_text(str(x)) for x in X]
