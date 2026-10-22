"""
Unit tests for text preprocessing and security feature extraction.
"""

from ml.preprocessor import clean_security_text, extract_security_indicators, SecurityTextPreprocessor

def test_clean_security_text_preserves_url_tokens():
    raw = "Visit http://phishing-site.xyz/login now for your reward!"
    cleaned = clean_security_text(raw)
    assert "__url__" in cleaned
    assert "reward" in cleaned
    assert "visit" in cleaned


def test_clean_security_text_preserves_currency():
    raw = "You have won $5,000 cash or £2,500 vouchers!"
    cleaned = clean_security_text(raw)
    assert "__currency__" in cleaned

def test_clean_security_text_preserves_phone():
    raw = "Call 08712400602 to claim or text back to 87007 immediately"
    cleaned = clean_security_text(raw)
    assert "__phone__" in cleaned

def test_clean_security_text_empty_input():
    assert clean_security_text("") == ""
    assert clean_security_text("   ") == ""
    assert clean_security_text(None) == ""

def test_extract_security_indicators_detects_urgency_and_actions():
    msg = "URGENT: Alert! Your account is suspended. Click http://verify-now.com to confirm your password and claim $500 refund!!!"
    indicators = extract_security_indicators(msg)
    
    assert len(indicators["urls_detected"]) > 0
    assert "urgent" in indicators["urgency_cues"]
    assert "suspended" in indicators["urgency_cues"]
    assert "verify" in indicators["action_cues"]
    assert "password" in indicators["action_cues"]
    assert len(indicators["currencies_detected"]) > 0
    assert indicators["excessive_punctuation"] is True

def test_security_text_preprocessor_transformer():
    transformer = SecurityTextPreprocessor()
    transformed = transformer.transform(["Check http://link.com now!"])
    assert len(transformed) == 1
    assert "__url__" in transformed[0]
