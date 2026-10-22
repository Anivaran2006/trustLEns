"""
Unit tests for database repository operations, privacy sanitization, and metrics.
"""

from app.db.repository import ScanRepository, FeedbackRepository
from app.db.models import ScanRecord

def test_scan_repository_crud(test_db):
    repo = ScanRepository(test_db)
    
    # Create scan
    scan = repo.create_scan(
        raw_text="Test message with card 4532 1234 5678 9010",
        classification="SPAM",
        is_suspicious=True,
        risk_score=0.92,
        risk_level="HIGH",
        model_version="1.0.0",
        model_name="TestModel",
        indicators={"urls_detected": []},
        explanation={"summary": "Suspicious card data"}
    )
    assert scan.id is not None
    # Ensure sensitive card number was redacted in message_preview
    assert "4532" not in scan.message_preview
    assert "[REDACTED_CARD_NUMBER]" in scan.message_preview

    # Read scan
    fetched = repo.get_by_id(scan.id)
    assert fetched is not None
    assert fetched.risk_level == "HIGH"

    # List scans
    records, count = repo.list_scans()
    assert count == 1
    assert len(records) == 1

    # Filter scans
    records_low, count_low = repo.list_scans(risk_level="LOW")
    assert count_low == 0

    # Delete scan
    deleted = repo.delete_by_id(scan.id)
    assert deleted is True
    assert repo.get_by_id(scan.id) is None

def test_scan_repository_metrics(test_db):
    repo = ScanRepository(test_db)
    # Empty metrics
    empty_metrics = repo.get_aggregated_metrics()
    assert empty_metrics["total_scans"] == 0

    # Add 2 scans
    repo.create_scan("Msg 1", "HAM", False, 0.1, "LOW", "1.0", "Model", {}, {})
    repo.create_scan("Msg 2", "SPAM", True, 0.9, "HIGH", "1.0", "Model", {}, {})

    metrics = repo.get_aggregated_metrics()
    assert metrics["total_scans"] == 2
    assert metrics["suspicious_scans"] == 1
    assert metrics["legitimate_scans"] == 1
    assert metrics["risk_distribution"]["LOW"] == 1
    assert metrics["risk_distribution"]["HIGH"] == 1
    assert 0.4 < metrics["average_risk_score"] < 0.6

def test_sensitive_pii_redaction_coverage(test_db):
    repo = ScanRepository(test_db)
    raw = "Alert: verification code: 948201 for ssn 123-45-6789 email user@test.com and password: SuperSecret!"
    scan = repo.create_scan(
        raw_text=raw,
        classification="SPAM",
        is_suspicious=True,
        risk_score=0.88,
        risk_level="HIGH",
        model_version="1.0.0",
        model_name="TestModel",
        indicators={},
        explanation={}
    )
    assert "948201" not in scan.message_preview
    assert "123-45-6789" not in scan.message_preview
    assert "user@test.com" not in scan.message_preview
    assert "SuperSecret!" not in scan.message_preview
    assert "[REDACTED_CODE]" in scan.message_preview
    assert "[REDACTED_SSN]" in scan.message_preview
    assert "[REDACTED_EMAIL]" in scan.message_preview
    assert "[REDACTED_SECRET]" in scan.message_preview

