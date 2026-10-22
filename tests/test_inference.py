"""
Unit tests for ML inference service, model loading, and score calibration.
"""

from app.ml.inference import MLInferenceService

def test_inference_service_initialization():
    service = MLInferenceService.get_instance()
    assert service.is_ready is True
    assert service.pipeline is not None
    assert "model_version" in service.metadata

def test_inference_positive_spam_example():
    service = MLInferenceService.get_instance()
    spam_text = "WINNER! You have won a £1000 cash prize or a guaranteed iPhone. Call 09061701461 to claim now!"
    result = service.predict(spam_text)
    
    assert result["classification"] == "SPAM"
    assert result["is_suspicious"] is True
    assert result["risk_score"] > 0.5
    assert result["risk_level"] in ["MEDIUM", "HIGH"]
    assert "observable_indicators" in result

def test_inference_negative_ham_example():
    service = MLInferenceService.get_instance()
    ham_text = "Hey are we still meeting tomorrow for coffee around noon?"
    result = service.predict(ham_text)
    
    assert result["classification"] == "HAM"
    assert result["is_suspicious"] is False
    assert result["risk_score"] < 0.5
    assert result["risk_level"] == "LOW"

def test_inference_empty_and_whitespace():
    service = MLInferenceService.get_instance()
    result = service.predict("")
    assert result["classification"] == "HAM"
    assert result["risk_score"] == 0.0
    assert result["risk_level"] == "LOW"

def test_inference_very_long_message():
    service = MLInferenceService.get_instance()
    long_text = "Normal message content. " * 300
    result = service.predict(long_text)
    assert "classification" in result
    assert 0.0 <= result["risk_score"] <= 1.0
