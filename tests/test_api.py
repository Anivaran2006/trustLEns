"""
Integration tests for FastAPI endpoints:
- GET /health
- GET /ready
- POST /api/v1/analyze
- GET /api/v1/history
- GET /api/v1/history/{scan_id}
- DELETE /api/v1/history/{scan_id}
- DELETE /api/v1/history
- GET /api/v1/metrics
- GET /api/v1/samples
- POST /api/v1/feedback
"""

def test_health_check(client):
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert "version" in data

def test_ready_check(client):
    response = client.get("/ready")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ready"
    assert data["model_loaded"] is True
    assert data["database_connected"] is True

def test_unauthenticated_access_rejected(client):
    """Verify that all protected endpoints reject unauthenticated requests with HTTP 401."""
    # 1. Analyze endpoint
    res_analyze = client.post("/api/v1/analyze", json={"message": "Suspicious login attempt detected"})
    assert res_analyze.status_code == 401
    assert "Authentication required" in res_analyze.json()["detail"]

    # 2. History endpoint
    res_history = client.get("/api/v1/history")
    assert res_history.status_code == 401

    # 3. Metrics endpoint
    res_metrics = client.get("/api/v1/metrics")
    assert res_metrics.status_code == 401

    # 4. Copilot query
    res_copilot = client.post("/api/v1/copilot/query", json={"question": "Why was this flagged?"})
    assert res_copilot.status_code == 401

    # 5. Feedback
    res_feedback = client.post("/api/v1/feedback", json={"scan_id": 1, "is_helpful": True})
    assert res_feedback.status_code == 401

def test_analyze_suspicious_message(auth_client):
    payload = {
        "message": "URGENT: Alert! Your account is compromised. Click http://verify-secure.org to confirm your PIN."
    }
    response = auth_client.post("/api/v1/analyze", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "scan_id" in data
    assert data["classification"] == "SPAM"
    assert data["is_suspicious"] is True
    assert data["risk_score"] > 0.5
    assert data["risk_level"] in ["MEDIUM", "HIGH"]
    assert "investigation" in data
    assert "observable_indicators" in data
    assert len(data["investigation"]["observable_warning_signs"]) > 0

def test_analyze_empty_message_validation_error(auth_client):
    response = auth_client.post("/api/v1/analyze", json={"message": ""})
    assert response.status_code == 422

def test_analyze_whitespace_message_validation_error(auth_client):
    response = auth_client.post("/api/v1/analyze", json={"message": "    "})
    assert response.status_code == 422

def test_history_flow(auth_client):
    # 1. Submit scan
    res = auth_client.post("/api/v1/analyze", json={"message": "Free prize claim £1000 cash! http://prize.com"})
    scan_id = res.json()["scan_id"]

    # 2. Retrieve history list
    hist_res = auth_client.get("/api/v1/history")
    assert hist_res.status_code == 200
    hist_data = hist_res.json()
    assert hist_data["total"] >= 1
    assert any(item["id"] == scan_id for item in hist_data["items"])

    # 3. Retrieve single detail
    detail_res = auth_client.get(f"/api/v1/history/{scan_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert detail["id"] == scan_id
    assert "investigation" in detail

    # 4. Delete single record
    del_res = auth_client.delete(f"/api/v1/history/{scan_id}")
    assert del_res.status_code == 200
    assert del_res.json()["status"] == "deleted"

    # 5. Confirm 404 on deleted record
    not_found_res = auth_client.get(f"/api/v1/history/{scan_id}")
    assert not_found_res.status_code == 404

def test_metrics_endpoint(auth_client):
    response = auth_client.get("/api/v1/metrics")
    assert response.status_code == 200
    data = response.json()
    assert "total_scans" in data
    assert "risk_distribution" in data
    assert "model_metrics" in data

def test_samples_endpoint(client):
    response = client.get("/api/v1/samples")
    assert response.status_code == 200
    samples = response.json()
    assert len(samples) >= 3
    assert all("text" in s and "category" in s for s in samples)

def test_static_frontend_serving(client):
    res_index = client.get("/")
    assert res_index.status_code == 200
    assert "TrustLens" in res_index.text

    res_css = client.get("/static/css/style.css")
    assert res_css.status_code == 200
    assert "--navy-dark" in res_css.text

    res_js = client.get("/static/js/app.js")
    assert res_js.status_code == 200
    assert "TrustLens AI" in res_js.text

def test_feedback_submission(auth_client):
    res = auth_client.post("/api/v1/analyze", json={"message": "Your parcel delivery #4820 is pending payment. http://track-parcel.xyz"})
    scan_id = res.json()["scan_id"]

    fb_payload = {
        "scan_id": scan_id,
        "is_helpful": True,
        "user_label": "spam",
        "user_notes": "Accurate detection of parcel scam."
    }
    fb_res = auth_client.post("/api/v1/feedback", json=fb_payload)
    assert fb_res.status_code == 201
    assert fb_res.json()["status"] == "recorded"

def test_copilot_query_prescan(auth_client):
    response = auth_client.post("/api/v1/copilot/query", json={"question": "Why is this message suspicious?"})
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert data["context_grounded"] is False
    assert len(data["suggested_followups"]) > 0

def test_copilot_query_with_scan_id(auth_client):
    res = auth_client.post("/api/v1/analyze", json={"message": "URGENT: Click http://phish-secure.xyz now or account suspended!"})
    scan_id = res.json()["scan_id"]

    response = auth_client.post("/api/v1/copilot/query", json={
        "question": "What evidence supports the prediction?",
        "scan_id": scan_id
    })
    assert response.status_code == 200
    data = response.json()
    assert "answer" in data
    assert data["context_grounded"] is True
    assert "http://phish-secure.xyz" in data["answer"] or "Evidence" in data["answer"]


