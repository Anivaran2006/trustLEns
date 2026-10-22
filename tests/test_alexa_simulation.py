"""
Integration tests for Alexa+ Simulated Experience:
- GET /api/v1/alexa/presets
- GET /api/v1/alexa/tools
- POST /api/v1/alexa/simulate (Suspicious Message, Clean Message, Follow-up Questions, Reset)
"""

def test_alexa_presets(client):
    res = client.get("/api/v1/alexa/presets")
    assert res.status_code == 200
    presets = res.json()
    assert len(presets) >= 4
    assert any(p["id"] == "bank_phishing" for p in presets)
    assert any(p["id"] == "legit_appointment" for p in presets)

def test_alexa_mcp_tools(client):
    res = client.get("/api/v1/alexa/tools")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "active"
    tools = data["tools"]
    tool_names = [t["name"] for t in tools]
    assert "trustlens_inspect_message" in tool_names
    assert "trustlens_explain_threat" in tool_names
    assert "trustlens_get_safety_actions" in tool_names

def test_alexa_simulate_suspicious_message(client):
    payload = {
        "user_prompt": "Alexa, is this a scam: 'URGENT: Your Chase account is locked. Verify at http://chase-security-verify.net/login immediately!'"
    }
    res = client.post("/api/v1/alexa/simulate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["tool_invoked"] == "trustlens_inspect_message"
    assert data["context_grounded"] is True
    assert "scan_result" in data and data["scan_result"] is not None
    sr = data["scan_result"]
    assert sr["classification"] == "SPAM"
    assert sr["risk_level"] in ["HIGH", "MEDIUM"]
    assert sr["risk_score"] > 0.5
    assert len(sr["warning_signs"]) > 0
    assert len(data["suggested_prompts"]) > 0
    assert "spoken_text" in data
    assert "disclaimer" in data

def test_alexa_simulate_legitimate_message(client):
    payload = {
        "user_prompt": "Alexa, can you check this message: 'Hi Alex, confirming our lunch meeting tomorrow at 12:30 at the cafe. See you then!'"
    }
    res = client.post("/api/v1/alexa/simulate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert data["tool_invoked"] == "trustlens_inspect_message"
    sr = data["scan_result"]
    assert sr["classification"] == "HAM"
    assert sr["risk_level"] == "LOW"
    assert sr["risk_score"] < 0.35

def test_alexa_simulate_followup_question(client):
    # First turn: analyze suspicious message
    initial_payload = {
        "user_prompt": "Is this suspicious: URGENT: Your bank account is locked! Go to http://phish-secure.xyz to unlock."
    }
    first_res = client.post("/api/v1/alexa/simulate", json=initial_payload)
    assert first_res.status_code == 200
    first_data = first_res.json()

    # Second turn: ask why it's suspicious with active scan data
    followup_payload = {
        "user_prompt": "Why is this message suspicious?",
        "active_scan_id": first_data.get("scan_id"),
        "active_scan_data": {
            "scan_id": first_data.get("scan_id"),
            "message_text": "URGENT: Your bank account is locked! Go to http://phish-secure.xyz to unlock.",
            "ml_result": {
                "classification": "SPAM",
                "risk_score": 0.95,
                "risk_level": "HIGH",
                "is_suspicious": True,
                "model_name": "LogisticRegression_Baseline",
                "model_version": "1.0.0"
            },
            "investigation": first_data["scan_result"]
        }
    }
    followup_res = client.post("/api/v1/alexa/simulate", json=followup_payload)
    assert followup_res.status_code == 200
    f_data = followup_res.json()
    assert f_data["tool_invoked"] == "trustlens_explain_threat"
    assert f_data["context_grounded"] is True
    assert "SPAM" in f_data["conversational_response"] or "risk" in f_data["conversational_response"].lower()

def test_alexa_simulate_reset(client):
    payload = {"user_prompt": "clear conversation"}
    res = client.post("/api/v1/alexa/simulate", json=payload)
    assert res.status_code == 200
    data = res.json()
    assert "reset" in data["conversational_response"].lower()
