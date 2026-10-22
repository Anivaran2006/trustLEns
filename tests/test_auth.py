"""
Comprehensive test suite for TrustLens AI authentication, session security,
Argon2 password hashing, CSRF protection, and user scan isolation.
"""

import pytest
from app.core.auth import hash_password, verify_password, validate_password_complexity
from app.db.models import User, UserSession, ScanRecord
from app.core.config import settings

def test_argon2_password_hashing():
    raw_pass = "SecurePass2026!"
    hashed = hash_password(raw_pass)
    
    # Must use Argon2id
    assert hashed.startswith("$argon2id$")
    assert raw_pass != hashed
    assert verify_password(raw_pass, hashed) is True
    assert verify_password("WrongPassword123!", hashed) is False
    assert verify_password("", hashed) is False

def test_password_complexity_rules():
    assert validate_password_complexity("short")[0] is False
    assert validate_password_complexity("alllowercase123")[0] is True
    assert validate_password_complexity("LettersOnlyWithoutDigits")[0] is False
    assert validate_password_complexity("Valid123!")[0] is True

def test_user_registration_success(client):
    payload = {
        "full_name": "Alice Security",
        "email": "alice@trustlens.ai",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["user"]["email"] == "alice@trustlens.ai"
    assert data["user"]["full_name"] == "Alice Security"
    assert "password" not in data["user"]
    assert "hashed_password" not in data["user"]
    assert "csrf_token" in data
    assert settings.SESSION_COOKIE_NAME in response.cookies
    assert settings.CSRF_COOKIE_NAME in response.cookies

def test_user_registration_duplicate_email(client):
    payload = {
        "full_name": "Bob Analyst",
        "email": "bob@trustlens.ai",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    r1 = client.post("/api/v1/auth/register", json=payload)
    assert r1.status_code == 201

    # Attempt registration with same email (different case)
    payload["email"] = "BOB@trustlens.ai"
    r2 = client.post("/api/v1/auth/register", json=payload)
    assert r2.status_code == 409
    assert "already exists" in r2.json()["detail"]

def test_user_registration_mismatched_password(client):
    payload = {
        "full_name": "Charlie",
        "email": "charlie@trustlens.ai",
        "password": "Password123!",
        "confirm_password": "DifferentPassword!"
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 422
    assert "do not match" in response.json()["detail"]

def test_user_login_success_and_logout(client):
    # Register
    reg_payload = {
        "full_name": "Diana Prince",
        "email": "diana@trustlens.ai",
        "password": "Amazonian123!",
        "confirm_password": "Amazonian123!"
    }
    client.post("/api/v1/auth/register", json=reg_payload)

    # Clear client cookies to simulate clean login
    client.cookies.clear()

    # Login
    login_payload = {
        "email": "diana@trustlens.ai",
        "password": "Amazonian123!"
    }
    res_login = client.post("/api/v1/auth/login", json=login_payload)
    assert res_login.status_code == 200
    assert res_login.json()["user"]["email"] == "diana@trustlens.ai"
    assert settings.SESSION_COOKIE_NAME in res_login.cookies

    # Verify session via /auth/me
    res_me = client.get("/api/v1/auth/me")
    assert res_me.status_code == 200
    assert res_me.json()["user"]["full_name"] == "Diana Prince"

    # Logout
    res_logout = client.post("/api/v1/auth/logout")
    assert res_logout.status_code == 200

    # Ensure /auth/me is now unauthorized
    res_me_after = client.get("/api/v1/auth/me")
    assert res_me_after.status_code == 401

def test_user_login_invalid_credentials(client):
    # Unknown user
    response = client.post("/api/v1/auth/login", json={
        "email": "unknown@nowhere.com",
        "password": "WrongPassword123!"
    })
    assert response.status_code == 401
    assert "Invalid email or password" in response.json()["detail"]

def test_csrf_protection_on_mutating_requests(client):
    # Register and get session
    reg_payload = {
        "full_name": "Eve Tester",
        "email": "eve@trustlens.ai",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    reg_res = client.post("/api/v1/auth/register", json=reg_payload)
    assert reg_res.status_code == 201
    csrf_token = reg_res.json()["csrf_token"]

    # Delete personal scans without CSRF header -> should be 403 Forbidden
    res_no_csrf = client.delete("/api/v1/auth/my-scans")
    assert res_no_csrf.status_code == 403

    # Delete with invalid CSRF token -> 403
    res_bad_csrf = client.delete("/api/v1/auth/my-scans", headers={"X-CSRF-Token": "invalid_token_value"})
    assert res_bad_csrf.status_code == 403

    # Delete with valid CSRF header -> 200 OK
    res_valid_csrf = client.delete("/api/v1/auth/my-scans", headers={"X-CSRF-Token": csrf_token})
    assert res_valid_csrf.status_code == 200

def test_unauthenticated_scanning_rejected_with_401(client):
    """Verify that unauthenticated callers cannot use the scanner API."""
    client.cookies.clear()
    scan_payload = {
        "message": "URGENT: Your account access will be terminated unless you click http://verify-now.secure-bank.com immediately!"
    }
    response = client.post("/api/v1/analyze", json=scan_payload)
    assert response.status_code == 401
    assert "detail" in response.json()

def test_user_scan_history_isolation(client):
    # 1. Register User Alpha
    client.cookies.clear()
    reg_a = client.post("/api/v1/auth/register", json={
        "full_name": "Alpha User",
        "email": "alpha@trustlens.ai",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })
    token_a = reg_a.json()["csrf_token"]

    # Alpha scans a message (passing CSRF token for mutating request with cookies)
    scan_a = client.post(
        "/api/v1/analyze",
        json={"message": "ALPHA_PRIVATE_SECRET_SCAN: Win $1,000,000 cash prize instantly at http://lottery-claim.com"},
        headers={"X-CSRF-Token": token_a}
    )
    assert scan_a.status_code == 200
    scan_id_a = scan_a.json()["scan_id"]

    # 2. Register User Beta
    client.cookies.clear()
    reg_b = client.post("/api/v1/auth/register", json={
        "full_name": "Beta User",
        "email": "beta@trustlens.ai",
        "password": "Password123!",
        "confirm_password": "Password123!"
    })
    token_b = reg_b.json()["csrf_token"]

    # Beta scans a message
    scan_b = client.post(
        "/api/v1/analyze",
        json={"message": "BETA_PRIVATE_INVESTIGATION: Urgent invoice #9928 attached for payment"},
        headers={"X-CSRF-Token": token_b}
    )
    assert scan_b.status_code == 200
    scan_id_b = scan_b.json()["scan_id"]

    # 3. Check Beta's history: MUST contain Beta's scan, MUST NOT contain Alpha's scan
    beta_history = client.get("/api/v1/history")
    assert beta_history.status_code == 200
    beta_ids = [s["id"] for s in beta_history.json()["items"]]
    assert scan_id_b in beta_ids
    assert scan_id_a not in beta_ids

    # 4. Beta tries to access Alpha's private scan detail -> 404 Not Found
    detail_res = client.get(f"/api/v1/history/{scan_id_a}")
    assert detail_res.status_code == 404

    # 5. Beta tries to delete Alpha's private scan -> 404 Not Found
    del_res = client.delete(f"/api/v1/history/{scan_id_a}", headers={"X-CSRF-Token": token_b})
    assert del_res.status_code == 404

    # 6. Unauthenticated visitor checks history -> 401 Unauthorized
    client.cookies.clear()
    unauth_history = client.get("/api/v1/history")
    assert unauth_history.status_code == 401

    # Unauthenticated visitor tries to access Alpha's private scan detail -> 401 Unauthorized
    unauth_detail = client.get(f"/api/v1/history/{scan_id_a}")
    assert unauth_detail.status_code == 401

