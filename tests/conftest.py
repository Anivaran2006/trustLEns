"""
Pytest fixtures for TrustLens AI test suite.
Configures isolated in-memory test database and FastAPI TestClient.
"""

import os
import sys
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

# Ensure project root is in sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.main import app
from app.db.session import Base, get_db
from app.db import models  # Ensure all tables are registered with Base.metadata

from sqlalchemy.pool import StaticPool


TEST_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    TEST_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)

@pytest.fixture(scope="function")
def test_db():
    Base.metadata.create_all(bind=engine)
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        Base.metadata.drop_all(bind=engine)

@pytest.fixture(scope="function")
def client(test_db):
    def override_get_db():
        try:
            yield test_db
        finally:
            pass

    app.dependency_overrides[get_db] = override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()

@pytest.fixture(scope="function")
def auth_client(client):
    """Client authenticated as a registered user with CSRF token header set."""
    reg_payload = {
        "full_name": "Test Investigator",
        "email": "investigator@trustlens.ai",
        "password": "Password123!",
        "confirm_password": "Password123!"
    }
    res = client.post("/api/v1/auth/register", json=reg_payload)
    csrf_token = res.json()["csrf_token"]
    client.headers.update({"X-CSRF-Token": csrf_token})
    return client
