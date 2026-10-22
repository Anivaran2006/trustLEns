"""
Configuration management for TrustLens AI using Pydantic Settings.
Reads environment variables with secure defaults suitable for local and low-cost deployment.
"""

import os
from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    APP_NAME: str = "TrustLens AI"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = False
    ENV: str = "production"

    # API Configuration
    API_V1_PREFIX: str = "/api/v1"
    CORS_ORIGINS: List[str] = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "http://localhost:3000",
        "http://127.0.0.1:5500",
        "*"
    ]

    # Security & Input Constraints
    MAX_MESSAGE_LENGTH: int = 5000
    RATE_LIMIT_PER_MINUTE: str = "60/minute"
    LOGIN_RATE_LIMIT: str = "10/minute"
    REDACT_SENSITIVE_DATA_IN_STORAGE: bool = True

    # Authentication & Session Security
    AUTH_SECRET_KEY: str = Field(
        default_factory=lambda: os.getenv("AUTH_SECRET_KEY", "trustlens-insecure-dev-secret-key-change-in-prod-7f9e1b")
    )
    SESSION_COOKIE_NAME: str = "trustlens_session"
    CSRF_COOKIE_NAME: str = "trustlens_csrf"
    SESSION_MAX_AGE_DAYS: int = 7
    COOKIE_SECURE: bool = Field(
        default_factory=lambda: os.getenv("COOKIE_SECURE", "false").lower() in ("true", "1", "yes")
    )
    COOKIE_SAMESITE: str = "lax"

    # Database
    DATABASE_URL: str = Field(
        default_factory=lambda: f"sqlite:///{os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), 'trustlens.db')}"
    )

    # ML Artifacts
    ARTIFACTS_DIR: str = Field(
        default_factory=lambda: os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "artifacts")
    )

    # AI Agent / LLM Configuration
    # Supported: "auto", "bedrock", "rule_based_fallback"
    LLM_PROVIDER: str = "auto"
    AWS_REGION: str = "us-east-1"
    BEDROCK_MODEL_ID: str = "anthropic.claude-3-haiku-20240307-v1:0"
    BEDROCK_TIMEOUT_SECONDS: int = 8

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore"
    )

settings = Settings()
