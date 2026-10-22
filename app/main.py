"""
FastAPI Application Entry Point for TrustLens AI.
Provides:
- Liveness (/health) and Readiness (/ready) probes
- Global error handling without exposing stack traces
- Rate limiting via SlowAPI
- Database schema initialization
- Static frontend mounting
"""

import os
import sys
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from fastapi import FastAPI, Request, status
from fastapi.responses import JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles
from fastapi.middleware.cors import CORSMiddleware
from slowapi.errors import RateLimitExceeded

# Add project root to sys.path
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from app.core.config import settings
from app.core.security import limiter
from app.db.session import engine, Base, SessionLocal, init_db
from app.db import models  # Ensures models are registered with Base.metadata
from app.ml.inference import inference_service
from app.ai.agent import investigation_agent
from app.api.v1.router import api_v1_router
from app.api.schemas import HealthResponse, ReadinessResponse
from sqlalchemy import text

# Setup logging
logging.basicConfig(
    level=logging.INFO if not settings.DEBUG else logging.DEBUG,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
)
logger = logging.getLogger("trustlens.main")

# Initialize database schema immediately
init_db()

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup phase
    logger.info("Initializing TrustLens AI backend services...")
    
    # Verify DB tables
    try:
        init_db()
        logger.info("Database schemas verified.")
    except Exception as e:
        logger.error(f"Database schema initialization failed: {e}")

    # Verify ML Model Pipeline readiness
    if inference_service.is_ready:
        logger.info(f"ML Pipeline is active (Version: {inference_service.metadata.get('model_version')}).")
    else:
        logger.warning("ML Pipeline could not be loaded into memory. Check artifacts directory.")

    yield

    # Shutdown phase
    logger.info("Shutting down TrustLens AI backend.")

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Intelligent AI Message Deception and Fraud Investigation Platform.",
    lifespan=lifespan
)

# SlowAPI Rate Limiter integration
app.state.limiter = limiter

@app.exception_handler(RateLimitExceeded)
async def rate_limit_handler(request: Request, exc: RateLimitExceeded):
    return JSONResponse(
        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
        content={"detail": "Request limit exceeded. Please wait a moment before sending more messages."}
    )

# Secure Error Handler to prevent stack trace leaks
@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled exception on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content={"detail": "An internal system error occurred while processing your request."}
    )

# CORS Middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "DELETE", "OPTIONS"],
    allow_headers=["*"],
)

# Include API v1 Routes
app.include_router(api_v1_router, prefix=settings.API_V1_PREFIX)

# Liveness Probe
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["System"],
    summary="Application liveness probe"
)
def health_check():
    return HealthResponse(
        status="healthy",
        timestamp=datetime.now(timezone.utc),
        version=settings.APP_VERSION
    )

# Readiness Probe
@app.get(
    "/ready",
    response_model=ReadinessResponse,
    tags=["System"],
    summary="Application readiness probe"
)
def readiness_check():
    # 1. Check ML Model in memory
    model_ready = inference_service.is_ready and (inference_service.pipeline is not None)

    # 2. Check Database connectivity
    db_connected = False
    try:
        db = SessionLocal()
        db.execute(text("SELECT 1"))
        db.close()
        db_connected = True
    except Exception as e:
        logger.warning(f"Readiness check DB query failed: {e}")
        db_connected = False

    is_overall_ready = model_ready and db_connected
    overall_status = "ready" if is_overall_ready else "not_ready"

    # Identify LLM Provider mode
    provider_status = "Rule-Based NLP Engine (Active)"
    if settings.LLM_PROVIDER in ["bedrock", "auto"]:
        if investigation_agent.bedrock.check_availability():
            provider_status = f"Amazon Bedrock ({settings.BEDROCK_MODEL_ID})"

    return ReadinessResponse(
        status=overall_status,
        model_loaded=model_ready,
        database_connected=db_connected,
        model_version=inference_service.metadata.get("model_version"),
        selected_model=inference_service.metadata.get("selected_model"),
        llm_provider=provider_status
    )

# Serve Frontend static assets
FRONTEND_DIR = os.path.join(PROJECT_ROOT, "frontend")
if os.path.exists(FRONTEND_DIR):
    app.mount("/static", StaticFiles(directory=FRONTEND_DIR), name="static")

    @app.get("/", include_in_schema=False)
    @app.get("/home", include_in_schema=False)
    @app.get("/scanner", include_in_schema=False)
    @app.get("/dashboard", include_in_schema=False)
    @app.get("/history", include_in_schema=False)
    @app.get("/samples", include_in_schema=False)
    @app.get("/model", include_in_schema=False)
    @app.get("/alexa", include_in_schema=False)
    def serve_frontend_index():
        index_file = os.path.join(FRONTEND_DIR, "index.html")
        if os.path.exists(index_file):
            return FileResponse(index_file)
        return {"message": "TrustLens AI Backend is running. Frontend index.html not yet initialized."}
