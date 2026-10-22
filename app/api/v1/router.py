"""
API v1 main router uniting all endpoint groups.
"""

from fastapi import APIRouter
from app.api.v1.analyze import router as analyze_router
from app.api.v1.history import router as history_router
from app.api.v1.metrics import router as metrics_router
from app.api.v1.feedback import router as feedback_router
from app.api.v1.copilot import router as copilot_router
from app.api.v1.auth import router as auth_router
from app.api.v1.alexa_sim import router as alexa_sim_router

api_v1_router = APIRouter()

api_v1_router.include_router(auth_router, tags=["Authentication & Accounts"])
api_v1_router.include_router(analyze_router, tags=["Investigation"])
api_v1_router.include_router(copilot_router, tags=["AI Assistant Copilot"])
api_v1_router.include_router(alexa_sim_router, tags=["Alexa+ Simulated Experience"])
api_v1_router.include_router(history_router, tags=["History & Audit"])
api_v1_router.include_router(metrics_router, tags=["Metrics & Samples"])
api_v1_router.include_router(feedback_router, tags=["User Feedback"])



