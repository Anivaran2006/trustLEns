"""
FastAPI Endpoints for Alexa+ Simulated Experience.
Amazon Developer Hackathon — Simulated Track Implementation.
Provides conversational endpoints, MCP tool declarations, and preset threat scenarios.
"""

from typing import Optional, Dict, Any, List
from pydantic import BaseModel, Field
from fastapi import APIRouter, Depends, Request, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import User
from app.db.repository import ScanRepository
from app.core.auth import get_optional_current_user
from app.core.security import limiter, sanitize_and_encode_input
from app.core.config import settings
from app.alexa_simulation.service import alexa_simulator
from app.alexa_simulation.tools import get_mcp_tool_definitions

router = APIRouter()

class AlexaTurnRequest(BaseModel):
    user_prompt: str = Field(..., min_length=1, max_length=1500, description="The user query or pasted message")
    active_scan_id: Optional[str] = Field(None, description="Optional active scan UUID for follow-up questions")
    active_scan_data: Optional[Dict[str, Any]] = Field(None, description="Optional active scan payload cached in client")

class AlexaTurnResponse(BaseModel):
    conversational_response: str
    spoken_text: str
    tool_invoked: Optional[str] = None
    scan_result: Optional[Dict[str, Any]] = None
    suggested_prompts: List[str]
    provider_used: str
    context_grounded: bool
    disclaimer: str
    scan_id: Optional[str] = None

@router.get(
    "/alexa/presets",
    summary="Get sample threat and legitimate scenarios for testing the Alexa+ simulator"
)
def get_preset_scenarios():
    """Returns curated realistic threat samples and a clean sample for 1-click evaluation."""
    return alexa_simulator.PRESET_SCENARIOS

@router.get(
    "/alexa/tools",
    summary="Get MCP tool definitions representing the TrustLens Agent Skill for Alexa+"
)
def get_alexa_mcp_tools():
    """Returns Model Context Protocol tool specifications for the TrustLens AI Agent Skill."""
    return {
        "status": "active",
        "agent_name": "TrustLens_AI_Agent_Skill",
        "runtime_target": "Alexa+ (Simulated Experience)",
        "tools": get_mcp_tool_definitions()
    }

@router.post(
    "/alexa/simulate",
    response_model=AlexaTurnResponse,
    status_code=status.HTTP_200_OK,
    summary="Simulate a conversational Alexa+ turn invoking the real TrustLens AI backend"
)
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
def simulate_alexa_turn(
    payload: AlexaTurnRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: Optional[User] = Depends(get_optional_current_user)
):
    """
    Simulates a natural language Alexa+ interaction.
    - If user asks to check a message or pastes message text, invokes the real ML pipeline and NLP indicator extractor.
    - If user asks follow-up questions about evidence, warning signs, or safety actions, grounds response in the active scan findings.
    - Persists the scan record in the database for audit history if an analysis was performed.
    """
    clean_prompt = sanitize_and_encode_input(payload.user_prompt, max_length=1500)
    
    # Reconstruct active scan context if available
    active_scan = None
    if payload.active_scan_data:
        active_scan = payload.active_scan_data
    elif payload.active_scan_id:
        repo = ScanRepository(db)
        record = repo.get_by_id(payload.active_scan_id)
        if record:
            import json
            expl = {}
            if record.explanation_json:
                try:
                    expl = json.loads(record.explanation_json)
                except Exception:
                    pass
            active_scan = {
                "scan_id": record.id,
                "message_text": record.message_preview,
                "ml_result": {
                    "classification": record.classification,
                    "risk_score": record.risk_score,
                    "risk_level": record.risk_level,
                    "is_suspicious": record.is_suspicious,
                    "model_name": record.model_name,
                    "model_version": record.model_version
                },
                "investigation": expl,
                "scan_result": {
                    "classification": record.classification,
                    "is_suspicious": record.is_suspicious,
                    "risk_score": record.risk_score,
                    "risk_percentage": f"{record.risk_score * 100:.1f}%",
                    "risk_level": record.risk_level,
                    "summary": expl.get("summary", ""),
                    "warning_signs": expl.get("observable_warning_signs", []),
                    "direct_observations": expl.get("evidence_vs_assumptions", {}).get("direct_observations", []),
                    "potential_implications": expl.get("evidence_vs_assumptions", {}).get("potential_implications", []),
                    "recommended_actions": expl.get("recommended_actions", []),
                    "uncertainty_statement": expl.get("uncertainty_statement", ""),
                    "provider_used": expl.get("provider_used", "rule_based_nlp_engine")
                }
            }

    # Process conversational turn
    turn_result = alexa_simulator.process_turn(clean_prompt, active_scan=active_scan)

    scan_id = None
    # If a new scan was generated and tool was trustlens_inspect_message, persist in DB
    if turn_result.get("tool_invoked") == "trustlens_inspect_message" and turn_result.get("scan_result"):
        try:
            repo = ScanRepository(db)
            sr = turn_result["scan_result"]
            scan_rec = repo.create_scan(
                raw_text=sr["message_analyzed"],
                classification=sr["classification"],
                is_suspicious=sr["is_suspicious"],
                risk_score=sr["risk_score"],
                risk_level=sr["risk_level"],
                model_version=sr["model_version"],
                model_name=sr["model_name"],
                indicators=sr["observable_indicators"],
                explanation=turn_result.get("investigation", {}),
                user_id=current_user.id if current_user else None
            )
            scan_id = scan_rec.id
            turn_result["scan_result"]["scan_id"] = scan_rec.id
        except Exception as e:
            # Persistence is non-fatal for demo
            pass
    elif active_scan and active_scan.get("scan_id"):
        scan_id = active_scan.get("scan_id")

    return AlexaTurnResponse(
        conversational_response=turn_result["conversational_response"],
        spoken_text=turn_result["spoken_text"],
        tool_invoked=turn_result.get("tool_invoked"),
        scan_result=turn_result.get("scan_result"),
        suggested_prompts=turn_result.get("suggested_prompts", []),
        provider_used=turn_result.get("provider_used", "rule_based_nlp_engine"),
        context_grounded=turn_result.get("context_grounded", False),
        disclaimer=turn_result.get("disclaimer", "Simulated Alexa+ Developer Hackathon Experience"),
        scan_id=scan_id
    )
