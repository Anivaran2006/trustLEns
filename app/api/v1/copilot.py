"""
AI Copilot Follow-up and Investigation Assistant Endpoints.
Allows interactive interrogation of scan results, suggested questions, and cybersecurity guidance.
"""

from typing import Optional
import json
from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import User
from app.db.repository import ScanRepository
from app.ml.inference import inference_service
from app.ai.agent import investigation_agent
from app.core.security import sanitize_and_encode_input, limiter
from app.core.auth import get_current_user
from app.core.config import settings
from app.api.schemas import CopilotQueryRequest, CopilotQueryResponse

router = APIRouter()

@router.post(
    "/copilot/query",
    response_model=CopilotQueryResponse,
    status_code=status.HTTP_200_OK,
    summary="Interrogate the AI Assistant about an active or prior investigation"
)
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
def query_copilot(
    payload: CopilotQueryRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    question = sanitize_and_encode_input(payload.question, max_length=1000)
    if not question:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Question cannot be empty."
        )

    investigation = None
    ml_result = None
    message_text = payload.message

    if payload.scan_id:
        repo = ScanRepository(db)
        record = repo.get_by_id(payload.scan_id)
        if record:
            if record.user_id is not None and record.user_id != current_user.id:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="Access denied: This scan belongs to another investigator."
                )
            if not message_text:
                message_text = record.message_preview
            if record.explanation_json:
                try:
                    investigation = json.loads(record.explanation_json)
                except Exception:
                    pass
            ml_result = {
                "classification": record.classification,
                "risk_score": record.risk_score,
                "risk_level": record.risk_level,
                "model_name": record.model_name,
                "model_version": record.model_version
            }

    # If no scan_id was provided but message_text was provided, predict if needed
    elif message_text and len(message_text.strip()) > 0:
        try:
            clean_msg = sanitize_and_encode_input(message_text, max_length=settings.MAX_MESSAGE_LENGTH)
            ml_result = inference_service.predict(clean_msg)
            investigation = investigation_agent.investigate(clean_msg, ml_result)
        except Exception:
            pass

    response_dict = investigation_agent.answer_copilot_question(
        question=question,
        message=message_text,
        investigation=investigation,
        ml_result=ml_result
    )

    return CopilotQueryResponse(
        question=question,
        answer=response_dict["answer"],
        suggested_followups=response_dict.get("suggested_followups", []),
        provider_used=response_dict.get("provider_used", "rule_based_nlp_engine"),
        context_grounded=response_dict.get("context_grounded", False),
        scan_id=payload.scan_id
    )
