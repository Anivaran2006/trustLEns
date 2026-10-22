"""
Analysis endpoint for TrustLens AI.
Orchestrates ML inference, AI investigation, and database persistence.
"""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request, status, UploadFile, File, Form
from sqlalchemy.orm import Session
from datetime import datetime, timezone


from app.db.session import get_db
from app.db.models import User
from app.db.repository import ScanRepository
from app.ml.inference import inference_service
from app.ai.agent import investigation_agent
from app.core.security import sanitize_and_encode_input, limiter
from app.core.auth import get_current_user
from app.core.config import settings
from app.api.schemas import (
    AnalyzeRequest,
    AnalyzeResponse,
    ObservableIndicators,
    AIExplanation,
    EvidenceVsAssumptions,
    MultimodalAnalyzeResponse
)

router = APIRouter()

@router.post(
    "/analyze",
    response_model=AnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Investigate a message for fraud, phishing, or deceptive language"
)
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
def analyze_message(
    payload: AnalyzeRequest,
    request: Request,
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):

    clean_text = sanitize_and_encode_input(payload.message, max_length=settings.MAX_MESSAGE_LENGTH)
    if not clean_text:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Message content cannot be empty or solely whitespace."
        )

    # 1. ML Inference Service
    try:
        ml_result = inference_service.predict(clean_text)
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Inference pipeline execution error: {str(e)}"
        )

    # 2. AI Investigation Agent
    try:
        investigation = investigation_agent.investigate(clean_text, ml_result)
    except Exception as e:
        # Fallback if agent crashes
        investigation = {
            "summary": "AI explanation could not be completed; defaulting to statistical evaluation.",
            "observable_warning_signs": [],
            "evidence_vs_assumptions": {
                "direct_observations": ["Statistical inference completed."],
                "potential_implications": ["External verification recommended."]
            },
            "risk_level": ml_result["risk_level"],
            "recommended_actions": ["Exercise caution and independently verify the communication."],
            "uncertainty_statement": "Automated fallback mode active.",
            "provider_used": "emergency_fallback"
        }

    # 3. Database Persistence
    repo = ScanRepository(db)
    scan_record = repo.create_scan(
        raw_text=clean_text,
        classification=ml_result["classification"],
        is_suspicious=ml_result["is_suspicious"],
        risk_score=ml_result["risk_score"],
        risk_level=ml_result["risk_level"],
        model_version=ml_result["model_version"],
        model_name=ml_result["model_name"],
        indicators=ml_result["observable_indicators"],
        explanation=investigation,
        user_id=current_user.id
    )

    return AnalyzeResponse(
        scan_id=scan_record.id,
        classification=scan_record.classification,
        is_suspicious=scan_record.is_suspicious,
        risk_score=scan_record.risk_score,
        risk_level=scan_record.risk_level,
        score_interpretation=ml_result["score_interpretation"],
        model_version=scan_record.model_version,
        model_name=scan_record.model_name,
        observable_indicators=ObservableIndicators(**ml_result["observable_indicators"]),
        investigation=AIExplanation(
            summary=investigation["summary"],
            observable_warning_signs=investigation.get("observable_warning_signs", []),
            evidence_vs_assumptions=EvidenceVsAssumptions(
                direct_observations=investigation.get("evidence_vs_assumptions", {}).get("direct_observations", []),
                potential_implications=investigation.get("evidence_vs_assumptions", {}).get("potential_implications", [])
            ),
            risk_level=investigation["risk_level"],
            recommended_actions=investigation.get("recommended_actions", []),
            uncertainty_statement=investigation["uncertainty_statement"],
            provider_used=investigation["provider_used"]
        ),
        created_at=scan_record.created_at
    )

@router.post(
    "/analyze-multimodal",
    response_model=MultimodalAnalyzeResponse,
    status_code=status.HTTP_200_OK,
    summary="Multi-Modal Scam Forensic Investigation (Images, QR Codes, Invoices, PDFs)"
)
@limiter.limit(settings.RATE_LIMIT_PER_MINUTE)
async def analyze_multimodal(
    request: Request,
    file: UploadFile = File(...),
    user_note: Optional[str] = Form(None),
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    """
    Accepts image files (PNG, JPG, WEBP) or PDF documents to inspect for:
    - QR Code Smishing / Quishing
    - Fake Invoices and Extortion Charges
    - Brand Impersonation and Visual Phishing
    """
    # 1. Validate file extension & size
    filename = file.filename or "uploaded_media.png"
    content_type = file.content_type or "image/png"
    
    file_bytes = await file.read()
    if len(file_bytes) == 0:
        raise HTTPException(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail="Uploaded file is empty."
        )
    if len(file_bytes) > 10 * 1024 * 1024:  # 10 MB limit
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="File size exceeds maximum permitted limit (10MB)."
        )

    # 2. Run Multimodal Forensic Engine
    try:
        from app.ai.multimodal import multimodal_analyzer
        result = multimodal_analyzer.analyze(
            file_bytes=file_bytes,
            filename=filename,
            content_type=content_type,
            user_note=user_note or ""
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Multimodal forensic processing error: {str(e)}"
        )

    # 3. Persist in Database with Privacy Redaction
    repo = ScanRepository(db)
    raw_desc = f"[File: {filename}] {result.get('extracted_text_preview') or user_note or 'Visual Forensic Media'}"
    
    scan_record = repo.create_scan(
        raw_text=raw_desc,
        classification="SPAM" if result["is_suspicious"] else "HAM",
        is_suspicious=result["is_suspicious"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        model_version="2.0.0-multimodal",
        model_name="Bedrock_Multimodal_Vision" if "bedrock" in result.get("provider_used", "") else "CV_Multimodal_Forensics",
        indicators={
            "detected_brands": result.get("detected_brands", []),
            "qr_forensics": result.get("qr_forensics"),
            "observable_warning_signs": result.get("observable_warning_signs", [])
        },
        explanation=result,
        user_id=current_user.id
    )

    return MultimodalAnalyzeResponse(
        scan_id=scan_record.id,
        filename=filename,
        classification=result["classification"],
        is_suspicious=result["is_suspicious"],
        risk_score=result["risk_score"],
        risk_level=result["risk_level"],
        detected_brands=result.get("detected_brands", []),
        qr_forensics=result.get("qr_forensics"),
        investigation=AIExplanation(
            summary=result["summary"],
            observable_warning_signs=result.get("observable_warning_signs", []),
            evidence_vs_assumptions=EvidenceVsAssumptions(
                direct_observations=result.get("evidence_vs_assumptions", {}).get("direct_observations", []),
                potential_implications=result.get("evidence_vs_assumptions", {}).get("potential_implications", [])
            ),
            risk_level=result["risk_level"],
            recommended_actions=result.get("recommended_actions", []),
            uncertainty_statement=result.get("uncertainty_statement", "Assessment based on observable visual heuristics."),
            provider_used=result["provider_used"]
        ),
        extracted_text_preview=result.get("extracted_text_preview"),
        created_at=scan_record.created_at
    )

