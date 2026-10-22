"""
Metrics and Demonstration Samples endpoints for TrustLens AI.
Reports real aggregated database statistics, active model evaluation metrics,
and pre-configured demonstration samples.
"""

import os
import json
from typing import List
from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.db.models import User
from app.db.repository import ScanRepository
from app.core.auth import get_current_user
from app.core.config import settings
from app.api.schemas import SystemMetricsResponse, SampleMessage

router = APIRouter()

DEMO_SAMPLES: List[SampleMessage] = [
    SampleMessage(
        id="sample-1",
        category="Banking Fraud / Impersonation",
        title="Urgent Bank Account Suspension",
        description="Emulates classic bank impersonation with false urgency and a credential-harvesting link.",
        text="URGENT: Chase Bank Alert. Your debit card has been suspended due to unusual activity. Verify your identity immediately to restore access: http://chase-secure-verify.com/login",
        expected_risk="HIGH"
    ),
    SampleMessage(
        id="sample-2",
        category="Package / Delivery Scam",
        title="Missed Package Delivery Fee",
        description="Common smishing lure claiming an undelivered parcel requiring an unverified redelivery payment.",
        text="USPS Notice: Your parcel package #US982420 cannot be delivered due to an unpaid postage fee of $2.49. Please update your details within 24 hours at http://usps-redelivery-portal.xyz/pay",
        expected_risk="HIGH"
    ),
    SampleMessage(
        id="sample-3",
        category="Advance-Fee / Lottery Scam",
        title="Unsolicited Cash Prize Claim",
        description="Lure promising massive financial returns for an initial fee or personal identification disclosure.",
        text="Congratulations! You have been selected as the winner of the £1,000,000 Walmart customer lottery. Call 08712400602 now to claim your cash prize! T&Cs apply.",
        expected_risk="HIGH"
    ),
    SampleMessage(
        id="sample-4",
        category="Legitimate Transactional",
        title="Legitimate Security OTP",
        description="Standard transactional one-time passcode notice from an authentication provider.",
        text="Your Google verification code is 482910. Do not share this code with anyone.",
        expected_risk="LOW"
    ),
    SampleMessage(
        id="sample-5",
        category="Legitimate Conversational",
        title="Casual Social Message",
        description="Typical peer-to-peer informal communication without suspicious patterns.",
        text="Hey Sarah! Are we still meeting for lunch at 12:30 tomorrow? Let me know if that time works for you.",
        expected_risk="LOW"
    )
]

@router.get(
    "/metrics",
    response_model=SystemMetricsResponse,
    summary="Retrieve live database scan aggregates and model test metrics"
)
def get_system_metrics(
    db: Session = Depends(get_db),
    current_user: User = Depends(get_current_user)
):
    repo = ScanRepository(db)
    db_metrics = repo.get_aggregated_metrics(user_id=current_user.id)

    # Load evaluated model metrics from artifacts
    metadata_path = os.path.join(settings.ARTIFACTS_DIR, "metadata.json")
    model_metrics = {}
    if os.path.exists(metadata_path):
        try:
            with open(metadata_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                model_metrics = data.get("metrics", {})
        except Exception:
            pass

    return SystemMetricsResponse(
        total_scans=db_metrics["total_scans"],
        suspicious_scans=db_metrics["suspicious_scans"],
        legitimate_scans=db_metrics["legitimate_scans"],
        average_risk_score=db_metrics["average_risk_score"],
        risk_distribution=db_metrics["risk_distribution"],
        model_metrics=model_metrics
    )

@router.get(
    "/samples",
    response_model=List[SampleMessage],
    summary="Get pre-configured demonstration messages for security testing"
)
def get_sample_messages():
    return DEMO_SAMPLES
