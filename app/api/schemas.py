"""
Pydantic Request and Response Schemas for TrustLens AI API.
Strict type validation, informative descriptions, and OpenAPI examples.
"""

from datetime import datetime
from typing import List, Dict, Any, Optional
from pydantic import BaseModel, Field

# --- Health & Readiness ---
class HealthResponse(BaseModel):
    status: str = Field("healthy", description="Application liveness status")
    timestamp: datetime = Field(..., description="Current UTC timestamp")
    version: str = Field(..., description="API version")

class ReadinessResponse(BaseModel):
    status: str = Field(..., description="Readiness status ('ready' or 'not_ready')")
    model_loaded: bool = Field(..., description="Whether the ML inference pipeline is loaded in memory")
    database_connected: bool = Field(..., description="Whether database connection is verified")
    model_version: Optional[str] = Field(None, description="Active ML model version")
    selected_model: Optional[str] = Field(None, description="Active ML classifier architecture")
    llm_provider: str = Field(..., description="Active AI explanation provider (Bedrock or Rule-Based Fallback)")

# --- Analysis & Investigation ---
class AnalyzeRequest(BaseModel):
    message: str = Field(
        ...,
        min_length=1,
        max_length=5000,
        description="The suspicious or untrusted message text to investigate",
        json_schema_extra={"example": "Urgent: Your bank account has been suspended! Click http://secure-verify.com to login now or funds will be lost."}
    )

class ObservableIndicators(BaseModel):
    urls_detected: List[str] = Field(default_factory=list)
    phones_detected: List[str] = Field(default_factory=list)
    currencies_detected: List[str] = Field(default_factory=list)
    urgency_cues: List[str] = Field(default_factory=list)
    action_cues: List[str] = Field(default_factory=list)
    all_caps_ratio: float = 0.0
    excessive_punctuation: bool = False
    char_length: int = 0
    word_count: int = 0

class EvidenceVsAssumptions(BaseModel):
    direct_observations: List[str] = Field(default_factory=list)
    potential_implications: List[str] = Field(default_factory=list)

class AIExplanation(BaseModel):
    summary: str
    observable_warning_signs: List[str] = Field(default_factory=list)
    evidence_vs_assumptions: EvidenceVsAssumptions
    risk_level: str
    recommended_actions: List[str] = Field(default_factory=list)
    uncertainty_statement: str
    provider_used: str

class AnalyzeResponse(BaseModel):
    scan_id: str
    classification: str = Field(..., description="'HAM' (Legitimate) or 'SPAM' (Deceptive/Suspicious)")
    is_suspicious: bool
    risk_score: float = Field(..., description="Statistical confidence score between 0.0 and 1.0")
    risk_level: str = Field(..., description="'LOW', 'MEDIUM', or 'HIGH'")
    score_interpretation: str
    model_version: str
    model_name: str
    observable_indicators: ObservableIndicators
    investigation: AIExplanation
    created_at: datetime

# --- Scan History ---
class ScanSummaryItem(BaseModel):
    id: str
    created_at: datetime
    message_preview: str
    classification: str
    is_suspicious: bool
    risk_score: float
    risk_level: str
    model_version: str

class ScanHistoryResponse(BaseModel):
    total: int
    skip: int
    limit: int
    items: List[ScanSummaryItem]

class ScanDetailResponse(BaseModel):
    id: str
    created_at: datetime
    message_preview: str
    classification: str
    is_suspicious: bool
    risk_score: float
    risk_level: str
    model_version: str
    model_name: str
    observable_indicators: Dict[str, Any]
    investigation: Dict[str, Any]

# --- Feedback ---
class FeedbackRequest(BaseModel):
    scan_id: str = Field(..., description="ID of the scan being evaluated")
    is_helpful: Optional[bool] = Field(None, description="Whether the scan was helpful to the user")
    user_label: Optional[str] = Field(None, description="'ham', 'spam', or 'unsure'")
    user_notes: Optional[str] = Field(None, max_length=1000, description="Optional user comments")

class FeedbackResponse(BaseModel):
    id: str
    scan_id: str
    status: str = "received"
    message: str = "Thank you. Feedback recorded separately from ground-truth data."

# --- Metrics ---
class SystemMetricsResponse(BaseModel):
    total_scans: int
    suspicious_scans: int
    legitimate_scans: int
    average_risk_score: float
    risk_distribution: Dict[str, int]
    model_metrics: Dict[str, Any]

# --- Sample Demonstrations ---
class SampleMessage(BaseModel):
    id: str
    category: str
    title: str
    description: str
    text: str
    expected_risk: str

# --- Multimodal Forensic Schemas ---
class MultimodalAnalyzeResponse(BaseModel):
    scan_id: str
    filename: str
    classification: str
    is_suspicious: bool
    risk_score: float
    risk_level: str
    detected_brands: List[str] = Field(default_factory=list)
    qr_forensics: Optional[Dict[str, Any]] = None
    investigation: AIExplanation
    extracted_text_preview: Optional[str] = None
    created_at: datetime

# --- AI Copilot / Assistant Schemas ---
class CopilotQueryRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=1000, description="The user question or selected suggestion")
    scan_id: Optional[str] = Field(None, description="Optional scan ID for contextual investigation grounding")
    message: Optional[str] = Field(None, max_length=5000, description="Optional raw or sanitized message text")

class CopilotQueryResponse(BaseModel):
    question: str
    answer: str
    suggested_followups: List[str] = Field(default_factory=list)
    provider_used: str
    context_grounded: bool
    scan_id: Optional[str] = None

# --- User Authentication & Account Schemas ---
class UserRegisterRequest(BaseModel):
    full_name: str = Field(..., min_length=2, max_length=100, description="User's full legal or preferred name")
    email: str = Field(..., min_length=5, max_length=255, description="Valid email address")
    password: str = Field(..., min_length=8, max_length=128, description="Strong password (min 8 chars, 1 letter, 1 number/symbol)")
    confirm_password: str = Field(..., min_length=8, max_length=128, description="Must match password")

class UserLoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255, description="Registered email address")
    password: str = Field(..., min_length=1, max_length=128, description="Account password")

class UserResponse(BaseModel):
    id: str
    email: str
    full_name: str
    created_at: datetime
    total_scans: int = 0

class UserSessionResponse(BaseModel):
    user: UserResponse
    csrf_token: str
    message: str = "Authenticated successfully"

class MyScansResponse(BaseModel):
    total: int
    skip: int
    limit: int
    items: List[ScanSummaryItem]


