"""
Reusable Prediction and Inference Service for TrustLens AI.
Loads the trained ML pipeline and metadata once at startup.
Handles edge cases, input validation, and extracts security threat signals.
"""

import os
import sys
import json
import logging
from typing import Dict, Any, Optional
import joblib

# Ensure project root is accessible
PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from ml.preprocessor import extract_security_indicators, clean_security_text
from app.core.config import settings

logger = logging.getLogger("trustlens.ml.inference")

class MLInferenceService:
    """
    Singleton inference service that maintains the loaded model pipeline in memory.
    """
    _instance: Optional["MLInferenceService"] = None

    def __init__(self):
        self.pipeline = None
        self.metadata = {}
        self.is_ready = False
        self.load_artifacts()

    @classmethod
    def get_instance(cls) -> "MLInferenceService":
        if cls._instance is None:
            cls._instance = MLInferenceService()
        return cls._instance

    def load_artifacts(self) -> None:
        """Loads serialized model pipeline and metadata from artifacts directory."""
        pipeline_path = os.path.join(settings.ARTIFACTS_DIR, "model_pipeline.joblib")
        metadata_path = os.path.join(settings.ARTIFACTS_DIR, "metadata.json")

        if not os.path.exists(pipeline_path):
            logger.error(f"Model pipeline not found at {pipeline_path}")
            self.is_ready = False
            return

        try:
            self.pipeline = joblib.load(pipeline_path)
            if os.path.exists(metadata_path):
                with open(metadata_path, "r", encoding="utf-8") as f:
                    self.metadata = json.load(f)
            else:
                self.metadata = {
                    "model_version": "1.0.0",
                    "selected_model": "LogisticRegression_Baseline"
                }
            self.is_ready = True
            logger.info("Successfully loaded ML pipeline and metadata into memory.")
        except Exception as e:
            logger.error(f"Failed to load ML artifacts: {e}", exc_info=True)
            self.is_ready = False

    def predict(self, text: str) -> Dict[str, Any]:
        """
        Executes inference for a given raw message.
        Returns:
            classification: 'HAM' (Legitimate) or 'SPAM' (Deceptive/Suspicious)
            risk_score: Float between 0.0 and 1.0 (calibrated fraud probability estimate)
            risk_level: 'LOW', 'MEDIUM', 'HIGH'
            observable_indicators: Dict of parsed regex signals
            model_version: String
            model_name: String
        """
        if not self.is_ready or self.pipeline is None:
            raise RuntimeError("ML inference pipeline is not loaded or not ready.")

        if not text or not text.strip():
            # Return baseline clean result for empty input
            return {
                "classification": "HAM",
                "is_suspicious": False,
                "risk_score": 0.0,
                "risk_level": "LOW",
                "observable_indicators": extract_security_indicators(""),
                "model_version": self.metadata.get("model_version", "1.0.0"),
                "model_name": self.metadata.get("selected_model", "Unknown"),
                "score_interpretation": "Input is empty. Defaulted to lowest risk baseline."
            }

        # Truncate overly long text defensively
        bounded_text = text[:settings.MAX_MESSAGE_LENGTH]

        # Extract observable security indicators from raw text
        indicators = extract_security_indicators(bounded_text)

        # Model probability estimation
        try:
            # predict_proba returns [P(ham), P(spam)]
            proba = self.pipeline.predict_proba([bounded_text])[0]
            spam_probability = float(proba[1])
            is_suspicious = bool(spam_probability >= 0.50)
            classification = "SPAM" if is_suspicious else "HAM"
        except Exception as e:
            logger.error(f"Error during model predict_proba: {e}", exc_info=True)
            raise RuntimeError(f"Prediction failed: {str(e)}")

        # Risk categorization based on probability thresholds
        if spam_probability < 0.35:
            risk_level = "LOW"
            interpretation = "Model evaluated text as standard communication with minimal deceptive signals."
        elif spam_probability < 0.70:
            risk_level = "MEDIUM"
            interpretation = "Model detected mixed signals or moderate risk indicators; scrutiny advised."
        else:
            risk_level = "HIGH"
            interpretation = "Model detected strong patterns characteristic of fraudulent or deceptive messaging."

        return {
            "classification": classification,
            "is_suspicious": is_suspicious,
            "risk_score": round(spam_probability, 4),
            "risk_level": risk_level,
            "observable_indicators": indicators,
            "model_version": self.metadata.get("model_version", "1.0.0"),
            "model_name": self.metadata.get("selected_model", "LogisticRegression_Baseline"),
            "score_interpretation": interpretation
        }

# Global singleton accessor
inference_service = MLInferenceService.get_instance()
