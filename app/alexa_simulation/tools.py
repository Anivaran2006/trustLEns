"""
Model Context Protocol (MCP) Tool Specifications & Agent Skills for Alexa+ Simulated Experience.
Represents the tools exposed by the TrustLens AI Agent Skill to the Alexa+ Conversational Runtime.
"""

from typing import List, Dict, Any, Optional
from app.ml.inference import MLInferenceService
from app.ai.agent import InvestigationAgent

_inference_service = MLInferenceService.get_instance()
_investigation_agent = InvestigationAgent()

MCP_TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "trustlens_inspect_message",
        "description": (
            "Analyzes an untrusted communication (SMS, email, text message, delivery notification) "
            "using TrustLens AI's trained statistical machine learning classifier and NLP threat indicator engine. "
            "Returns classification (SPAM/HAM), probability risk score (0.0 to 1.0), risk tier, "
            "extracted indicators (URLs, phone numbers, urgency keywords, financial demands), and grounded explanation."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "message_text": {
                    "type": "string",
                    "description": "The exact untrusted message body or communication snippet to evaluate."
                }
            },
            "required": ["message_text"]
        }
    },
    {
        "name": "trustlens_explain_threat",
        "description": (
            "Provides an in-depth conversational explanation of why a message was flagged as suspicious or safe, "
            "answering specific user inquiries grounded strictly in empirical evidence vs potential implications."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "question": {
                    "type": "string",
                    "description": "The user's follow-up question (e.g. 'Why is this suspicious?', 'What evidence was found?')"
                },
                "message_text": {
                    "type": "string",
                    "description": "The message text that was inspected."
                },
                "scan_id": {
                    "type": "integer",
                    "description": "Optional ID of a previously recorded TrustLens scan."
                }
            },
            "required": ["question"]
        }
    },
    {
        "name": "trustlens_get_safety_actions",
        "description": (
            "Retrieves practical, prioritized cybersecurity safety actions and incident response procedures "
            "customized for the evaluated threat type (e.g., bank impersonation, parcel tracking smishing, advance-fee fraud)."
        ),
        "parameters": {
            "type": "object",
            "properties": {
                "threat_level": {
                    "type": "string",
                    "enum": ["LOW", "MEDIUM", "HIGH"],
                    "description": "The risk level assessed by TrustLens."
                },
                "threat_indicators": {
                    "type": "array",
                    "items": {"type": "string"},
                    "description": "Observed warning signs or indicators."
                }
            },
            "required": ["threat_level"]
        }
    }
]

def get_mcp_tool_definitions() -> List[Dict[str, Any]]:
    """Returns the list of MCP tool definitions for the Alexa+ Agent Skill."""
    return MCP_TOOL_DEFINITIONS


def trustlens_inspect_message(message_text: str) -> Dict[str, Any]:
    """
    Executes actual TrustLens AI machine learning inference and NLP threat indicator engine.
    Returns empirical classification, risk score, observable indicators, and grounded explanation.
    """
    if not message_text or not message_text.strip():
        raise ValueError("message_text cannot be empty.")

    ml_result = _inference_service.predict(message_text)
    investigation = _investigation_agent.investigate(message_text, ml_result)

    score_pct = f"{ml_result['risk_score'] * 100:.1f}%"
    return {
        "message_analyzed": message_text,
        "classification": ml_result["classification"],
        "is_suspicious": ml_result["is_suspicious"],
        "risk_score": ml_result["risk_score"],
        "risk_percentage": score_pct,
        "risk_level": ml_result["risk_level"],
        "score_interpretation": ml_result["score_interpretation"],
        "model_name": ml_result["model_name"],
        "model_version": ml_result["model_version"],
        "observable_indicators": ml_result.get("observable_indicators", {}),
        "summary": investigation.get("summary", ""),
        "warning_signs": investigation.get("observable_warning_signs", []),
        "direct_observations": investigation.get("evidence_vs_assumptions", {}).get("direct_observations", []),
        "potential_implications": investigation.get("evidence_vs_assumptions", {}).get("potential_implications", []),
        "recommended_actions": investigation.get("recommended_actions", []),
        "uncertainty_statement": investigation.get("uncertainty_statement", ""),
        "provider_used": investigation.get("provider_used", "rule_based_nlp_engine"),
        "ml_result": ml_result,
        "investigation": investigation
    }


def trustlens_explain_threat(
    question: str,
    message_text: Optional[str] = None,
    scan_id: Optional[int] = None,
    active_scan: Optional[Dict[str, Any]] = None
) -> Dict[str, Any]:
    """
    Provides an in-depth conversational explanation of threat indicators,
    grounded in actual ML and NLP analysis.
    """
    if not question or not question.strip():
        raise ValueError("question cannot be empty.")

    if active_scan:
        if "ml_result" in active_scan and active_scan.get("ml_result"):
            ml_res = active_scan.get("ml_result", {})
            inv_res = active_scan.get("investigation", {})
            msg_text = active_scan.get("message_text", message_text or "")
        else:
            ml_res = {
                "classification": active_scan.get("classification", "HAM"),
                "risk_score": active_scan.get("risk_score", 0.0),
                "risk_level": active_scan.get("risk_level", "LOW"),
                "is_suspicious": active_scan.get("is_suspicious", False),
                "model_name": active_scan.get("model_name", "LogisticRegression_Baseline"),
                "model_version": active_scan.get("model_version", "1.0.0"),
                "observable_indicators": active_scan.get("observable_indicators", {})
            }
            inv_res = {
                "summary": active_scan.get("summary", ""),
                "observable_warning_signs": active_scan.get("warning_signs", []),
                "evidence_vs_assumptions": {
                    "direct_observations": active_scan.get("direct_observations", []),
                    "potential_implications": active_scan.get("potential_implications", [])
                },
                "recommended_actions": active_scan.get("recommended_actions", []),
                "risk_level": active_scan.get("risk_level", "LOW")
            }
            msg_text = active_scan.get("message_analyzed", message_text or "")
    elif message_text:
        inspection = trustlens_inspect_message(message_text)
        ml_res = inspection["ml_result"]
        inv_res = inspection["investigation"]
        msg_text = message_text
    else:
        ml_res = {}
        inv_res = {}
        msg_text = ""

    answer_dict = _investigation_agent.answer_copilot_question(
        question=question,
        message=msg_text,
        investigation=inv_res,
        ml_result=ml_res
    )

    return {
        "question": question,
        "answer": answer_dict.get("answer", ""),
        "suggested_followups": answer_dict.get("suggested_followups", []),
        "provider_used": answer_dict.get("provider_used", "rule_based_nlp_engine"),
        "context_grounded": bool(ml_res or inv_res)
    }


def trustlens_get_safety_actions(
    threat_level: str,
    threat_indicators: Optional[List[str]] = None
) -> Dict[str, Any]:
    """
    Retrieves prioritized cybersecurity defensive guidance based on assessed threat level.
    """
    threat_upper = (threat_level or "LOW").upper()
    indicators = threat_indicators or []

    if threat_upper in ["HIGH", "SPAM"]:
        actions = [
            "Do not click or tap any links, phone numbers, or attachments in the communication.",
            "Never provide passwords, one-time passcodes (OTP), SSN, or financial credentials.",
            "Contact the purported institution through official channels (e.g., phone number on physical debit/credit card or genuine official website).",
            "Forward the smishing SMS to your cellular provider via 7726 (SPAM) to help block malicious infrastructure.",
            "If account details were already entered, immediately reset your password and check for unauthorized transactions."
        ]
        summary = "High risk deceptive communication detected. Strict containment and zero-trust verification required."
    elif threat_upper == "MEDIUM":
        actions = [
            "Treat the communication with elevated caution; do not share sensitive personal information.",
            "Independently verify the sender's identity through a separate, confirmed channel before taking action.",
            "Do not wire money or purchase gift cards upon request."
        ]
        summary = "Moderate risk indicators detected. Verification advised before interacting."
    else:
        actions = [
            "Standard security hygiene applies. No urgent threats or deceptive patterns detected.",
            "Always verify unknown senders before sharing personal information."
        ]
        summary = "Low threat level evaluated. Routine communication vigilance."

    return {
        "threat_level": threat_upper,
        "summary": summary,
        "recommended_actions": actions,
        "observable_indicators_considered": indicators
    }


def execute_mcp_tool(tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
    """
    Model Context Protocol (MCP) tool dispatcher.
    Directly executes the requested tool using genuine backend functions.
    """
    if tool_name == "trustlens_inspect_message":
        msg = arguments.get("message_text", "")
        return {
            "tool": tool_name,
            "status": "success",
            "output": trustlens_inspect_message(msg)
        }
    elif tool_name == "trustlens_explain_threat":
        q = arguments.get("question", "")
        msg = arguments.get("message_text")
        scan_id = arguments.get("scan_id")
        return {
            "tool": tool_name,
            "status": "success",
            "output": trustlens_explain_threat(question=q, message_text=msg, scan_id=scan_id)
        }
    elif tool_name == "trustlens_get_safety_actions":
        threat_level = arguments.get("threat_level", "LOW")
        indicators = arguments.get("threat_indicators", [])
        return {
            "tool": tool_name,
            "status": "success",
            "output": trustlens_get_safety_actions(threat_level=threat_level, threat_indicators=indicators)
        }
    else:
        raise ValueError(f"Unknown MCP tool: '{tool_name}'")

