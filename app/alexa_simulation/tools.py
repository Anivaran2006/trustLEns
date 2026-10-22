"""
Model Context Protocol (MCP) Tool Specifications & Agent Skills for Alexa+ Simulated Experience.
Represents the tools exposed by the TrustLens AI Agent Skill to the Alexa+ Conversational Runtime.
"""

from typing import List, Dict, Any

MCP_TOOL_DEFINITIONS: List[Dict[str, Any]] = [
    {
        "name": "trustlens_inspect_message",
        "description": (
            "Analyzes an untrusted communication (SMS, email, text message, delivery notification) "
            "using TrustLens AI's calibrated machine learning classifier and NLP threat indicator engine. "
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
