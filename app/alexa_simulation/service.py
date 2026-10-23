"""
Alexa+ Simulation Engine for TrustLens AI.
Provides a simulated Alexa+ conversational assistant experience that invokes
the actual TrustLens AI machine learning pipeline, NLP threat indicator engine,
and evidence-grounded investigation agent.
"""

import re
import logging
from typing import Dict, Any, Optional, List, Tuple
from app.ml.inference import inference_service
from app.ai.agent import investigation_agent
from app.core.security import sanitize_and_encode_input
from app.core.config import settings
from app.alexa_simulation.tools import (
    trustlens_inspect_message,
    trustlens_explain_threat,
    trustlens_get_safety_actions
)

logger = logging.getLogger("trustlens.alexa_simulation")

class AlexaSimulationEngine:
    """
    Simulates the conversational experience of an Alexa+ assistant equipped with
    the TrustLens AI Agent Skill and MCP tools.
    """

    PRESET_SCENARIOS = [
        {
            "id": "bank_phishing",
            "title": "Chase Bank Account Impersonation",
            "category": "High Risk Smishing",
            "message": (
                "CHASE ALERT: Your account has been temporarily locked due to unusual debit activity. "
                "Verify your identity immediately to prevent suspension: http://chase-security-verify.net/login"
            )
        },
        {
            "id": "parcel_smishing",
            "title": "USPS Package Delivery Fee Scam",
            "category": "High Risk Smishing",
            "message": (
                "USPS Notification: Package #US984210 cannot be delivered due to missing house number and an unpaid "
                "customs fee of $2.49. Update address and pay online within 12h: http://usps-track-redelivery.org"
            )
        },
        {
            "id": "lottery_fraud",
            "title": "Unclaimed Prize / Advance-Fee Fraud",
            "category": "High Risk Fraud",
            "message": (
                "CONGRATULATIONS! You have been selected as the 2nd place winner of £1,000,000 cash in the National Lottery. "
                "Call 08712345678 immediately with your claim code WIN992 to arrange disbursement."
            )
        },
        {
            "id": "legit_appointment",
            "title": "Doctor Appointment Confirmation",
            "category": "Legitimate (Clean HAM)",
            "message": (
                "Hey Alex, confirming our doctor appointment tomorrow at 2:30 PM with Dr. Miller at the clinic. "
                "See you then!"
            )
        }
    ]

    def extract_message_from_prompt(self, user_prompt: str) -> Optional[str]:
        """
        Extracts message payload if embedded inside a prompt like:
        'Alexa, check this message: "..."' or 'Is this suspicious: ...'
        """
        prompt = user_prompt.strip()
        p_lower = prompt.lower()

        # Check if requesting one of the presets
        if "chase" in p_lower and ("sample" in p_lower or "bank" in p_lower or "alert" in p_lower):
            for s in self.PRESET_SCENARIOS:
                if s["id"] == "bank_phishing":
                    return s["message"]
        if "usps" in p_lower and ("sample" in p_lower or "fee" in p_lower or "package" in p_lower or "delivery" in p_lower):
            for s in self.PRESET_SCENARIOS:
                if s["id"] == "parcel_smishing":
                    return s["message"]
        if "lottery" in p_lower and ("sample" in p_lower or "prize" in p_lower or "winner" in p_lower):
            for s in self.PRESET_SCENARIOS:
                if s["id"] == "lottery_fraud":
                    return s["message"]
        if ("appointment" in p_lower or "doctor" in p_lower or "dental" in p_lower or "clinic" in p_lower) and ("sample" in p_lower or "reminder" in p_lower or "check" in p_lower or "confirm" in p_lower):
            for s in self.PRESET_SCENARIOS:
                if s["id"] == "legit_appointment":
                    return s["message"]

        # Questions about analysis or safety are queries, NOT messages to inspect
        if p_lower.startswith(("why", "what", "how", "who", "which", "where", "explain", "tell me", "should i", "do i")):
            return None

        # Check for explicit quotes
        quote_match = re.search(r'["\']([^"\']{15,})["\']', prompt)
        if quote_match:
            return quote_match.group(1).strip()

        # Check for command prefix: 'Alexa, check this: <message>'
        colon_match = re.search(r'^(?:alexa,?\s*)?(?:please\s+)?(?:check|analyze|inspect|verify|evaluate|read|is this(?: suspicious| a scam)?):?\s*["\']?(.*)$', prompt, re.IGNORECASE)
        if colon_match:
            candidate = colon_match.group(1).strip().strip('"\'')
            if len(candidate) >= 15 and not candidate.lower().startswith(("why", "what", "how", "which")):
                return candidate

        # If user directly pasted an SMS / email text with security signals or length
        # (e.g. contains URL, alert keywords, or is longer than 25 chars and not a simple query)
        is_simple_query = bool(re.match(r'^(what|why|who|how|can you|is it|is this)\b', prompt, re.IGNORECASE))
        if len(prompt) >= 30 and (
            "http" in prompt.lower() or 
            "alert" in prompt.lower() or 
            "urgent" in prompt.lower() or 
            "account" in prompt.lower() or 
            "verify" in prompt.lower() or 
            "package" in prompt.lower() or
            "winner" in prompt.lower() or
            not is_simple_query
        ):
            return prompt

        return None


    def determine_intent(
        self,
        user_prompt: str,
        extracted_message: Optional[str],
        has_active_context: bool
    ) -> str:
        """Determines the conversation intent."""
        p_lower = user_prompt.strip().lower()

        if p_lower in ["reset", "clear", "start over", "clear conversation", "restart"]:
            return "reset"

        if extracted_message:
            return "analyze_message"

        if any(w in p_lower for w in ["what can you do", "help", "who are you", "what is trustlens"]):
            return "capabilities"

        if has_active_context:
            if any(w in p_lower for w in ["why", "suspicious", "flagged", "classification", "fraud", "scam"]):
                return "followup_why"
            if any(w in p_lower for w in ["evidence", "proof", "support", "findings", "indicators"]):
                return "followup_evidence"
            if any(w in p_lower for w in ["next", "action", "do", "recommend", "how to protect", "safe"]):
                return "followup_action"
            if any(w in p_lower for w in ["phrase", "word", "warning", "signs", "keywords", "cue"]):
                return "followup_phrases"
            # General follow-up with active context
            return "followup_general"

        # Pre-scan questions
        if any(w in p_lower for w in ["why", "suspicious", "scam", "phishing", "smishing"]):
            return "pre_scan_inquiry"

        return "general_greeting"

    def process_turn(
        self,
        user_prompt: str,
        active_scan: Optional[Dict[str, Any]] = None
    ) -> Dict[str, Any]:
        """
        Executes a conversational turn in the simulated Alexa+ experience.
        Grounds all responses in real TrustLens ML and NLP execution.
        """
        clean_prompt = sanitize_and_encode_input(user_prompt, max_length=1500)
        if not clean_prompt:
            return {
                "conversational_response": "I didn't catch that. Could you paste a message you'd like me to check?",
                "spoken_text": "I didn't catch that. Please provide a message for me to check.",
                "tool_invoked": None,
                "scan_result": None,
                "suggested_prompts": [
                    "Why is this suspicious?",
                    "What should I do next?",
                    "Check Chase bank alert sample"
                ],
                "provider_used": "rule_based_nlp_engine",
                "context_grounded": False,
                "disclaimer": "Simulated Alexa+ Developer Hackathon Experience — Uses real TrustLens AI ML & NLP backend"
            }

        # Normalize active_scan format if provided in alternative schemas (e.g. flat scan_result or nested)
        normalized_scan = None
        if active_scan:
            if "ml_result" in active_scan and active_scan.get("ml_result"):
                normalized_scan = active_scan
            elif "classification" in active_scan or "risk_level" in active_scan or "message_analyzed" in active_scan:
                # Flat scan_result payload
                normalized_scan = {
                    "scan_id": active_scan.get("scan_id"),
                    "message_text": active_scan.get("message_analyzed") or active_scan.get("message_text", ""),
                    "ml_result": {
                        "classification": active_scan.get("classification", "HAM"),
                        "risk_score": active_scan.get("risk_score", 0.0),
                        "risk_level": active_scan.get("risk_level", "LOW"),
                        "is_suspicious": active_scan.get("is_suspicious", False),
                        "model_name": active_scan.get("model_name", "LogisticRegression_Baseline"),
                        "model_version": active_scan.get("model_version", "1.0.0"),
                        "observable_indicators": active_scan.get("observable_indicators", {})
                    },
                    "investigation": {
                        "summary": active_scan.get("summary", ""),
                        "observable_warning_signs": active_scan.get("warning_signs", []),
                        "evidence_vs_assumptions": {
                            "direct_observations": active_scan.get("direct_observations", []),
                            "potential_implications": active_scan.get("potential_implications", [])
                        },
                        "recommended_actions": active_scan.get("recommended_actions", []),
                        "uncertainty_statement": active_scan.get("uncertainty_statement", ""),
                        "provider_used": active_scan.get("provider_used", "rule_based_nlp_engine")
                    },
                    "scan_result": active_scan
                }
            elif "scan_result" in active_scan and active_scan.get("scan_result"):
                sr = active_scan["scan_result"]
                normalized_scan = {
                    "scan_id": active_scan.get("scan_id") or sr.get("scan_id"),
                    "message_text": sr.get("message_analyzed") or active_scan.get("message_text", ""),
                    "ml_result": {
                        "classification": sr.get("classification", "HAM"),
                        "risk_score": sr.get("risk_score", 0.0),
                        "risk_level": sr.get("risk_level", "LOW"),
                        "is_suspicious": sr.get("is_suspicious", False),
                        "model_name": sr.get("model_name", "LogisticRegression_Baseline"),
                        "model_version": sr.get("model_version", "1.0.0"),
                        "observable_indicators": sr.get("observable_indicators", {})
                    },
                    "investigation": {
                        "summary": sr.get("summary", ""),
                        "observable_warning_signs": sr.get("warning_signs", []),
                        "evidence_vs_assumptions": {
                            "direct_observations": sr.get("direct_observations", []),
                            "potential_implications": sr.get("potential_implications", [])
                        },
                        "recommended_actions": sr.get("recommended_actions", []),
                        "uncertainty_statement": sr.get("uncertainty_statement", ""),
                        "provider_used": sr.get("provider_used", "rule_based_nlp_engine")
                    },
                    "scan_result": sr
                }

        has_active_context = bool(normalized_scan and normalized_scan.get("ml_result"))
        extracted_message = self.extract_message_from_prompt(clean_prompt)
        intent = self.determine_intent(clean_prompt, extracted_message, has_active_context)

        # 1. Reset Intent
        if intent == "reset":
            return {
                "conversational_response": (
                    "I've reset our conversation. You can paste any suspicious SMS, email snippet, "
                    "or delivery notice, and I'll analyze it for fraud indicators using TrustLens AI."
                ),
                "spoken_text": "Conversation reset. What message would you like me to inspect next?",
                "tool_invoked": None,
                "scan_result": None,
                "suggested_prompts": [
                    "Check Chase bank alert sample",
                    "Check USPS delivery fee sample",
                    "Check doctor appointment sample"
                ],
                "provider_used": "rule_based_nlp_engine",
                "context_grounded": False,
                "disclaimer": "Simulated Alexa+ Developer Hackathon Experience — Uses real TrustLens AI ML & NLP backend"
            }

        # 2. Analyze Message Intent (Real ML Inference + Observable NLP Indicators via MCP Tool)
        if intent == "analyze_message":
            msg_to_analyze = extracted_message or clean_prompt

            # Execute genuine MCP tool function
            tool_output = trustlens_inspect_message(msg_to_analyze)
            ml_result = tool_output["ml_result"]
            investigation = tool_output["investigation"]

            risk_level = tool_output["risk_level"]
            score_pct = tool_output["risk_percentage"]
            classification = tool_output["classification"]
            indicators = tool_output["observable_indicators"]

            # Construct Alexa+ natural voice response
            if risk_level in ["HIGH", "MEDIUM"]:
                obs_summary = ""
                urls = indicators.get("urls_detected", [])
                urgency = indicators.get("urgency_cues", [])
                if urls:
                    obs_summary += f" It includes an unverified external link ({urls[0]})."
                if urgency:
                    obs_summary += f" It also uses high-urgency keywords like '{urgency[0]}'."

                conversational_text = (
                    f"I analyzed this message with TrustLens AI. Based on our machine learning model, "
                    f"this message is assessed as **{risk_level} RISK** with a **{score_pct} threat probability** "
                    f"({classification}).{obs_summary} "
                    f"I strongly recommend that you do not click any links or provide credentials. "
                    f"Would you like me to explain the specific warning signs, or review recommended safety actions?"
                )
                spoken_text = (
                    f"I analyzed the message using TrustLens AI. It has a {score_pct} risk score and appears to be "
                    f"a suspicious {classification} communication. Do not click any links. "
                    f"Would you like to hear the warning signs or safety steps?"
                )
                suggested_prompts = [
                    "Why is this message suspicious?",
                    "What evidence supports the prediction?",
                    "What should I do next?",
                    "Which phrases are warning signs?"
                ]
            else:
                conversational_text = (
                    f"I analyzed this message with TrustLens AI. It is evaluated as **LOW RISK** with a **{score_pct} risk score** "
                    f"({classification} - Legitimate). No urgent payment demands, unverified credential portals, or deceptive cues "
                    f"were detected. However, always exercise normal caution when communicating with unknown numbers."
                )
                spoken_text = (
                    f"TrustLens evaluated this message as low risk, with a score of {score_pct}. "
                    f"It looks like standard communication. Normal caution still applies."
                )
                suggested_prompts = [
                    "Why was this classified as legitimate?",
                    "What evidence supports the prediction?",
                    "What should I do next?",
                    "Check a suspicious message"
                ]

            scan_card = {
                "message_analyzed": tool_output["message_analyzed"],
                "classification": classification,
                "is_suspicious": tool_output["is_suspicious"],
                "risk_score": tool_output["risk_score"],
                "risk_percentage": score_pct,
                "risk_level": risk_level,
                "score_interpretation": tool_output["score_interpretation"],
                "model_name": tool_output["model_name"],
                "model_version": tool_output["model_version"],
                "observable_indicators": indicators,
                "summary": tool_output["summary"],
                "warning_signs": tool_output["warning_signs"],
                "direct_observations": tool_output["direct_observations"],
                "potential_implications": tool_output["potential_implications"],
                "recommended_actions": tool_output["recommended_actions"],
                "uncertainty_statement": tool_output["uncertainty_statement"],
                "provider_used": tool_output["provider_used"]
            }

            return {
                "conversational_response": conversational_text,
                "spoken_text": spoken_text,
                "tool_invoked": "trustlens_inspect_message",
                "scan_result": scan_card,
                "ml_result": ml_result,
                "investigation": investigation,
                "message_text": msg_to_analyze,
                "suggested_prompts": suggested_prompts,
                "provider_used": tool_output["provider_used"],
                "context_grounded": True,
                "disclaimer": "Simulated Alexa+ Developer Hackathon Experience — Uses real TrustLens AI ML & NLP backend"
            }

        # 3. Grounded Follow-up Intents (Why, Evidence, Actions, Phrases via MCP Tools)
        if has_active_context and normalized_scan:
            ml_res = normalized_scan.get("ml_result", {})
            inv_res = normalized_scan.get("investigation", {})
            msg_text = normalized_scan.get("message_text", "")

            if intent == "followup_action":
                tool_name = "trustlens_get_safety_actions"
                actions_res = trustlens_get_safety_actions(
                    threat_level=ml_res.get("risk_level", "LOW"),
                    threat_indicators=ml_res.get("observable_indicators", {}).get("urgency_cues", [])
                )
                action_bullets = "\n".join([f"• {a}" for a in actions_res["recommended_actions"]])
                conversational_text = (
                    f"Here are the prioritized defensive actions recommended for this **{actions_res['threat_level']}** threat scenario:\n\n"
                    f"{action_bullets}\n\n"
                    f"{actions_res['summary']}"
                )
                spoken_text = f"Here are the recommended safety actions. First: {actions_res['recommended_actions'][0]}"
                suggested_prompts = [
                    "Why is this message suspicious?",
                    "What evidence supports the prediction?",
                    "Check another message"
                ]
                provider_used = "rule_based_nlp_engine"
            else:
                tool_name = "trustlens_explain_threat"
                explain_res = trustlens_explain_threat(
                    question=clean_prompt,
                    message_text=msg_text,
                    active_scan=normalized_scan
                )
                conversational_text = explain_res["answer"]
                spoken_text = explain_res["answer"].split("\n\n")[0]
                suggested_prompts = explain_res.get("suggested_followups", [
                    "Why is this message suspicious?",
                    "What should I do next?",
                    "Check another message"
                ])
                provider_used = explain_res.get("provider_used", "rule_based_nlp_engine")

            return {
                "conversational_response": conversational_text,
                "spoken_text": spoken_text,
                "tool_invoked": tool_name,
                "scan_result": normalized_scan.get("scan_result"),
                "ml_result": ml_res,
                "investigation": inv_res,
                "message_text": msg_text,
                "suggested_prompts": suggested_prompts,
                "provider_used": provider_used,
                "context_grounded": True,
                "disclaimer": "Simulated Alexa+ Developer Hackathon Experience — Uses real TrustLens AI ML & NLP backend"
            }

        # 4. Capabilities / General Greeting
        if intent == "capabilities":
            return {
                "conversational_response": (
                    "I am the **TrustLens AI Alexa+ Assistant**. I help protect you from deceptive communications by:\n\n"
                    "• **Real-Time Scanning:** Evaluating SMS smishing, fake bank alerts, parcel scams, and phishing emails.\n"
                    "• **Empirical Machine Learning:** Applying a trained scikit-learn statistical model (TF-IDF + Logistic Regression).\n"
                    "• **Observable Threat Indicators:** Detecting unverified links, urgency keywords, phone shortcodes, and credential solicitations.\n"
                    "• **Actionable Guidance:** Providing step-by-step defensive safety procedures.\n\n"
                    "You can paste any untrusted message or pick one of the sample scenarios to test me!"
                ),
                "spoken_text": (
                    "I'm the TrustLens AI Assistant. I detect smishing, fake bank alerts, and parcel scams using machine learning. "
                    "Paste any message to test me."
                ),
                "tool_invoked": None,
                "scan_result": None,
                "suggested_prompts": [
                    "Check Chase bank alert sample",
                    "Check USPS delivery fee sample",
                    "Check doctor appointment sample"
                ],
                "provider_used": "rule_based_nlp_engine",
                "context_grounded": False,
                "disclaimer": "Simulated Alexa+ Developer Hackathon Experience — Uses real TrustLens AI ML & NLP backend"
            }

        # Default Greeting / Instructions
        return {
            "conversational_response": (
                "Hello! I am your **Alexa+ Cybersecurity Assistant**, powered by **TrustLens AI**. "
                "You can ask me to evaluate whether a text message, delivery notification, or email looks like a scam.\n\n"
                "**How to test:**\n"
                "1. Click one of the sample scenarios below, or\n"
                "2. Paste a message directly into the chat: *'Alexa, is this a scam: [message]'*.\n\n"
                "I will invoke the TrustLens AI inspection tool and provide a grounded threat evaluation."
            ),
            "spoken_text": (
                "Hello! I'm your Alexa+ Cybersecurity Assistant powered by TrustLens AI. "
                "Paste any suspicious text or choose a sample to begin."
            ),
            "tool_invoked": None,
            "scan_result": None,
            "suggested_prompts": [
                "Check Chase bank alert sample",
                "Check USPS delivery fee sample",
                "Check doctor appointment sample"
            ],
            "provider_used": "rule_based_nlp_engine",
            "context_grounded": False,
            "disclaimer": "Simulated Alexa+ Developer Hackathon Experience — Uses real TrustLens AI ML & NLP backend"
        }

# Global simulator engine singleton
alexa_simulator = AlexaSimulationEngine()
