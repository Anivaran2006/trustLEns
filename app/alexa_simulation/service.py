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

        extracted_message = self.extract_message_from_prompt(clean_prompt)
        has_active_context = bool(active_scan and active_scan.get("ml_result"))
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

        # 2. Analyze Message Intent (Real ML Inference + Observable NLP Indicators)
        if intent == "analyze_message":
            msg_to_analyze = extracted_message or clean_prompt
            
            # Execute genuine ML inference
            ml_result = inference_service.predict(msg_to_analyze)
            # Execute genuine investigation agent (Bedrock if configured, else Rule-Based NLP engine)
            investigation = investigation_agent.investigate(msg_to_analyze, ml_result)

            risk_level = ml_result["risk_level"]
            score_pct = f"{ml_result['risk_score'] * 100:.1f}%"
            classification = ml_result["classification"]
            indicators = ml_result.get("observable_indicators", {})

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
                "message_analyzed": msg_to_analyze,
                "classification": classification,
                "is_suspicious": ml_result["is_suspicious"],
                "risk_score": ml_result["risk_score"],
                "risk_percentage": score_pct,
                "risk_level": risk_level,
                "score_interpretation": ml_result["score_interpretation"],
                "model_name": ml_result["model_name"],
                "model_version": ml_result["model_version"],
                "observable_indicators": indicators,
                "summary": investigation.get("summary", ""),
                "warning_signs": investigation.get("observable_warning_signs", []),
                "direct_observations": investigation.get("evidence_vs_assumptions", {}).get("direct_observations", []),
                "potential_implications": investigation.get("evidence_vs_assumptions", {}).get("potential_implications", []),
                "recommended_actions": investigation.get("recommended_actions", []),
                "uncertainty_statement": investigation.get("uncertainty_statement", ""),
                "provider_used": investigation.get("provider_used", "rule_based_nlp_engine")
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
                "provider_used": investigation.get("provider_used", "rule_based_nlp_engine"),
                "context_grounded": True,
                "disclaimer": "Simulated Alexa+ Developer Hackathon Experience — Uses real TrustLens AI ML & NLP backend"
            }

        # 3. Grounded Follow-up Intents (Why, Evidence, Actions, Phrases)
        if has_active_context:
            ml_res = active_scan.get("ml_result", {})
            inv_res = active_scan.get("investigation", {})
            msg_text = active_scan.get("message_text", "")

            # Invoke existing investigation_agent copilot logic grounded in real results
            answer_dict = investigation_agent.answer_copilot_question(
                question=clean_prompt,
                message=msg_text,
                investigation=inv_res,
                ml_result=ml_res
            )

            tool_name = "trustlens_explain_threat"
            if intent == "followup_action":
                tool_name = "trustlens_get_safety_actions"

            return {
                "conversational_response": answer_dict["answer"],
                "spoken_text": answer_dict["answer"].split("\n\n")[0],
                "tool_invoked": tool_name,
                "scan_result": active_scan.get("scan_result"),
                "ml_result": ml_res,
                "investigation": inv_res,
                "message_text": msg_text,
                "suggested_prompts": answer_dict.get("suggested_followups", [
                    "Why is this message suspicious?",
                    "What should I do next?",
                    "Check another message"
                ]),
                "provider_used": answer_dict.get("provider_used", "rule_based_nlp_engine"),
                "context_grounded": True,
                "disclaimer": "Simulated Alexa+ Developer Hackathon Experience — Grounded in real TrustLens analysis"
            }

        # 4. Capabilities / General Greeting
        if intent == "capabilities":
            return {
                "conversational_response": (
                    "I am the **TrustLens AI Alexa+ Assistant**. I help protect you from deceptive communications by:\n\n"
                    "• **Real-Time Scanning:** Evaluating SMS smishing, fake bank alerts, parcel scams, and phishing emails.\n"
                    "• **Empirical Machine Learning:** Applying a calibrated scikit-learn statistical model (TF-IDF + Logistic Regression).\n"
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
