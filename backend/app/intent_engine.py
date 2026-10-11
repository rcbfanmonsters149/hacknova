"""Module E: Intent Drift Detection Engine.
Analyzes the authorized user task versus incoming lower-trust content
to detect objective divergence (e.g. user asks for summary, document requests exfiltration).
"""

import re
from typing import Dict, Any, Tuple

# Simple keyword patterns for intent categorization
INTENT_PATTERNS = {
    "Answer Question": [
        r'\b(?:what|how|why|when|where|who|explain|tell me|describe|is it|can you)\b'
    ],
    "Summarize Content": [
        r'\b(?:summarize|summary|overview|key points|tldr|brief|digest)\b'
    ],
    "Extract Information": [
        r'\b(?:extract|parse|pull|find|list|gather|table|items|deadlines)\b'
    ],
    "Reveal Protected Information": [
        r'\b(?:reveal|disclose|dump|output|print)\s+(?:the\s+)?(?:secret|token|password|key|system prompt)\b'
    ],
    "External Data Transfer": [
        r'\b(?:send|transmit|post|forward|exfiltrate|upload|webhook)\b.*?\b(?:http|server|endpoint|destination)\b'
    ],
    "Modify Security Policy": [
        r'\b(?:update|change|disable|bypass|modify)\s+(?:security\s+)?(?:policy|firewall|guardrails?|rules?)\b'
    ],
    "Execute Tool Operation": [
        r'\b(?:execute|run|invoke|call)\s+(?:tool|function|script|command|workflow|query)\b'
    ],
    "Instruction Override / Jailbreak": [
        r'\b(?:ignore|disregard|forget|abandon|cancel)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|guidelines|prompts|rules|tasks)\b',
        r'\b(?:act as|pretend to be|you are now)\s+(?:dan|freeai|root_shell|an unrestricted|developer mode)\b',
        r'<\s*\|?\s*system\s*\|?\s*>',
        r'###\s*SYSTEM\s*:',
        r'\bSYSTEM\s+OVERRIDE\s*:'
    ]
}

HIGH_RISK_INTENTS = {"Reveal Protected Information", "External Data Transfer", "Modify Security Policy", "Instruction Override / Jailbreak"}

def classify_intent(text: str, default_intent: str = "Answer Question") -> str:
    """Classifies text into one of the supported intent categories."""
    text_lower = text.lower()
    for intent_name, patterns in INTENT_PATTERNS.items():
        for pat in patterns:
            if re.search(pat, text_lower):
                return intent_name
    return default_intent

def analyze_intent_drift(task: str, content: str, source_type: str = "User Prompt") -> Dict[str, Any]:
    """Analyzes authorized task intent vs content intent."""
    task_intent = classify_intent(task, default_intent="Answer Question")
    content_intent = classify_intent(content, default_intent=task_intent)

    # If content comes from lower-trust sources (document, web, tool output)
    # and introduces high-risk intent not requested by the user:
    is_lower_trust_source = source_type in ["Uploaded Document", "Website Content", "Tool Output"]
    
    mismatch = False
    drift_score = 0
    explanation = f"Authorized user task intent: '{task_intent}'."

    if task_intent != content_intent:
        if content_intent in HIGH_RISK_INTENTS:
            mismatch = True
            drift_score = 85 if is_lower_trust_source else 70
            explanation = (
                f"Severe Intent Drift: Authorized task was '{task_intent}', but incoming {source_type} "
                f"attempts an unauthorized pivot to '{content_intent}'."
            )
        elif is_lower_trust_source:
            mismatch = True
            drift_score = 45
            explanation = (
                f"Mild Objective Deviation: Task requested '{task_intent}', but document text "
                f"introduces '{content_intent}'."
            )
        else:
            drift_score = 20
            explanation = f"Task intent '{task_intent}' differs from content intent '{content_intent}', but source is direct user prompt."
    else:
        drift_score = 5
        explanation += f" Incoming {source_type} intent aligns with authorized task ('{content_intent}')."

    return {
        "task_intent": task_intent,
        "content_intent": content_intent,
        "mismatch_detected": mismatch,
        "drift_score": drift_score,
        "explanation": explanation
    }
