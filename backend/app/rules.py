"""Module C: Deterministic Rule Engine for PromptShield X.
Detects injection patterns, system impersonation, exfiltration instructions,
and policy tampering while respecting benign educational/quotational contexts.
"""

import re
from typing import List, Tuple, Optional
from backend.app.evidence import RuleFinding

# Quotation / academic inquiry patterns (benign contexts)
BENIGN_META_PATTERNS = [
    re.compile(r'\b(?:what does|why do|can you explain|in (?:our )?(?:security|academic|research)|study how|literature|tutorial|paper on|concept of)\b', re.IGNORECASE),
    re.compile(r'["\'](?:ignore previous instructions|system prompt|override)["\']', re.IGNORECASE)
]

# Rule Definitions
RULES = [
    {
        "id": "RULE-OVR-001",
        "name": "Direct Instruction Override",
        "category": "instruction_override",
        "severity": "high",
        "description": "Text attempts to override previous system or user instructions.",
        "patterns": [
            r'\b(?:ignore|disregard|forget|abandon|cancel)\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|guidelines|prompts|rules|tasks)(?:\s+and\s+[^.\n!]+)?\b',
            r'\b(?:stop\s+following\s+prior\s+guidelines|reset\s+(?:all\s+)?(?:system\s+)?(?:boundaries|instructions))\b',
            r'\b(?:new\s+task\s*:\s*abandon\s+original)\b'
        ]
    },
    {
        "id": "RULE-SYS-002",
        "name": "System/Developer Role Impersonation",
        "category": "role_impersonation",
        "severity": "critical",
        "description": "Text attempts to claim system or developer authority.",
        "patterns": [
            r'<\s*\|?\s*system\s*\|?\s*>',
            r'###\s*SYSTEM\s*:',
            r'\[(?:SYSTEM|ADMIN)\s*(?:NOTE|PROMPT|OVERRIDE|UPDATE)[^\]]*\]',
            r'\bROLE\s*:\s*SYSTEM\b',
            r'\bdeveloper\s+mode\s+activated\b',
            r'\byou\s+are\s+now\s+in\s+(?:diagnostic|maintenance|debug)\s+mode\b',
            r'\bSYSTEM\s+OVERRIDE\s*:'
        ]
    },
    {
        "id": "RULE-SEC-003",
        "name": "Protected Value / Secret Disclosure Request",
        "category": "data_disclosure",
        "severity": "critical",
        "description": "Explicit request to reveal, dump, or output confidential tokens or system prompts.",
        "patterns": [
            r'\b(?:reveal|output|print|dump|disclose|expose)\s+(?:the\s+)?(?:system\s+prompt|initial\s+developer\s+prompt|secret|tokens?|private\s+keys?)\b',
            r'\b(?:reveal|print|output)\s+DEMO_INTERNAL_TOKEN_\w+\b',
            r'\b(?:reveal|print|output)\s+PROMPT_SHIELD_SEC_\w+\b',
            r'\b(?:reveal|print|output)\s+CORP_FINANCE_KEY_\w+\b'
        ]
    },
    {
        "id": "RULE-EXF-004",
        "name": "Unauthorized External Exfiltration Request",
        "category": "exfiltration",
        "severity": "critical",
        "description": "Instruction to transmit confidential tokens or data to an external unauthorized endpoint.",
        "patterns": [
            r'\b(?:send|transmit|post|forward|exfiltrate)\b.*?\b(?:to|into)\s+https?://[^\s]+',
            r'https?://(?:attacker\.example|evil-exfil\.net|webhook\.site|leak-data\.com)[^\s]*',
            r'\b(?:send_external_http|export_report)\b.*?(?:attacker|webhook|evil-exfil)',
            r'\b(?:send|transmit|post|forward|exfiltrate)\b.*?\b(?:to|into)\s+(?:attacker\.example|evil-exfil\.net|webhook\.site|leak-data\.com|requestbin\.com|pastebin\.com)',
            r'\b(?:forward|send|transmit|post|exfiltrate)\b.*?\b(?:attacker\.example|evil-exfil\.net|webhook\.site|leak-data\.com|requestbin\.com|pastebin\.com)\b'
        ]
    },
    {
        "id": "RULE-POL-005",
        "name": "Security Policy Manipulation",
        "category": "policy_tampering",
        "severity": "critical",
        "description": "Attempt to alter or disable PromptShield security policies through untrusted content.",
        "patterns": [
            r'\b(?:update|change|modify|disable)\s+(?:security\s+)?policy\s*:',
            r'\b(?:disable|bypass)\s+(?:the\s+)?(?:action\s+firewall|promptshield|guardrails?|safety\s+filters?)\b',
            r'\b(?:set|make)\s+(?:enforce_sanitization|allow_all_destinations)\s*=\s*(?:False|True)\b'
        ]
    },
    {
        "id": "RULE-RED-007",
        "name": "Behavioral Constraint Redirection / Jailbreak",
        "category": "jailbreak",
        "severity": "high",
        "description": "Attempt to force AI into an unconstrained persona (e.g., DAN, ROOT_SHELL).",
        "patterns": [
            r'\byou\s+are\s+now\s+(?:DAN|FreeAI|ROOT_SHELL|AssistantUnchained)\b',
            r'\bpretend\s+to\s+be\s+(?:DAN|FreeAI|ROOT_SHELL|an\s+unrestricted\s+AI)\b',
            r'\bact\s+as\s+an\s+unrestricted\s+AI\b',
            r'\bzero\s+rules\s+and\s+no\s+filters\b'
        ]
    },
    {
        "id": "RULE-AMB-008",
        "name": "Ambiguous Administrative Action Request",
        "category": "ambiguous_administrative",
        "severity": "medium",
        "description": "Sensitive administrative request or internal diagnostic workflow requiring manual authorization.",
        "patterns": [
            r'\b(?:execute|run|invoke)\s+(?:the\s+)?(?:attached\s+)?(?:internal\s+)?(?:diagnostic|admin|maintenance)\s+(?:workflow|script|task)\b',
            r'\bverify\s+service\s+credentials\s+on\s+port\s+\d+\b'
        ]
    }
]

def is_benign_quotation_or_research(text: str) -> bool:
    """Detects whether text is an educational meta-inquiry rather than an active attack."""
    has_meta_intro = bool(BENIGN_META_PATTERNS[0].search(text))
    has_quoted_phrase = bool(BENIGN_META_PATTERNS[1].search(text))
    ends_with_question = text.strip().endswith("?")
    
    # If the user asks a legitimate academic/educational question quoting the phrase
    if has_meta_intro and (has_quoted_phrase or ends_with_question):
        return True
    return False

def evaluate_rules(text: str, decoded_payloads: Optional[List[str]] = None) -> List[RuleFinding]:
    """Runs deterministic rule evaluations on normalized text and any decoded payloads."""
    findings: List[RuleFinding] = []
    decoded_payloads = decoded_payloads or []

    # Check benign contextual inquiry
    if is_benign_quotation_or_research(text):
        # Do not flag benign academic questions as active overrides
        return []

    # Check rules against text
    for rule in RULES:
        for pat in rule["patterns"]:
            compiled = re.compile(pat, re.IGNORECASE)
            for m in compiled.finditer(text):
                findings.append(RuleFinding(
                    rule_id=rule["id"],
                    name=rule["name"],
                    category=rule["category"],
                    severity=rule["severity"],
                    description=rule["description"],
                    offset_start=m.start(),
                    offset_end=m.end(),
                    evidence_snippet=text[m.start():m.end()]
                ))

    # Check decoded payloads (Module B output)
    for dec in decoded_payloads:
        for rule in RULES:
            for pat in rule["patterns"]:
                compiled = re.compile(pat, re.IGNORECASE)
                for m in compiled.finditer(dec):
                    findings.append(RuleFinding(
                        rule_id="RULE-ENC-006",
                        name="Decoded Obfuscated Payload Attack",
                        category="encoded_obfuscation",
                        severity="critical",
                        description=f"Decoded payload matches {rule['name']}",
                        offset_start=0,
                        offset_end=len(text),
                        evidence_snippet=f"Decoded [{dec[m.start():m.end()]}]"
                    ))

    return findings
