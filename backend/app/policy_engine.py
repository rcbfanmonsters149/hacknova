"""Module H: Deterministic Policy Engine for PromptShield X.
Applies deterministic rule precedence, evaluates active security policies,
and determines ALLOW / BLOCK / SANITIZE / ESCALATE decisions.
"""

from typing import List, Dict, Any, Optional
from backend.app.evidence import RuleFinding
from backend.app.protected_values import ProtectedValueFinding
from backend.app.storage import get_policies, get_policy_settings

DEFAULT_POLICIES = [
    {
        "id": "POL-001",
        "version": "v2.1",
        "name": "Hard Block: Protected Token Disclosure",
        "category": "data_protection",
        "rule_id": "RULE-SEC-003",
        "action": "BLOCK",
        "priority": 1,
        "is_hard_rule": True,
        "enabled": True,
        "description": "Strictly prohibits any instruction attempting to dump or reveal internal tokens or secret keys."
    },
    {
        "id": "POL-002",
        "version": "v2.1",
        "name": "Hard Block: Unauthorized External Exfiltration",
        "category": "exfiltration_prevention",
        "rule_id": "RULE-EXF-004",
        "action": "BLOCK",
        "priority": 2,
        "is_hard_rule": True,
        "enabled": True,
        "description": "Prohibits instructions requesting outbound data transfers to unauthorized external endpoints."
    },
    {
        "id": "POL-003",
        "version": "v2.1",
        "name": "Hard Block: Security Policy Tampering",
        "category": "governance",
        "rule_id": "RULE-POL-005",
        "action": "BLOCK",
        "priority": 3,
        "is_hard_rule": True,
        "enabled": True,
        "description": "Untrusted content cannot modify, disable, or alter firewall policies."
    },
    {
        "id": "POL-004",
        "version": "v2.1",
        "name": "Block System Authority Impersonation",
        "category": "authority_spoofing",
        "rule_id": "RULE-SYS-002",
        "action": "BLOCK",
        "priority": 4,
        "is_hard_rule": True,
        "enabled": True,
        "description": "Prevents documents or web inputs from claiming system or developer mode authority."
    },
    {
        "id": "POL-005",
        "version": "v2.1",
        "name": "Surgical Sanitization for Salvageable Content",
        "category": "content_cleaning",
        "rule_id": "RULE-OVR-001",
        "action": "SANITIZE",
        "priority": 5,
        "is_hard_rule": False,
        "enabled": True,
        "description": "If an untrusted document contains an isolated injection, remove the offending span and reinspect."
    },
    {
        "id": "POL-006",
        "version": "v2.1",
        "name": "Escalate Uncertain High-Drift / Ambiguous Cases",
        "category": "human_in_the_loop",
        "rule_id": "RULE-AMB-008",
        "action": "ESCALATE",
        "priority": 6,
        "is_hard_rule": False,
        "enabled": True,
        "description": "Holds sensitive or ambiguous instructions for manual reviewer approval before AI execution."
    },
    {
        "id": "POL-007",
        "version": "v2.1",
        "name": "Permit Verified Safe Inquiries",
        "category": "access_control",
        "rule_id": "RULE-ALLOW-009",
        "action": "ALLOW",
        "priority": 10,
        "is_hard_rule": False,
        "enabled": True,
        "description": "Allows legitimate user inquiries that satisfy all security checks."
    }
]

def get_active_policies_list() -> List[Dict[str, Any]]:
    stored = get_policies()
    if stored:
        return stored
    return DEFAULT_POLICIES

def get_active_settings() -> Dict[str, Any]:
    stored = get_policy_settings()
    defaults = {
        "enable_sanitization": True,
        "enable_deep_decoding": True,
        "escalate_uncertain_cases": True,
        "escalate_threshold_drift": 75,
        "policy_version": "v2.1"
    }
    defaults.update(stored)
    return defaults

def evaluate_security_policy(
    rule_findings: List[RuleFinding],
    protected_findings: List[ProtectedValueFinding],
    ml_result: Dict[str, Any],
    intent_result: Dict[str, Any],
    can_sanitize: bool = False,
    is_reinspection: bool = False
) -> Dict[str, Any]:
    settings = get_active_settings()
    triggered_rules = [f.rule_id for f in rule_findings]
    all_findings_snippets = [f.evidence_snippet for f in rule_findings]

    # Precedence 1: Hard Block - Secret Disclosure or Exfiltration
    has_secret_disclosure = any(f.rule_id == "RULE-SEC-003" for f in rule_findings) or any(pf.is_exfiltration_request for pf in protected_findings)
    if has_secret_disclosure:
        return {
            "decision": "BLOCK",
            "triggered_policy": "POL-001 (Hard Block: Protected Token Disclosure)",
            "triggered_rules": list(set(triggered_rules + ["RULE-SEC-003"])),
            "summary_explanation": "Content blocked under strict security policy POL-001: Attempted to expose or exfiltrate protected internal system tokens.",
            "forwarding_permitted": False,
            "policy_version": settings.get("policy_version", "v2.1")
        }

    # Precedence 2: Hard Block - External Exfiltration Request
    has_exfil = any(f.rule_id == "RULE-EXF-004" for f in rule_findings)
    if has_exfil:
        return {
            "decision": "BLOCK",
            "triggered_policy": "POL-002 (Hard Block: Unauthorized External Exfiltration)",
            "triggered_rules": list(set(triggered_rules + ["RULE-EXF-004"])),
            "summary_explanation": "Content blocked under strict security policy POL-002: Requested transmission of data to an unauthorized external endpoint.",
            "forwarding_permitted": False,
            "policy_version": settings.get("policy_version", "v2.1")
        }

    # Precedence 3: Hard Block - Policy Tampering
    has_pol_tamper = any(f.rule_id == "RULE-POL-005" for f in rule_findings)
    if has_pol_tamper:
        return {
            "decision": "BLOCK",
            "triggered_policy": "POL-003 (Hard Block: Security Policy Tampering)",
            "triggered_rules": list(set(triggered_rules + ["RULE-POL-005"])),
            "summary_explanation": "Content blocked under strict security policy POL-003: Untrusted input attempted to modify or disable security gateway policies.",
            "forwarding_permitted": False,
            "policy_version": settings.get("policy_version", "v2.1")
        }

    # Precedence 4: Hard Block - Role Impersonation
    has_role_spoof = any(f.rule_id == "RULE-SYS-002" for f in rule_findings)
    if has_role_spoof:
        return {
            "decision": "BLOCK",
            "triggered_policy": "POL-004 (Block System Authority Impersonation)",
            "triggered_rules": list(set(triggered_rules + ["RULE-SYS-002"])),
            "summary_explanation": "Content blocked under security policy POL-004: Text attempted to spoof system or developer administrative authority.",
            "forwarding_permitted": False,
            "policy_version": settings.get("policy_version", "v2.1")
        }

    # Precedence 5: Surgical Sanitization
    has_override = any(f.rule_id in ["RULE-OVR-001", "RULE-RED-007"] for f in rule_findings)
    if has_override and can_sanitize and settings.get("enable_sanitization", True) and not is_reinspection:
        return {
            "decision": "SANITIZE",
            "triggered_policy": "POL-005 (Surgical Sanitization for Salvageable Content)",
            "triggered_rules": triggered_rules,
            "summary_explanation": "Offending instruction span identified in document. Surgically excised malicious injection while preserving legitimate context.",
            "forwarding_permitted": False,  # Only permitted after reinspection passes!
            "policy_version": settings.get("policy_version", "v2.1")
        }

    # If instruction override could NOT be safely sanitized
    if has_override:
        return {
            "decision": "BLOCK",
            "triggered_policy": "POL-005 (Direct Instruction Override Violation)",
            "triggered_rules": triggered_rules,
            "summary_explanation": "Content blocked under security policy POL-005: Detected unsalvageable direct prompt injection attempting to override assistant instructions.",
            "forwarding_permitted": False,
            "policy_version": settings.get("policy_version", "v2.1")
        }

    # Precedence 6: Escalation (Human Review)
    # Ambiguous administrative instructions, high intent drift, or degraded detector
    is_degraded = ml_result.get("status") == "degraded"
    has_high_drift = intent_result.get("drift_score", 0) >= settings.get("escalate_threshold_drift", 75)
    has_ambiguous_rule = any(f.rule_id == "RULE-AMB-008" for f in rule_findings)

    if (is_degraded or has_high_drift or has_ambiguous_rule) and settings.get("escalate_uncertain_cases", True):
        if has_ambiguous_rule:
            reason = "Sensitive administrative instruction with ambiguous authorization requiring human review"
        elif has_high_drift:
            reason = "Unresolved high intent drift"
        else:
            reason = "ML detector in conservative degraded mode with ambiguous input"
        return {
            "decision": "ESCALATE",
            "triggered_policy": "POL-006 (Escalate Uncertain / High-Drift Cases)",
            "triggered_rules": ["RULE-AMB-008"],
            "summary_explanation": f"Held for human review under policy POL-006: {reason}. Forwarding paused until administrator verification.",
            "forwarding_permitted": False,
            "policy_version": settings.get("policy_version", "v2.1")
        }

    # If any other rule triggered
    if rule_findings:
        return {
            "decision": "BLOCK",
            "triggered_policy": "POL-GEN (General Security Violation)",
            "triggered_rules": triggered_rules,
            "summary_explanation": f"Content blocked due to rule violation: {', '.join(triggered_rules)}.",
            "forwarding_permitted": False,
            "policy_version": settings.get("policy_version", "v2.1")
        }

    # Precedence 7: ALLOW
    return {
        "decision": "ALLOW",
        "triggered_policy": "POL-007 (Permit Verified Safe Inquiries)",
        "triggered_rules": [],
        "summary_explanation": "Content verified safe under policy POL-007: No policy violations, protected token exposure, or unauthorized instructions detected.",
        "forwarding_permitted": True,
        "policy_version": settings.get("policy_version", "v2.1")
    }
