"""Structured evidence representation for PromptShield X findings."""

from typing import List, Dict, Any

class RuleFinding:
    def __init__(
        self,
        rule_id: str,
        name: str,
        category: str,
        severity: str,  # critical, high, medium, low
        description: str,
        offset_start: int,
        offset_end: int,
        evidence_snippet: str
    ):
        self.rule_id = rule_id
        self.name = name
        self.category = category
        self.severity = severity
        self.description = description
        self.offset_start = offset_start
        self.offset_end = offset_end
        self.evidence_snippet = evidence_snippet

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "name": self.name,
            "category": self.category,
            "severity": self.severity,
            "description": self.description,
            "offset_start": self.offset_start,
            "offset_end": self.offset_end,
            "evidence_snippet": self.evidence_snippet
        }
