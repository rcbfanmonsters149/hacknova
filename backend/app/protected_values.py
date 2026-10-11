"""Module D: Protected-Value and Data-Exfiltration Detection.
Checks for literal, spaced, and encoded matches of configured fictional tokens,
and checks for requests attempting to exfiltrate or disclose them to external destinations.
"""

import json
import os
import re
from typing import List, Dict, Any, Tuple, Optional

CONFIG_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "config",
    "protected_values.json"
)

def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            pass
    return {
        "protected_tokens": [
            {
                "id": "TOKEN-001",
                "name": "Demo Internal Token",
                "value": "DEMO_INTERNAL_TOKEN_4821",
                "category": "authentication"
            }
        ],
        "unauthorized_domains": ["attacker.example", "evil-exfil.net", "webhook.site"],
        "authorized_domains": ["api.company.internal", "safe-analytics.internal"]
    }

class ProtectedValueFinding:
    def __init__(self, token_id: str, token_name: str, match_type: str, offset_start: int, offset_end: int, snippet: str, is_exfiltration_request: bool = False, destination: Optional[str] = None):
        self.token_id = token_id
        self.token_name = token_name
        self.match_type = match_type  # literal, spaced, encoded, disclosure_request
        self.offset_start = offset_start
        self.offset_end = offset_end
        self.snippet = snippet
        self.is_exfiltration_request = is_exfiltration_request
        self.destination = destination

def mask_text(text: str) -> str:
    """Masks protected tokens in text for safe logging and display."""
    config = load_config()
    masked = text
    for token in config.get("protected_tokens", []):
        val = token["value"]
        if val in masked:
            # Mask middle characters: e.g. DEMO_INTERNAL_****_4821
            parts = val.split("_")
            if len(parts) >= 3:
                prefix = "_".join(parts[:-2]) + "_"
                suffix = "_" + parts[-1]
                masked_val = f"{prefix}****{suffix}"
            elif len(val) > 8:
                masked_val = val[:8] + "****" + val[-4:]
            else:
                masked_val = "[MASKED_TOKEN]"
            masked = masked.replace(val, masked_val)
    return masked

def inspect_protected_values(text: str, decoded_payloads: Optional[List[str]] = None) -> List[ProtectedValueFinding]:
    config = load_config()
    findings: List[ProtectedValueFinding] = []
    decoded_payloads = decoded_payloads or []

    # Check for unauthorized destination URLs
    unauthorized_domains = config.get("unauthorized_domains", [])
    found_unauthorized_dest = None
    for domain in unauthorized_domains:
        if domain.lower() in text.lower():
            found_unauthorized_dest = domain
            break

    # Disclosure request keywords
    disclosure_triggers = [
        "reveal", "output", "print", "disclose", "display", "dump",
        "send", "exfiltrate", "forward", "transmit", "post", "leak"
    ]

    for token in config.get("protected_tokens", []):
        val = token["value"]
        val_lower = val.lower()

        # 1. Literal match (case-insensitive) in original text
        pattern = re.compile(re.escape(val), re.IGNORECASE)
        for m in pattern.finditer(text):
            # Check context around token for disclosure/exfiltration keywords
            start_ctx = max(0, m.start() - 60)
            end_ctx = min(len(text), m.end() + 60)
            surrounding = text[start_ctx:end_ctx].lower()

            is_disclosure = any(trigger in surrounding for trigger in disclosure_triggers)
            is_exfil = is_disclosure and (found_unauthorized_dest is not None)

            findings.append(ProtectedValueFinding(
                token_id=token["id"],
                token_name=token["name"],
                match_type="literal",
                offset_start=m.start(),
                offset_end=m.end(),
                snippet=text[m.start():m.end()],
                is_exfiltration_request=is_exfil or is_disclosure,
                destination=found_unauthorized_dest
            ))

        # 2. Check in decoded payloads (e.g. from Base64 or Hex)
        for dec in decoded_payloads:
            if val_lower in dec.lower():
                findings.append(ProtectedValueFinding(
                    token_id=token["id"],
                    token_name=token["name"],
                    match_type="encoded",
                    offset_start=0,
                    offset_end=len(text),
                    snippet=f"[Decoded Payload contains {token['name']}]",
                    is_exfiltration_request=True,
                    destination=found_unauthorized_dest
                ))

        # 3. Spaced match check
        # e.g. "D E M O _ I N T E R N A L"
        letters = list(val.replace("_", ""))
        spaced_regex = r'\b' + r'[\s_]*'.join(re.escape(c) for c in letters) + r'\b'
        try:
            for sm in re.finditer(spaced_regex, text, re.IGNORECASE):
                # Avoid duplicate if it was already matched literally
                if not any(f.offset_start == sm.start() for f in findings):
                    findings.append(ProtectedValueFinding(
                        token_id=token["id"],
                        token_name=token["name"],
                        match_type="spaced",
                        offset_start=sm.start(),
                        offset_end=sm.end(),
                        snippet=text[sm.start():sm.end()],
                        is_exfiltration_request=True,
                        destination=found_unauthorized_dest
                    ))
        except Exception:
            pass

    return findings
