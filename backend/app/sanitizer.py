"""Module I: Surgical Sanitization with Mandatory Reinspection.
Removes validated offending spans from text, preserving legitimate surrounding context,
and enforces a full reinspection pass.
"""

from typing import List, Tuple, Optional
from backend.app.evidence import RuleFinding

def surgical_sanitize(text: str, findings: List[RuleFinding]) -> Tuple[Optional[str], str]:
    """Attempts to remove offending spans cleanly. Returns (sanitized_text, reason)."""
    if not findings:
        return text, "No offending findings to sanitize"

    # Filter out findings with invalid offsets
    valid_spans = []
    for f in findings:
        if 0 <= f.offset_start < f.offset_end <= len(text):
            valid_spans.append((f.offset_start, f.offset_end))

    if not valid_spans:
        return None, "Offsets could not be mapped to original text reliably"

    # Merge overlapping spans
    valid_spans.sort(key=lambda x: x[0])
    merged_spans = []
    curr_start, curr_end = valid_spans[0]

    for s, e in valid_spans[1:]:
        if s <= curr_end:
            curr_end = max(curr_end, e)
        else:
            merged_spans.append((curr_start, curr_end))
            curr_start, curr_end = s, e
    merged_spans.append((curr_start, curr_end))

    # Calculate total offending length vs total text length
    offending_len = sum(e - s for s, e in merged_spans)
    remaining_len = len(text) - offending_len

    # If the attack constitutes nearly the entire input, sanitization is destructive
    if remaining_len < 10 or (remaining_len / len(text)) < 0.15:
        return None, "Destructive sanitization: Legitimate content is insufficient to salvage"

    # Excise the offending spans
    sanitized_parts = []
    last_idx = 0
    for s, e in merged_spans:
        sanitized_parts.append(text[last_idx:s])
        last_idx = e
    sanitized_parts.append(text[last_idx:])

    sanitized_text = "".join(sanitized_parts).strip()
    # Clean up excess spaces or dangling punctuation
    import re
    sanitized_text = re.sub(r' {2,}', ' ', sanitized_text)
    sanitized_text = re.sub(r'\n{3,}', '\n\n', sanitized_text)
    sanitized_text = re.sub(r'\.\s*\.', '.', sanitized_text)
    sanitized_text = re.sub(r'\s+\.', '.', sanitized_text)

    return sanitized_text, "Surgically removed validated offending span"
