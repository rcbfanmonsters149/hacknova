"""Module B: Text Normalization and Obfuscation Detection.
Handles Unicode NFKC normalization, whitespace collapsing, spaced secret detection,
and bounded strict Base64 / Hexadecimal decoding.
"""

import re
import base64
import unicodedata
from typing import List, Dict, Any, Tuple

# Regex to detect plausible base64 strings (minimum length 16, valid characters, optional padding)
BASE64_PATTERN = re.compile(r'\b[A-Za-z0-9+/]{16,}={0,2}\b')

# Regex to detect plausible hex strings (minimum 16 hex chars)
HEX_PATTERN = re.compile(r'\b(?:0x)?([0-9a-fA-F]{16,})\b')

# Regex for spaced tokens like "D E M O _ I N T E R N A L"
SPACED_LETTERS_PATTERN = re.compile(r'\b(?:[A-Za-z0-9_]\s+){4,}[A-Za-z0-9_]\b')

MAX_DECODE_PAYLOAD_LEN = 10000

class NormalizationResult:
    def __init__(self, original_text: str):
        self.original_text: str = original_text
        self.normalized_text: str = original_text
        self.transformations_applied: List[str] = []
        self.decoded_payloads: List[str] = []

def normalize_text(text: str, max_depth: int = 2) -> NormalizationResult:
    result = NormalizationResult(text)
    current = text

    # 1. Unicode NFKC Normalization
    nfkc_text = unicodedata.normalize("NFKC", current)
    if nfkc_text != current:
        result.transformations_applied.append("unicode_nfkc_normalization")
        current = nfkc_text

    # 2. Whitespace Normalization (collapsing repeated spaces and non-standard whitespace)
    clean_whitespace = re.sub(r'[\r\t\f\v]+', ' ', current)
    clean_whitespace = re.sub(r' {2,}', ' ', clean_whitespace)
    if clean_whitespace != current:
        result.transformations_applied.append("whitespace_collapse")
        current = clean_whitespace

    # 3. Detect & collapse spaced letter sequences (e.g. "D E M O _ I N T E R N A L")
    def collapse_spaced(match):
        matched_str = match.group(0)
        collapsed = re.sub(r'\s+', '', matched_str)
        return collapsed

    if SPACED_LETTERS_PATTERN.search(current):
        collapsed_text = SPACED_LETTERS_PATTERN.sub(collapse_spaced, current)
        if collapsed_text != current:
            result.transformations_applied.append("spaced_characters_reconstructed")
            current = collapsed_text

    # 4. Strict Base64 Decoding (Bounded)
    b64_matches = BASE64_PATTERN.findall(text)
    for candidate in b64_matches:
        if len(candidate) > MAX_DECODE_PAYLOAD_LEN:
            continue
        try:
            # Add padding if needed
            padded = candidate + '=' * ((4 - len(candidate) % 4) % 4)
            decoded_bytes = base64.b64decode(padded, validate=True)
            # Check if printable UTF-8
            decoded_str = decoded_bytes.decode('utf-8')
            # Verify decoded string contains mostly printable ASCII or letters
            if len(decoded_str) >= 4 and all(c.isprintable() or c in '\n\r\t' for c in decoded_str):
                result.decoded_payloads.append(decoded_str)
                result.transformations_applied.append(f"base64_decoded: '{candidate[:12]}...'")
        except Exception:
            pass

    # 5. Hexadecimal Decoding (Bounded)
    hex_matches = HEX_PATTERN.findall(text)
    for candidate in hex_matches:
        if len(candidate) % 2 != 0 or len(candidate) > MAX_DECODE_PAYLOAD_LEN:
            continue
        try:
            decoded_bytes = bytes.fromhex(candidate)
            decoded_str = decoded_bytes.decode('utf-8')
            if len(decoded_str) >= 4 and all(c.isprintable() or c in '\n\r\t' for c in decoded_str):
                result.decoded_payloads.append(decoded_str)
                result.transformations_applied.append(f"hex_decoded: '{candidate[:12]}...'")
        except Exception:
            pass

    result.normalized_text = current
    return result
