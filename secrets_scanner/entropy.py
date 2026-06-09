from __future__ import annotations
import math
import re

# Matches quoted string literals long enough to be interesting
_STRING_RE = re.compile(r"""['"]([^'"\\]{12,})['"]""")

# Characters typical in non-secret strings (lower weight)
_COMMON = set(" \t.,;:!?-_()[]{}abcdefghijklmnopqrstuvwxyz")


def shannon_entropy(text: str) -> float:
    """Return Shannon entropy in bits per character (0.0 for empty string)."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def high_entropy_strings(
    line: str,
    min_length: int = 16,
    threshold: float = 4.5,
) -> list[str]:
    """Return quoted string literals that look like high-entropy secrets."""
    results: list[str] = []
    for m in _STRING_RE.finditer(line):
        s = m.group(1)
        if len(s) < min_length:
            continue
        # Skip strings that are mostly plain English / URLs / paths
        if s.startswith(("http://", "https://", "/", "./")):
            continue
        lower_ratio = sum(1 for c in s if c in _COMMON) / len(s)
        if lower_ratio > 0.7:
            continue
        if shannon_entropy(s) >= threshold:
            results.append(s)
    return results
