"""Tests for Shannon entropy and high-entropy string detection."""

import math
import pytest
from secrets_scanner.entropy import shannon_entropy, high_entropy_strings


# ── shannon_entropy ───────────────────────────────────────────────────────────

def test_entropy_empty_string():
    assert shannon_entropy("") == 0.0

def test_entropy_single_char():
    # All same characters → entropy = 0
    assert shannon_entropy("aaaaaaaaaa") == pytest.approx(0.0)

def test_entropy_two_equal_chars():
    # "ab" repeated → max entropy for 2 symbols = 1.0 bit
    assert shannon_entropy("ababababab") == pytest.approx(1.0)

def test_entropy_uniform_ascii():
    # 256 distinct chars each once → log2(256) = 8.0
    text = "".join(chr(i) for i in range(256))
    assert shannon_entropy(text) == pytest.approx(8.0)

def test_entropy_high_for_random_base64():
    # A random-looking base64 string should be high entropy
    s = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    assert shannon_entropy(s) > 4.0

def test_entropy_low_for_plain_text():
    assert shannon_entropy("hello world") < 4.0

def test_entropy_known_value():
    # "ab" → -0.5*log2(0.5) - 0.5*log2(0.5) = 1.0
    assert shannon_entropy("ab") == pytest.approx(1.0)


# ── high_entropy_strings ──────────────────────────────────────────────────────

def test_high_entropy_detects_secret_like_string():
    line = 'token = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    found = high_entropy_strings(line)
    assert len(found) == 1
    assert "wJalrXUtnFEMI" in found[0]

def test_high_entropy_ignores_short_strings():
    # Under min_length → not flagged
    line = 'key = "ShortKey"'
    assert high_entropy_strings(line) == []

def test_high_entropy_ignores_plain_english():
    line = 'description = "This is a normal sentence with low entropy value here"'
    assert high_entropy_strings(line) == []

def test_high_entropy_ignores_urls():
    line = 'endpoint = "https://api.example.com/v1/data"'
    assert high_entropy_strings(line) == []

def test_high_entropy_multiple_on_same_line():
    s1 = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    s2 = "AbCdEfGhIjKlMnOpQrStUvWxYz0123456789ABCDE"
    line = f'a = "{s1}" b = "{s2}"'
    found = high_entropy_strings(line)
    assert len(found) == 2

def test_high_entropy_ignores_path_like_strings():
    line = 'path = "/usr/local/bin/python3"'
    assert high_entropy_strings(line) == []
