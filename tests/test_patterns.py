"""Tests for regex secret patterns."""

import pytest
from secrets_scanner.patterns import SECRET_PATTERNS

_by_name = {p.name: p for p in SECRET_PATTERNS}


def _matches(pattern_name: str, text: str) -> bool:
    return bool(_by_name[pattern_name].regex.search(text))


# ── AWS ──────────────────────────────────────────────────────────────────────

def test_aws_access_key_matches():
    assert _matches("AWS Access Key", "AKIAIOSFODNN7EXAMPLE")

def test_aws_access_key_too_short():
    assert not _matches("AWS Access Key", "AKIA123SHORT")

def test_aws_access_key_wrong_prefix():
    assert not _matches("AWS Access Key", "BKIAIOSFODNN7EXAMPLE")

def test_aws_secret_key_matches():
    line = 'aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"'
    assert _matches("AWS Secret Key", line)


# ── GitHub ────────────────────────────────────────────────────────────────────

def test_github_token_ghp():
    assert _matches("GitHub Token", "ghp_" + "A" * 36)

def test_github_token_gho():
    assert _matches("GitHub Token", "gho_" + "B" * 36)

def test_github_token_ghs():
    assert _matches("GitHub Token", "ghs_" + "C" * 36)

def test_github_token_wrong_prefix():
    assert not _matches("GitHub Token", "ghz_" + "D" * 36)

def test_github_token_too_short():
    assert not _matches("GitHub Token", "ghp_SHORT")


# ── Stripe ────────────────────────────────────────────────────────────────────

def test_stripe_live_key():
    assert _matches("Stripe Live Key", "sk_live_" + "x" * 24)

def test_stripe_test_key():
    assert _matches("Stripe Test Key", "sk_test_" + "y" * 24)

def test_stripe_live_wrong_prefix():
    assert not _matches("Stripe Live Key", "pk_live_" + "z" * 24)


# ── Google ────────────────────────────────────────────────────────────────────

def test_google_api_key():
    assert _matches("Google API Key", "AIza" + "A" * 35)

def test_google_api_key_too_short():
    assert not _matches("Google API Key", "AIzaABCDEF")


# ── Slack ─────────────────────────────────────────────────────────────────────

def test_slack_bot_token():
    assert _matches("Slack Token", "xoxb-1234567890-abcdefghij")

def test_slack_user_token():
    assert _matches("Slack Token", "xoxp-9876543210-zyxwvutsrq")


# ── Private key ───────────────────────────────────────────────────────────────

def test_rsa_private_key():
    assert _matches("Private Key Header", "-----BEGIN RSA PRIVATE KEY-----")

def test_ec_private_key():
    assert _matches("Private Key Header", "-----BEGIN EC PRIVATE KEY-----")

def test_generic_private_key():
    assert _matches("Private Key Header", "-----BEGIN PRIVATE KEY-----")


# ── Passwords ─────────────────────────────────────────────────────────────────

def test_hardcoded_password_equals():
    assert _matches("Hardcoded Password", "password = 'SuperSecret123'")

def test_hardcoded_password_colon():
    assert _matches("Hardcoded Password", "passwd: 'hunter2!!'")

def test_hardcoded_password_too_short():
    assert not _matches("Hardcoded Password", "password = 'abc'")


# ── Database URLs ─────────────────────────────────────────────────────────────

def test_postgres_url():
    assert _matches("Database URL", "postgres://user:pass@localhost:5432/db")

def test_mysql_url():
    assert _matches("Database URL", "mysql://admin:secret@db.example.com/mydb")

def test_mongodb_uri():
    assert _matches("MongoDB URI", "mongodb://user:pass@cluster.mongodb.net/db")


# ── Generic API key ───────────────────────────────────────────────────────────

def test_generic_api_key_single_quotes():
    assert _matches("Generic API Key", "api_key = 'abcdef1234567890abcd'")

def test_generic_api_key_double_quotes():
    assert _matches("Generic API Key", 'apikey = "zyxwvutsrqponmlkjihg"')
