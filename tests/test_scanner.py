"""Tests for file and directory scanning."""

import pytest
from pathlib import Path
from secrets_scanner.scanner import scan_file, scan_directory


@pytest.fixture
def tmp_py(tmp_path):
    """Return a helper that writes a .py file and returns its Path."""
    def _make(name: str, content: str) -> Path:
        p = tmp_path / name
        p.write_text(content, encoding="utf-8")
        return p
    return _make


# ── scan_file ─────────────────────────────────────────────────────────────────

def test_scan_file_finds_aws_key(tmp_py):
    f = tmp_py("cfg.py", 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n')
    findings = scan_file(f)
    assert any(fi.secret_type == "AWS Access Key" for fi in findings)

def test_scan_file_finds_github_token(tmp_py):
    token = "ghp_" + "A" * 36
    f = tmp_py("auth.py", f'TOKEN = "{token}"\n')
    findings = scan_file(f)
    assert any(fi.secret_type == "GitHub Token" for fi in findings)

def test_scan_file_finds_stripe_live(tmp_py):
    key = "sk_live_" + "x" * 24
    f = tmp_py("payments.py", f'STRIPE_KEY = "{key}"\n')
    findings = scan_file(f)
    assert any(fi.secret_type == "Stripe Live Key" for fi in findings)

def test_scan_file_finds_private_key_header(tmp_py):
    f = tmp_py("key.pem", "-----BEGIN RSA PRIVATE KEY-----\nMIIEo...\n")
    findings = scan_file(f)
    assert any(fi.secret_type == "Private Key Header" for fi in findings)

def test_scan_file_finds_hardcoded_password(tmp_py):
    f = tmp_py("db.py", "password = 'SuperSecret123!'\n")
    findings = scan_file(f)
    assert any(fi.secret_type == "Hardcoded Password" for fi in findings)

def test_scan_file_finds_postgres_url(tmp_py):
    f = tmp_py("settings.py", 'DB = "postgres://admin:pass123@db.host/mydb"\n')
    findings = scan_file(f)
    assert any(fi.secret_type == "Database URL" for fi in findings)

def test_scan_file_clean_file_returns_empty(tmp_py):
    f = tmp_py("clean.py", "x = 1\nprint('hello')\n")
    assert scan_file(f) == []

def test_scan_file_records_correct_line_number(tmp_py):
    f = tmp_py("multi.py", "# comment\n# another\nAWS_KEY = 'AKIAIOSFODNN7EXAMPLE'\n")
    findings = scan_file(f)
    aws = [fi for fi in findings if fi.secret_type == "AWS Access Key"]
    assert aws and aws[0].line_number == 3

def test_scan_file_redacts_matched_text(tmp_py):
    key = "sk_live_" + "z" * 24
    f = tmp_py("pay.py", f'KEY = "{key}"\n')
    findings = scan_file(f)
    stripe = [fi for fi in findings if fi.secret_type == "Stripe Live Key"]
    assert stripe
    redacted = stripe[0].redacted()
    assert key not in redacted
    assert redacted.startswith("sk_l")

def test_scan_file_nonexistent_returns_empty():
    assert scan_file(Path("/nonexistent/file.py")) == []

def test_scan_file_high_entropy_detected(tmp_py):
    secret = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    f = tmp_py("misc.py", f'custom_token = "{secret}"\n')
    findings = scan_file(f)
    assert any(fi.secret_type == "High-Entropy String" for fi in findings)


# ── scan_directory ────────────────────────────────────────────────────────────

def test_scan_directory_finds_secrets_in_nested_file(tmp_path):
    sub = tmp_path / "config"
    sub.mkdir()
    (sub / "secrets.py").write_text(
        'API_KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
    )
    findings = scan_directory(tmp_path)
    assert any(fi.secret_type == "AWS Access Key" for fi in findings)

def test_scan_directory_skips_venv(tmp_path):
    venv = tmp_path / ".venv" / "lib"
    venv.mkdir(parents=True)
    (venv / "leaked.py").write_text(
        'KEY = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8"
    )
    findings = scan_directory(tmp_path)
    # .venv should be skipped, nothing found
    assert findings == []

def test_scan_directory_multiple_files(tmp_path):
    (tmp_path / "a.py").write_text('k = "AKIAIOSFODNN7EXAMPLE"\n', encoding="utf-8")
    (tmp_path / "b.py").write_text("x = 1\n", encoding="utf-8")
    (tmp_path / "c.env").write_text(
        "GITHUB_TOKEN=ghp_" + "B" * 36 + "\n", encoding="utf-8"
    )
    findings = scan_directory(tmp_path)
    types = {f.secret_type for f in findings}
    assert "AWS Access Key" in types
    assert "GitHub Token" in types

def test_scan_directory_sorted_by_severity(tmp_path):
    (tmp_path / "x.py").write_text(
        'pw = "password=hello123"\n'
        'key = "AKIAIOSFODNN7EXAMPLE"\n',
        encoding="utf-8",
    )
    findings = scan_directory(tmp_path)
    severities = [f.severity for f in findings]
    # critical should come before medium
    if "critical" in severities and "medium" in severities:
        assert severities.index("critical") < severities.index("medium")
