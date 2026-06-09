"""Tests for report generation (console, CSV, HTML)."""

import csv
import io
import pytest
from secrets_scanner.models import Finding
from secrets_scanner.report import to_console, to_csv, to_html


def _finding(**kwargs) -> Finding:
    defaults = dict(
        file_path="app/config.py", line_number=42,
        secret_type="AWS Access Key", matched_text="AKIAIOSFODNN7EXAMPLE",
        raw_line='AWS_KEY = "AKIAIOSFODNN7EXAMPLE"',
        entropy=3.58, severity="critical",
    )
    defaults.update(kwargs)
    return Finding(**defaults)


# ── to_console ────────────────────────────────────────────────────────────────

def test_console_empty():
    out = to_console([])
    assert "No secrets found" in out

def test_console_empty_with_target():
    out = to_console([], scanned="/my/repo")
    assert "/my/repo" in out

def test_console_shows_count(capsys):
    findings = [_finding(), _finding(severity="high", secret_type="GitHub Token")]
    out = to_console(findings)
    assert "2 potential secret(s)" in out

def test_console_shows_severity_counts():
    findings = [_finding(severity="critical"), _finding(severity="medium", secret_type="X")]
    out = to_console(findings)
    assert "critical=1" in out
    assert "medium=1" in out

def test_console_redacts_secret():
    f = _finding(matched_text="AKIAIOSFODNN7EXAMPLE")
    out = to_console([f])
    assert "AKIAIOSFODNN7EXAMPLE" not in out
    assert "AKIA" in out  # first 4 chars shown


# ── to_csv ────────────────────────────────────────────────────────────────────

def test_csv_empty_has_header_only():
    out = to_csv([])
    rows = list(csv.reader(io.StringIO(out)))
    assert len(rows) == 1
    assert rows[0][0] == "severity"

def test_csv_one_finding():
    f = _finding()
    out = to_csv([f])
    rows = list(csv.reader(io.StringIO(out)))
    assert len(rows) == 2
    assert rows[1][0] == "critical"
    assert rows[1][2] == "app/config.py"

def test_csv_redacts_secret():
    f = _finding(matched_text="AKIAIOSFODNN7EXAMPLE")
    out = to_csv([f])
    assert "AKIAIOSFODNN7EXAMPLE" not in out

def test_csv_entropy_formatted():
    f = _finding(entropy=4.1234)
    out = to_csv([f])
    assert "4.12" in out


# ── to_html ───────────────────────────────────────────────────────────────────

def test_html_empty_shows_clean_message():
    out = to_html([])
    assert "No secrets detected" in out
    assert "<!DOCTYPE html>" in out

def test_html_contains_finding_type():
    f = _finding(secret_type="AWS Access Key")
    out = to_html([f], target="/repo")
    assert "AWS Access Key" in out

def test_html_redacts_in_output():
    f = _finding(matched_text="AKIAIOSFODNN7EXAMPLE")
    out = to_html([f])
    assert "AKIAIOSFODNN7EXAMPLE" not in out

def test_html_severity_kpi_counts():
    findings = [
        _finding(severity="critical"),
        _finding(severity="critical"),
        _finding(severity="high", secret_type="X"),
    ]
    out = to_html(findings)
    assert "2</div>" in out  # two criticals

def test_html_includes_target():
    out = to_html([], target="/my/project")
    assert "/my/project" in out

def test_html_git_column_when_present():
    f = _finding(commit_hash="abc123def456", commit_message="init")
    out = to_html([f])
    assert "Commit" in out
    assert "abc123d" in out  # first 8 chars

def test_html_no_git_column_when_absent():
    f = _finding()
    out = to_html([f])
    assert "<th>Commit</th>" not in out
