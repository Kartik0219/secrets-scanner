"""File-system and git-history secret scanner."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

from .entropy import high_entropy_strings, shannon_entropy
from .models import Finding
from .patterns import SECRET_PATTERNS

_TEXT_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java", ".php",
    ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".zsh",
    ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".env", ".properties", ".xml", ".html", ".tf", ".tfvars",
    ".pem", ".key", ".txt", ".md",
}
_SKIP_DIRS = {
    ".git", "__pycache__", "node_modules", ".venv", "venv", "env",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache",
}
_MAX_FILE_BYTES = 512 * 1024


def _should_scan(path: Path) -> bool:
    try:
        if path.stat().st_size > _MAX_FILE_BYTES:
            return False
    except OSError:
        return False
    return path.suffix.lower() in _TEXT_EXTS or path.name.startswith(".env")


def _scan_lines(
    lines: list[str],
    file_path: str,
    commit_hash: str | None = None,
    commit_message: str | None = None,
) -> list[Finding]:
    findings: list[Finding] = []

    for lineno, line in enumerate(lines, 1):
        matched_spans: list[tuple[int, int]] = []

        for pat in SECRET_PATTERNS:
            for m in pat.regex.finditer(line):
                matched_spans.append((m.start(), m.end()))
                findings.append(Finding(
                    file_path=file_path,
                    line_number=lineno,
                    secret_type=pat.name,
                    matched_text=m.group(0),
                    raw_line=line.rstrip(),
                    entropy=shannon_entropy(m.group(0)),
                    severity=pat.severity,
                    commit_hash=commit_hash,
                    commit_message=commit_message,
                ))

        # Entropy-based detection for unknown secret formats
        for s in high_entropy_strings(line):
            # Skip if already caught by a pattern match
            s_start = line.find(s)
            already = any(
                s_start >= span[0] and s_start + len(s) <= span[1]
                for span in matched_spans
            )
            if not already:
                findings.append(Finding(
                    file_path=file_path,
                    line_number=lineno,
                    secret_type="High-Entropy String",
                    matched_text=s,
                    raw_line=line.rstrip(),
                    entropy=shannon_entropy(s),
                    severity="medium",
                    commit_hash=commit_hash,
                    commit_message=commit_message,
                ))

    return findings


def scan_file(path: Path) -> list[Finding]:
    """Scan a single file for secrets."""
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except (OSError, PermissionError):
        return []
    return _scan_lines(text.splitlines(), str(path))


def scan_directory(root: Path) -> list[Finding]:
    """Recursively scan all text files under root for secrets."""
    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _SKIP_DIRS]
        for name in filenames:
            p = Path(dirpath) / name
            if _should_scan(p):
                findings.extend(scan_file(p))
    return sorted(findings, key=lambda f: f.sort_key)


def scan_git_history(repo: Path) -> list[Finding]:
    """Scan added lines across all commits in the git history for secrets."""
    try:
        result = subprocess.run(
            [
                "git", "log", "--all", "--full-diff", "-p",
                "--format=COMMIT:%H %s",
                "--diff-filter=A",
            ],
            cwd=repo,
            capture_output=True,
            text=True,
            timeout=120,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    findings: list[Finding] = []
    current_hash: str | None = None
    current_msg: str | None = None
    current_file: str | None = None

    for line in result.stdout.splitlines():
        if line.startswith("COMMIT:"):
            parts = line[7:].split(" ", 1)
            current_hash = parts[0]
            current_msg = parts[1] if len(parts) > 1 else ""
        elif line.startswith("+++ b/"):
            current_file = line[6:]
        elif line.startswith("+") and not line.startswith("+++") and current_file:
            added_line = line[1:]
            hits = _scan_lines([added_line], current_file, current_hash, current_msg)
            findings.extend(hits)

    return sorted(findings, key=lambda f: f.sort_key)
