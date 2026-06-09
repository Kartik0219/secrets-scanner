"""Generate a sample secrets scan report from realistic fake credentials.

Secrets are constructed at runtime from parts so no literal secret strings
exist in this source file (which would trigger GitHub push protection).
"""

from __future__ import annotations

import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from secrets_scanner import scan_directory
from secrets_scanner.report import to_console, to_html


def _s(*parts: str) -> str:
    """Join parts at runtime — avoids literal secret strings in source."""
    return "".join(parts)


def _build_sample_files() -> dict[str, str]:
    """Return filename → content mapping with fake-but-pattern-matching values."""

    # Constructed at runtime so no scanner (including GitHub) flags this file.
    aws_key       = _s("AKIA", "IOSFODNN7EXAMPLE")
    aws_secret    = _s("wJalrXUtnFEM", "I/K7MDENG/bPxRfiCYEXAMPLEKEY")
    github_token  = _s("ghp_", "A" * 36)
    stripe_live   = _s("sk_live_", "X" * 28)
    stripe_test   = _s("sk_test_", "Y" * 28)
    slack_token   = _s("xoxb-", "1234567890-9876543210-abcdefghijklmnop")
    google_key    = _s("AIza", "SyD-9tSrke72I6e0H3IwPmx5GqKzwqK8aBc")

    return {
        "config/aws.py": (
            "# AWS configuration — DEMO ONLY, all values are fake\n"
            f'AWS_ACCESS_KEY_ID     = "{aws_key}"\n'
            f'aws_secret_key = "{aws_secret}"\n'
            'AWS_REGION = "us-east-1"\n'
        ),
        ".env": (
            "# Environment variables — DEMO ONLY\n"
            f"GITHUB_TOKEN={github_token}\n"
            "DATABASE_URL=postgres://admin:hunter2secret@db.prod.example.com/appdb\n"
            f"STRIPE_SECRET={stripe_live}\n"
        ),
        "app/payments.py": (
            "import stripe\n\n"
            "# TODO: move to environment variable\n"
            f'stripe.api_key = "{stripe_test}"\n\n'
            "def charge(amount, token):\n"
            "    return stripe.Charge.create(amount=amount, source=token)\n"
        ),
        "scripts/deploy.sh": (
            "#!/bin/bash\n"
            "# Deployment script — DEMO ONLY\n"
            f'SLACK_TOKEN="{slack_token}"\n'
            f'GOOGLE_KEY="{google_key}"\n'
            'echo "Deploying..."\n'
        ),
        "app/legacy_client.py": (
            "# Legacy integration — high-entropy string, no known pattern\n"
            "class LegacyClient:\n"
            f'    _auth = "{aws_secret}+extra/data="\n\n'
            "    def connect(self): pass\n"
        ),
        "app/database.py": (
            "import psycopg2\n\n"
            "# Hardcoded for local dev — never commit to production!\n"
            "conn = psycopg2.connect(\n"
            '    host="localhost", database="myapp", user="admin",\n'
            "    password=\"Sup3rS3cr3tP@ssw0rd\"\n"
            ")\n"
        ),
    }


def main() -> None:
    out_html = Path(__file__).parent / "sample_report.html"
    sample_files = _build_sample_files()

    with tempfile.TemporaryDirectory() as tmpdir:
        root = Path(tmpdir)

        for rel, content in sample_files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text(content, encoding="utf-8")

        findings = scan_directory(root)
        for f in findings:
            f.file_path = os.path.relpath(f.file_path, tmpdir)

        print(to_console(findings, "sample/"))
        print()

        out_html.write_text(to_html(findings, "sample/"), encoding="utf-8")
        print(f"HTML report written to: {out_html}")


if __name__ == "__main__":
    main()
