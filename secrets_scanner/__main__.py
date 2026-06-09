"""CLI entry point: python -m secrets_scanner <path> [options]"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .scanner import scan_directory, scan_file, scan_git_history
from .report import to_console, to_csv, to_html


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="python -m secrets_scanner",
        description="Scan files or git history for hardcoded secrets.",
    )
    parser.add_argument("path", help="File or directory to scan")
    parser.add_argument(
        "--git", action="store_true",
        help="Also scan full git commit history (requires git)",
    )
    parser.add_argument("--html", metavar="FILE", help="Write HTML report to FILE")
    parser.add_argument("--csv", metavar="FILE", help="Write CSV report to FILE")
    args = parser.parse_args()

    target = Path(args.path)
    if not target.exists():
        print(f"error: path not found: {target}", file=sys.stderr)
        sys.exit(2)

    findings = scan_directory(target) if target.is_dir() else scan_file(target)

    if args.git and target.is_dir():
        git_findings = scan_git_history(target)
        findings = sorted(findings + git_findings, key=lambda f: f.sort_key)

    print(to_console(findings, str(target)))

    if args.html:
        out = Path(args.html)
        out.write_text(to_html(findings, str(target)), encoding="utf-8")
        print(f"\nHTML report: {out}")

    if args.csv:
        out = Path(args.csv)
        out.write_text(to_csv(findings), encoding="utf-8")
        print(f"CSV  report: {out}")

    sys.exit(1 if findings else 0)


main()
