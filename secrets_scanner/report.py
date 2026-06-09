"""Renders findings as a console table, CSV, or self-contained HTML report."""

from __future__ import annotations

import csv
import html as _html
import io
from collections import Counter
from datetime import datetime, timezone

from .models import SEVERITY_ORDER, Finding


# ── Console ───────────────────────────────────────────────────────────────────

def to_console(findings: list[Finding], scanned: str = "") -> str:
    loc = f" in {scanned}" if scanned else ""
    if not findings:
        return f"No secrets found{loc}."

    counts = Counter(f.severity for f in findings)
    lines = [
        f"Found {len(findings)} potential secret(s){loc}:",
        f"  critical={counts.get('critical', 0)}  high={counts.get('high', 0)}"
        f"  medium={counts.get('medium', 0)}  low={counts.get('low', 0)}",
        "",
    ]
    headers = ["Severity", "Type", "File", "Line", "Redacted", "Entropy"]
    table = [headers] + [
        [f.severity.upper(), f.secret_type, f.file_path,
         str(f.line_number), f.redacted(), f"{f.entropy:.2f}"]
        for f in findings
    ]
    widths = [max(len(str(r[i])) for r in table) for i in range(len(headers))]
    for idx, row in enumerate(table):
        lines.append(" | ".join(str(c).ljust(widths[j]) for j, c in enumerate(row)))
        if idx == 0:
            lines.append("-+-".join("-" * w for w in widths))
    return "\n".join(lines)


# ── CSV ───────────────────────────────────────────────────────────────────────

def to_csv(findings: list[Finding]) -> str:
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["severity", "type", "file", "line", "redacted",
                "entropy", "commit_hash", "commit_message"])
    for f in findings:
        w.writerow([f.severity, f.secret_type, f.file_path, f.line_number,
                    f.redacted(), f"{f.entropy:.2f}",
                    f.commit_hash or "", f.commit_message or ""])
    return buf.getvalue()


# ── HTML ──────────────────────────────────────────────────────────────────────

_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Secrets Scan Report &mdash; {title}</title>
<style>
  *, *::before, *::after {{ box-sizing: border-box; }}
  body {{
    font-family: -apple-system, "Helvetica Neue", Arial, sans-serif;
    background: #f5f5f7; margin: 0;
    padding: 2.5rem 1.5rem 5rem; color: #1d1d1f;
    -webkit-font-smoothing: antialiased;
  }}
  .container {{ max-width: 1100px; margin: 0 auto; }}
  h1 {{ font-size: 2.2rem; font-weight: 700; letter-spacing: -0.025em; margin: 0 0 0.4rem; }}
  h2 {{
    font-size: 0.72rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.07em; color: #6e6e73; margin: 2.5rem 0 0.8rem;
  }}
  .meta {{ font-size: 0.88rem; color: #6e6e73; margin: 0 0 1.25rem; }}
  .kpis {{ display: flex; gap: 0.75rem; flex-wrap: wrap; margin-bottom: 0.5rem; }}
  .kpi {{
    background: #fff; border-radius: 14px; padding: 1rem 1.5rem; min-width: 130px;
    box-shadow: 0 2px 10px rgba(0,0,0,.06);
  }}
  .kpi .val {{ font-size: 2rem; font-weight: 700; letter-spacing: -0.03em; line-height: 1; }}
  .kpi .lbl {{ font-size: 0.75rem; color: #6e6e73; margin-top: 0.3rem; }}
  .kpi.vc .val {{ color: #ff3b30; }}
  .kpi.vh .val {{ color: #ff6700; }}
  .kpi.vm .val {{ color: #ff9500; }}
  .kpi.vl .val {{ color: #34c759; }}
  .card {{
    background: #fff; border-radius: 18px;
    box-shadow: 0 2px 14px rgba(0,0,0,.06); overflow: hidden; margin-bottom: 1rem;
  }}
  table {{ border-collapse: collapse; width: 100%; font-size: 0.87rem; }}
  th {{
    font-size: 0.7rem; font-weight: 600; text-transform: uppercase;
    letter-spacing: 0.06em; color: #6e6e73; padding: 0.85rem 1.25rem;
    text-align: left; background: #fafafa; border-bottom: 1px solid #f0f0f0;
    white-space: nowrap;
  }}
  td {{ padding: 0.8rem 1.25rem; border-bottom: 1px solid #f5f5f7; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  tr.critical {{ background: rgba(255,59,48,.04); }}
  tr.high     {{ background: rgba(255,103,0,.04); }}
  tr.medium   {{ background: rgba(255,149,0,.03); }}
  .badge {{
    display: inline-block; font-size: 0.68rem; font-weight: 600; letter-spacing: 0.02em;
    padding: 0.18rem 0.65rem; border-radius: 20px; color: #fff; white-space: nowrap;
  }}
  .badge.critical {{ background: #ff3b30; }}
  .badge.high     {{ background: #ff6700; }}
  .badge.medium   {{ background: #ff9500; color: #fff; }}
  .badge.low      {{ background: #34c759; }}
  code {{
    font-family: "SF Mono", Menlo, Monaco, Consolas, monospace;
    font-size: 0.81em; background: #f5f5f7; padding: 0.1em 0.45em; border-radius: 5px;
  }}
  .ent {{ font-size: 0.78rem; color: #6e6e73; }}
  .clean {{
    text-align: center; padding: 3.5rem; color: #34c759;
    font-size: 1.1rem; font-weight: 600; letter-spacing: -0.01em;
  }}
</style>
</head>
<body>
<div class="container">
  <h1>Secrets Scan Report</h1>
  <p class="meta">Target: <code>{title}</code> &middot; Generated {generated} &middot; {summary}</p>

  <div class="kpis">
    <div class="kpi vc"><div class="val">{n_crit}</div><div class="lbl">Critical</div></div>
    <div class="kpi vh"><div class="val">{n_high}</div><div class="lbl">High</div></div>
    <div class="kpi vm"><div class="val">{n_med}</div><div class="lbl">Medium</div></div>
    <div class="kpi vl"><div class="val">{n_low}</div><div class="lbl">Low</div></div>
  </div>

  <h2>Findings</h2>
  <div class="card">{table}</div>
</div>
</body>
</html>
"""

_TABLE_TMPL = (
    "<table><thead><tr>"
    "<th>Severity</th><th>Type</th><th>File</th><th>Line</th>"
    "<th>Redacted Value</th><th>Entropy</th>{git_col}"
    "</tr></thead><tbody>{rows}</tbody></table>"
)


def to_html(findings: list[Finding], target: str = "") -> str:
    counts = Counter(f.severity for f in findings)
    if findings:
        summary = (
            f"{len(findings)} finding(s) &mdash; "
            f"{counts.get('critical', 0)} critical, "
            f"{counts.get('high', 0)} high, "
            f"{counts.get('medium', 0)} medium, "
            f"{counts.get('low', 0)} low"
        )
    else:
        summary = "No secrets detected"

    has_git = any(f.commit_hash for f in findings)
    git_col = "<th>Commit</th>" if has_git else ""

    if not findings:
        table_html = '<div class="clean">&#10003; No secrets detected</div>'
    else:
        rows = []
        for f in findings:
            git_cell = (
                f'<td><code>{_html.escape(f.commit_hash[:8])}</code></td>'
                if has_git else ""
            )
            rows.append(
                f'<tr class="{f.severity}">'
                f'<td><span class="badge {f.severity}">{f.severity.upper()}</span></td>'
                f'<td>{_html.escape(f.secret_type)}</td>'
                f'<td><code>{_html.escape(f.file_path)}</code></td>'
                f'<td>{f.line_number}</td>'
                f'<td><code>{_html.escape(f.redacted())}</code></td>'
                f'<td class="ent">{f.entropy:.2f}</td>'
                f'{git_cell}</tr>'
            )
        table_html = _TABLE_TMPL.format(
            git_col=git_col,
            rows="\n".join(rows),
        )

    return _HTML.format(
        title=_html.escape(target or "unknown"),
        generated=datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        summary=summary,
        n_crit=counts.get("critical", 0),
        n_high=counts.get("high", 0),
        n_med=counts.get("medium", 0),
        n_low=counts.get("low", 0),
        table=table_html,
    )
