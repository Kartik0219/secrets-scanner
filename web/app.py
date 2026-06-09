"""Flask web frontend for the secrets scanner."""

from __future__ import annotations

import os
import zipfile
from collections import Counter
from pathlib import Path
import tempfile

from flask import Flask, jsonify, render_template, request

from secrets_scanner import scan_directory, scan_file

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 2 * 1024 * 1024  # 2 MB hard limit

_ALLOWED_EXTS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".rb", ".go", ".java", ".php",
    ".cs", ".cpp", ".c", ".h", ".sh", ".bash", ".zsh",
    ".env", ".yaml", ".yml", ".json", ".toml", ".ini", ".cfg", ".conf",
    ".txt", ".md", ".pem", ".key",
}
_ZIP_MAX_FILES = 150


@app.route("/")
def index():
    return render_template("index.html")


@app.route("/scan", methods=["POST"])
def scan():
    code   = request.form.get("code", "").strip()
    upload = request.files.get("file")

    if not code and (not upload or not upload.filename):
        return jsonify({"error": "Provide code to paste or a file to upload."}), 400

    findings = []
    label    = ""

    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)

        if code:
            target = root / "paste.py"
            target.write_text(code, encoding="utf-8")
            findings = scan_file(target)
            label = "pasted code"
            for f in findings:
                f.file_path = "paste"

        else:
            name = Path(upload.filename).name
            ext  = Path(name).suffix.lower()
            dest = root / name
            upload.save(dest)
            label = name

            if ext == ".zip":
                out = root / "src"
                out.mkdir()
                with zipfile.ZipFile(dest) as z:
                    members = [m for m in z.namelist() if not m.endswith("/")]
                    if len(members) > _ZIP_MAX_FILES:
                        return jsonify({"error": f"ZIP exceeds {_ZIP_MAX_FILES}-file limit."}), 400
                    z.extractall(out)
                findings = scan_directory(out)
                for f in findings:
                    try:
                        f.file_path = os.path.relpath(f.file_path, str(out))
                    except ValueError:
                        pass
            elif ext in _ALLOWED_EXTS:
                findings = scan_file(dest)
                for f in findings:
                    f.file_path = name
            else:
                return jsonify({"error": f"Unsupported file type '{ext}'."}), 400

    counts = Counter(f.severity for f in findings)
    return jsonify({
        "scanned": label,
        "total":   len(findings),
        "counts": {
            "critical": counts.get("critical", 0),
            "high":     counts.get("high",     0),
            "medium":   counts.get("medium",   0),
            "low":      counts.get("low",      0),
        },
        "findings": [
            {
                "severity": f.severity,
                "type":     f.secret_type,
                "file":     f.file_path,
                "line":     f.line_number,
                "redacted": f.redacted(),
                "entropy":  round(f.entropy, 2),
            }
            for f in findings
        ],
    })


if __name__ == "__main__":
    app.run(debug=True)
