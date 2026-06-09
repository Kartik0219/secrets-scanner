from __future__ import annotations
import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Pattern:
    name: str
    regex: re.Pattern
    severity: str
    description: str


# fmt: off
_RAW: list[tuple[str, str, str, str]] = [
    ("AWS Access Key",
     r"AKIA[0-9A-Z]{16}",
     "critical", "AWS IAM access key identifier"),

    ("AWS Secret Key",
     r"(?i)aws.{0,20}secret.{0,20}['\"][0-9a-zA-Z/+]{40}['\"]",
     "critical", "AWS IAM secret access key"),

    ("GitHub Token",
     r"gh[pousr]_[0-9a-zA-Z]{36}",
     "critical", "GitHub personal/OAuth access token"),

    ("GitHub Fine-Grained Token",
     r"github_pat_[0-9a-zA-Z_]{82}",
     "critical", "GitHub fine-grained personal access token"),

    ("Private Key Header",
     r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
     "critical", "PEM-encoded private key block"),

    ("Stripe Live Key",
     r"sk_live_[0-9a-zA-Z]{24,}",
     "critical", "Stripe live secret key"),

    ("JWT Token",
     r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}",
     "high", "JSON Web Token"),

    ("Stripe Test Key",
     r"sk_test_[0-9a-zA-Z]{24,}",
     "high", "Stripe test secret key"),

    ("Slack Token",
     r"xox[baprs]-[0-9a-zA-Z\-]{10,}",
     "high", "Slack API token"),

    ("Google API Key",
     r"AIza[0-9A-Za-z\-_]{35}",
     "high", "Google Cloud / Firebase API key"),

    ("Twilio SID",
     r"\bAC[0-9a-fA-F]{32}\b",
     "high", "Twilio account SID"),

    ("Twilio Auth Token",
     r"\bSK[0-9a-fA-F]{32}\b",
     "high", "Twilio auth token"),

    ("SendGrid Key",
     r"SG\.[0-9a-zA-Z\-_]{22}\.[0-9a-zA-Z\-_]{43}",
     "high", "SendGrid API key"),

    ("MongoDB URI",
     r"mongodb(?:\+srv)?://[^:\s]+:[^@\s]+@",
     "high", "MongoDB connection string with credentials"),

    ("Database URL",
     r"(?i)(?:postgres|mysql|redis)://[^:\s]+:[^@\s]+@",
     "high", "Database connection string with credentials"),

    ("Hardcoded Password",
     r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"][^'\"]{6,}['\"]",
     "medium", "Hardcoded password in assignment"),

    ("Generic API Key",
     r"(?i)(?:api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['\"][0-9a-zA-Z\-_]{16,}['\"]",
     "medium", "Generic API key assignment"),

    ("Bearer Token",
     r"(?i)Bearer\s+[0-9a-zA-Z\-_\.]{20,}",
     "medium", "HTTP Bearer token in source"),
]
# fmt: on

SECRET_PATTERNS: list[Pattern] = [
    Pattern(name=n, regex=re.compile(p), severity=s, description=d)
    for n, p, s, d in _RAW
]
