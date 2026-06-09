from __future__ import annotations
from dataclasses import dataclass

SEVERITY_ORDER = ["critical", "high", "medium", "low"]


@dataclass
class Finding:
    file_path: str
    line_number: int
    secret_type: str
    matched_text: str
    raw_line: str
    entropy: float
    severity: str
    commit_hash: str | None = None
    commit_message: str | None = None

    def redacted(self) -> str:
        t = self.matched_text
        if len(t) <= 6:
            return "****"
        return t[:4] + "*" * min(len(t) - 4, 24)

    @property
    def sort_key(self) -> tuple:
        order = {s: i for i, s in enumerate(SEVERITY_ORDER)}
        return (order.get(self.severity, 99), self.file_path, self.line_number)
