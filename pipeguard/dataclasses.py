"""Shared dataclasses and enums used across all PipeGuard modules."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum


class Severity(StrEnum):
    ERROR = "error"
    WARNING = "warning"
    INFO = "info"


@dataclass
class Finding:
    rule: str
    message: str
    file: str
    line: int
    col: int
    severity: Severity = Severity.ERROR
    fix_suggestion: str | None = None  # human-readable hint (Free + Pro)
    patch: str | None = None           # machine-applicable YAML fix (Pro: SHA-Pinning, Permissions)
    score: int | None = None           # numeric score 0–100 (Pro: Trust Score, CVSS)
    detail: list[str] | None = None    # structured context (Pro: flow path, dep chain, score)
    id: str = field(default="", init=True)

    def __post_init__(self) -> None:
        if not self.id:
            raw = f"{self.rule}:{self.line}:{self.message}"
            self.id = hashlib.sha256(raw.encode()).hexdigest()[:12]
