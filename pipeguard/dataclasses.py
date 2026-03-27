"""Shared dataclasses and enums used across all PipeGuard modules."""

from __future__ import annotations

from dataclasses import dataclass
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
    detail: list[str] | None = None    # structured context (Pro: flow path, dep chain, score breakdown)
