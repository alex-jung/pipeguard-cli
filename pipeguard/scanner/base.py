"""Base types shared across all scanner modules and platforms."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class Finding:
    rule: str
    message: str
    file: str
    line: int
    col: int
    severity: str = "error"  # "error" | "warning" | "info"
    fix_suggestion: str | None = None


class BaseScanner(ABC):
    @abstractmethod
    def check(self, workflow_path: str) -> list[Finding]:
        """Run this scanner against a single workflow file."""
        ...
