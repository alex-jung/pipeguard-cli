"""Base types shared across all scanner modules and platforms."""

from __future__ import annotations

from abc import ABC, abstractmethod

from pipeguard.dataclasses import Finding  # noqa: F401  re-exported for compat


class BaseScanner(ABC):
    @abstractmethod
    def check(self, workflow_path: str) -> list[Finding]:
        """Run this scanner against a single workflow file."""
        ...
