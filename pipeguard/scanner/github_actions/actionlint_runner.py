"""Runs actionlint as a subprocess and wraps its output as PipeGuard findings."""

from __future__ import annotations

import json
import subprocess

from pipeguard.dataclasses import Finding, Severity
from pipeguard.scanner.base import BaseScanner


def run_actionlint(workflow_path: str) -> list[Finding]:
    """Run actionlint on *workflow_path* and return findings.

    Returns an empty list if actionlint is not installed — fail loud via a
    warning, but do not block other checks.
    """
    try:
        result = subprocess.run(
            ["actionlint", "-format", "{{json .}}", workflow_path],
            capture_output=True,
            text=True,
        )
    except FileNotFoundError:
        print("[pipeguard] WARNING: actionlint not found. Install it for full analysis.")
        return []

    if not result.stdout.strip():
        return []

    raw: list[dict[str, int | str]] = json.loads(result.stdout)
    findings: list[Finding] = []
    for item in raw:
        findings.append(
            Finding(
                rule=str(item.get("kind", "actionlint")),
                message=str(item.get("message", "")),
                file=str(item.get("filepath", workflow_path)),
                line=int(item.get("line", 0)),
                col=int(item.get("column", 0)),
                severity=Severity.ERROR,
            )
        )
    return findings


class ActionlintScanner(BaseScanner):
    def check(self, workflow_path: str) -> list[Finding]:
        return run_actionlint(workflow_path)
