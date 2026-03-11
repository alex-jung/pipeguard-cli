"""Runs actionlint as a subprocess and wraps its output as PipeGuard findings."""

from __future__ import annotations

import json
import subprocess
from dataclasses import dataclass


@dataclass
class Finding:
    rule: str
    message: str
    file: str
    line: int
    col: int
    severity: str = "error"
    fix_suggestion: str | None = None


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
        # actionlint not installed — warn but continue
        print("[pipeguard] WARNING: actionlint not found. Install it for full analysis.")
        return []

    if not result.stdout.strip():
        return []

    raw: list[dict] = json.loads(result.stdout)
    findings: list[Finding] = []
    for item in raw:
        findings.append(
            Finding(
                rule=item.get("kind", "actionlint"),
                message=item.get("message", ""),
                file=item.get("filepath", workflow_path),
                line=item.get("line", 0),
                col=item.get("column", 0),
                severity="error",
            )
        )
    return findings
