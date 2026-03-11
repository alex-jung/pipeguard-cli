"""Tracks secrets through workflow steps and flags potential leaks."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from pipeguard.scanner.base import Finding

# Patterns that suggest a secret value is being echoed or logged.
_LEAK_PATTERNS = [
    re.compile(r"echo\s+\$\{\{\s*secrets\.", re.IGNORECASE),
    re.compile(r"echo\s+\$[A-Z_]+_TOKEN", re.IGNORECASE),
    re.compile(r"curl\s+.*-H\s+['\"]Authorization", re.IGNORECASE),
]


def check_secrets_flow(workflow_path: str) -> list[Finding]:
    """Return findings for steps that may leak secrets to the log."""
    text = Path(workflow_path).read_text()
    data = yaml.safe_load(text)
    lines = text.splitlines()

    findings: list[Finding] = []
    jobs = data.get("jobs", {}) if isinstance(data, dict) else {}
    for _job_id, job in jobs.items():
        steps = job.get("steps", []) if isinstance(job, dict) else []
        for step in steps:
            run_block = step.get("run", "") if isinstance(step, dict) else ""
            if not run_block:
                continue
            for pattern in _LEAK_PATTERNS:
                if pattern.search(run_block):
                    snippet = run_block.splitlines()[0]
                    line_no = next(
                        (i + 1 for i, line in enumerate(lines) if snippet in line),
                        0,
                    )
                    findings.append(
                        Finding(
                            rule="secrets-leak",
                            message="Potential secret leak: a secret value may be printed to the log.",  # noqa: E501
                            file=workflow_path,
                            line=line_no,
                            col=0,
                            severity="error",
                            fix_suggestion="Use add-mask or avoid echoing secret values directly.",
                        )
                    )
                    break  # one finding per step is enough
    return findings
