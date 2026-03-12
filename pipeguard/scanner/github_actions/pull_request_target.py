"""Detects dangerous pull_request_target trigger configurations."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from pipeguard.scanner.base import Finding

# Expressions that reference the PR contributor's code in a checkout ref.
_HEAD_REF_PATTERNS = [
    re.compile(r"github\.event\.pull_request\.head\.(ref|sha)"),
    re.compile(r"github\.head_ref"),
]


def _uses_head_ref(value: str) -> bool:
    return any(p.search(value) for p in _HEAD_REF_PATTERNS)


def _has_pwn_request(jobs: dict[str, object]) -> bool:
    """Return True if any job checks out untrusted PR head code."""
    for job in jobs.values():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            uses = step.get("uses", "") or ""
            if not uses.startswith("actions/checkout"):
                continue
            with_block = step.get("with", {}) or {}
            ref = str(with_block.get("ref", ""))
            if _uses_head_ref(ref):
                return True
    return False


def check_pull_request_target(workflow_path: str) -> list[Finding]:
    """Return findings for dangerous pull_request_target configurations."""
    text = Path(workflow_path).read_text()
    data = yaml.safe_load(text)

    if not isinstance(data, dict):
        return []

    on = data.get("on") or data.get(True)  # YAML parses bare 'on' as True
    if not on:
        return []

    # Normalise: "on: pull_request_target" or "on: [pull_request_target, ...]"
    if isinstance(on, str):
        triggers: list[str] = [on]
    elif isinstance(on, list):
        triggers = [str(t) for t in on]
    elif isinstance(on, dict):
        triggers = list(on.keys())
    else:
        return []

    if "pull_request_target" not in triggers:
        return []

    lines = text.splitlines()
    line_no = next((i + 1 for i, line in enumerate(lines) if "pull_request_target" in line), 1)
    jobs = data.get("jobs") or {}

    if _has_pwn_request(jobs):
        return [
            Finding(
                rule="pull-request-target-pwn",
                message=(
                    "Workflow uses 'pull_request_target' and checks out the PR head ref. "
                    "This allows untrusted code from a fork to run with repository write "
                    "permissions and access to secrets (Pwn Request)."
                ),
                file=workflow_path,
                line=line_no,
                col=0,
                severity="error",
                fix_suggestion=(
                    "Never check out 'github.event.pull_request.head.ref' or "
                    "'github.head_ref' in a pull_request_target workflow. "
                    "Use 'pull_request' instead, or add an environment with required reviewers."
                ),
            )
        ]

    return [
        Finding(
            rule="pull-request-target",
            message=(
                "'pull_request_target' runs with write permissions of the base repository "
                "and has access to secrets — even for PRs from forks."
            ),
            file=workflow_path,
            line=line_no,
            col=0,
            severity="warning",
            fix_suggestion=(
                "Avoid 'pull_request_target' unless required. If needed, never check out "
                "PR head code, and use an environment with required reviewers "
                "to gate secret access."
            ),
        )
    ]
