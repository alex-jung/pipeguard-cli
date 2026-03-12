"""Checks whether third-party Actions and reusable workflows are pinned to a full commit SHA."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from pipeguard.scanner.base import Finding

# Matches "owner/repo[@ref]" in `uses:` lines.
_USES_RE = re.compile(r"^(?P<action>[^@]+)@(?P<ref>.+)$")
# A full SHA is 40 hex chars.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def check_sha_pinning(workflow_path: str) -> list[Finding]:
    """Return findings for actions or reusable workflows not pinned to a full commit SHA."""
    text = Path(workflow_path).read_text()
    data = yaml.safe_load(text)

    findings: list[Finding] = []
    lines = text.splitlines()

    jobs = data.get("jobs", {}) if isinstance(data, dict) else {}
    for _job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue

        # ── Reusable workflow call (jobs.<id>.uses) ──────────────────────────
        job_uses = job.get("uses", "")
        if job_uses:
            findings += _check_uses(job_uses, lines, workflow_path, reusable=True)

        # ── Step-level actions (jobs.<id>.steps[].uses) ───────────────────────
        for step in job.get("steps", []) or []:
            step_uses = step.get("uses", "") if isinstance(step, dict) else ""
            if step_uses:
                findings += _check_uses(step_uses, lines, workflow_path, reusable=False)

    return findings


def _check_uses(
    uses: str,
    lines: list[str],
    workflow_path: str,
    *,
    reusable: bool,
) -> list[Finding]:
    if uses.startswith("./"):
        return []  # local action / local reusable workflow — skip

    m = _USES_RE.match(uses)
    if not m:
        return []

    action, ref = m.group("action"), m.group("ref")
    if _SHA_RE.match(ref):
        return []  # already pinned

    line_no = next((i + 1 for i, line in enumerate(lines) if uses in line), 0)

    if reusable:
        rule = "sha-pinning-reusable"
        message = (
            f"Reusable workflow '{action}' is called with ref '{ref}' "
            "instead of a full commit SHA — supply-chain risk."
        )
        fix = f"Pin to a specific commit SHA: uses: {action}@<sha>  # {ref}"
    else:
        rule = "sha-pinning"
        message = (
            f"Action '{action}' is pinned to '{ref}' instead of a full commit SHA. "
            "This is a supply-chain risk (cf. CVE-2025-30066)."
        )
        fix = f"Pin to a specific commit SHA: uses: {action}@<sha>  # {ref}"

    return [
        Finding(
            rule=rule,
            message=message,
            file=workflow_path,
            line=line_no,
            col=0,
            severity="error",
            fix_suggestion=fix,
        )
    ]
