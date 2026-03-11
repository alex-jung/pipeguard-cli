"""Checks whether third-party Actions are pinned to a full commit SHA."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from pipeguard.scanner.actionlint_runner import Finding

# Matches "owner/repo@ref" in `uses:` lines.
_USES_RE = re.compile(r"^(?P<action>[^@]+)@(?P<ref>.+)$")
# A full SHA is 40 hex chars.
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def check_sha_pinning(workflow_path: str) -> list[Finding]:
    """Return a finding for every action that is not pinned to a full commit SHA."""
    text = Path(workflow_path).read_text()
    data = yaml.safe_load(text)

    findings: list[Finding] = []
    lines = text.splitlines()

    jobs = data.get("jobs", {}) if isinstance(data, dict) else {}
    for _job_id, job in jobs.items():
        steps = job.get("steps", []) if isinstance(job, dict) else []
        for step in steps:
            uses = step.get("uses", "") if isinstance(step, dict) else ""
            if not uses:
                continue
            m = _USES_RE.match(uses)
            if not m:
                continue
            action, ref = m.group("action"), m.group("ref")
            if action.startswith("./"):
                continue  # local action — skip
            if _SHA_RE.match(ref):
                continue  # already pinned

            # Find the line number of this `uses:` entry.
            line_no = next(
                (i + 1 for i, line in enumerate(lines) if uses in line),
                0,
            )
            findings.append(
                Finding(
                    rule="sha-pinning",
                    message=f"Action '{action}' is pinned to '{ref}' instead of a full commit SHA. "
                    "This is a supply-chain risk (cf. CVE-2025-30066).",
                    file=workflow_path,
                    line=line_no,
                    col=0,
                    severity="error",
                    fix_suggestion=f"Pin to a specific commit SHA: uses: {action}@<sha>  # {ref}",
                )
            )
    return findings
