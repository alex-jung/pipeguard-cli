"""Checks used Actions against a local database of known critical CVEs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import TypedDict

import yaml

from pipeguard.scanner.base import Finding

_USES_RE = re.compile(r"^(?P<action>[^@]+)@(?P<ref>.+)$")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


class CveRecord(TypedDict):
    cve_id: str
    description: str
    affected_refs: list[str]  # "all_tags" | specific tag/SHA
    advisory_url: str


# Local CVE database — fully offline, no API calls.
# "all_tags" means any non-SHA ref is considered affected.
# Extend this dict as new advisories are published.
_CVE_DB: dict[str, list[CveRecord]] = {
    "tj-actions/changed-files": [
        {
            "cve_id": "CVE-2025-30066",
            "description": (
                "tj-actions/changed-files was compromised in a supply-chain attack. "
                "All tag-based refs are potentially affected — pin to a known-good SHA."
            ),
            "affected_refs": ["all_tags"],
            "advisory_url": "https://www.cve.org/CVERecord?id=CVE-2025-30066",
        }
    ],
    "reviewdog/action-setup": [
        {
            "cve_id": "CVE-2025-30154",
            "description": (
                "reviewdog/action-setup was compromised in the same supply-chain campaign "
                "as tj-actions/changed-files. Pin to a vetted SHA."
            ),
            "affected_refs": ["all_tags"],
            "advisory_url": "https://www.cve.org/CVERecord?id=CVE-2025-30154",
        }
    ],
}


def check_cve(workflow_path: str) -> list[Finding]:
    """Return findings for actions that match known CVEs in the local database."""
    text = Path(workflow_path).read_text()
    data = yaml.safe_load(text)
    lines = text.splitlines()

    findings: list[Finding] = []
    jobs = data.get("jobs", {}) if isinstance(data, dict) else {}
    for _job_id, job in jobs.items():
        steps = job.get("steps", []) if isinstance(job, dict) else []
        for step in steps:
            uses = step.get("uses", "") if isinstance(step, dict) else ""
            if not uses or uses.startswith("./"):
                continue
            m = _USES_RE.match(uses)
            if not m:
                continue
            action, ref = m.group("action"), m.group("ref")

            for record in _CVE_DB.get(action.lower(), []):
                is_tag = not _SHA_RE.match(ref)
                hit = ("all_tags" in record["affected_refs"] and is_tag) or (
                    ref in record["affected_refs"]
                )
                if not hit:
                    continue

                line_no = next(
                    (i + 1 for i, line in enumerate(lines) if uses in line), 0
                )
                cve_id = record["cve_id"]
                findings.append(
                    Finding(
                        rule=f"cve-{cve_id.lower()}",
                        message=(
                            f"Action '{action}@{ref}' is affected by {cve_id}: "
                            f"{record['description']}"
                        ),
                        file=workflow_path,
                        line=line_no,
                        col=0,
                        severity="error",
                        fix_suggestion=(
                            f"Immediately pin '{action}' to a verified safe SHA. "
                            f"See {record['advisory_url']}"
                        ),
                    )
                )
    return findings
