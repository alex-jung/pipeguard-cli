"""Checks used Actions against a local database of known critical CVEs."""

from __future__ import annotations

import json
from pathlib import Path
from typing import TypedDict

import yaml

from pipeguard.const import SHA_RE, USES_RE
from pipeguard.dataclasses import Finding, Severity

_CVE_DB_PATH = Path(__file__).parent / "cve_db.json"


class CveRecord(TypedDict):
    action: str
    cve_id: str
    description: str
    affected_refs: list[str]  # "all_tags" | specific tag/SHA
    advisory_url: str


def _load_cve_db() -> dict[str, list[CveRecord]]:
    """Load CVE database from the bundled JSON file, keyed by action (lowercase)."""
    records: list[CveRecord] = json.loads(_CVE_DB_PATH.read_text())
    db: dict[str, list[CveRecord]] = {}
    for record in records:
        key = record["action"].lower()
        db.setdefault(key, []).append(record)
    return db


def check_cve(workflow_path: str) -> list[Finding]:
    """Return findings for actions that match known CVEs in the local database."""
    cve_db = _load_cve_db()

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
            m = USES_RE.match(uses)
            if not m:
                continue
            action, ref = m.group("action"), m.group("ref")

            for record in cve_db.get(action.lower(), []):
                is_tag = not SHA_RE.match(ref)
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
                        severity=Severity.ERROR,
                        fix_suggestion=(
                            f"Immediately pin '{action}' to a verified safe SHA. "
                            f"See {record['advisory_url']}"
                        ),
                    )
                )
    return findings
