"""Lists all third-party Actions used in a workflow as an inventory."""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

import yaml

from pipeguard.scanner.base import Finding

_USES_RE = re.compile(r"^(?P<action>[^@]+)@(?P<ref>.+)$")


def check_action_inventory(workflow_path: str) -> list[Finding]:
    """Return one info-level finding per unique third-party action used."""
    text = Path(workflow_path).read_text()
    data = yaml.safe_load(text)
    lines = text.splitlines()

    # action_slug -> list of (ref, line_no)
    inventory: dict[str, list[tuple[str, int]]] = defaultdict(list)

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
            line_no = next(
                (i + 1 for i, line in enumerate(lines) if uses in line), 0
            )
            inventory[action].append((ref, line_no))

    findings: list[Finding] = []
    for action, occurrences in sorted(inventory.items()):
        refs = sorted({ref for ref, _ in occurrences})
        first_line = occurrences[0][1]
        findings.append(
            Finding(
                rule="action-inventory",
                message=(
                    f"Action '{action}' used with ref(s): "
                    + ", ".join(f"'{r}'" for r in refs)
                    + f" ({len(occurrences)} occurrence(s))."
                ),
                file=workflow_path,
                line=first_line,
                col=0,
                severity="info",
            )
        )
    return findings
