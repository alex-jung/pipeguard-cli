"""Builds a dependency graph of Actions and assigns a basic trust score."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

import yaml

from pipeguard.scanner.actionlint_runner import Finding

# Well-known trusted publisher prefixes (allowlist seed).
_TRUSTED_PUBLISHERS = {"actions/", "github/", "docker/"}

_USES_RE = re.compile(r"^(?P<action>[^@]+)@(?P<ref>.+)$")


@dataclass
class ActionNode:
    action: str
    ref: str
    trusted: bool


def _is_trusted(action: str) -> bool:
    return any(action.startswith(prefix) for prefix in _TRUSTED_PUBLISHERS)


def build_dependency_graph(workflow_path: str) -> list[ActionNode]:
    """Return all third-party actions used in the workflow."""
    text = Path(workflow_path).read_text()
    data = yaml.safe_load(text)

    nodes: list[ActionNode] = []
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
            nodes.append(ActionNode(action=action, ref=ref, trusted=_is_trusted(action)))
    return nodes


def check_supply_chain(workflow_path: str) -> list[Finding]:
    """Return findings for untrusted third-party actions."""
    text = Path(workflow_path).read_text()
    lines = text.splitlines()

    findings: list[Finding] = []
    for node in build_dependency_graph(workflow_path):
        if not node.trusted:
            uses_str = f"{node.action}@{node.ref}"
            line_no = next(
                (i + 1 for i, l in enumerate(lines) if uses_str in l),
                0,
            )
            findings.append(
                Finding(
                    rule="supply-chain",
                    message=f"Untrusted action '{node.action}' — verify publisher and pin to a SHA.",
                    file=workflow_path,
                    line=line_no,
                    col=0,
                    severity="warning",
                    fix_suggestion=f"Review {node.action} and pin: uses: {node.action}@<sha>  # {node.ref}",
                )
            )
    return findings
