"""Builds a dependency graph of Actions and assigns a basic trust score."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

import yaml

from pipeguard.config import SupplyChainScannerConfig
from pipeguard.const import TRUSTED_PUBLISHERS, USES_RE
from pipeguard.dataclasses import Finding, Severity
from pipeguard.scanner.base import BaseScanner


@dataclass
class ActionNode:
    action: str
    ref: str
    trusted: bool


def _is_trusted(action: str, config: SupplyChainScannerConfig | None = None) -> bool:
    if any(action.startswith(prefix) for prefix in TRUSTED_PUBLISHERS):
        return True
    if config is None:
        return False
    if any(action.startswith(prefix) for prefix in config.trusted_publishers):
        return True
    if action in config.trusted_actions:
        return True
    return False


def build_dependency_graph(
    workflow_path: str, config: SupplyChainScannerConfig | None = None
) -> list[ActionNode]:
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
            m = USES_RE.match(uses)
            if not m:
                continue
            action, ref = m.group("action"), m.group("ref")
            nodes.append(ActionNode(action=action, ref=ref, trusted=_is_trusted(action, config)))
    return nodes


def check_supply_chain(
    workflow_path: str, config: SupplyChainScannerConfig | None = None
) -> list[Finding]:
    """Return findings for untrusted third-party actions."""
    text = Path(workflow_path).read_text()
    lines = text.splitlines()

    findings: list[Finding] = []
    for node in build_dependency_graph(workflow_path, config):
        if not node.trusted:
            uses_str = f"{node.action}@{node.ref}"
            line_no = next(
                (i + 1 for i, line in enumerate(lines) if uses_str in line),
                0,
            )
            findings.append(
                Finding(
                    rule="supply-chain",
                    message=f"Untrusted action '{node.action}' — verify publisher and pin to a SHA.",  # noqa: E501
                    file=workflow_path,
                    line=line_no,
                    col=0,
                    severity=Severity.WARNING,
                    fix_suggestion=f"Review {node.action} and pin: uses: {node.action}@<sha>  # {node.ref}",  # noqa: E501
                )
            )
    return findings


class SupplyChainScanner(BaseScanner):
    def __init__(self, config: SupplyChainScannerConfig | None = None) -> None:
        self.config = config or SupplyChainScannerConfig()

    def check(self, workflow_path: str) -> list[Finding]:
        assert isinstance(self.config, SupplyChainScannerConfig)
        return check_supply_chain(workflow_path, self.config)
