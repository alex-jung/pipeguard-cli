"""Applies auto-fixes by calling the PipeGuard Pro API backend."""

from __future__ import annotations

import os
from pathlib import Path
from typing import TYPE_CHECKING

import requests

if TYPE_CHECKING:
    from pipeguard.dataclasses import Finding

from pipeguard.const import API_TIMEOUT, DEFAULT_API_URL


def apply_fixes(
    findings: list[Finding],
    workflow_path: str,
    license_key: str,
    api_url: str | None = None,
) -> tuple[int, int]:
    """Request auto-fixes from the Pro API and write the patched file.

    Returns (applied, skipped) counts.
    """
    api_url = api_url or os.environ.get("PIPEGUARD_API_URL", DEFAULT_API_URL)

    try:
        workflow_yaml = Path(workflow_path).read_text()
    except OSError:
        return 0, 0

    try:
        resp = requests.post(
            f"{api_url}/v1/fix",
            headers={"Authorization": f"Bearer {license_key}"},
            json={
                "workflow": workflow_yaml,
                "findings": [
                    {"rule": f.rule, "line": f.line, "col": f.col}
                    for f in findings
                    if f.fix_suggestion
                ],
            },
            timeout=API_TIMEOUT,
        )
    except requests.RequestException:
        return 0, 0

    if not resp.ok:
        return 0, 0

    data = resp.json()
    patched: str | None = data.get("patched_workflow")
    applied: int = data.get("applied", 0)
    skipped: int = data.get("skipped", 0)

    if patched and patched != workflow_yaml:
        Path(workflow_path).write_text(patched)

    return applied, skipped
