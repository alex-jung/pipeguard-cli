"""License key resolution and Pro API communication."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import TYPE_CHECKING

import requests

from pipeguard.const import API_TIMEOUT, CREDENTIALS_FILE, DEFAULT_API_URL
from pipeguard.dataclasses import Finding, Severity

if TYPE_CHECKING:
    from pipeguard.config import PipeGuardConfig


def resolve_license_key() -> str | None:
    """Return license key from env var or ~/.pipeguard/credentials."""
    if key := os.environ.get("PIPEGUARD_LICENSE_KEY"):
        return key
    if CREDENTIALS_FILE.is_file():
        try:
            data = json.loads(CREDENTIALS_FILE.read_text())
            return data.get("license_key") or None
        except (json.JSONDecodeError, OSError):
            return None
    return None


def save_license_key(key: str) -> None:
    """Persist license key to ~/.pipeguard/credentials."""
    CREDENTIALS_FILE.parent.mkdir(parents=True, exist_ok=True)
    CREDENTIALS_FILE.write_text(json.dumps({"license_key": key}))


def _serialize_config(config: PipeGuardConfig | None) -> dict[str, object]:
    """Serialize scanner config for the Pro API request body.

    Only fields that differ from their defaults are included so the payload
    stays minimal and the backend can apply its own defaults for anything
    that is not present.
    """
    if config is None:
        return {}
    scanners: dict[str, object] = {}
    for name, sc in config.scanners.items():
        entry: dict[str, object] = {}
        if sc.skip:
            entry["skip"] = True
        if hasattr(sc, "trusted_publishers") and sc.trusted_publishers:
            entry["trusted_publishers"] = sc.trusted_publishers
        if hasattr(sc, "trusted_actions") and sc.trusted_actions:
            entry["trusted_actions"] = sc.trusted_actions
        if hasattr(sc, "min_cvss") and sc.min_cvss != 9.0:
            entry["min_cvss"] = sc.min_cvss
        if entry:
            scanners[name] = entry
    return {"scanners": scanners} if scanners else {}


def call_pro_api(
    workflow_path: str,
    key: str,
    config: PipeGuardConfig | None = None,
    api_url: str | None = None,
    verbose: bool = False,
) -> list[Finding] | None:
    """Send workflow to Pro backend. Returns findings or None on error.

    None means the call failed (network, invalid key, etc.) — caller decides
    whether to warn the user or silently skip Pro features.
    """
    api_url = api_url or os.environ.get("PIPEGUARD_API_URL", DEFAULT_API_URL)
    try:
        workflow_yaml = Path(workflow_path).read_text()
    except OSError:
        return None

    try:
        resp = requests.post(
            f"{api_url}/v1/analyze",
            headers={"Authorization": f"Bearer {key}"},
            json={
                "workflow": workflow_yaml,
                "config": _serialize_config(config),
            },
            timeout=API_TIMEOUT,
        )
    except requests.RequestException:
        return None

    if verbose:
        print(  # noqa: T201
            f"[pipeguard] Pro API response ({resp.status_code}):\n"
            + json.dumps(resp.json(), indent=2),
            file=sys.stderr,
        )

    if resp.status_code == 401:
        raise InvalidLicenseKeyError(resp.json().get("error", "Invalid license key."))

    if not resp.ok:
        return None

    return [
        Finding(
            rule=f.get("rule", ""),
            message=f.get("message", ""),
            severity=Severity(f.get("severity", Severity.INFO)),
            file=workflow_path,
            line=f.get("line") or 0,
            col=f.get("col") or 0,
            fix_suggestion=f.get("fix_suggestion"),
            patch=f.get("patch"),
            score=f.get("score"),
            detail=f.get("detail"),
            id=f.get("id", ""),
        )
        for f in resp.json().get("findings", [])
    ]


class InvalidLicenseKeyError(Exception):
    pass
