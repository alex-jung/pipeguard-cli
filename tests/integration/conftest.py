"""Shared helpers for integration tests."""

from __future__ import annotations

import json


def parse_json_output(output: str) -> list[dict]:
    """Extract the JSON array from CLI output.

    The output may contain banner or warning lines before the JSON
    (e.g. 'actionlint not found' or 'Pro license active').
    Finds the first line that is a bare '[' (start of a JSON array).
    """
    lines = output.splitlines()
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped == "[" or stripped.startswith("[{"):
            return json.loads("\n".join(lines[i:]))
    return json.loads(output)


def parse_sarif_output(output: str) -> dict:
    """Extract the SARIF object from CLI output (strips any banner lines)."""
    lines = output.splitlines()
    for i, line in enumerate(lines):
        if line.strip().startswith("{"):
            return json.loads("\n".join(lines[i:]))
    return json.loads(output)
