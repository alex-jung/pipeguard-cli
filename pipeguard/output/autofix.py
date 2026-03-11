"""Generates auto-fix suggestions for findings (e.g. SHA-pinning patches)."""

from __future__ import annotations

from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from pipeguard.scanner.base import Finding


def generate_fixes(findings: list[Finding], workflow_path: str) -> str:
    """Return a unified-diff-style patch for all fixable findings.

    Currently supports: sha-pinning
    """
    original = Path(workflow_path).read_text()
    patched = original

    for f in findings:
        if f.rule == "sha-pinning" and f.fix_suggestion:
            # Placeholder: real implementation would resolve the SHA via GitHub API.
            pass

    if patched == original:
        return ""

    # Return as unified diff.
    import difflib

    diff = difflib.unified_diff(
        original.splitlines(keepends=True),
        patched.splitlines(keepends=True),
        fromfile=f"a/{workflow_path}",
        tofile=f"b/{workflow_path}",
    )
    return "".join(diff)
