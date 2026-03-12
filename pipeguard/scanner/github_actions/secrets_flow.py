"""Tracks secrets through workflow steps and flags potential leaks."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from pipeguard.scanner.base import Finding

# Patterns that suggest a secret value is being echoed or logged.
_LEAK_PATTERNS = [
    re.compile(r"echo\s+\$\{\{\s*secrets\.", re.IGNORECASE),
    re.compile(r"echo\s+\$[A-Z_]+_TOKEN", re.IGNORECASE),
    re.compile(r"curl\s+.*-H\s+['\"]Authorization", re.IGNORECASE),
]

# Patterns that enable bash/sh debug mode (prints every expanded command).
_SET_X_PATTERNS = [
    re.compile(r"set\s+-[a-z]*x", re.IGNORECASE),   # set -x, set -ex, set -euxo pipefail …
    re.compile(r"set\s+-o\s+xtrace", re.IGNORECASE),  # set -o xtrace
    re.compile(r"#!.*sh\b.*-[a-z]*x", re.IGNORECASE), # #!/bin/bash -x shebang
]

_SECRETS_REF = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)


def _env_has_secrets(env: object) -> bool:
    """Return True if an env mapping references any secret."""
    if not isinstance(env, dict):
        return False
    return any(_SECRETS_REF.search(str(v)) for v in env.values())


def _has_set_x(run_block: str) -> bool:
    return any(p.search(run_block) for p in _SET_X_PATTERNS)


def check_secrets_flow(workflow_path: str) -> list[Finding]:
    """Return findings for steps that may leak secrets to the log."""
    text = Path(workflow_path).read_text()
    data = yaml.safe_load(text)
    lines = text.splitlines()

    findings: list[Finding] = []
    jobs = data.get("jobs", {}) if isinstance(data, dict) else {}
    for _job_id, job in jobs.items():
        steps = job.get("steps", []) if isinstance(job, dict) else []
        for step in steps:
            run_block = step.get("run", "") if isinstance(step, dict) else ""
            if not run_block:
                continue
            for pattern in _LEAK_PATTERNS:
                if pattern.search(run_block):
                    snippet = run_block.splitlines()[0]
                    line_no = next(
                        (i + 1 for i, line in enumerate(lines) if snippet in line),
                        0,
                    )
                    findings.append(
                        Finding(
                            rule="secrets-leak",
                            message="Potential secret leak: a secret value may be printed to the log.",  # noqa: E501
                            file=workflow_path,
                            line=line_no,
                            col=0,
                            severity="error",
                            fix_suggestion="Use add-mask or avoid echoing secret values directly.",
                        )
                    )
                    break  # one finding per step is enough

    findings += check_debug_leak(workflow_path, data, lines)
    return findings


def check_debug_leak(
    workflow_path: str,
    data: object,
    lines: list[str],
) -> list[Finding]:
    """Flag run: steps using set -x when secrets are accessible in env."""
    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []
    workflow_env = data.get("env") or {}
    jobs = data.get("jobs") or {}

    for _job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_env = job.get("env") or {}
        steps = job.get("steps") or []

        for step in steps:
            if not isinstance(step, dict):
                continue
            run_block = step.get("run", "") or ""
            if not run_block or not _has_set_x(run_block):
                continue

            step_env = step.get("env") or {}
            secrets_in_scope = (
                _env_has_secrets(step_env)
                or _env_has_secrets(job_env)
                or _env_has_secrets(workflow_env)
            )

            snippet = run_block.splitlines()[0]
            line_no = next(
                (i + 1 for i, line in enumerate(lines) if snippet in line), 0
            )

            if secrets_in_scope:
                findings.append(
                    Finding(
                        rule="secrets-leak-debug",
                        message=(
                            "'set -x' enables shell debug mode — every command and its "
                            "expanded arguments are printed to the log. "
                            "Secrets in env will be exposed in plain text."
                        ),
                        file=workflow_path,
                        line=line_no,
                        col=0,
                        severity="error",
                        fix_suggestion=(
                            "Remove 'set -x' or add "
                            "\"echo '::add-mask::$SECRET_NAME'\" before enabling debug mode."
                        ),
                    )
                )
            else:
                findings.append(
                    Finding(
                        rule="secrets-leak-debug",
                        message=(
                            "'set -x' enables shell debug mode — every command and its "
                            "expanded arguments are printed to the log. "
                            "GITHUB_TOKEN and other implicit credentials may be exposed."
                        ),
                        file=workflow_path,
                        line=line_no,
                        col=0,
                        severity="warning",
                        fix_suggestion=(
                            "Avoid 'set -x' in CI run steps. "
                            "Use 'set -euo pipefail' for strict mode without debug output."
                        ),
                    )
                )

    return findings
