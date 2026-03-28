"""Detects over-provisioned permissions in GitHub Actions workflows."""

from __future__ import annotations

from pathlib import Path

import yaml

from pipeguard.const import (
    IMPLICIT_PERMISSIONS_MESSAGE,
    OIDC_ACTIONS,
    SENSITIVE_SCOPES,
    VALID_PERMISSION_LEVELS,
)
from pipeguard.dataclasses import Finding, Severity


def check_permissions(workflow_path: str) -> list[Finding]:
    """Return findings for permission over-provisioning."""
    text = Path(workflow_path).read_text()
    data = yaml.safe_load(text)
    lines = text.splitlines()

    if not isinstance(data, dict):
        return []

    findings: list[Finding] = []

    if "permissions" not in data:
        findings.append(
            Finding(
                rule="permissions-missing",
                message=IMPLICIT_PERMISSIONS_MESSAGE,
                file=workflow_path,
                line=1,
                col=0,
                severity=Severity.ERROR,
                fix_suggestion="Add 'permissions: read-all' at the top level, then grant only what each job needs.",  # noqa: E501
            )
        )
        return findings

    top_perms = data["permissions"]

    if top_perms == "write-all":
        findings.append(
            Finding(
                rule="permissions-write-all",
                message="'permissions: write-all' grants write access to every scope — severe over-provisioning.",  # noqa: E501
                file=workflow_path,
                line=_find_line(lines, "write-all"),
                col=0,
                severity=Severity.ERROR,
                fix_suggestion="Replace with 'permissions: read-all' and add write scopes only where needed.",  # noqa: E501
            )
        )
        return findings

    if isinstance(top_perms, dict):
        findings += _check_scope_dict(top_perms, workflow_path, lines, context="top-level")

    findings += _check_id_token_write(top_perms, data.get("jobs") or {}, workflow_path, lines)

    for job_id, job in (data.get("jobs") or {}).items():
        if not isinstance(job, dict):
            continue
        job_perms = job.get("permissions")
        if job_perms is None:
            continue
        if job_perms == "write-all":
            findings.append(
                Finding(
                    rule="permissions-write-all",
                    message=f"Job '{job_id}' uses 'permissions: write-all'.",
                    file=workflow_path,
                    line=_find_line(lines, "write-all"),
                    col=0,
                    severity=Severity.ERROR,
                    fix_suggestion=f"Scope job '{job_id}' permissions to only what it needs.",
                )
            )
        elif isinstance(job_perms, dict):
            findings += _check_scope_dict(
                job_perms, workflow_path, lines, context=f"job '{job_id}'"
            )

    return findings


def _check_scope_dict(
    perms: dict[str, str],
    workflow_path: str,
    lines: list[str],
    context: str,
) -> list[Finding]:
    findings: list[Finding] = []
    for scope, level in perms.items():
        if level not in VALID_PERMISSION_LEVELS:
            findings.append(
                Finding(
                    rule="permissions-invalid",
                    message=f"Unknown permission level '{level}' for scope '{scope}' in {context}.",
                    file=workflow_path,
                    line=_find_line(lines, scope),
                    col=0,
                    severity=Severity.ERROR,
                    fix_suggestion="Use one of: read, write, none.",
                )
            )
            continue

        if level == "write" and scope in SENSITIVE_SCOPES:
            findings.append(
                Finding(
                    rule="permissions-excessive",
                    message=f"Scope '{scope}' is set to 'write' in {context} — rarely needed, high risk.",  # noqa: E501
                    file=workflow_path,
                    line=_find_line(lines, scope),
                    col=0,
                    severity=Severity.WARNING,
                    fix_suggestion=f"Set '{scope}: read' or '{scope}: none' unless write access is explicitly required.",  # noqa: E501
                )
            )
    return findings


def _steps_use_oidc(steps: list[object]) -> bool:
    """Return True if any step uses a known OIDC-consuming action."""
    for step in steps:
        uses = step.get("uses", "") if isinstance(step, dict) else ""
        if uses:
            action = uses.split("@")[0].lower()
            if action in OIDC_ACTIONS:
                return True
    return False


def _check_id_token_write(
    top_perms: object,
    jobs: dict[str, object],
    workflow_path: str,
    lines: list[str],
) -> list[Finding]:
    """Flag id-token: write when no OIDC action is present in the relevant scope."""
    findings: list[Finding] = []

    # Top-level id-token: write — check all jobs for OIDC usage.
    if isinstance(top_perms, dict) and top_perms.get("id-token") == "write":
        all_steps: list[object] = []
        for job in jobs.values():
            if isinstance(job, dict):
                all_steps.extend(job.get("steps", []) or [])
        if not _steps_use_oidc(all_steps):
            findings.append(
                Finding(
                    rule="permissions-id-token-unused",
                    message=(
                        "'id-token: write' is set but no OIDC-consuming action was found. "
                        "This permission allows minting cloud credentials — "
                        "grant it only where needed."
                    ),
                    file=workflow_path,
                    line=_find_line(lines, "id-token"),
                    col=0,
                    severity=Severity.WARNING,
                    fix_suggestion=(
                        "Remove 'id-token: write' or move it to the job that uses "
                        "an OIDC action (e.g. aws-actions/configure-aws-credentials)."
                    ),
                )
            )
        return findings

    # Per-job id-token: write — check only that job's steps.
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        job_perms = job.get("permissions")
        if not isinstance(job_perms, dict):
            continue
        if job_perms.get("id-token") != "write":
            continue
        steps = job.get("steps", []) or []
        if not _steps_use_oidc(steps):
            findings.append(
                Finding(
                    rule="permissions-id-token-unused",
                    message=(
                        f"Job '{job_id}' sets 'id-token: write' but uses no OIDC action. "
                        "This permission allows minting cloud credentials — "
                        "grant it only where needed."
                    ),
                    file=workflow_path,
                    line=_find_line(lines, "id-token"),
                    col=0,
                    severity=Severity.WARNING,
                    fix_suggestion=(
                        f"Remove 'id-token: write' from job '{job_id}' or add an OIDC action "
                        "(e.g. aws-actions/configure-aws-credentials)."
                    ),
                )
            )

    return findings


def _find_line(lines: list[str], keyword: str) -> int:
    return next((i + 1 for i, line in enumerate(lines) if keyword in line), 0)
