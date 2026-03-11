"""Detects over-provisioned permissions in GitHub Actions workflows."""

from __future__ import annotations

from pathlib import Path

import yaml

from pipeguard.scanner.base import Finding

_VALID_LEVELS = {"read", "write", "none"}

_SENSITIVE_SCOPES = {
    "actions",
    "administration",
    "deployments",
    "environments",
    "packages",
    "pages",
    "repository-projects",
    "secrets",
    "security-events",
    "statuses",
    "workflows",
}

_IMPLICIT_DEFAULT_MESSAGE = (
    "No top-level 'permissions:' key found. "
    "GitHub grants write access to most scopes by default — "
    "add 'permissions: read-all' or scope explicitly."
)


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
                message=_IMPLICIT_DEFAULT_MESSAGE,
                file=workflow_path,
                line=1,
                col=0,
                severity="error",
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
                severity="error",
                fix_suggestion="Replace with 'permissions: read-all' and add write scopes only where needed.",  # noqa: E501
            )
        )
        return findings

    if isinstance(top_perms, dict):
        findings += _check_scope_dict(top_perms, workflow_path, lines, context="top-level")

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
                    severity="error",
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
        if level not in _VALID_LEVELS:
            findings.append(
                Finding(
                    rule="permissions-invalid",
                    message=f"Unknown permission level '{level}' for scope '{scope}' in {context}.",
                    file=workflow_path,
                    line=_find_line(lines, scope),
                    col=0,
                    severity="error",
                    fix_suggestion="Use one of: read, write, none.",
                )
            )
            continue

        if level == "write" and scope in _SENSITIVE_SCOPES:
            findings.append(
                Finding(
                    rule="permissions-excessive",
                    message=f"Scope '{scope}' is set to 'write' in {context} — rarely needed, high risk.",  # noqa: E501
                    file=workflow_path,
                    line=_find_line(lines, scope),
                    col=0,
                    severity="warning",
                    fix_suggestion=f"Set '{scope}: read' or '{scope}: none' unless write access is explicitly required.",  # noqa: E501
                )
            )
    return findings


def _find_line(lines: list[str], keyword: str) -> int:
    return next((i + 1 for i, line in enumerate(lines) if keyword in line), 0)
