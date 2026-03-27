"""Mock server for PipeGuard Pro API — returns realistic findings for all Pro scanner types."""

from __future__ import annotations

import re

import yaml
from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_USES_RE = re.compile(r"uses:\s+(?P<action>[^@\s]+)@(?P<ref>\S+)")
_SHA_RE = re.compile(r"^[0-9a-f]{40}$")


def _parse_actions(workflow_yaml: str) -> list[tuple[str, str, int]]:
    """Return list of (action, ref, line_no) for all `uses:` entries."""
    results = []
    for i, line in enumerate(workflow_yaml.splitlines(), start=1):
        m = _USES_RE.search(line)
        if m:
            results.append((m.group("action"), m.group("ref"), i))
    return results


def _parse_workflow(workflow_yaml: str) -> dict:
    try:
        return yaml.safe_load(workflow_yaml) or {}
    except yaml.YAMLError:
        return {}


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------

@app.get("/v1/health")
def health():
    return jsonify({"status": "ok", "version": "mock-1.0.0"})


@app.post("/v1/analyze")
def analyze():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header."}), 401

    key = auth.removeprefix("Bearer ").strip()
    if not key:
        return jsonify({"error": "Invalid or expired license key."}), 401

    body = request.get_json(silent=True) or {}
    workflow_yaml: str = body.get("workflow", "")
    trusted_actions: list[str] = body.get("trusted_actions", [])

    findings = []
    actions = _parse_actions(workflow_yaml)
    data = _parse_workflow(workflow_yaml)

    for action, ref, line_no in actions:
        if any(action.startswith(t) for t in trusted_actions):
            continue

        # ── SHA-Pinning Pro: resolved SHA + YAML patch ──────────────────────
        if not _SHA_RE.match(ref):
            mock_sha = "a" * 40  # mock SHA — real backend resolves via GitHub API
            findings.append({
                "rule": "sha-pinning-pro",
                "severity": "error",
                "message": (
                    f"Action '{action}@{ref}' is not pinned to a SHA. "
                    f"Resolved SHA: {mock_sha[:12]}…"
                ),
                "line": line_no,
                "col": 0,
                "fix_suggestion": f"Pin to commit SHA (resolved from '{ref}').",
                "patch": f"uses: {action}@{mock_sha}  # {ref}",
                "score": None,
                "detail": None,
            })

        # ── Maintainer Trust Score ───────────────────────────────────────────
        mock_score = 38 if "third-party" in action else 71
        findings.append({
            "rule": "trust-score",
            "severity": "warning" if mock_score < 50 else "info",
            "message": f"Maintainer trust score for '{action}': {mock_score}/100.",
            "line": line_no,
            "col": 0,
            "fix_suggestion": "Review maintainer activity and CVE history before using." if mock_score < 50 else None,
            "patch": None,
            "score": mock_score,
            "detail": [
                f"activity: {mock_score - 10}/100",
                f"cve_history: {100 - mock_score}/100 (lower is better)",
                f"repo_hygiene: {mock_score + 5}/100",
            ],
        })

    # ── Secrets-Flow Pro: taint-flow path ────────────────────────────────────
    jobs = data.get("jobs", {}) if isinstance(data, dict) else {}
    for job_id, job in jobs.items():
        if not isinstance(job, dict):
            continue
        for step in job.get("steps", []) or []:
            if not isinstance(step, dict):
                continue
            run = step.get("run", "")
            env = step.get("env", {}) or {}
            if isinstance(run, str) and "secrets." in run.lower():
                secret_name = re.search(r"secrets\.(\w+)", run, re.IGNORECASE)
                sname = secret_name.group(1) if secret_name else "SECRET"
                step_name = step.get("name", f"step in {job_id}")
                lines = workflow_yaml.splitlines()
                line_no = next(
                    (i + 1 for i, l in enumerate(lines) if run.strip()[:30] in l), 0
                )
                findings.append({
                    "rule": "secrets-flow-pro",
                    "severity": "error",
                    "message": (
                        f"Secret '{sname}' flows into shell command in step '{step_name}' "
                        f"(job '{job_id}') — potential exposure."
                    ),
                    "line": line_no,
                    "col": 0,
                    "fix_suggestion": "Use masked environment variables instead of inline secret references.",
                    "patch": None,
                    "score": None,
                    "detail": [
                        f"source: secrets.{sname}",
                        f"via: run script in step '{step_name}'",
                        f"sink: shell stdout (job '{job_id}')",
                        "risk: secret value may appear in workflow logs",
                    ],
                })
            # env-var taint path
            for env_key, env_val in env.items():
                if isinstance(env_val, str) and "secrets." in env_val.lower():
                    secret_name = re.search(r"secrets\.(\w+)", env_val, re.IGNORECASE)
                    sname = secret_name.group(1) if secret_name else "SECRET"
                    step_name = step.get("name", f"step in {job_id}")
                    findings.append({
                        "rule": "secrets-flow-pro",
                        "severity": "warning",
                        "message": (
                            f"Secret '{sname}' mapped to env var '{env_key}' "
                            f"in step '{step_name}' — verify it is not logged."
                        ),
                        "line": 0,
                        "col": 0,
                        "fix_suggestion": None,
                        "patch": None,
                        "score": None,
                        "detail": [
                            f"source: secrets.{sname}",
                            f"via: env.{env_key} in step '{step_name}'",
                            f"sink: environment of job '{job_id}'",
                        ],
                    })

    # ── Granular Permission Audit Pro ────────────────────────────────────────
    if isinstance(data, dict):
        top_perms = data.get("permissions")
        if top_perms == "write-all" or top_perms is None:
            findings.append({
                "rule": "permissions-pro",
                "severity": "warning",
                "message": (
                    "Pro analysis: workflow uses broad permissions. "
                    "Minimal required scope based on actions used: contents:read, pull-requests:write."
                ),
                "line": 1,
                "col": 0,
                "fix_suggestion": "Apply minimal permissions patch below.",
                "patch": "permissions:\n  contents: read\n  pull-requests: write",
                "score": None,
                "detail": [
                    "contents:read — required by actions/checkout",
                    "pull-requests:write — required by PR comment action",
                    "all other scopes: none",
                ],
            })

    # ── Transitive Dependency-Graph ──────────────────────────────────────────
    for action, ref, line_no in actions[:2]:  # limit to first 2 for mock brevity
        findings.append({
            "rule": "dep-graph-pro",
            "severity": "info",
            "message": f"Transitive dependency graph for '{action}' (first level).",
            "line": line_no,
            "col": 0,
            "fix_suggestion": None,
            "patch": None,
            "score": None,
            "detail": [
                f"{action} → actions/toolkit@v2.1.0",
                f"{action} → actions/core@v1.10.0",
                f"{action} → @actions/io@1.1.3 (npm)",
            ],
        })

    return jsonify({"tier": "pro", "findings": findings})


@app.post("/v1/fix")
def fix():
    auth = request.headers.get("Authorization", "")
    if not auth.startswith("Bearer "):
        return jsonify({"error": "Missing Authorization header."}), 401

    body = request.get_json(silent=True) or {}
    workflow_yaml: str = body.get("workflow", "")
    findings: list[dict] = body.get("findings", [])

    # Apply mock SHA-pinning patches: replace tag refs with mock SHA
    patched = workflow_yaml
    applied = 0
    for action, ref, _ in _parse_actions(workflow_yaml):
        if not _SHA_RE.match(ref):
            mock_sha = "a" * 40
            patched = patched.replace(
                f"{action}@{ref}",
                f"{action}@{mock_sha}  # {ref}",
            )
            applied += 1

    skipped = max(0, len(findings) - applied)
    return jsonify({
        "patched_workflow": patched,
        "applied": applied,
        "skipped": skipped,
        "pr_title": f"fix: pin {applied} action(s) to commit SHA [pipeguard-pro]",
        "pr_body": (
            "## PipeGuard Pro — Auto-Fix\n\n"
            f"Pinned {applied} action(s) to full commit SHAs to prevent supply-chain attacks.\n\n"
            "> Generated by [PipeGuard Pro](https://pipe-guard.de)"
        ),
    })


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, debug=True)
