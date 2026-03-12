"""Tests for set -x / debug-mode secrets leak detection."""

import pytest

from pipeguard.scanner.github_actions.secrets_flow import check_secrets_flow

# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------

def _wf(run: str, step_env: str = "", job_env: str = "", workflow_env: str = "") -> str:
    wf_env_block = f"env:\n  {workflow_env}\n" if workflow_env else ""
    job_env_block = f"    env:\n      {job_env}\n" if job_env else ""
    step_env_block = f"        env:\n          {step_env}\n" if step_env else ""
    # Indent every line of the run block to 10 spaces (under `run: |`)
    run_indented = "\n".join(f"          {line}" for line in run.splitlines())
    return (
        "on: [push]\n"
        f"{wf_env_block}"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        f"{job_env_block}"
        "    steps:\n"
        "      - run: |\n"
        f"{run_indented}\n"
        f"{step_env_block}"
    )


# ---------------------------------------------------------------------------
# set -x with secrets in env → error
# ---------------------------------------------------------------------------

def test_set_x_with_step_secret_is_error(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(_wf("set -x\nmake test", step_env="TOKEN: ${{ secrets.API_TOKEN }}"))
    findings = check_secrets_flow(str(wf))
    assert any(f.rule == "secrets-leak-debug" and f.severity == "error" for f in findings)


def test_set_x_with_job_secret_is_error(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(_wf("set -x\nmake test", job_env="TOKEN: ${{ secrets.API_TOKEN }}"))
    findings = check_secrets_flow(str(wf))
    assert any(f.rule == "secrets-leak-debug" and f.severity == "error" for f in findings)


def test_set_x_with_workflow_secret_is_error(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(_wf("set -x\nmake test", workflow_env="TOKEN: ${{ secrets.API_TOKEN }}"))
    findings = check_secrets_flow(str(wf))
    assert any(f.rule == "secrets-leak-debug" and f.severity == "error" for f in findings)


# ---------------------------------------------------------------------------
# set -x without explicit secrets → warning
# ---------------------------------------------------------------------------

def test_set_x_without_secrets_is_warning(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(_wf("set -x\nmake test"))
    findings = check_secrets_flow(str(wf))
    assert any(f.rule == "secrets-leak-debug" and f.severity == "warning" for f in findings)


# ---------------------------------------------------------------------------
# variant patterns
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("cmd", [
    "set -ex",
    "set -euxo pipefail",
    "set -o xtrace",
    "#!/bin/bash -x",
])
def test_set_x_variants_detected(tmp_path, cmd):
    wf = tmp_path / "wf.yml"
    wf.write_text(_wf(cmd, step_env="TOKEN: ${{ secrets.TOKEN }}"))
    findings = check_secrets_flow(str(wf))
    assert any(f.rule == "secrets-leak-debug" for f in findings), (
        f"'{cmd}' should be detected"
    )


# ---------------------------------------------------------------------------
# no false positives
# ---------------------------------------------------------------------------

def test_no_set_x_no_finding(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(_wf("set -euo pipefail\nmake test", step_env="TOKEN: ${{ secrets.TOKEN }}"))
    findings = check_secrets_flow(str(wf))
    assert not any(f.rule == "secrets-leak-debug" for f in findings)


def test_existing_echo_leak_unaffected(tmp_path):
    """Original echo-leak check still works alongside the new check."""
    wf = tmp_path / "wf.yml"
    wf.write_text(_wf("echo ${{ secrets.TOKEN }}"))
    findings = check_secrets_flow(str(wf))
    assert any(f.rule == "secrets-leak" for f in findings)
    assert not any(f.rule == "secrets-leak-debug" for f in findings)
