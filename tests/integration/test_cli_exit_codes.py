"""Integration tests: CLI exit codes."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from pipeguard.cli import main
from pipeguard.dataclasses import Finding, Severity

FIXTURES = Path("tests/fixtures")
E2E = Path("tests/fixtures/e2e")


def test_exit_0_on_clean_workflow():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(E2E / "all_clean.yml")])
    assert result.exit_code == 0


def test_exit_1_on_warnings(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v3\n"  # unpinned → sha-pinning warning
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(wf)])
    assert result.exit_code == 1


def test_exit_1_on_errors():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(FIXTURES / "insecure_workflow.yml")])
    assert result.exit_code == 1


def test_exit_0_on_empty_directory(tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_exit_2_on_invalid_license_key(tmp_path, monkeypatch):
    """InvalidLicenseKeyError from Pro API → exit code 2."""
    from pipeguard.license import InvalidLicenseKeyError

    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo hi\n"
    )

    monkeypatch.setattr("pipeguard.cli.resolve_license_key", lambda: "bad-key")
    monkeypatch.setattr(
        "pipeguard.cli.call_pro_api",
        lambda *a, **kw: (_ for _ in ()).throw(InvalidLicenseKeyError("Invalid key")),
    )

    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(wf)])
    assert result.exit_code == 2


def test_exit_0_info_only(tmp_path):
    """Exit 0 when only INFO findings (no warnings or errors)."""
    from unittest.mock import patch

    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n"
        "    steps:\n      - run: echo hi\n"
    )

    info_finding = Finding(
        rule="test-rule", message="info only", file=str(wf),
        line=1, col=0, severity=Severity.INFO,
    )
    with patch("pipeguard.cli._scan_file", return_value=[info_finding]):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf)])
    assert result.exit_code == 0
