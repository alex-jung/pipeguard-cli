"""Tests for folder scanning (pipeguard scan <directory>)."""

from pathlib import Path

from click.testing import CliRunner

from pipeguard.cli import main

FIXTURES = Path("tests/fixtures")


def test_scan_single_file():
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(FIXTURES / "insecure_workflow.yml")])
    assert result.exit_code == 1
    assert "sha-pinning" in result.output


def test_scan_directory_finds_multiple_files(tmp_path):
    wf1 = tmp_path / "a.yml"
    wf2 = tmp_path / "b.yml"
    for wf in (wf1, wf2):
        wf.write_text(
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 1
    assert "a.yml" in result.output or "Scanned 2 file(s)" in result.output
    assert "Scanned 2 file(s)" in result.output


def test_scan_directory_clean(tmp_path):
    wf = tmp_path / "clean.yml"
    wf.write_text(
        "on: [push]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0


def test_scan_empty_directory(tmp_path):
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path)])
    assert result.exit_code == 0
    assert "No workflow files found" in result.output


def test_scan_default_path_missing(tmp_path):
    """scan without args uses .github/workflows — error if not present."""
    runner = CliRunner()
    # Pass a non-existent path explicitly to simulate missing default
    result = runner.invoke(main, ["scan", str(tmp_path / "nonexistent")])
    assert result.exit_code != 0


def test_scan_json_format_directory(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: third-party/action@v1\n"
    )
    runner = CliRunner()
    result = runner.invoke(main, ["scan", str(tmp_path), "--format", "json"])
    assert result.exit_code == 1
    assert '"rule"' in result.output
