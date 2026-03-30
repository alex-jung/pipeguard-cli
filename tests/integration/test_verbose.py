"""Integration tests: verbose mode and autofix."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from pipeguard.cli import main
from pipeguard.dataclasses import Finding, Severity

FIXTURES = Path("tests/fixtures")


class TestVerboseMode:
    def test_verbose_shows_scan_progress(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--verbose"])
        assert "[pipeguard]" in result.output

    def test_verbose_shows_skipped_scanner(self, tmp_path):
        config = tmp_path / ".pipeguard.yml"
        config.write_text("scanners:\n  sha-pinning:\n    skip: true\n")

        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--config", str(config), "--verbose"])
        assert "skipped" in result.output

    def test_non_verbose_no_progress_lines(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf)])
        # Without --verbose, no scanner progress lines (format: "· sha-pinning  N finding(s)")
        assert "finding(s)" not in result.output


class TestAutofix:
    def test_fix_without_license_does_nothing(self, tmp_path):
        """--fix without a license key should not call apply_fixes."""
        wf = tmp_path / "wf.yml"
        original = (
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        wf.write_text(original)

        runner = CliRunner()
        runner.invoke(main, ["scan", str(wf), "--fix"])
        # File should be unchanged (no license key → apply_fixes not called)
        assert wf.read_text() == original

    def test_fix_with_license_calls_apply_fixes(self, tmp_path, monkeypatch):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )

        pro_finding = Finding(
            rule="sha-pinning", message="Pin this", file=str(wf),
            line=6, col=0, severity=Severity.WARNING, fix_suggestion="use SHA",
        )
        monkeypatch.setattr("pipeguard.cli.resolve_license_key", lambda: "valid-key")
        monkeypatch.setattr("pipeguard.cli.call_pro_api", lambda *a, **kw: [pro_finding])

        apply_calls: list[tuple] = []

        def fake_apply_fixes(findings, path, key, api_url):
            apply_calls.append((findings, path, key))
            return (1, 0)

        monkeypatch.setattr("pipeguard.cli.apply_fixes", fake_apply_fixes)

        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--fix"])
        assert len(apply_calls) == 1
        assert "Auto-fixed 1 issue(s)" in result.output
