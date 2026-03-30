"""Integration tests: --scanner option for targeted single-scanner runs."""

from __future__ import annotations

from pathlib import Path

from click.testing import CliRunner

from pipeguard.cli import main

from .conftest import parse_json_output

FIXTURES = Path("tests/fixtures")


class TestScannerOption:
    def test_single_scanner_only_emits_that_rule(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
            "      - uses: untrusted-org/action@abc1234def5678901234567890abcdef01234567\n"
        )
        runner = CliRunner()
        result = runner.invoke(
            main, ["scan", str(wf), "--scanner", "sha-pinning", "--format", "json"]
        )
        findings = parse_json_output(result.output)
        rules = {f["rule"] for f in findings}
        assert "sha-pinning" in rules
        assert "supply-chain" not in rules

    def test_multiple_scanners_run_only_those(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
            "      - uses: untrusted-org/action@abc1234def5678901234567890abcdef01234567\n"
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", str(wf), "--scanner", "sha-pinning", "--scanner", "supply-chain",
             "--format", "json"],
        )
        findings = parse_json_output(result.output)
        rules = {f["rule"] for f in findings}
        assert "sha-pinning" in rules
        assert "supply-chain" in rules
        assert "permissions" not in rules
        assert "action-inventory" not in rules

    def test_scanner_option_overrides_skip_in_config(self, tmp_path):
        """--scanner runs the scanner even if skip: true is set in config."""
        config = tmp_path / ".pipeguard.yml"
        config.write_text("scanners:\n  sha-pinning:\n    skip: true\n")

        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", str(wf), "--scanner", "sha-pinning",
             "--config", str(config), "--format", "json"],
        )
        findings = parse_json_output(result.output)
        assert any(f["rule"] == "sha-pinning" for f in findings)

    def test_scanner_option_respects_trusted_publishers(self, tmp_path):
        """--scanner still applies trusted_publishers from config."""
        config = tmp_path / ".pipeguard.yml"
        config.write_text(
            "scanners:\n  supply-chain:\n    trusted_publishers:\n      - my-trusted-org\n"
        )

        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
            "      - uses: my-trusted-org/action@abc1234def5678901234567890abcdef01234567\n"
            "      - uses: untrusted-org/tool@deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n"
        )
        runner = CliRunner()
        result = runner.invoke(
            main,
            ["scan", str(wf), "--scanner", "supply-chain",
             "--config", str(config), "--format", "json"],
        )
        findings = parse_json_output(result.output)
        supply = [f for f in findings if f["rule"] == "supply-chain"]
        # trusted org should be suppressed, untrusted should be flagged
        assert not any("my-trusted-org" in f["message"] for f in supply)
        assert any("untrusted-org" in f["message"] for f in supply)

    def test_scanner_option_bypasses_pro_api(self, tmp_path, monkeypatch):
        """--scanner always runs locally, even when a license key is present."""
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )

        api_calls: list[str] = []

        def fake_call_pro_api(*args, **kwargs):
            api_calls.append("called")
            return None

        monkeypatch.setattr("pipeguard.cli.resolve_license_key", lambda: "valid-key")
        monkeypatch.setattr("pipeguard.cli.call_pro_api", fake_call_pro_api)

        runner = CliRunner()
        runner.invoke(main, ["scan", str(wf), "--scanner", "sha-pinning"])
        assert api_calls == []

    def test_invalid_scanner_name_shows_error(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text("on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n")
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--scanner", "nonexistent"])
        assert result.exit_code != 0
        assert "nonexistent" in result.output or "Invalid value" in result.output

    def test_scanner_option_exit_code(self, tmp_path):
        """Exit code follows findings severity even with --scanner."""
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--scanner", "sha-pinning"])
        assert result.exit_code == 1  # sha-pinning error

    def test_scanner_option_all_rules_available(self, tmp_path):
        """Each valid scanner name can be passed without error."""
        from pipeguard.cli import SCANNER_NAMES

        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\npermissions:\n  contents: read\n"
            "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
        )
        runner = CliRunner()
        for name in SCANNER_NAMES:
            result = runner.invoke(main, ["scan", str(wf), "--scanner", name])
            assert result.exit_code in (0, 1), f"Scanner '{name}' crashed: {result.output}"
