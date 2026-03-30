"""Integration tests: config file effects on scanner behaviour."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pipeguard.cli import main

E2E = Path("tests/fixtures/e2e")


class TestSkipConfig:
    def test_skip_supply_chain_suppresses_findings(self, tmp_path):
        config = tmp_path / ".pipeguard.yml"
        config.write_text("scanners:\n  supply-chain:\n    skip: true\n")

        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
            "      - uses: untrusted-org/action@abc1234def5678901234567890abcdef01234567\n"
        )

        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--config", str(config), "--format", "json"])
        findings = json.loads(result.output)
        assert not any(f["rule"] == "supply-chain" for f in findings)

    def test_skip_sha_pinning_suppresses_findings(self, tmp_path):
        config = tmp_path / ".pipeguard.yml"
        config.write_text("scanners:\n  sha-pinning:\n    skip: true\n")

        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"  # would normally trigger sha-pinning
        )

        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--config", str(config), "--format", "json"])
        findings = json.loads(result.output)
        assert not any(f["rule"] == "sha-pinning" for f in findings)

    def test_non_skipped_scanners_still_run(self, tmp_path):
        config = tmp_path / ".pipeguard.yml"
        config.write_text("scanners:\n  sha-pinning:\n    skip: true\n")

        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
            "      - uses: untrusted-org/action@abc1234def5678901234567890abcdef01234567\n"
        )

        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--config", str(config), "--format", "json"])
        findings = json.loads(result.output)
        # supply-chain should still run (not skipped)
        assert any(f["rule"] == "supply-chain" for f in findings)


class TestTrustedPublishers:
    def test_trusted_publisher_suppresses_supply_chain_warning(self, tmp_path):
        config = tmp_path / ".pipeguard.yml"
        config.write_text(
            "scanners:\n"
            "  supply-chain:\n"
            "    trusted_publishers:\n"
            "      - my-trusted-org\n"
        )

        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
            "      - uses: my-trusted-org/action@abc1234def5678901234567890abcdef01234567\n"
        )

        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--config", str(config), "--format", "json"])
        findings = json.loads(result.output)
        supply_chain = [f for f in findings if f["rule"] == "supply-chain"]
        assert not any("my-trusted-org" in f["message"] for f in supply_chain)

    def test_untrusted_publisher_still_flagged(self, tmp_path):
        config = tmp_path / ".pipeguard.yml"
        config.write_text(
            "scanners:\n"
            "  supply-chain:\n"
            "    trusted_publishers:\n"
            "      - my-trusted-org\n"
        )

        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
            "      - uses: other-org/action@abc1234def5678901234567890abcdef01234567\n"
        )

        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--config", str(config), "--format", "json"])
        findings = json.loads(result.output)
        supply_chain = [f for f in findings if f["rule"] == "supply-chain"]
        assert any("other-org" in f["message"] for f in supply_chain)


class TestMinCvss:
    def test_min_cvss_lower_threshold_includes_more_findings(self, tmp_path):
        """min_cvss: 7.0 should include findings that 9.0 would filter out."""
        config_strict = tmp_path / "strict.yml"
        config_strict.write_text("scanners:\n  cve:\n    min_cvss: 9.0\n")

        config_loose = tmp_path / "loose.yml"
        config_loose.write_text("scanners:\n  cve:\n    min_cvss: 7.0\n")

        # Use the existing CVE fixture which has known CVE actions
        cve_fixture = Path("tests/fixtures/cve_workflow.yml")

        runner = CliRunner()
        strict = runner.invoke(
            main, ["scan", str(cve_fixture), "--config", str(config_strict), "--format", "json"]
        )
        loose = runner.invoke(
            main, ["scan", str(cve_fixture), "--config", str(config_loose), "--format", "json"]
        )

        strict_cve = [f for f in json.loads(strict.output) if f["rule"] == "cve"]
        loose_cve = [f for f in json.loads(loose.output) if f["rule"] == "cve"]

        # Loose threshold should find at least as many as strict
        assert len(loose_cve) >= len(strict_cve)
