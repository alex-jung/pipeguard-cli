"""Integration tests: JSON and SARIF output formats."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pipeguard.cli import main

FIXTURES = Path("tests/fixtures")
E2E = Path("tests/fixtures/e2e")


class TestJsonOutput:
    def test_valid_json_emitted(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: third-party/action@abc123\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--format", "json"])
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert isinstance(data, list)

    def test_json_finding_has_required_fields(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--format", "json"])
        findings = json.loads(result.output)
        assert len(findings) > 0
        f = findings[0]
        assert "id" in f
        assert "rule" in f
        assert "severity" in f
        assert "message" in f
        assert "file" in f
        assert "line" in f
        assert "col" in f

    def test_json_id_is_12_hex_chars(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--format", "json"])
        findings = json.loads(result.output)
        for f in findings:
            assert len(f["id"]) == 12
            assert all(c in "0123456789abcdef" for c in f["id"])

    def test_json_no_warnings_or_errors_on_clean_workflow(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(E2E / "all_clean.yml"), "--format", "json"])
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert not any(f["severity"] in ("error", "warning") for f in data)

    def test_json_severity_values(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--format", "json"])
        findings = json.loads(result.output)
        for f in findings:
            assert f["severity"] in ("error", "warning", "info")


class TestSarifOutput:
    def test_valid_sarif_emitted(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--format", "sarif"])
        assert result.exit_code == 1
        sarif = json.loads(result.output)
        assert sarif["version"] == "2.1.0"
        assert "runs" in sarif
        assert len(sarif["runs"]) == 1

    def test_sarif_has_tool_driver(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--format", "sarif"])
        sarif = json.loads(result.output)
        driver = sarif["runs"][0]["tool"]["driver"]
        assert driver["name"] == "pipeguard"
        assert "rules" in driver

    def test_sarif_result_structure(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--format", "sarif"])
        sarif = json.loads(result.output)
        results = sarif["runs"][0]["results"]
        assert len(results) > 0
        r = results[0]
        assert "ruleId" in r
        assert "level" in r
        assert r["level"] in ("error", "warning", "note")
        assert "message" in r
        assert "locations" in r
        loc = r["locations"][0]["physicalLocation"]
        assert "artifactLocation" in loc
        assert "region" in loc

    def test_sarif_no_warnings_or_errors_on_clean_workflow(self):
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(E2E / "all_clean.yml"), "--format", "sarif"])
        sarif = json.loads(result.output)
        results = sarif["runs"][0]["results"]
        # action-inventory emits INFO; no errors or warnings on a clean workflow
        assert not any(r["level"] == "error" for r in results)
