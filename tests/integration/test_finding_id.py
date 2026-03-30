"""Integration tests: Finding ID determinism and stability."""

from __future__ import annotations

import json
from pathlib import Path

from click.testing import CliRunner

from pipeguard.cli import main
from pipeguard.dataclasses import Finding, Severity

FIXTURES = Path("tests/fixtures")


class TestFindingIdDeterminism:
    def test_same_input_produces_same_id(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result1 = runner.invoke(main, ["scan", str(wf), "--format", "json"])
        result2 = runner.invoke(main, ["scan", str(wf), "--format", "json"])

        findings1 = {f["id"] for f in json.loads(result1.output)}
        findings2 = {f["id"] for f in json.loads(result2.output)}
        assert findings1 == findings2

    def test_id_changes_when_line_changes(self, tmp_path):
        """Adding a line before a finding shifts line numbers → different IDs."""
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result1 = runner.invoke(main, ["scan", str(wf), "--format", "json"])
        ids_before = {f["id"] for f in json.loads(result1.output)}

        # Prepend a comment — shifts all line numbers
        wf.write_text(
            "# extra comment\n"
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        result2 = runner.invoke(main, ["scan", str(wf), "--format", "json"])
        ids_after = {f["id"] for f in json.loads(result2.output)}

        assert ids_before != ids_after

    def test_id_is_12_hex_chars(self):
        f = Finding(rule="test", message="msg", file="f.yml", line=1, col=0)
        assert len(f.id) == 12
        assert all(c in "0123456789abcdef" for c in f.id)

    def test_id_differs_by_rule(self):
        f1 = Finding(rule="rule-a", message="same", file="f.yml", line=1, col=0)
        f2 = Finding(rule="rule-b", message="same", file="f.yml", line=1, col=0)
        assert f1.id != f2.id

    def test_id_differs_by_line(self):
        f1 = Finding(rule="rule", message="same", file="f.yml", line=1, col=0)
        f2 = Finding(rule="rule", message="same", file="f.yml", line=2, col=0)
        assert f1.id != f2.id

    def test_id_differs_by_message(self):
        f1 = Finding(rule="rule", message="msg-a", file="f.yml", line=1, col=0)
        f2 = Finding(rule="rule", message="msg-b", file="f.yml", line=1, col=0)
        assert f1.id != f2.id

    def test_custom_id_preserved(self):
        f = Finding(rule="rule", message="msg", file="f.yml", line=1, col=0, id="custom-id-42")
        assert f.id == "custom-id-42"

    def test_id_present_in_json_output(self, tmp_path):
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )
        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--format", "json"])
        findings = json.loads(result.output)
        assert all(f["id"] for f in findings)


class TestOptionA:
    def _parse_json_output(self, output: str) -> list[dict]:
        """Extract the JSON array from CLI output (strips any banner lines)."""
        # Find the first line that is the start of a JSON array (bare '[')
        lines = output.splitlines()
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped == "[" or stripped.startswith("[{"):
                return json.loads("\n".join(lines[i:]))
        return json.loads(output)

    def test_pro_api_replaces_free_scanners(self, tmp_path, monkeypatch):
        """When Pro key present, only Pro API findings returned (no free scanner runs)."""
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )

        pro_finding = Finding(
            rule="pro-rule", message="Pro finding", file=str(wf),
            line=1, col=0, severity=Severity.WARNING, id="pro-id-12345",
        )

        monkeypatch.setattr("pipeguard.cli.resolve_license_key", lambda: "test-key-123")
        monkeypatch.setattr("pipeguard.cli.call_pro_api", lambda *a, **kw: [pro_finding])

        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--format", "json"])
        findings = self._parse_json_output(result.output)

        rules = {f["rule"] for f in findings}
        assert "pro-rule" in rules
        # Free scanner rules should not appear since Pro API returned findings
        assert "sha-pinning" not in rules

    def test_fallback_to_free_when_pro_api_fails(self, tmp_path, monkeypatch):
        """When Pro API returns None (failure), free scanners run as fallback."""
        wf = tmp_path / "wf.yml"
        wf.write_text(
            "on: [push]\njobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
            "      - uses: actions/checkout@v3\n"
        )

        monkeypatch.setattr("pipeguard.cli.resolve_license_key", lambda: "test-key-123")
        monkeypatch.setattr("pipeguard.cli.call_pro_api", lambda *a, **kw: None)

        runner = CliRunner()
        result = runner.invoke(main, ["scan", str(wf), "--format", "json"])
        findings = self._parse_json_output(result.output)

        rules = {f["rule"] for f in findings}
        assert "sha-pinning" in rules
