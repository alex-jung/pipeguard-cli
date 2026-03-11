"""Tests for the CVE check scanner."""

from pipeguard.scanner.github_actions.cve_check import check_cve

FIXTURES = "tests/fixtures"


def test_tj_actions_tag_flagged(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\npermissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: tj-actions/changed-files@v35\n"
    )
    findings = check_cve(str(wf))
    assert any("CVE-2025-30066" in f.message for f in findings)
    assert all(f.severity == "error" for f in findings)


def test_tj_actions_sha_not_flagged(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\npermissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: tj-actions/changed-files@d6e91e26fd39a8a0e0d8e34c0c44c9b3f2d6a7b1\n"
    )
    findings = check_cve(str(wf))
    assert not any("CVE-2025-30066" in f.message for f in findings)


def test_reviewdog_tag_flagged(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\npermissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: reviewdog/action-setup@v1\n"
    )
    findings = check_cve(str(wf))
    assert any("CVE-2025-30154" in f.message for f in findings)


def test_unknown_action_clean(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\npermissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: some-org/some-action@v2\n"
    )
    findings = check_cve(str(wf))
    assert findings == []


def test_cve_fixture():
    findings = check_cve(f"{FIXTURES}/cve_workflow.yml")
    cve_ids = [f.rule for f in findings]
    assert "cve-cve-2025-30066" in cve_ids
    assert "cve-cve-2025-30154" in cve_ids


def test_insecure_fixture_cve_hit():
    findings = check_cve(f"{FIXTURES}/insecure_workflow.yml")
    assert any("CVE-2025-30066" in f.message for f in findings)
