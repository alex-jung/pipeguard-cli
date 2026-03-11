"""Tests for SHA pinning checker."""

from pipeguard.scanner.github_actions.sha_pinning import check_sha_pinning

FIXTURES = "tests/fixtures"


def test_detects_tag_pinning(tmp_path):
    wf = tmp_path / "workflow.yml"
    wf.write_text(
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v3\n"
    )
    findings = check_sha_pinning(str(wf))
    assert any(f.rule == "sha-pinning" for f in findings)


def test_no_finding_for_sha_pinned(tmp_path):
    wf = tmp_path / "workflow.yml"
    wf.write_text(
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
    )
    findings = check_sha_pinning(str(wf))
    assert not any(f.rule == "sha-pinning" for f in findings)


def test_insecure_fixture():
    findings = check_sha_pinning(f"{FIXTURES}/insecure_workflow.yml")
    assert len(findings) >= 2


def test_secure_fixture():
    findings = check_sha_pinning(f"{FIXTURES}/secure_workflow.yml")
    assert findings == []
