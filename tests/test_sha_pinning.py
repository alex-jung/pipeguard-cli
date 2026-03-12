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


# ── Reusable workflow pinning ─────────────────────────────────────────────────

def test_reusable_unpinned_flagged():
    findings = check_sha_pinning(f"{FIXTURES}/reusable_unpinned.yml")
    assert any(f.rule == "sha-pinning-reusable" for f in findings)
    assert all(f.severity == "error" for f in findings if f.rule == "sha-pinning-reusable")


def test_reusable_pinned_clean():
    findings = check_sha_pinning(f"{FIXTURES}/reusable_pinned.yml")
    assert not any(f.rule == "sha-pinning-reusable" for f in findings)


def test_reusable_tag_flagged(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "jobs:\n"
        "  call:\n"
        "    uses: my-org/workflows/.github/workflows/ci.yml@v2.1.0\n"
        "    secrets: inherit\n"
    )
    findings = check_sha_pinning(str(wf))
    assert any(f.rule == "sha-pinning-reusable" for f in findings)


def test_local_reusable_skipped(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "jobs:\n"
        "  call:\n"
        "    uses: ./.github/workflows/build.yml\n"
    )
    findings = check_sha_pinning(str(wf))
    assert not any(f.rule == "sha-pinning-reusable" for f in findings)


def test_reusable_and_step_both_unpinned(tmp_path):
    """Both job-level reusable call and step-level action are caught."""
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "jobs:\n"
        "  call:\n"
        "    uses: my-org/workflows/.github/workflows/ci.yml@main\n"
        "    secrets: inherit\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@v4\n"
    )
    findings = check_sha_pinning(str(wf))
    assert any(f.rule == "sha-pinning-reusable" for f in findings)
    assert any(f.rule == "sha-pinning" for f in findings)
