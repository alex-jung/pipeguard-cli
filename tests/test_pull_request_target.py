"""Tests for pull_request_target trigger detection."""

from pipeguard.scanner.github_actions.pull_request_target import check_pull_request_target

FIXTURES = "tests/fixtures"


def test_pwn_request_flagged_as_error():
    findings = check_pull_request_target(f"{FIXTURES}/pr_target_pwn.yml")
    assert len(findings) == 1
    assert findings[0].rule == "pull-request-target-pwn"
    assert findings[0].severity == "error"


def test_pr_target_without_head_checkout_is_warning():
    findings = check_pull_request_target(f"{FIXTURES}/pr_target_safe.yml")
    assert len(findings) == 1
    assert findings[0].rule == "pull-request-target"
    assert findings[0].severity == "warning"


def test_pull_request_trigger_not_flagged(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push, pull_request]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
        "        with:\n"
        "          ref: ${{ github.event.pull_request.head.ref }}\n"
    )
    findings = check_pull_request_target(str(wf))
    assert findings == []


def test_github_head_ref_triggers_error(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: pull_request_target\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683\n"
        "        with:\n"
        "          ref: ${{ github.head_ref }}\n"
    )
    findings = check_pull_request_target(str(wf))
    assert any(f.rule == "pull-request-target-pwn" and f.severity == "error" for f in findings)


def test_pr_target_in_list_form(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [pull_request_target, push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    findings = check_pull_request_target(str(wf))
    assert any(f.rule == "pull-request-target" for f in findings)


def test_pr_target_in_map_form(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on:\n"
        "  pull_request_target:\n"
        "    types: [opened, synchronize]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    findings = check_pull_request_target(str(wf))
    assert any(f.rule == "pull-request-target" for f in findings)


def test_no_trigger_no_findings(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    assert check_pull_request_target(str(wf)) == []
