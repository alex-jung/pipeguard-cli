"""Tests for the action inventory scanner."""

from pipeguard.scanner.github_actions.action_inventory import check_action_inventory

FIXTURES = "tests/fixtures"


def test_inventory_lists_all_actions(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v3\n"
        "      - uses: actions/setup-python@v5\n"
        "      - uses: third-party/action@v1\n"
    )
    findings = check_action_inventory(str(wf))
    assert len(findings) == 3
    assert all(f.rule == "action-inventory" for f in findings)
    assert all(f.severity == "info" for f in findings)


def test_inventory_skips_local_actions(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: ./local-action\n"
    )
    findings = check_action_inventory(str(wf))
    assert findings == []


def test_inventory_deduplicates_actions(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "permissions:\n  contents: read\n"
        "jobs:\n  build:\n    runs-on: ubuntu-latest\n    steps:\n"
        "      - uses: actions/checkout@v3\n"
        "      - uses: actions/checkout@v3\n"
    )
    findings = check_action_inventory(str(wf))
    assert len(findings) == 1
    assert "2 occurrence(s)" in findings[0].message


def test_inventory_on_secure_fixture():
    findings = check_action_inventory(f"{FIXTURES}/secure_workflow.yml")
    rules = [f.rule for f in findings]
    assert all(r == "action-inventory" for r in rules)
    actions = [f.message for f in findings]
    assert any("actions/checkout" in a for a in actions)
