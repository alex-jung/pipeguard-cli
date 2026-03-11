"""Tests for the permission analysis checker."""

from pipeguard.scanner.github_actions.permissions import check_permissions

FIXTURES = "tests/fixtures"


def test_missing_permissions_block():
    findings = check_permissions(f"{FIXTURES}/permissions_missing.yml")
    assert len(findings) == 1
    assert findings[0].rule == "permissions-missing"
    assert findings[0].severity == "error"


def test_write_all_flagged():
    findings = check_permissions(f"{FIXTURES}/permissions_overprovision.yml")
    assert any(f.rule == "permissions-write-all" for f in findings)
    assert all(f.severity == "error" for f in findings if f.rule == "permissions-write-all")


def test_minimal_permissions_clean():
    findings = check_permissions(f"{FIXTURES}/permissions_ok.yml")
    assert findings == []


def test_sensitive_scope_write(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "permissions:\n"
        "  secrets: write\n"
        "  contents: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    findings = check_permissions(str(wf))
    assert any(f.rule == "permissions-excessive" and "secrets" in f.message for f in findings)


def test_per_job_write_all(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions: write-all\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    findings = check_permissions(str(wf))
    assert any(f.rule == "permissions-write-all" and "deploy" in f.message for f in findings)


def test_read_all_is_clean(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    findings = check_permissions(str(wf))
    assert findings == []


def test_invalid_permission_level(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "permissions:\n"
        "  contents: admin\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    findings = check_permissions(str(wf))
    assert any(f.rule == "permissions-invalid" for f in findings)
