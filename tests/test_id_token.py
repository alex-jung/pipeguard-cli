"""Tests for id-token: write without OIDC usage."""

from pipeguard.scanner.github_actions.permissions import check_permissions

FIXTURES = "tests/fixtures"


def test_id_token_write_without_oidc_flagged():
    findings = check_permissions(f"{FIXTURES}/id_token_unused.yml")
    assert any(f.rule == "permissions-id-token-unused" for f in findings)
    flagged = [f for f in findings if f.rule == "permissions-id-token-unused"]
    assert flagged[0].severity == "warning"


def test_id_token_write_with_oidc_action_clean():
    findings = check_permissions(f"{FIXTURES}/id_token_used.yml")
    assert not any(f.rule == "permissions-id-token-unused" for f in findings)


def test_id_token_write_per_job_without_oidc(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "      contents: read\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    findings = check_permissions(str(wf))
    assert any(f.rule == "permissions-id-token-unused" and "build" in f.message for f in findings)


def test_id_token_write_per_job_with_oidc_clean(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "permissions: read-all\n"
        "jobs:\n"
        "  deploy:\n"
        "    runs-on: ubuntu-latest\n"
        "    permissions:\n"
        "      id-token: write\n"
        "      contents: read\n"
        "    steps:\n"
        "      - uses: google-github-actions/auth@71f986410dfbc7added4569d411d040a91dc6935\n"
        "        with:\n"
        "          workload_identity_provider: projects/123/locations/global/"  # noqa: E501
        "workloadIdentityPools/my-pool/providers/my-provider\n"
    )
    findings = check_permissions(str(wf))
    assert not any(f.rule == "permissions-id-token-unused" for f in findings)


def test_id_token_read_not_flagged(tmp_path):
    """id-token: read is harmless — only write triggers the check."""
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "permissions:\n"
        "  contents: read\n"
        "  id-token: read\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        "      - run: echo hi\n"
    )
    findings = check_permissions(str(wf))
    assert not any(f.rule == "permissions-id-token-unused" for f in findings)
