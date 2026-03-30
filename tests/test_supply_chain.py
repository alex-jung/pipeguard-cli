"""Tests for supply-chain trusted publisher check."""

import pytest

from pipeguard.config import SupplyChainScannerConfig, load_config
from pipeguard.scanner.github_actions.supply_chain import check_supply_chain

TRUSTED = [
    "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683",
    "github/codeql-action/analyze@v3",
    "docker/build-push-action@v6",
    "aws-actions/configure-aws-credentials@v4",
    "google-github-actions/auth@v2",
    "azure/login@v2",
    "hashicorp/setup-terraform@v3",
    "microsoft/playwright-github-action@v1",
    "sigstore/cosign-installer@v3",
    "aquasecurity/trivy-action@v0.20.0",
    "helm/kind-action@v1",
    "codecov/codecov-action@v4",
    "coverallsapp/github-action@v2",
    "pnpm/action-setup@v3",
    "ruby/setup-ruby@v1",
    "gradle/actions@v3",
]

UNTRUSTED = [
    "some-random-org/cool-action@v1",
    "my-company/deploy-action@v2",
    "unknown/setup-tool@abc123",
]


@pytest.mark.parametrize("uses", TRUSTED)
def test_trusted_publisher_not_flagged(tmp_path, uses):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: {uses}\n"
    )
    findings = check_supply_chain(str(wf))
    assert not any(f.rule == "supply-chain" for f in findings), (
        f"{uses} should be trusted but was flagged"
    )


@pytest.mark.parametrize("uses", UNTRUSTED)
def test_untrusted_publisher_flagged(tmp_path, uses):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: {uses}\n"
    )
    findings = check_supply_chain(str(wf))
    assert any(f.rule == "supply-chain" for f in findings), (
        f"{uses} should be untrusted but was not flagged"
    )


def _workflow(tmp_path, uses: str):
    wf = tmp_path / "wf.yml"
    wf.write_text(
        "on: [push]\n"
        "jobs:\n"
        "  build:\n"
        "    runs-on: ubuntu-latest\n"
        "    steps:\n"
        f"      - uses: {uses}\n"
    )
    return str(wf)


def test_config_trusted_publisher_suppresses_warning(tmp_path):
    wf = _workflow(tmp_path, "my-company/deploy-action@v2")
    config = SupplyChainScannerConfig(trusted_publishers=["my-company/"])
    assert not any(f.rule == "supply-chain" for f in check_supply_chain(wf, config))


def test_config_trusted_publisher_without_slash_normalised(tmp_path):
    wf = _workflow(tmp_path, "my-company/deploy-action@v2")
    config = SupplyChainScannerConfig(trusted_publishers=["my-company/"])
    assert not any(f.rule == "supply-chain" for f in check_supply_chain(wf, config))


def test_config_trusted_action_suppresses_warning(tmp_path):
    wf = _workflow(tmp_path, "some-random-org/cool-action@v1")
    config = SupplyChainScannerConfig(trusted_actions=["some-random-org/cool-action"])
    assert not any(f.rule == "supply-chain" for f in check_supply_chain(wf, config))


def test_config_does_not_suppress_other_actions(tmp_path):
    wf = _workflow(tmp_path, "other-org/other-action@v1")
    config = SupplyChainScannerConfig(trusted_publishers=["my-company/"])
    assert any(f.rule == "supply-chain" for f in check_supply_chain(wf, config))


def test_load_config_from_file(tmp_path):
    cfg_file = tmp_path / ".pipeguard.yml"
    cfg_file.write_text(
        "scanners:\n"
        "  supply-chain:\n"
        "    trusted_publishers:\n"
        "      - my-org\n"
        "    trusted_actions:\n"
        "      - other-org/specific-action\n"
    )
    config = load_config(tmp_path)
    sc = config.scanners.get("supply-chain")
    assert isinstance(sc, SupplyChainScannerConfig)
    assert "my-org/" in sc.trusted_publishers
    assert "other-org/specific-action" in sc.trusted_actions


def test_load_config_missing_file(tmp_path):
    config = load_config(tmp_path)
    assert config.scanners == {}
