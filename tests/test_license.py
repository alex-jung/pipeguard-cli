"""Tests for license key resolution and Pro API helpers."""

from __future__ import annotations

from pipeguard.config import (
    CveScannerConfig,
    PipeGuardConfig,
    ScannerConfig,
    SupplyChainScannerConfig,
)
from pipeguard.license import _serialize_config


class TestSerializeConfig:
    def test_none_returns_empty(self) -> None:
        assert _serialize_config(None) == {}

    def test_empty_config_returns_empty(self) -> None:
        assert _serialize_config(PipeGuardConfig()) == {}

    def test_all_defaults_omitted(self) -> None:
        config = PipeGuardConfig(
            scanners={
                "sha-pinning": ScannerConfig(skip=False),
                "supply-chain": SupplyChainScannerConfig(),
                "cve": CveScannerConfig(),
            }
        )
        assert _serialize_config(config) == {}

    def test_skip_true_included(self) -> None:
        config = PipeGuardConfig(scanners={"sha-pinning": ScannerConfig(skip=True)})
        result = _serialize_config(config)
        assert result == {"scanners": {"sha-pinning": {"skip": True}}}

    def test_trusted_publishers_included_when_set(self) -> None:
        config = PipeGuardConfig(
            scanners={
                "supply-chain": SupplyChainScannerConfig(trusted_publishers=["my-org/"])
            }
        )
        result = _serialize_config(config)
        assert result["scanners"]["supply-chain"]["trusted_publishers"] == ["my-org/"]  # type: ignore[index]
        assert "skip" not in result["scanners"]["supply-chain"]  # type: ignore[index]

    def test_trusted_actions_included_when_set(self) -> None:
        config = PipeGuardConfig(
            scanners={
                "supply-chain": SupplyChainScannerConfig(trusted_actions=["foo/bar"])
            }
        )
        result = _serialize_config(config)
        assert result["scanners"]["supply-chain"]["trusted_actions"] == ["foo/bar"]  # type: ignore[index]

    def test_min_cvss_included_when_non_default(self) -> None:
        config = PipeGuardConfig(scanners={"cve": CveScannerConfig(min_cvss=7.0)})
        result = _serialize_config(config)
        assert result["scanners"]["cve"]["min_cvss"] == 7.0  # type: ignore[index]

    def test_min_cvss_omitted_when_default(self) -> None:
        config = PipeGuardConfig(scanners={"cve": CveScannerConfig(min_cvss=9.0)})
        assert _serialize_config(config) == {}

    def test_mixed_scanners(self) -> None:
        config = PipeGuardConfig(
            scanners={
                "sha-pinning": ScannerConfig(skip=True),
                "cve": CveScannerConfig(min_cvss=7.5),
                "supply-chain": SupplyChainScannerConfig(),  # all defaults → omitted
            }
        )
        result = _serialize_config(config)
        assert set(result["scanners"].keys()) == {"sha-pinning", "cve"}  # type: ignore[index]
        assert result["scanners"]["sha-pinning"] == {"skip": True}  # type: ignore[index]
        assert result["scanners"]["cve"] == {"min_cvss": 7.5}  # type: ignore[index]
