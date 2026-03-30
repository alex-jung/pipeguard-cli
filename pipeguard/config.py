"""Loads .pipeguard.yml config from the project root."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class ScannerConfig:
    skip: bool = False


@dataclass
class SupplyChainScannerConfig(ScannerConfig):
    trusted_publishers: list[str] = field(default_factory=list)
    trusted_actions: list[str] = field(default_factory=list)


@dataclass
class CveScannerConfig(ScannerConfig):
    min_cvss: float = 9.0


@dataclass
class PipeGuardConfig:
    api_url: str | None = None
    scanners: dict[str, ScannerConfig] = field(default_factory=dict)


_CONFIG_FILENAMES = (".pipeguard.yml", ".pipeguard.yaml", "pipeguard.yml", "pipeguard.yaml")


def load_config(start_dir: str | Path | None = None) -> PipeGuardConfig:
    """Search for a pipeguard config file and return a PipeGuardConfig.

    Walks up from *start_dir* (default: cwd) until it finds a config file or
    reaches the filesystem root.  Returns an empty config if nothing is found.
    """
    directory = Path(start_dir).resolve() if start_dir else Path.cwd()

    for parent in (directory, *directory.parents):
        for name in _CONFIG_FILENAMES:
            candidate = parent / name
            if candidate.is_file():
                return _parse(candidate)

    return PipeGuardConfig()


def _parse(path: Path) -> PipeGuardConfig:
    data = yaml.safe_load(path.read_text()) or {}
    if not isinstance(data, dict):
        return PipeGuardConfig()

    api_url = data.get("api_url")
    scanners: dict[str, ScannerConfig] = {}

    for name, scanner_data in (data.get("scanners") or {}).items():
        if not isinstance(scanner_data, dict):
            scanners[name] = ScannerConfig()
            continue

        skip = bool(scanner_data.get("skip", False))

        if name == "supply-chain":
            publishers = scanner_data.get("trusted_publishers") or []
            actions = scanner_data.get("trusted_actions") or []
            if not isinstance(publishers, list):
                publishers = []
            if not isinstance(actions, list):
                actions = []
            normalised = [p if p.endswith("/") else p + "/" for p in publishers]
            scanners[name] = SupplyChainScannerConfig(
                skip=skip,
                trusted_publishers=normalised,
                trusted_actions=[str(a) for a in actions],
            )
        elif name == "cve":
            scanners[name] = CveScannerConfig(
                skip=skip,
                min_cvss=float(scanner_data.get("min_cvss", 9.0)),
            )
        else:
            scanners[name] = ScannerConfig(skip=skip)

    return PipeGuardConfig(
        api_url=str(api_url) if api_url else None,
        scanners=scanners,
    )
