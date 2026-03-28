"""Loads .pipeguard.yml config from the project root."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class PipeGuardConfig:
    trusted_publishers: list[str] = field(default_factory=list)
    trusted_actions: list[str] = field(default_factory=list)
    api_url: str | None = None  # overrides DEFAULT_API_URL and PIPEGUARD_API_URL env var


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

    publishers = data.get("trusted_publishers", [])
    actions = data.get("trusted_actions", [])

    if not isinstance(publishers, list):
        publishers = []
    if not isinstance(actions, list):
        actions = []

    # Normalise: publisher prefixes must end with "/"
    normalised = [p if p.endswith("/") else p + "/" for p in publishers]

    api_url = data.get("api_url")

    return PipeGuardConfig(
        trusted_publishers=normalised,
        trusted_actions=[str(a) for a in actions],
        api_url=str(api_url) if api_url else None,
    )
