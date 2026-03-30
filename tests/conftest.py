"""Shared pytest fixtures for pipeguard tests."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def no_license_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Prevent tests from picking up a real license key from the environment
    or credentials file. Tests that need Pro behaviour must explicitly patch
    resolve_license_key themselves."""
    monkeypatch.setenv("PIPEGUARD_LICENSE_KEY", "")
    monkeypatch.setattr("pipeguard.cli.resolve_license_key", lambda: None)
