"""Module-level constants shared across PipeGuard."""

from __future__ import annotations

import re
from pathlib import Path

# ---------------------------------------------------------------------------
# API / Infrastructure
# ---------------------------------------------------------------------------

DEFAULT_API_URL = "https://api.pipe-guard.de"
API_TIMEOUT = 30
CREDENTIALS_FILE = Path.home() / ".pipeguard" / "credentials"

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

WORKFLOW_GLOB = ("*.yml", "*.yaml")

# ---------------------------------------------------------------------------
# Shared regex (used across multiple scanners)
# ---------------------------------------------------------------------------

# Matches "owner/repo@ref" in `uses:` lines.
USES_RE = re.compile(r"^(?P<action>[^@]+)@(?P<ref>.+)$")

# A full commit SHA is exactly 40 hex characters.
SHA_RE = re.compile(r"^[0-9a-f]{40}$")

# ---------------------------------------------------------------------------
# Supply-chain scanner
# ---------------------------------------------------------------------------

# Well-known trusted publisher prefixes (allowlist seed).
# Includes official publishers from GitHub, major cloud providers,
# and widely adopted ecosystem tools.
TRUSTED_PUBLISHERS: frozenset[str] = frozenset({
    # GitHub official
    "actions/",
    "github/",
    # Container / packaging
    "docker/",
    # Cloud providers
    "aws-actions/",
    "google-github-actions/",
    "azure/",
    # HashiCorp
    "hashicorp/",
    # Microsoft
    "microsoft/",
    # Security / signing
    "sigstore/",
    "aquasecurity/",
    # Kubernetes ecosystem
    "helm/",
    # Code quality
    "codecov/",
    "coverallsapp/",
    # Package managers / runtimes
    "pnpm/",
    "ruby/",
    "gradle/",
})

# ---------------------------------------------------------------------------
# Secrets-flow scanner
# ---------------------------------------------------------------------------

# Patterns that suggest a secret value is being echoed or logged.
SECRETS_LEAK_PATTERNS = [
    re.compile(r"echo\s+\$\{\{\s*secrets\.", re.IGNORECASE),
    re.compile(r"echo\s+\$[A-Z_]+_TOKEN", re.IGNORECASE),
    re.compile(r"curl\s+.*-H\s+['\"]Authorization", re.IGNORECASE),
]

# Patterns that enable bash/sh debug mode (prints every expanded command).
SECRETS_SET_X_PATTERNS = [
    re.compile(r"set\s+-[a-z]*x", re.IGNORECASE),        # set -x, set -ex, set -euxo pipefail …
    re.compile(r"set\s+-o\s+xtrace", re.IGNORECASE),      # set -o xtrace
    re.compile(r"#!.*sh\b.*-[a-z]*x", re.IGNORECASE),    # #!/bin/bash -x shebang
]

SECRETS_REF_RE = re.compile(r"\$\{\{\s*secrets\.", re.IGNORECASE)

# ---------------------------------------------------------------------------
# Permissions scanner
# ---------------------------------------------------------------------------

VALID_PERMISSION_LEVELS: frozenset[str] = frozenset({"read", "write", "none"})

# Actions that legitimately consume an OIDC token.
OIDC_ACTIONS: frozenset[str] = frozenset({
    "aws-actions/configure-aws-credentials",
    "google-github-actions/auth",
    "azure/login",
    "sigstore/cosign-installer",
    "sigstore/cosign-action",
    "actions/attest-build-provenance",
    "actions/attest",
})

SENSITIVE_SCOPES: frozenset[str] = frozenset({
    "actions",
    "administration",
    "deployments",
    "environments",
    "packages",
    "pages",
    "repository-projects",
    "secrets",
    "security-events",
    "statuses",
    "workflows",
})

IMPLICIT_PERMISSIONS_MESSAGE = (
    "No top-level 'permissions:' key found. "
    "GitHub grants write access to most scopes by default — "
    "add 'permissions: read-all' or scope explicitly."
)

# ---------------------------------------------------------------------------
# Pull-request-target scanner
# ---------------------------------------------------------------------------

# Expressions that reference the PR contributor's code in a checkout ref.
HEAD_REF_PATTERNS = [
    re.compile(r"github\.event\.pull_request\.head\.(ref|sha)"),
    re.compile(r"github\.head_ref"),
]
