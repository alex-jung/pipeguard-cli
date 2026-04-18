# PipeGuard

<div align="center">

[![CI](https://github.com/alex-jung/pipeguard-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/alex-jung/pipeguard-cli/actions/workflows/ci.yml)
[![PyPI Version](https://img.shields.io/pypi/v/pipeguard-cli)](https://pypi.org/project/pipeguard-cli/)
[![Downloads](https://img.shields.io/pypi/dw/pipeguard-cli)](https://pypi.org/project/pipeguard-cli/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue)](LICENSE)

</div>

<div align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="assets/logo-dark.svg">
    <img src="assets/logo-light.svg" alt="PipeGuard" width="200">
  </picture>
</div>

> Catch GitHub Actions security issues before they reach your runners.

Pre-commit security scanner for GitHub Actions workflows. Catches supply-chain risks, unpinned actions, known CVEs, and secret leaks — before you push.

---

## PipeGuard vs. the alternatives

| Feature | PipeGuard | actionlint | StepSecurity | act |
|---------|:---------:|:----------:|:------------:|:---:|
| SHA-pinning check | ✅ | ❌ | ✅ | ❌ |
| CVE database (offline) | ✅ | ❌ | ✅ (online) | ❌ |
| Permissions analysis | ✅ | ⚠️ syntax only | ✅ | ❌ |
| Secrets-leak detection | ✅ | ❌ | ✅ (runtime) | ❌ |
| Supply-chain audit | ✅ | ❌ | ✅ | ❌ |
| Syntax / type checks | ✅ via actionlint | ✅ | ❌ | ❌ |
| Run workflows locally | ❌ | ❌ | ❌ | ✅ |
| Runtime hardening | ❌ | ❌ | ✅ | ❌ |
| Pre-commit hook | ✅ | ✅ | ❌ | ❌ |
| SARIF output | ✅ | ✅ | ❌ | ❌ |
| No API key required | ✅ | ✅ | ❌ | ✅ |
| Fully offline | ✅ | ✅ | ❌ | ⚠️ needs images |
| Open source | ✅ | ✅ | ✅ | ✅ |
| Free | ✅ core | ✅ | ⚠️ freemium | ✅ |

PipeGuard fills the gap between authoring and execution: static security analysis, offline, before you push, without any external service.

---

## Installation

**Prerequisites:** Python 3.11+

```bash
pip install pipeguard-cli
```

**Install actionlint** (required for syntax checks, optional for other checks):

```bash
# Linux
curl -fsSL https://github.com/rhysd/actionlint/releases/latest/download/actionlint_linux_amd64.tar.gz \
  | tar xz actionlint && sudo mv actionlint /usr/local/bin/

# macOS
brew install actionlint

# Ubuntu/Debian (snap)
sudo snap install actionlint
```

---

## Usage

```bash
pipeguard scan [PATH]
```

`PATH` can be a single workflow file or a directory. If omitted, defaults to `.github/workflows`.

### Examples

```bash
# Scan entire .github/workflows directory (default)
pipeguard scan

# Scan a specific directory
pipeguard scan .github/workflows/

# Scan a single file
pipeguard scan .github/workflows/ci.yml

# JSON output (for scripts / CI pipelines)
pipeguard scan --format json

# SARIF output (for IDE integration, GitHub Code Scanning)
pipeguard scan --format sarif

# Use a custom config file
pipeguard scan --config path/to/.pipeguard.yml

# Run only specific scanner(s) — always runs locally
pipeguard scan --scanner sha-pinning
pipeguard scan --scanner sha-pinning --scanner cve
```

When scanning a directory, pipeguard prints a per-file header and a summary at the end:

```
.github/workflows/ci.yml
  ✓ No issues found

.github/workflows/deploy.yml
  ✗ error     sha-pinning               line   12  Action 'actions/checkout' is pinned to 'v3' instead of a full commit SHA.
  ✗ error     cve-cve-2025-30066        line   15  Action 'tj-actions/changed-files@v35' is affected by CVE-2025-30066: ...
  ⚠ warning   supply-chain              line   15  Untrusted action 'tj-actions/changed-files' — verify publisher and pin to a SHA.
  ✗ error     permissions-missing       line    1  No top-level 'permissions:' key found.
  · info      action-inventory          line   12  Action 'actions/checkout' used with ref(s): 'v3' (1 occurrence(s)).

  5 issue(s) found (3 error(s), 1 warning(s))

Scanned 2 file(s) — 3 error(s), 1 warning(s), 1 info(s) total.
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No errors or warnings |
| `1`  | One or more errors or warnings found |
| `2`  | Invalid or expired Pro license key |

Info-level findings (action inventory) do not affect the exit code.

### Options

| Flag | Description |
|------|-------------|
| `--format terminal\|json\|sarif` | Output format (default: `terminal`) |
| `--fix` | Apply auto-fixes via Pro API (requires license key) |
| `--config PATH` | Path to a `.pipeguard.yml` config file |
| `--verbose` / `-v` | Show per-scanner progress and Pro API response |
| `--scanner NAME` | Run only this scanner. Can be repeated. Respects config file settings (e.g. `trusted_publishers`, `min_cvss`) but overrides `skip`. Bypasses Pro API — always runs locally. Valid names: `sha-pinning`, `supply-chain`, `cve`, `permissions`, `secrets-flow`, `pull-request-target`, `actionlint`, `action-inventory` |

---

## Security checks

### Errors & Warnings

| Rule | Severity | Description |
|------|----------|-------------|
| `sha-pinning` | error | Action pinned to a tag or branch instead of a full commit SHA — supply-chain risk (cf. [CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066)) |
| `sha-pinning-reusable` | error | Reusable workflow called with a tag or branch ref instead of a full commit SHA — same supply-chain risk as unpinned actions |
| `cve-<id>` | error | Action matches a known CVE in the local database (offline, no API) |
| `supply-chain` | warning | Third-party action from an unverified publisher — suppress per publisher or action via `.pipeguard.yml` |
| `secrets-leak` | error | Secret value echoed or logged in a `run:` step |
| `secrets-leak-debug` | error / warning | `set -x` or `set -o xtrace` in a `run:` step — shell debug mode prints every expanded command; error when secrets are in env scope, warning otherwise |
| `permissions-missing` | error | No `permissions:` block — GitHub grants write access to most scopes by default |
| `permissions-write-all` | error | `permissions: write-all` at top-level or per-job |
| `permissions-excessive` | warning | Sensitive scope (e.g. `secrets`, `workflows`) set to `write` |
| `permissions-id-token-unused` | warning | `id-token: write` is set but no OIDC-consuming action is present — allows minting cloud credentials unnecessarily |
| `permissions-invalid` | error | Unknown permission level (not `read`, `write`, or `none`) |
| `pull-request-target` | warning | `pull_request_target` trigger runs with base-repo write permissions and secret access — even for fork PRs |
| `pull-request-target-pwn` | error | `pull_request_target` combined with checkout of the PR head ref — allows untrusted fork code to run with secrets (Pwn Request) |
| `actionlint` | error | Syntax and type errors (requires actionlint) |

### Info

| Rule | Severity | Description |
|------|----------|-------------|
| `action-inventory` | info | Inventory of all third-party actions used — ref(s) and occurrence count |

---

## CVE database

PipeGuard ships with a built-in offline CVE database — no API key, no network call during scan. The database is updated daily via NVD and shipped with each new weekly release.

<!-- cve-updated-start -->
> [!NOTE]
> Last updated: 2026-04-18
<!-- cve-updated-end -->

<!-- cve-table-start -->
| CVE | Action | Description |
|-----|--------|-------------|
| [CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066) | `tj-actions/changed-files` | tj-actions/changed-files was compromised in a supply-chain attack. All tag-based refs are potentially affected — pin to a known-good SHA. |
| [CVE-2025-30154](https://www.cve.org/CVERecord?id=CVE-2025-30154) | `reviewdog/action-setup` | reviewdog/action-setup was compromised in the same supply-chain campaign as tj-actions/changed-files. Pin to a vetted SHA. |
| [CVE-2023-49291](https://www.cve.org/CVERecord?id=CVE-2023-49291) | `tj-actions/branch-names` | tj-actions/branch-names improperly references github.event.pull_request.head.ref and github.head_ref in a run step, allowing a specially crafted branch name to execute arbitrary code and steal secrets or abuse GITHUB_TOKEN permissions. |
<!-- cve-table-end -->

SHA-pinned refs are not flagged — another reason to always pin to a commit SHA.

To get the latest CVEs, upgrade to the newest release:

```bash
pip install --upgrade pipeguard-cli
```

---

## Configuration

PipeGuard looks for a `.pipeguard.yml` (or `.pipeguard.yaml`, `pipeguard.yml`, `pipeguard.yaml`) in the current directory and its parents.

All scanner settings live under a `scanners:` key. Each scanner can be configured independently:

```yaml
# .pipeguard.yml

scanners:
  # Disable a scanner entirely
  supply-chain:
    skip: false                 # default; set to true to disable
    trusted_publishers:
      - my-org                  # suppresses warnings for my-org/*
      - some-vendor
    trusted_actions:
      - other-org/specific-action  # exact match, without @ref

  # Lower the CVE severity threshold (default: 9.0)
  cve:
    min_cvss: 7.0

  # Skip a scanner entirely
  actionlint:
    skip: true
```

**Scanner names:** `sha-pinning`, `supply-chain`, `cve`, `permissions`, `secrets-flow`, `pull-request-target`, `actionlint`, `action-inventory`.

- `trusted_publishers` matches as a prefix — every action from `my-org/*` is considered trusted.
- `trusted_actions` requires an exact match on the action name (without the `@ref`).
- A trailing `/` in publisher names is optional; PipeGuard normalises it automatically.
- Scanners not listed in the config file run with their defaults.

The built-in allowlist (GitHub, AWS, Azure, Google, Docker, HashiCorp, etc.) is always active and cannot be removed.

---

## CI integration

Add pipeguard as a pre-push check or CI step:

```yaml
# .github/workflows/pipeguard.yml
- name: Scan workflows
  run: |
    pip install pipeguard-cli
    pipeguard scan .github/workflows/
```

Or as a pre-commit hook (`.pre-commit-config.yaml`):

```yaml
repos:
  - repo: local
    hooks:
      - id: pipeguard
        name: PipeGuard workflow scan
        entry: pipeguard scan
        language: python
        additional_dependencies: [pipeguard-cli]
        files: \.github/workflows/.*\.ya?ml$
```

---

## Output formats

**Terminal** (default) — human-readable table with rule, location, and fix suggestions.

**JSON** — machine-readable, one object per finding:

```json
[
  {
    "id": "a1b2c3d4e5f6",
    "rule": "cve-cve-2025-30066",
    "severity": "error",
    "message": "Action 'tj-actions/changed-files@v35' is affected by CVE-2025-30066: ...",
    "file": ".github/workflows/ci.yml",
    "line": 12,
    "col": 0,
    "fix_suggestion": "Immediately pin 'tj-actions/changed-files' to a verified safe SHA.",
    "patch": null,
    "score": null,
    "detail": null
  }
]
```

Each finding has a stable `id` (`sha256(rule:line:message)[:12]`) — valid within one scan session. Use it to reference specific findings when calling the Pro API for auto-fixes.

**SARIF** — compatible with GitHub Code Scanning.

---

## PipeGuard Pro

PipeGuard Pro extends the free CLI with deeper analysis and auto-fix capabilities via a cloud API.

### Activate a license key

```bash
pipeguard auth <your-license-key>
```

The key is stored in `~/.pipeguard/credentials` and picked up automatically on every `pipeguard scan`. You can also set it via the environment:

```bash
export PIPEGUARD_LICENSE_KEY=<your-license-key>
```

### How Pro mode works

When a license key is present, **all scanning is handled by the Pro API** — free local scanners are skipped entirely. The Pro API runs the same free checks plus additional deep-analysis scanners, and returns findings with optional `patch` and `score` fields.

If the Pro API is unreachable or returns an error, PipeGuard automatically falls back to the free local scanners.

### Auto-fix

```bash
pipeguard scan --fix
```

Sends findings with available patches back to the Pro API (`POST /v1/fix`). The patched workflow is written back to disk. Applied and skipped counts are printed at the end.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).
