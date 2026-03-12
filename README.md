# PipeGuard

<div align="center">

[![CI](https://github.com/alex-jung/pipeguard-cli/actions/workflows/ci.yml/badge.svg)](https://github.com/alex-jung/pipeguard-cli/actions/workflows/ci.yml)
[![PyPI Version](https://img.shields.io/pypi/v/pipeguard-cli)](https://pypi.org/project/pipeguard-cli/)
[![Downloads](https://img.shields.io/pypi/dm/pipeguard-cli)](https://pypi.org/project/pipeguard-cli/)
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

## Demo

![Demo](assets/demo.gif)

The recording shows a scan of a real workflow file with multiple security issues.
PipeGuard detects them all in under a second — no API key, no network call, fully offline:

- No top-level `permissions:` block — GitHub grants write access to all scopes by default
- `tj-actions/changed-files@v35` and `reviewdog/action-setup@v1` match known CVEs in the bundled database
- All actions are pinned to tags instead of commit SHAs — a supply-chain risk
- `echo ${{ secrets.DEPLOY_TOKEN }}` leaks a secret value to the workflow log
- `8398a7/action-slack` is a third-party action from an unverified publisher

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
```

When scanning a directory, pipeguard prints a per-file header and a summary at the end:

```
Scanning: .github/workflows/ci.yml
  ✓ No issues found

Scanning: .github/workflows/deploy.yml
  ╭─────────┬──────────────────┬──────────────────────────┬──────────────╮
  │ Severity│ Rule             │ Location                 │ Message      │
  ├─────────┼──────────────────┼──────────────────────────┼──────────────┤
  │ error   │ cve-cve-2025-... │ deploy.yml:12            │ Action ...   │
  │ error   │ sha-pinning      │ deploy.yml:15            │ Action ...   │
  ╰─────────┴──────────────────┴──────────────────────────┴──────────────╯

Scanned 2 file(s) — 2 error(s), 1 warning(s), 3 info(s) total.
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No errors or warnings |
| `1`  | One or more errors or warnings found |

Info-level findings (action inventory) do not affect the exit code.

---

## Security checks

### Errors & Warnings

| Rule | Severity | Description |
|------|----------|-------------|
| `sha-pinning` | error | Action pinned to a tag or branch instead of a full commit SHA — supply-chain risk (cf. [CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066)) |
| `cve-<id>` | error | Action matches a known CVE in the local database (offline, no API) |
| `supply-chain` | warning | Third-party action from an unverified publisher |
| `secrets-leak` | error | Secret value echoed or logged in a `run:` step |
| `permissions-missing` | error | No `permissions:` block — GitHub grants write access to most scopes by default |
| `permissions-write-all` | error | `permissions: write-all` at top-level or per-job |
| `permissions-excessive` | warning | Sensitive scope (e.g. `secrets`, `workflows`) set to `write` |
| `permissions-id-token-unused` | warning | `id-token: write` is set but no OIDC-consuming action is present — allows minting cloud credentials unnecessarily |
| `permissions-invalid` | error | Unknown permission level (not `read`, `write`, or `none`) |
| `actionlint` | error | Syntax and type errors (requires actionlint) |

### Info

| Rule | Severity | Description |
|------|----------|-------------|
| `action-inventory` | info | Inventory of all third-party actions used — ref(s) and occurrence count |

---

## CVE database

PipeGuard ships with a built-in offline CVE database — no API key, no network call during scan. The database is updated daily via NVD and shipped with each new weekly release.

| CVE | Action | Description |
|-----|--------|-------------|
| [CVE-2025-30066](https://www.cve.org/CVERecord?id=CVE-2025-30066) | `tj-actions/changed-files` | Supply-chain attack — all tag-based refs affected |
| [CVE-2025-30154](https://www.cve.org/CVERecord?id=CVE-2025-30154) | `reviewdog/action-setup` | Supply-chain attack — same campaign as CVE-2025-30066 |
| [CVE-2023-49291](https://www.cve.org/CVERecord?id=CVE-2023-49291) | `tj-actions/branch-names` | Script injection via crafted branch name — steals secrets and abuses GITHUB_TOKEN |

SHA-pinned refs are not flagged — another reason to always pin to a commit SHA.

To get the latest CVEs, upgrade to the newest release:

```bash
pip install --upgrade pipeguard-cli
```

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
    "rule": "cve-cve-2025-30066",
    "severity": "error",
    "message": "Action 'tj-actions/changed-files@v35' is affected by CVE-2025-30066: ...",
    "file": ".github/workflows/ci.yml",
    "line": 12,
    "fix_suggestion": "Immediately pin 'tj-actions/changed-files' to a verified safe SHA."
  }
]
```

**SARIF** — compatible with GitHub Code Scanning.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Status

In active development. All Free-tier scanners are functional.
Planned: auto-fix PRs (Pro), Maintainer Trust Score (Pro), cloud sandbox testing, IDE plugin.

Free-tier checks: SHA-pinning, CVE database, permissions audit (incl. `id-token: write` without OIDC), secrets-leak detection, action inventory, actionlint syntax checks.
