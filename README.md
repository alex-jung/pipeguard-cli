# PipeGuard

<img src="assets/logo.jpg" alt="PipeGuard" width="200">

> Catch GitHub Actions security issues before they reach your runners.

Pre-commit security scanner for GitHub Actions workflows. Catches supply-chain risks, unpinned actions, and secret leaks — before you push.

---

## Installation

**Prerequisites:** Python 3.11+

```bash
pip install pipeguard
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

# Show auto-fix suggestions
pipeguard scan --fix
```

When scanning a directory, pipeguard prints a per-file header and a summary at the end:

```
Scanning: .github/workflows/ci.yml
  ✓ No issues found

Scanning: .github/workflows/deploy.yml
  ╭─────────┬─────────────┬──────────────────────────┬──────────────╮
  │ Severity│ Rule        │ Location                 │ Message      │
  ├─────────┼─────────────┼──────────────────────────┼──────────────┤
  │ error   │ sha-pinning │ deploy.yml:12            │ Action ...   │
  ╰─────────┴─────────────┴──────────────────────────┴──────────────╯

Scanned 2 file(s) — 1 error(s), 0 warning(s) total.
```

### Exit codes

| Code | Meaning |
|------|---------|
| `0`  | No issues found |
| `1`  | One or more issues found |

Use exit code `1` to fail CI pipelines on findings.

---

## Security checks

| Rule | Severity | Description |
|------|----------|-------------|
| `sha-pinning` | error | Action pinned to a tag or branch instead of a full commit SHA — supply-chain risk (cf. [CVE-2025-30066](https://github.com/advisories/GHSA-mrrh-fwg3-99v7)) |
| `supply-chain` | warning | Third-party action from an unverified publisher |
| `secrets-leak` | error | Secret value echoed or logged in a `run:` step |
| `permissions-missing` | error | No `permissions:` block — GitHub grants write access to most scopes by default |
| `permissions-write-all` | error | `permissions: write-all` at top-level or per-job |
| `permissions-excessive` | warning | Sensitive scope (e.g. `secrets`, `workflows`) set to `write` |
| `permissions-invalid` | error | Unknown permission level (not `read`, `write`, or `none`) |
| `actionlint` | error | Syntax and type errors (requires actionlint) |

---

## CI integration

Add pipeguard as a pre-push check or CI step:

```yaml
# .github/workflows/pipeguard.yml
- name: Scan workflows
  run: |
    pip install pipeguard
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
        files: \.github/workflows/.*\.ya?ml$
```

---

## Output formats

**Terminal** (default) — human-readable table with rule, location, and fix suggestions.

**JSON** — machine-readable, one object per finding:

```json
[
  {
    "rule": "sha-pinning",
    "severity": "error",
    "message": "Action 'actions/checkout' is pinned to 'v3' instead of a full commit SHA.",
    "file": ".github/workflows/ci.yml",
    "line": 12,
    "fix_suggestion": "Pin to a specific commit SHA: uses: actions/checkout@<sha>  # v3"
  }
]
```

**SARIF** — compatible with GitHub Code Scanning and IDE plugins (VS Code, JetBrains).

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

## Status

In active development. Core scanner (SHA pinning, supply-chain, secrets flow, permission analysis) is functional.
Planned: cloud sandbox testing, auto-fix PRs, IDE plugin.
