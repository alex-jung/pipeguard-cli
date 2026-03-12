# Contributing to PipeGuard

Thank you for your interest in contributing! PipeGuard is an open-source security scanner for GitHub Actions workflows — every contribution that makes CI/CD pipelines safer matters.

---

## Table of Contents

- [Getting Started](#getting-started)
- [Ways to Contribute](#ways-to-contribute)
- [Development Setup](#development-setup)
- [Project Structure](#project-structure)
- [Writing a New Check](#writing-a-new-check)
- [Tests](#tests)
- [Code Style](#code-style)
- [Submitting a Pull Request](#submitting-a-pull-request)
- [Reporting Bugs](#reporting-bugs)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Getting Started

1. Fork the repository and clone your fork
2. Set up your development environment (see [Development Setup](#development-setup))
3. Open an issue before starting significant work — this avoids duplicate effort and lets us align on the approach

---

## Ways to Contribute

- **New security checks** — detected a dangerous workflow pattern PipeGuard misses? Open an issue with a real workflow example that demonstrates the problem
- **Expanding the CVE database** — found a GitHub Actions CVE with CVSS ≥ 9.0 that is missing? Open a PR against `pipeguard/scanner/github_actions/cve_db.json`
- **Improving fix suggestions** — better `fix_suggestion` wording is always welcome
- **Bug reports** — false positives and false negatives are bugs; please report them
- **Documentation** — corrections, clearer explanations, additional examples

---

## Development Setup

**Prerequisites:** Python 3.11+, [actionlint](https://github.com/rhysd/actionlint) (optional, required for syntax checks)

```bash
git clone https://github.com/alex-jung/pipeguard-cli.git
cd pipeguard-cli
python -m venv .venv
source .venv/bin/activate       # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

Verify everything works:

```bash
pytest
ruff check pipeguard tests
mypy pipeguard
```

---

## Project Structure

```
pipeguard/
├── cli.py                              # Entry point — wires all scanners together
├── scanner/
│   ├── base.py                         # Finding dataclass (rule, severity, message, …)
│   └── github_actions/
│       ├── sha_pinning.py              # SHA-pinning check (actions + reusable workflows)
│       ├── permissions.py              # Permission audit
│       ├── secrets_flow.py             # Secrets-leak detection (echo, set -x, …)
│       ├── pull_request_target.py      # Dangerous trigger detection
│       ├── supply_chain.py             # Untrusted publisher check
│       ├── cve_check.py                # Offline CVE database check
│       ├── action_inventory.py         # Action inventory (info-level)
│       ├── actionlint_runner.py        # actionlint subprocess wrapper
│       └── cve_db.json                 # Bundled CVE database
└── output/
    ├── formatter.py                    # Terminal / JSON / SARIF output
    └── autofix.py                      # Fix suggestion helpers
tests/
├── fixtures/                           # Real workflow examples used in tests
└── test_*.py
```

---

## Writing a New Check

### 1. Open an issue first

Include a concrete workflow file that demonstrates the problem. This is required before a PR will be reviewed.

### 2. Create the scanner module

```python
# pipeguard/scanner/github_actions/my_check.py
from __future__ import annotations
from pathlib import Path
import yaml
from pipeguard.scanner.base import Finding

def check_my_rule(workflow_path: str) -> list[Finding]:
    text = Path(workflow_path).read_text()
    data = yaml.safe_load(text)
    findings: list[Finding] = []
    # ... detection logic ...
    findings.append(
        Finding(
            rule="my-rule",
            message="Clear description of what is wrong.",
            file=workflow_path,
            line=0,
            col=0,
            severity="error",  # or "warning" or "info"
            fix_suggestion="Concrete, actionable fix.",
        )
    )
    return findings
```

**Severity guide:**

| Severity | When to use |
|----------|-------------|
| `error`  | Directly exploitable or high-confidence security risk |
| `warning`| Elevated risk, context-dependent, or best-practice violation |
| `info`   | Informational only — does not affect the exit code |

### 3. Register the check in `cli.py`

```python
from pipeguard.scanner.github_actions.my_check import check_my_rule

def _scan_file(workflow: Path) -> list[Finding]:
    findings = []
    ...
    findings += check_my_rule(str(workflow))
    ...
    return findings
```

### 4. Add fixtures and tests

Every new check **must** include:

- At least one fixture in `tests/fixtures/` — a real (or realistic) workflow file that triggers the finding. No synthetic or minimal YAML that would never appear in the wild.
- Tests covering: positive case (finding is raised), negative case (no false positive), and edge cases

```python
# tests/test_my_check.py
from pipeguard.scanner.github_actions.my_check import check_my_rule

FIXTURES = "tests/fixtures"

def test_my_rule_flagged():
    findings = check_my_rule(f"{FIXTURES}/my_rule_bad.yml")
    assert any(f.rule == "my-rule" for f in findings)

def test_my_rule_clean(tmp_path):
    wf = tmp_path / "wf.yml"
    wf.write_text("...")
    assert check_my_rule(str(wf)) == []
```

---

## Tests

```bash
pytest                        # run all tests
pytest tests/test_my_check.py # run a specific file
pytest --cov=pipeguard        # with coverage
```

All tests must pass before a PR can be merged. The CI runs the full suite against Python 3.11, 3.12, and 3.13.

**Rules for fixtures:**

- Use realistic workflow content — copy from public repos and anonymise if needed
- Never include real secrets, tokens, or API keys — use placeholder values like `${{ secrets.MY_SECRET }}`
- Add a comment at the top of every fixture explaining its purpose

---

## Code Style

PipeGuard uses [ruff](https://docs.astral.sh/ruff/) for linting and formatting, and [mypy](https://mypy.readthedocs.io/) for type checking.

```bash
ruff check pipeguard tests   # lint
mypy pipeguard               # type check
```

Key rules:

- Line length: **100 characters**
- All public functions must have type annotations
- No `# type: ignore` without a comment explaining why
- No secrets, tokens, or API keys anywhere in the codebase

---

## Submitting a Pull Request

1. **Branch naming:** `feature/<short-description>`, `fix/<short-description>`, `chore/<short-description>`
2. **Keep PRs focused** — one feature or fix per PR
3. **All checks must pass:** `pytest`, `ruff check`, `mypy`
4. **Update the README** if you add a new rule (Security checks table)
5. **No `Co-Authored-By: Claude` or similar AI attribution lines** in commit messages

PR title format:

```
feat: add <rule-name> check
fix: correct false positive in <scanner>
chore: update CVE database
```

---

## Reporting Bugs

Open a [GitHub Issue](https://github.com/alex-jung/pipeguard-cli/issues) and include:

- PipeGuard version (`pipeguard --version`)
- The workflow file that triggered the issue (or a minimal reproduction)
- Expected behavior vs. actual behavior
- Full terminal output

---

## Security Vulnerabilities

**Do not open a public issue for security vulnerabilities.**
Please follow the [Security Policy](SECURITY.md).
