# Security Policy

## Supported Versions

Only the latest release receives security fixes.

| Version | Supported |
|---------|:---------:|
| Latest  | ✅        |
| Older   | ❌        |

---

## Reporting a Vulnerability

**Please do not open a public GitHub issue for security vulnerabilities.**

Report vulnerabilities privately via [GitHub Security Advisories](https://github.com/alex-jung/pipeguard-cli/security/advisories/new).

Include as much detail as possible:

- Description of the vulnerability and its potential impact
- Steps to reproduce (workflow file, command, output)
- Affected version (`pipeguard --version`)
- Suggested fix if you have one

---

## Response Timeline

| Step | Target |
|------|--------|
| Acknowledgement | within 48 hours |
| Initial assessment | within 5 business days |
| Fix or mitigation | within 30 days for critical issues |
| Public disclosure | after fix is released |

---

## Scope

### In Scope

- **False negatives** — a dangerous workflow pattern that PipeGuard does not detect
- **False positives causing security bypass** — a check that can be silenced by crafting malicious input
- **Dependency vulnerabilities** — vulnerabilities in PipeGuard's own dependencies (`pyyaml`, `click`, `rich`, `requests`)
- **Supply-chain issues** — compromised actions or dependencies in PipeGuard's own CI/CD

### Out of Scope

- Vulnerabilities in workflows that PipeGuard is designed to *detect* (report those to the affected project)
- Missing checks for patterns not yet on the roadmap — open a regular issue instead
- actionlint bugs — report those upstream at [rhysd/actionlint](https://github.com/rhysd/actionlint/issues)

---

## Disclosure Policy

PipeGuard follows [coordinated disclosure](https://en.wikipedia.org/wiki/Coordinated_vulnerability_disclosure):

1. Reporter submits the vulnerability privately
2. Maintainer confirms, develops, and releases a fix
3. A [GitHub Security Advisory](https://github.com/alex-jung/pipeguard-cli/security/advisories) is published after the fix is available
4. Reporter is credited in the advisory (unless they prefer to remain anonymous)

---

## Security Design Notes

PipeGuard is a **static analysis tool** — it reads YAML files and never executes workflow code. Key design decisions relevant to security:

- **Fully offline by default** — no outbound network calls during a scan
- **No secrets required** — Free-tier scans need no API keys or tokens
- **No code execution** — workflow files are parsed, never run
- **Read-only filesystem access** — PipeGuard only reads files, never writes to the repository

If you find a way to make PipeGuard execute arbitrary code by crafting a malicious workflow file, please report it immediately — that would be a critical vulnerability.
