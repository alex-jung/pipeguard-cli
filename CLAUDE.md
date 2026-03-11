# PipeGuard — CLAUDE.md

> **"Catch problems before they reach your runners — not after."**
> Pre-commit security scanner + cloud sandbox for GitHub Actions workflows.

---

## Was ist PipeGuard?

PipeGuard analysiert GitHub Actions Workflows **vor dem Push** auf Security-Risiken und testet sie in einer vollwertigen Cloud-Sandbox. Es positioniert sich als fehlende Schicht zwischen Authoring und Execution — nicht als Ersatz für actionlint, StepSecurity oder act, sondern als Ergänzung.

---

## Architektur & Module

### Modul A: Deep Security Scanner (Pre-Commit)
Statische Analyse in der IDE oder als Git-Hook, bevor Code gepusht wird.

- **Action Supply-Chain Audit** — Dependency-Graph aller Actions inkl. transitiver Abhängigkeiten mit Risiko-Score
- **Permission-Explosion Detector** — simuliert effektiven Permission-Scope, warnt bei Over-Provisioning
- **Secrets-Flow-Analyse** — trackt Datenfluss von Secrets durch Steps, erkennt potenzielle Lecks
- **Maintainer Trust Score** — bewertet Third-Party Actions nach Aktivität, CVE-Historie, Repository-Hygiene
- **Auto-Fix PRs** — generiert automatisch PRs für SHA-Pinning und Permission-Einschränkungen

### Modul B: Workflow Test Lab (Cloud-Sandbox)
Vollwertiges Workflow-Testing ohne Commit/Push-Zyklus.

- **Full-Fidelity Cloud-Sandbox** — GitHub-Actions-kompatible Umgebung inkl. Services, Caches, Artifacts, Matrix-Strategien
- **One-Click Test aus der IDE** — VS Code / JetBrains: Workflow ändern → Strg+Shift+T → Run in Sandbox
- **Interactive Debugging** — Breakpoints setzen, SSH / Web-Terminal auf Runner
- **Cost Estimator** — schätzt Kosten vor Ausführung (Runner-Typ, Matrix-Größe, historische Daten)
- **Diff & Replay** — zwei Workflow-Versionen vergleichen, fehlgeschlagene Runs wiederholen

---

## Tech Stack

```
CLI:         Python — ruft actionlint als subprocess auf, erweitert die Ausgabe
IDE-Plugin:  VS Code Extension (TypeScript) + JetBrains Plugin (Kotlin) — geplant
Backend:     TBD — API für Cloud-Sandbox, Security-Analyse-Engine
Cloud-Infra: Partner-Runner für Sandbox-Umgebung (TBD)
Auth:        GitHub OAuth (Personal / Org-Level)
```

---

## Repo-Struktur

```
pipeguard/
├── CLAUDE.md                          ← dieser File
├── CLAUDE.private.md                  
├── README.md
├── pyproject.toml
├── pipeguard/
│   ├── __init__.py
│   ├── cli.py                         (Einstiegspunkt: pipeguard scan)
│   ├── scanner/
│   │   ├── actionlint_runner.py       (ruft actionlint als subprocess auf)
│   │   ├── sha_pinning.py             (prüft & pinnt Action-Versionen)
│   │   ├── supply_chain.py            (Dependency-Graph, Trust Score)
│   │   └── secrets_flow.py            (Secrets-Leak-Erkennung)
│   └── output/
│       ├── formatter.py               (Terminal-Output, JSON, SARIF)
│       └── autofix.py                 (generiert Fix-Vorschläge)
├── tests/
│   └── fixtures/                      (Beispiel-Workflows für Tests)
└── .github/
    └── workflows/
        └── ci.yml
```

---

## Design-Prinzipien

- **Standard-YAML-Kompatibilität** — kein proprietäres Format, kein Lock-in
- **Security first** — Security-Features haben Priorität vor UX-Features
- **OSS-Kern bleibt kostenlos** — Basis-Security-Checks sind immer öffentlich und gratis
- **Aufbauen, nicht ersetzen** — actionlint erweitern
- **Fail fast, fail loud** — Fehler sollen früh und klar sichtbar sein, nie still ignoriert werden

---

## Coding-Regeln

- Alle neuen Scanner-Module brauchen Fixtures in `tests/fixtures/` — echte Workflow-Beispiele, keine synthetischen
- Output immer in drei Formaten unterstützen: Terminal (human-readable), JSON (maschinenlesbar), SARIF (IDE-Integration)
- Externe Abhängigkeiten minimal halten — actionlint muss lokal installiert sein, alles andere optional
- Keine Secrets oder API-Keys im Code oder in Tests — Fixtures verwenden ausschließlich Mock-Daten
- Vor jedem neuen Feature: Issue öffnen mit konkretem Workflow-Beispiel das das Problem demonstriert

---

## Wichtige Referenzen

- [actionlint](https://github.com/rhysd/actionlint) — Basis-Linter, auf dem PipeGuard aufbaut
- [StepSecurity Harden-Runner](https://github.com/step-security/harden-runner) — komplementäres Runtime-Tool
- [nektos/act](https://github.com/nektos/act) — lokales Testing-Tool (Inspiration + Limitation)
- [CVE-2025-30066](https://github.com/advisories/GHSA-mrrh-fwg3-99v7) — tj-actions Supply-Chain-Angriff, Hauptmotivation für PipeGuard
- [CISA Advisory](https://www.cisa.gov/news-events/alerts) — offizielle Warnungen zu GitHub Actions Security
