"""Renders findings in terminal, JSON, and SARIF formats."""

from __future__ import annotations

import json
from enum import StrEnum
from typing import TYPE_CHECKING

from rich.console import Console

if TYPE_CHECKING:
    from pipeguard.dataclasses import Finding


class OutputFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"


class Formatter:
    def __init__(
        self,
        fmt: OutputFormat = OutputFormat.TERMINAL,
        show_fix: bool = False,
        verbose: bool = False,
    ) -> None:
        self.fmt = fmt
        self.show_fix = show_fix
        self.verbose = verbose
        import shutil

        self._console = Console(
            width=max(shutil.get_terminal_size(fallback=(200, 24)).columns, 200)
        )

    def render(self, findings: list[Finding], workflow_path: str) -> None:
        match self.fmt:
            case OutputFormat.TERMINAL:
                self._render_terminal(findings, workflow_path)
            case OutputFormat.JSON:
                self._render_json(findings)
            case OutputFormat.SARIF:
                self._render_sarif(findings, workflow_path)

    # ------------------------------------------------------------------
    # Terminal
    # ------------------------------------------------------------------

    _SEV_ICON: dict[str, tuple[str, str]] = {
        "error":   ("✗", "red"),
        "warning": ("⚠", "yellow"),
        "info":    ("·", "blue"),
    }

    def _render_terminal(self, findings: list[Finding], workflow_path: str) -> None:
        self._console.print(f"\n[bold]{workflow_path}[/bold]")
        if not findings:
            self._console.print("[green]  ✓ No issues found[/green]")
            return

        for f in findings:
            icon, sev_style = self._SEV_ICON.get(f.severity, ("·", "white"))
            score_tag = (
                f" [magenta][{f.score}/100][/magenta]"
                if self.verbose and f.score is not None
                else ""
            )
            self._console.print(
                f"  [{sev_style}]{icon} {f.severity:<8}[/{sev_style}]"
                f"  [cyan]{f.rule:<28}[/cyan]"
                f"  [dim]line {f.line:>4}[/dim]"
                f"{score_tag}"
                f"  {f.message}"
            )
            if self.show_fix and f.fix_suggestion:
                self._console.print(f"             [dim]↳[/dim] [green]{f.fix_suggestion}[/green]")
            if self.verbose:
                self._render_finding_detail(f)

        errors = sum(1 for f in findings if f.severity == "error")
        warnings = sum(1 for f in findings if f.severity == "warning")
        color = "red" if errors else "yellow"
        self._console.print(
            f"\n  [{color}]{len(findings)} issue(s) found "
            f"({errors} error(s), {warnings} warning(s))[/{color}]"
        )

    def _render_finding_detail(self, f: Finding) -> None:
        """Print detail chain and patch for a single finding (verbose mode)."""
        if f.detail:
            for line in f.detail:
                self._console.print(f"             [dim]│  {line}[/dim]")
        if f.patch:
            self._console.print("             [dim]│[/dim]  [green]patch:[/green]")
            for line in f.patch.splitlines():
                self._console.print(f"             [dim]│[/dim]    [green]{line}[/green]")

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def _render_json(self, findings: list[Finding]) -> None:
        output = [
            {
                "id": f.id,
                "rule": f.rule,
                "severity": f.severity,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "col": f.col,
                "fix_suggestion": f.fix_suggestion,
                "patch": f.patch,
                "score": f.score,
                "detail": f.detail,
            }
            for f in findings
        ]
        print(json.dumps(output, indent=2))

    # ------------------------------------------------------------------
    # SARIF 2.1.0
    # ------------------------------------------------------------------

    def _render_sarif(self, findings: list[Finding], workflow_path: str) -> None:
        results = []
        rules: dict[str, dict[str, object]] = {}

        for f in findings:
            rules[f.rule] = {
                "id": f.rule,
                "shortDescription": {"text": f.rule},
            }
            results.append(
                {
                    "ruleId": f.rule,
                    "level": "error" if f.severity == "error" else "warning",
                    "message": {"text": f.message},
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.file},
                                "region": {"startLine": f.line, "startColumn": f.col},
                            }
                        }
                    ],
                }
            )

        sarif = {
            "version": "2.1.0",
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "pipeguard",
                            "rules": list(rules.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }
        print(json.dumps(sarif, indent=2))
