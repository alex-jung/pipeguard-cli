"""Renders findings in terminal, JSON, and SARIF formats."""

from __future__ import annotations

import json
from enum import StrEnum
from typing import TYPE_CHECKING

from rich import box
from rich.console import Console
from rich.table import Table

if TYPE_CHECKING:
    from pipeguard.scanner.base import Finding


class OutputFormat(StrEnum):
    TERMINAL = "terminal"
    JSON = "json"
    SARIF = "sarif"


class Formatter:
    def __init__(self, fmt: OutputFormat = OutputFormat.TERMINAL) -> None:
        self.fmt = fmt
        self._console = Console()

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

    def _render_terminal(self, findings: list[Finding], workflow_path: str) -> None:
        self._console.print(f"\n[bold]Scanning:[/bold] {workflow_path}")
        if not findings:
            self._console.print("[green]  ✓ No issues found[/green]")
            return

        table = Table(box=box.ROUNDED, show_lines=True)
        table.add_column("Severity", style="bold", width=9)
        table.add_column("Rule", style="cyan", width=18)
        table.add_column("Location", width=30)
        table.add_column("Message")

        for f in findings:
            sev_style = {"error": "red", "warning": "yellow", "info": "blue"}.get(
                f.severity, "white"
            )
            table.add_row(
                f"[{sev_style}]{f.severity}[/{sev_style}]",
                f.rule,
                f"{f.file}:{f.line}",
                f.message + (f"\n[dim]Fix: {f.fix_suggestion}[/dim]" if f.fix_suggestion else ""),
            )

        self._console.print(table)
        self._console.print(
            f"\n[bold]{'[red]' if any(f.severity == 'error' for f in findings) else '[yellow]'}"
            f"{len(findings)} issue(s) found.[/bold]"
        )

    # ------------------------------------------------------------------
    # JSON
    # ------------------------------------------------------------------

    def _render_json(self, findings: list[Finding]) -> None:
        output = [
            {
                "rule": f.rule,
                "severity": f.severity,
                "message": f.message,
                "file": f.file,
                "line": f.line,
                "col": f.col,
                "fix_suggestion": f.fix_suggestion,
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
