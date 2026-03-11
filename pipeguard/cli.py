"""Entry point: pipeguard scan"""

from __future__ import annotations

import sys
from pathlib import Path

import click

from pipeguard import __version__
from pipeguard.output.formatter import Formatter, OutputFormat
from pipeguard.scanner.actionlint_runner import Finding, run_actionlint
from pipeguard.scanner.permissions import check_permissions
from pipeguard.scanner.secrets_flow import check_secrets_flow
from pipeguard.scanner.sha_pinning import check_sha_pinning
from pipeguard.scanner.supply_chain import check_supply_chain

_WORKFLOW_GLOB = ("*.yml", "*.yaml")


def _collect_workflows(path: str) -> list[Path]:
    """Return workflow files from a file path or directory."""
    p = Path(path)
    if p.is_file():
        return [p]
    files: list[Path] = []
    for pattern in _WORKFLOW_GLOB:
        files.extend(sorted(p.rglob(pattern)))
    return files


def _scan_file(workflow: Path) -> list[Finding]:
    findings: list[Finding] = []
    findings += run_actionlint(str(workflow))
    findings += check_sha_pinning(str(workflow))
    findings += check_secrets_flow(str(workflow))
    findings += check_supply_chain(str(workflow))
    findings += check_permissions(str(workflow))
    return findings


@click.group()
@click.version_option(__version__, prog_name="pipeguard")
def main() -> None:
    """PipeGuard — catch GitHub Actions security issues before they reach your runners."""


@main.command()
@click.argument("path", default=".github/workflows", type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json", "sarif"]),
    default="terminal",
    show_default=True,
    help="Output format.",
)
@click.option("--fix", is_flag=True, help="Generate auto-fix suggestions.")
def scan(path: str, output_format: str, fix: bool) -> None:
    """Scan a workflow FILE or DIRECTORY (default: .github/workflows)."""
    workflows = _collect_workflows(path)

    if not workflows:
        click.echo(f"[pipeguard] No workflow files found in '{path}'.", err=True)
        sys.exit(0)

    fmt = Formatter(OutputFormat(output_format))
    all_findings: list[Finding] = []

    for workflow in workflows:
        findings = _scan_file(workflow)
        all_findings.extend(findings)
        fmt.render(findings, str(workflow))

    if len(workflows) > 1:
        total = len(all_findings)
        errors = sum(1 for f in all_findings if f.severity == "error")
        warnings = total - errors
        click.echo(
            f"\nScanned {len(workflows)} file(s) — "
            f"{errors} error(s), {warnings} warning(s) total."
        )

    if all_findings:
        sys.exit(1)
