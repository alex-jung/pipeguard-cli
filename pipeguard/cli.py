"""Entry point: pipeguard scan"""

import click

from pipeguard import __version__
from pipeguard.scanner.actionlint_runner import run_actionlint
from pipeguard.scanner.sha_pinning import check_sha_pinning
from pipeguard.scanner.secrets_flow import check_secrets_flow
from pipeguard.scanner.supply_chain import check_supply_chain
from pipeguard.output.formatter import Formatter, OutputFormat


@click.group()
@click.version_option(__version__, prog_name="pipeguard")
def main() -> None:
    """PipeGuard — catch GitHub Actions security issues before they reach your runners."""


@main.command()
@click.argument("workflow", type=click.Path(exists=True))
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["terminal", "json", "sarif"]),
    default="terminal",
    show_default=True,
    help="Output format.",
)
@click.option("--fix", is_flag=True, help="Generate auto-fix suggestions.")
def scan(workflow: str, output_format: str, fix: bool) -> None:
    """Scan a GitHub Actions WORKFLOW file for security issues."""
    fmt = Formatter(OutputFormat(output_format))

    findings = []
    findings += run_actionlint(workflow)
    findings += check_sha_pinning(workflow)
    findings += check_secrets_flow(workflow)
    findings += check_supply_chain(workflow)

    fmt.render(findings, workflow)

    if findings:
        raise SystemExit(1)
