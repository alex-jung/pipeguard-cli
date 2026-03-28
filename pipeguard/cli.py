"""Entry point: pipeguard scan"""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click
import requests

from pipeguard import __version__
from pipeguard.config import PipeGuardConfig, load_config
from pipeguard.const import DEFAULT_API_URL, WORKFLOW_GLOB
from pipeguard.dataclasses import Finding, Severity
from pipeguard.license import (
    InvalidLicenseKeyError,
    call_pro_api,
    resolve_license_key,
    save_license_key,
)
from pipeguard.output.autofix import apply_fixes
from pipeguard.output.formatter import Formatter, OutputFormat
from pipeguard.scanner.github_actions.action_inventory import check_action_inventory
from pipeguard.scanner.github_actions.actionlint_runner import run_actionlint
from pipeguard.scanner.github_actions.cve_check import check_cve
from pipeguard.scanner.github_actions.permissions import check_permissions
from pipeguard.scanner.github_actions.pull_request_target import check_pull_request_target
from pipeguard.scanner.github_actions.secrets_flow import check_secrets_flow
from pipeguard.scanner.github_actions.sha_pinning import check_sha_pinning
from pipeguard.scanner.github_actions.supply_chain import check_supply_chain


def _collect_workflows(path: str) -> list[Path]:
    """Return workflow files from a file path or directory."""
    p = Path(path)
    if p.is_file():
        return [p]
    files: list[Path] = []
    for pattern in WORKFLOW_GLOB:
        files.extend(sorted(p.rglob(pattern)))
    return files


def _vlog(msg: str, verbose: bool) -> None:
    """Write a verbose log line to stderr."""
    if verbose:
        click.echo(f"[pipeguard] {msg}", err=True)


def _resolve_api_url(config: PipeGuardConfig | None) -> str:
    """Resolve Pro API URL: env var > config file > built-in default."""
    return (
        os.environ.get("PIPEGUARD_API_URL")
        or (config.api_url if config else None)
        or DEFAULT_API_URL
    )


def _scan_file(
    workflow: Path,
    config: PipeGuardConfig | None = None,
    license_key: str | None = None,
    verbose: bool = False,
    api_url: str = DEFAULT_API_URL,
) -> list[Finding]:
    findings: list[Finding] = []

    _free_scanners: list[tuple[str, list[Finding]]] = [
        ("actionlint",          run_actionlint(str(workflow))),
        ("sha-pinning",         check_sha_pinning(str(workflow))),
        ("secrets-flow",        check_secrets_flow(str(workflow))),
        ("supply-chain",        check_supply_chain(str(workflow), config)),
        ("permissions",         check_permissions(str(workflow))),
        ("pull-request-target", check_pull_request_target(str(workflow))),
        ("cve",                 check_cve(str(workflow))),
        ("action-inventory",    check_action_inventory(str(workflow))),
    ]

    for name, results in _free_scanners:
        findings += results
        icon = "✓" if not results else "!"
        _vlog(f"  {icon} {name:<22} {len(results)} finding(s)", verbose)

    # Pro — send workflow to backend, merge findings
    if license_key:
        _vlog(f"  → Pro API: {api_url}/v1/analyze", verbose)
        pro_findings = call_pro_api(
            str(workflow),
            license_key,
            trusted_publishers=config.trusted_publishers if config else [],
            trusted_actions=config.trusted_actions if config else [],
            api_url=api_url,
        )
        if pro_findings is not None:
            findings += pro_findings
            _vlog(f"  ← Pro API: {len(pro_findings)} finding(s) received", verbose)
        else:
            _vlog("  ✗ Pro API: request failed (skipping Pro checks)", verbose)

    return findings


@click.group()
@click.version_option(__version__, prog_name="pipeguard")
def main() -> None:
    """PipeGuard — catch GitHub Actions security issues before they reach your runners."""


@main.command()
@click.argument("key")
def auth(key: str) -> None:
    """Activate a PipeGuard Pro license key."""
    api_url = os.environ.get("PIPEGUARD_API_URL", DEFAULT_API_URL)
    try:
        resp = requests.get(f"{api_url}/v1/health", timeout=5)
        if not resp.ok:
            click.echo("[pipeguard] Could not reach the PipeGuard API.", err=True)
            sys.exit(1)
    except requests.RequestException:
        click.echo("[pipeguard] Could not reach the PipeGuard API.", err=True)
        sys.exit(1)

    save_license_key(key)
    click.echo("[pipeguard] License key saved. Pro features enabled.")


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
@click.option("--fix", is_flag=True, help="Apply auto-fixes (Pro).")
@click.option(
    "--config",
    "config_path",
    type=click.Path(exists=True, dir_okay=False),
    default=None,
    help="Path to a pipeguard config file (default: auto-detect .pipeguard.yml).",
)
@click.option(
    "--verbose", "-v",
    is_flag=True,
    help="Show detailed scan progress and finding metadata.",
)
def scan(path: str, output_format: str, fix: bool, config_path: str | None, verbose: bool) -> None:
    """Scan a workflow FILE or DIRECTORY (default: .github/workflows)."""
    config = load_config(Path(config_path).parent if config_path else None)
    license_key = resolve_license_key()
    api_url = _resolve_api_url(config)
    workflows = _collect_workflows(path)

    if not workflows:
        click.echo(f"[pipeguard] No workflow files found in '{path}'.", err=True)
        sys.exit(0)

    _vlog(f"Found {len(workflows)} workflow file(s) in '{path}'", verbose)

    if config:
        _vlog(
            f"Config loaded — trusted publishers: {len(config.trusted_publishers)}, "
            f"trusted actions: {len(config.trusted_actions)}"
            + (f", api_url: {config.api_url}" if config.api_url else ""),
            verbose,
        )

    if license_key:
        click.echo("[pipeguard] Pro license active — running extended checks.", err=True)
        _vlog(f"Pro API endpoint: {api_url}", verbose)

    fmt = Formatter(OutputFormat(output_format), show_fix=fix, verbose=verbose)
    all_findings: list[Finding] = []

    try:
        for workflow in workflows:
            _vlog(f"Scanning: {workflow}", verbose)
            findings = _scan_file(workflow, config, license_key, verbose, api_url)
            all_findings.extend(findings)
            fmt.render(findings, str(workflow))
            if fix and license_key:
                applied, skipped = apply_fixes(findings, str(workflow), license_key, api_url)
                if applied:
                    click.echo(
                        f"[pipeguard] Auto-fixed {applied} issue(s) in {workflow}.", err=True
                    )
                if skipped:
                    click.echo(
                        f"[pipeguard] {skipped} issue(s) could not be auto-fixed in {workflow} "
                        "(manual fix required).",
                        err=True,
                    )
    except InvalidLicenseKeyError as exc:
        click.echo(f"[pipeguard] License error: {exc}", err=True)
        click.echo("[pipeguard] Run 'pipeguard auth <key>' to update your license.", err=True)
        sys.exit(2)

    if len(workflows) > 1:
        errors = sum(1 for f in all_findings if f.severity == Severity.ERROR)
        warnings = sum(1 for f in all_findings if f.severity == Severity.WARNING)
        infos = sum(1 for f in all_findings if f.severity == Severity.INFO)
        click.echo(
            f"\nScanned {len(workflows)} file(s) — "
            f"{errors} error(s), {warnings} warning(s), {infos} info(s) total."
        )

    if any(f.severity in (Severity.ERROR, Severity.WARNING) for f in all_findings):
        sys.exit(1)
