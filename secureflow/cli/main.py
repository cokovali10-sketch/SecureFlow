"""SecureFlow CLI — main entry point for security scanning."""

from __future__ import annotations

import json
import logging
import sys
from pathlib import Path
from typing import Any

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.tree import Tree

from secureflow import __version__
from secureflow.core.config import Config
from secureflow.findings.models import ScanResult, Severity
from secureflow.risk.engine import RiskAssessment, RiskEngine
from secureflow.scanners.orchestrator import ScanOrchestrator

console = Console()
logger = logging.getLogger("secureflow")


def setup_logging(verbose: bool = False, quiet: bool = False) -> None:
    level = logging.DEBUG if verbose else (logging.WARNING if quiet else logging.INFO)
    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )


def format_human(result: ScanResult, assessment: RiskAssessment) -> None:
    """Display results in human-readable format."""
    # Header
    severity_colors = {
        "critical": "bold red",
        "high": "red",
        "medium": "yellow",
        "low": "cyan",
        "info": "dim",
    }

    console.print()
    console.print(Panel(
        f"[bold]SecureFlow Security Scan[/bold]\n"
        f"Target: {result.target}\n"
        f"Duration: {result.duration_seconds:.1f}s\n"
        f"Scanners: {', '.join(result.scanner_used)}",
        title="Scan Complete",
        border_style="green" if assessment.pass_fail else "red",
    ))

    # Score
    grade_color = "green" if assessment.pass_fail else "red"
    console.print(f"\n[{grade_color}]Risk Score: {assessment.score:.1f}/100 (Grade: {assessment.grade})[/{grade_color}]")
    console.print(f"Status: {'PASS' if assessment.pass_fail else 'FAIL'}")

    if not result.findings:
        console.print("\n[green]No security findings. Code looks clean![/green]")
        return

    # Findings summary
    counts = result.findings_by_severity
    console.print("\n[bold]Findings Summary:[/bold]")
    for sev in ["critical", "high", "medium", "low", "info"]:
        count = counts.get(sev, 0)
        if count > 0:
            console.print(f"  [{severity_colors[sev]}]{sev.upper()}: {count}[/{severity_colors[sev]}]")

    # Top findings
    console.print("\n[bold]Top Findings:[/bold]")
    for item in assessment.summary.get("top_risks", [])[:10]:
        sev = item["severity"]
        console.print(
            f"  [{severity_colors[sev]}]{sev.upper()}[/{severity_colors[sev]}] "
            f"{item['title']} "
            f"[dim]({item['file']}:{item['line']})[/dim]"
        )

    # Recommendations
    if assessment.recommendations:
        console.print("\n[bold]Recommendations:[/bold]")
        for rec in assessment.recommendations:
            console.print(f"  - {rec}")

    console.print()


def format_json(result: ScanResult, assessment: RiskAssessment) -> None:
    """Output results as JSON."""
    output = {
        "scan": {
            "target": result.target,
            "duration_seconds": result.duration_seconds,
            "scanners_used": result.scanner_used,
            "total_findings": result.total_findings,
            "active_findings": result.active_findings,
            "findings_by_severity": result.findings_by_severity,
        },
        "risk": {
            "score": assessment.score,
            "grade": assessment.grade,
            "pass_fail": assessment.pass_fail,
            "recommendations": assessment.recommendations,
        },
        "findings": [
            {
                "id": f.id,
                "scanner": f.scanner.value,
                "rule": f.rule,
                "severity": f.severity.value,
                "confidence": f.confidence.value,
                "title": f.title,
                "description": f.description,
                "file": f.location.file_path,
                "line": f.location.line,
                "evidence": f.evidence,
                "remediation": f.remediation,
                "status": f.status.value,
                "fingerprint": f.fingerprint,
            }
            for f in result.findings
        ],
    }
    print(json.dumps(output, indent=2))


@click.group()
@click.version_option(__version__, prog_name="secureflow")
@click.option("-v", "--verbose", is_flag=True, help="Verbose output")
@click.option("-q", "--quiet", is_flag=True, help="Suppress non-essential output")
@click.pass_context
def main(ctx: click.Context, verbose: bool, quiet: bool) -> None:
    """SecureFlow — Security platform for analyzing software projects."""
    ctx.ensure_object(dict)
    ctx.obj["verbose"] = verbose
    ctx.obj["quiet"] = quiet
    setup_logging(verbose, quiet)


@main.command()
@click.argument("target", type=click.Path(exists=True, path_type=Path))
@click.option("-s", "--scanners", multiple=True, help="Specific scanners to run")
@click.option("-o", "--output", type=click.Choice(["human", "json"]), default="human")
@click.option("--fail-on", type=click.Choice(["critical", "high", "medium", "low"]), default=None,
              help="Fail exit code if findings at this severity or above")
@click.option("--config-file", type=click.Path(path_type=Path), default=None, help="Config file path")
@click.pass_context
def scan(
    ctx: click.Context,
    target: Path,
    scanners: tuple[str, ...],
    output: str,
    fail_on: str | None,
    config_file: Path | None,
) -> None:
    """Scan a project for security issues.

    TARGET is the directory or file to scan.

    Examples:

        secureflow scan ./my-project

        secureflow scan ./src --scanners secrets sast

        secureflow scan . --output json --fail-on high
    """
    config = Config.from_file(config_file) if config_file else Config.from_env()

    scanner_list = list(scanners) if scanners else None

    orchestrator = ScanOrchestrator(config)
    result, assessment = orchestrator.scan_with_assessment(target, scanner_list)

    if output == "json":
        format_json(result, assessment)
    else:
        format_human(result, assessment)

    # Exit code logic
    if fail_on:
        fail_threshold = Severity(fail_on).weight
        has_failures = any(
            f.severity.weight >= fail_threshold
            for f in result.findings
            if f.is_active
        )
        if has_failures:
            sys.exit(1)

    if not assessment.pass_fail:
        sys.exit(1)


@main.command()
@click.pass_context
def scanners(ctx: click.Context) -> None:
    """List available scanners."""
    scanner_list = ScanOrchestrator.list_scanners()

    table = Table(title="Available Scanners")
    table.add_column("Name", style="cyan")
    table.add_column("Type", style="green")
    table.add_column("Description")

    for name, info in sorted(scanner_list.items()):
        table.add_row(name, info["type"], info["description"])

    console.print(table)


@main.command()
@click.pass_context
def version(ctx: click.Context) -> None:
    """Show version information."""
    console.print(f"SecureFlow v{__version__}")


@main.command()
@click.pass_context
def doctor(ctx: click.Context) -> None:
    """Check system dependencies and configuration."""
    import shutil

    table = Table(title="System Check")
    table.add_column("Component", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Details")

    # Python
    table.add_row("Python", "OK", sys.version.split()[0])

    # Bandit
    bandit_path = shutil.which("bandit")
    table.add_row("Bandit", "OK" if bandit_path else "MISSING", bandit_path or "pip install bandit")

    # pip-audit
    pip_audit = shutil.which("pip-audit")
    table.add_row("pip-audit", "OK" if pip_audit else "MISSING", pip_audit or "pip install pip-audit")

    # Trivy
    trivy = shutil.which("trivy")
    table.add_row("Trivy", "OK" if trivy else "MISSING", trivy or "https://trivy.dev")

    # Gitleaks
    gitleaks = shutil.which("gitleaks")
    table.add_row("Gitleaks", "OK" if gitleaks else "MISSING", gitleaks or "https://gitleaks.io")

    console.print(table)


if __name__ == "__main__":
    main()
