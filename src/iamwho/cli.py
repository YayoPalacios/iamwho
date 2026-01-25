# src/iamwho/cli.py
"""iamwho CLI - IAM principal security analyzer."""

import json

import typer
from rich.console import Console
from rich.table import Table

from iamwho.models import RiskLevel

app = typer.Typer(help="Analyze AWS IAM principals for security insights.")
console = Console(highlight=False)

# ─────────────────────────────────────────────────────────────
# Risk styling
# ─────────────────────────────────────────────────────────────
RISK_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}


def get_risk_label(risk: RiskLevel | str) -> str:
    """Return formatted risk label with consistent width."""
    risk_str = risk.value if isinstance(risk, RiskLevel) else risk
    style = RISK_STYLES.get(risk_str, "white")
    return f"[{style}]{risk_str:<8}[/{style}]"


# ─────────────────────────────────────────────────────────────
# Summary tracking (enhanced for per-check stats)
# ─────────────────────────────────────────────────────────────
class FindingsSummary:
    """Track findings across all checks."""

    def __init__(self):
        self.counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        self.checks_run = {}  # Dict: check_name -> {risk: count}

    def add(self, risk: str, count: int = 1):
        if risk in self.counts:
            self.counts[risk] += count

    def _make_check_counts(self) -> dict:
        return {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}

    def add_from_ingress(self, findings: list):
        check_counts = self._make_check_counts()
        for f in findings:
            risk_str = f.risk.value if hasattr(f.risk, 'value') else f.risk
            self.add(risk_str)
            if risk_str in check_counts:
                check_counts[risk_str] += 1
        self.checks_run["INGRESS"] = check_counts

    def add_from_egress(self, result: dict):
        check_counts = self._make_check_counts()
        if result.get("summary") and result["summary"].get("risk_counts"):
            for risk, count in result["summary"]["risk_counts"].items():
                self.add(risk, count)
                if risk in check_counts:
                    check_counts[risk] = count
        elif result.get("findings"):
            for finding in result["findings"]:
                risk = finding.get("risk", "INFO")
                self.add(risk)
                if risk in check_counts:
                    check_counts[risk] += 1
        self.checks_run["EGRESS"] = check_counts

    def add_from_mutation(self, result: dict):
        summary = result.get("summary", {})
        check_counts = {
            "CRITICAL": summary.get("critical_count", 0),
            "HIGH": summary.get("high_count", 0),
            "MEDIUM": summary.get("medium_count", 0),
            "LOW": 0,
        }
        for risk, count in check_counts.items():
            self.add(risk, count)
        self.checks_run["MUTATION"] = check_counts

    def total(self) -> int:
        return sum(self.counts.values())

    def highest_risk(self) -> str:
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if self.counts[level] > 0:
                return level
        return "NONE"

    def check_total(self, check_counts: dict) -> int:
        return sum(check_counts.values())

    def check_highest(self, check_counts: dict) -> str:
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            if check_counts.get(level, 0) > 0:
                return level
        return "PASS"


# ─────────────────────────────────────────────────────────────
# UI: Summary Table + Exit Line
# ─────────────────────────────────────────────────────────────
def print_summary(summary: FindingsSummary):
    """Print summary table and one-line exit."""
    if not summary.checks_run:
        return

    console.print()
    console.print("[dim]" + "━" * 60 + "[/dim]")

    # Summary table
    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Check", style="bold", width=10)
    table.add_column("Count", width=14)
    table.add_column("Risk", width=10)

    for check_name, counts in summary.checks_run.items():
        total = summary.check_total(counts)
        highest = summary.check_highest(counts)

        if highest == "PASS":
            table.add_row(check_name, "[dim]0 findings[/dim]", "[green]PASS[/green]")
        else:
            style = RISK_STYLES.get(highest, "white")
            table.add_row(check_name, f"{total} findings", f"[{style}]{highest}[/{style}]")

    console.print(table)
    console.print("[dim]" + "━" * 60 + "[/dim]")

    # One-line exit
    total = summary.total()
    if total == 0:
        console.print("[green]✓[/green] No security findings")
    else:
        parts = []
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = summary.counts[level]
            if count > 0:
                parts.append(f"{count} {level.lower()}")
        console.print(f"[dim]→[/dim] {total} findings ({', '.join(parts)})")

    console.print()


# ─────────────────────────────────────────────────────────────
# Main CLI
# ─────────────────────────────────────────────────────────────
@app.callback(invoke_without_command=True)
def main(
        ctx: typer.Context,
        version: bool = typer.Option(
            False, "--version", "-v", help="Show version and exit."
        ),
):
    """iamwho - Understand your IAM principals."""
    if version:
        typer.echo("iamwho v0.1.0")
        raise typer.Exit()

    if ctx.invoked_subcommand is None:
        typer.echo(ctx.get_help())


@app.command()
def analyze(
        principal_arn: str = typer.Argument(
            ..., help="The ARN of the IAM principal to analyze."
        ),
        check: str = typer.Option(
            "all", "--check", "-c", help="Type of check: ingress, egress, mutation, or all"
        ),
        verbose: bool = typer.Option(
            False, "--verbose", "-V", help="Show detailed explanations and remediations"
        ),
        output_json: bool = typer.Option(
            False, "--json", "-j", help="Output results as JSON"
        ),
        fail_on: str = typer.Option(
            None, "--fail-on", "-f",
            help="Exit 1 if findings at this severity or above (critical/high/medium/low)"
        ),
):
    """Analyze the specified IAM principal."""
    if not is_valid_arn(principal_arn):
        console.print("[red]Invalid ARN format.[/red]")
        raise typer.Exit(code=1)

    results: dict = {}
    summary = FindingsSummary()

    if not output_json:
        console.print()
        console.print(f"[bold]TARGET[/bold] {principal_arn}")

    if check in ("ingress", "all"):
        result = perform_ingress_check(principal_arn, output_json, summary, verbose)
        if output_json:
            results["ingress"] = result

    if check in ("egress", "all"):
        result = perform_egress_check(principal_arn, output_json, summary, verbose)
        if output_json:
            results["egress"] = result

    if check in ("mutation", "all"):
        result = perform_mutation_check(principal_arn, output_json, summary, verbose)
        if output_json:
            results["mutation"] = result

    if check not in ("ingress", "egress", "mutation", "all"):
        console.print(f"[red]Unsupported check type: {check}[/red]")
        raise typer.Exit(code=1)

    if output_json:
        console.print(json.dumps(results, indent=2))
    else:
        print_summary(summary)

    # ─────────────────────────────────────────────────────────────
    # Exit code logic for CI/CD
    # ─────────────────────────────────────────────────────────────
    if fail_on:
        severity_order = ["low", "medium", "high", "critical"]
        fail_on_lower = fail_on.lower()

        if fail_on_lower not in severity_order:
            console.print(f"[red]Invalid --fail-on value: {fail_on}[/red]")
            console.print("[dim]Valid values: critical, high, medium, low[/dim]")
            raise typer.Exit(code=2)

        highest = summary.highest_risk().lower()

        if highest not in ("none", "info"):
            threshold_idx = severity_order.index(fail_on_lower)
            highest_idx = severity_order.index(highest)

            if highest_idx >= threshold_idx:
                if not output_json:
                    console.print(f"[red]✗ Failing: found {highest.upper()} (threshold: {fail_on_lower})[/red]")
                raise typer.Exit(code=1)

    raise typer.Exit(code=0)


def is_valid_arn(arn: str) -> bool:
    """Basic ARN format validation."""_
