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


def is_valid_arn(arn: str) -> bool:
    """Basic ARN format validation."""
    return arn.startswith("arn:aws:iam::")


# ─────────────────────────────────────────────────────────────
# Compact finding renderer
# ─────────────────────────────────────────────────────────────
def print_finding(
    risk: str,
    scope: str,
    title: str,
    hint: str,
    verbose_lines: list[str] | None = None,
    verbose: bool = False,
):
    """Render a single finding: 2 lines default, more if verbose."""
    risk_label = get_risk_label(risk)
    scope_char = "[bold red]*[/bold red]" if scope == "ALL" else "[cyan]~[/cyan]"

    console.print(f"  {risk_label} {scope_char} {title}")
    console.print(f"           [dim]→ {hint}[/dim]")

    if verbose and verbose_lines:
        for line in verbose_lines:
            console.print(f"           [dim]{line}[/dim]")


# ─────────────────────────────────────────────────────────────
# INGRESS Check
# ─────────────────────────────────────────────────────────────
def perform_ingress_check(
        principal_arn: str,
        output_json: bool = False,
        summary: FindingsSummary | None = None,
        verbose: bool = False,
) -> dict | None:
    """Run the INGRESS check and display results."""
    from iamwho.checks.ingress import analyze_ingress

    result = analyze_ingress(principal_arn)

    if output_json:
        return result.to_dict()

    console.print()
    console.print("[bold cyan][ INGRESS ][/bold cyan] Who can assume this role?")
    console.print("[dim]" + "-" * 60 + "[/dim]")

    if result.error:
        console.print(f"  [red]Error:[/red] {result.error}")
        return None

    if not result.findings:
        console.print("  [dim]No trust relationships found[/dim]")
        return None

    if summary:
        summary.add_from_ingress(result.findings)

    console.print()
    sorted_findings = sorted(result.findings, key=lambda f: f.risk, reverse=True)

    for finding in sorted_findings:
        risk_str = finding.risk.value if hasattr(finding.risk, 'value') else finding.risk
        scope = "ALL" if finding.principal == "*" else "SCOPED"
        hint = finding.reasons[0] if finding.reasons else "Review trust policy"

        verbose_lines = []
        if verbose:
            verbose_lines.append(f"Type: {finding.principal_type.value} | Assume: {finding.assume_type.value}")
            protections = _get_protection_summary(finding.conditions)
            if protections:
                verbose_lines.append(f"+ {', '.join(protections)}")
            remediation = _get_ingress_remediation(finding)
            if remediation:
                verbose_lines.append(f"Fix: {remediation}")

        print_finding(risk_str, scope, finding.principal, hint, verbose_lines, verbose)
        console.print()

    return None


def _get_protection_summary(conditions) -> list[str]:
    """Extract list of active protections from conditions."""
    protections = []
    if conditions.has_external_id:
        protections.append("ExternalId")
    if conditions.has_source_arn:
        protections.append("SourceArn")
    if conditions.has_source_account:
        protections.append("SourceAccount")
    if conditions.has_principal_org_id:
        protections.append("PrincipalOrgID")
    if conditions.has_principal_arn:
        protections.append("PrincipalArn")
    if conditions.has_oidc_sub_claim:
        protections.append("OIDC:sub")
    if conditions.has_oidc_aud_claim:
        protections.append("OIDC:aud")
    if conditions.has_saml_aud:
        protections.append("SAML:aud")
    return protections


def _get_ingress_remediation(finding) -> str | None:
    """Get remediation hint for ingress finding."""
    if finding.principal == "*":
        return "Remove wildcard or add strict conditions"
    risk_str = finding.risk.value if hasattr(finding.risk, 'value') else finding.risk
    if risk_str == "CRITICAL":
        return "Add ExternalId or source conditions"
    if risk_str == "HIGH" and finding.principal_type.value == "Service":
        return "Add SourceArn/SourceAccount conditions"
    return None


# ─────────────────────────────────────────────────────────────
# EGRESS Check
# ─────────────────────────────────────────────────────────────
def perform_egress_check(
        principal_arn: str,
        output_json: bool = False,
        summary: FindingsSummary | None = None,
        verbose: bool = False,
) -> dict | None:
    """Run the EGRESS check and display results."""
    from iamwho.checks.egress import analyze_egress

    result = analyze_egress(principal_arn)

    if output_json:
        return result

    console.print()
    console.print("[bold cyan][ EGRESS ][/bold cyan] What can this role do?")
    console.print("[dim]" + "-" * 60 + "[/dim]")

    if result["status"] == "error":
        console.print(f"  [red]Error:[/red] {result['message']}")
        return None

    if result["status"] == "not_applicable":
        console.print(f"  [dim]{result['message']}[/dim]")
        return None

    result_summary = result["summary"]

    if not result_summary or result_summary["total_findings"] == 0:
        console.print("  [dim]No dangerous permissions detected[/dim]")
        return None

    if summary:
        summary.add_from_egress(result)

    console.print()

    for finding in result["findings"]:
        verbose_lines = []
        if verbose:
            verbose_lines.append(f"Source: {finding['source']}")
            if finding["conditions"]:
                verbose_lines.append(f"+ {', '.join(finding['conditions'].keys())}")

        print_finding(
            finding["risk"],
            finding["resource_scope"],
            finding["action"],
            finding["explanation"],
            verbose_lines,
            verbose,
        )
        console.print()

    return None


# ─────────────────────────────────────────────────────────────
# MUTATION Check
# ─────────────────────────────────────────────────────────────
def perform_mutation_check(
        principal_arn: str,
        output_json: bool = False,
        summary: FindingsSummary | None = None,
        verbose: bool = False,
) -> dict | None:
    """Run the PRIVILEGE MUTATION check."""
    from iamwho.checks import privilege_mutation

    result = privilege_mutation.run(principal_arn)

    if output_json:
        return result

    console.print()
    console.print("[bold cyan][ MUTATION ][/bold cyan] How could privileges escalate?")
    console.print("[dim]" + "-" * 60 + "[/dim]")

    if result.get("status") == "error":
        console.print(f"  [red]Error:[/red] {result.get('message', 'Unknown error')}")
        return None

    if result.get("status") == "not_applicable":
        console.print(f"  [dim]{result.get('message', 'Not applicable')}[/dim]")
        return None

    direct = result.get("direct_escalations", [])
    combos = result.get("combination_escalations", [])

    if not direct and not combos:
        console.print()
        console.print("  [green]✓ No escalation paths detected[/green]")
        console.print()
        return None

    if summary:
        summary.add_from_mutation(result)

    console.print()

    # Direct escalations
    for esc in direct:
        verbose_lines = []
        if verbose and esc.get("description"):
            verbose_lines.append(esc["description"])

        print_finding(
            esc["risk"],
            "ALL",
            esc["action"],
            esc["escalation_path"],
            verbose_lines,
            verbose,
        )
        console.print()

    # Combo escalations
    for combo in combos:
        actions = " + ".join(combo["actions"])
        verbose_lines = []
        if verbose and combo.get("description"):
            verbose_lines.append(combo["description"])

        print_finding(
            combo["risk"],
            "ALL",
            f"{actions} [magenta][COMBO][/magenta]",
            combo["escalation_path"],
            verbose_lines,
            verbose,
        )
        console.print()

    return None


if __name__ == "__main__":
    app()
