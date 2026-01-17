# src/iamwho/cli.py
"""iamwho CLI - IAM principal security analyzer."""

import json

import typer
from rich.console import Console

from iamwho.models import RiskLevel

app = typer.Typer(help="Analyze AWS IAM principals for security insights.")
console = Console()

# ─────────────────────────────────────────────────────────────
# Risk styling (color only, no emojis)
# ─────────────────────────────────────────────────────────────
RISK_STYLES = {
    "CRITICAL": "bold white on red",
    "HIGH":     "bold red",
    "MEDIUM":   "yellow",
    "LOW":      "green",
    "INFO":     "dim",
}


def get_risk_style(risk: RiskLevel | str) -> str:
    """Return Rich style for risk level."""
    risk_str = risk.value if isinstance(risk, RiskLevel) else risk
    return RISK_STYLES.get(risk_str, "white")


def get_risk_label(risk: RiskLevel | str) -> str:
    """Return formatted risk label with consistent width."""
    risk_str = risk.value if isinstance(risk, RiskLevel) else risk
    style = RISK_STYLES.get(risk_str, "white")
    # Fixed 8-char width for alignment
    return f"[{style}]{risk_str:<8}[/{style}]"


# ─────────────────────────────────────────────────────────────
# Summary tracking
# ─────────────────────────────────────────────────────────────
class FindingsSummary:
    """Track findings across all checks."""

    def __init__(self):
        self.counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        self.checks_run = []

    def add(self, risk: str, count: int = 1):
        if risk in self.counts:
            self.counts[risk] += count

    def add_from_ingress(self, findings: list):
        for f in findings:
            risk_str = f.risk.value if hasattr(f.risk, 'value') else f.risk
            self.add(risk_str)
        self.checks_run.append("INGRESS")

    def add_from_egress(self, result: dict):
        if result.get("summary") and result["summary"].get("risk_counts"):
            for risk, count in result["summary"]["risk_counts"].items():
                self.add(risk, count)
        self.checks_run.append("EGRESS")

    def add_from_mutation(self, result: dict):
        summary = result.get("summary", {})
        self.add("CRITICAL", summary.get("critical_count", 0))
        self.add("HIGH", summary.get("high_count", 0))
        self.add("MEDIUM", summary.get("medium_count", 0))
        self.checks_run.append("MUTATION")

    def total(self) -> int:
        return sum(self.counts.values())

    def highest_risk(self) -> str:
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]:
            if self.counts[level] > 0:
                return level
        return "LOW"


def print_summary_banner(summary: FindingsSummary):
    """Print the final summary banner."""
    if not summary.checks_run:
        return

    console.print()
    console.print("[dim]" + "=" * 60 + "[/dim]")

    total = summary.total()

    if total == 0:
        console.print("[bold green]  RESULT: PASS - No security findings[/bold green]")
    else:
        parts = []
        for level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            count = summary.counts[level]
            if count > 0:
                style = RISK_STYLES[level]
                parts.append(f"[{style}]{count} {level}[/{style}]")

        console.print(f"  RESULT: {' | '.join(parts)}")

    checks_str = ", ".join(summary.checks_run)
    console.print(f"  [dim]Checks: {checks_str}[/dim]")
    console.print("[dim]" + "=" * 60 + "[/dim]")
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
        console.print(f"[bold white]TARGET:[/bold white] {principal_arn}")

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
        print_summary_banner(summary)


def is_valid_arn(arn: str) -> bool:
    """Basic ARN format validation."""
    return arn.startswith("arn:aws:iam::")


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
        console.print(f"[red]Error:[/red] {result.error}")
        return None

    if not result.findings:
        console.print("[dim]  (No trust relationships found)[/dim]")
        return None

    if summary:
        summary.add_from_ingress(result.findings)

    sorted_findings = sorted(result.findings, key=lambda f: f.risk, reverse=True)

    for finding in sorted_findings:
        risk_label = get_risk_label(finding.risk)

        # Scope indicator
        if finding.principal == "*":
            scope = "[bold red]*[/bold red]"
        else:
            scope = " "

        console.print(f"  {risk_label} {scope} {finding.principal}")

        details = (
            f"           Type: [cyan]{finding.principal_type.value}[/cyan] | "
            f"Assume: [cyan]{finding.assume_type.value}[/cyan]"
        )
        if finding.statement_id:
            details += f" | Sid: {finding.statement_id}"
        console.print(details)

        # Always show reasons (they're useful)
        for reason in finding.reasons:
            console.print(f"           [dim]> {reason}[/dim]")

        protections = _get_protection_summary(finding.conditions)
        if protections:
            console.print(f"           [green]+ Conditions: {', '.join(protections)}[/green]")

        # Verbose: show remediation hints
        if verbose:
            remediation = _get_ingress_remediation(finding)
            if remediation:
                console.print(f"           [cyan]Remediation:[/cyan] [dim]{remediation}[/dim]")

        console.print()

    return None


def _get_protection_summary(conditions) -> list[str]:
    """Extract list of active protections from conditions."""
    protections: list[str] = []
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
    risk_str = finding.risk.value if hasattr(finding.risk, 'value') else finding.risk

    if finding.principal == "*":
        return "Remove wildcard principal or add strict conditions"

    if risk_str == "CRITICAL":
        return "Review trust policy - consider adding ExternalId or source conditions"

    if risk_str == "HIGH":
        if finding.principal_type.value == "AWS_SERVICE":
            return "Add SourceArn/SourceAccount conditions for confused deputy protection"
        return "Consider scoping down with conditions"

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
        console.print(f"[red]Error:[/red] {result['message']}")
        return None

    if result["status"] == "not_applicable":
        console.print(f"[dim]  {result['message']}[/dim]")
        return None

    result_summary = result["summary"]

    if not result_summary or result_summary["total_findings"] == 0:
        console.print("[dim]  (No dangerous permissions detected)[/dim]")
        return None

    if summary:
        summary.add_from_egress(result)

    if result_summary["categories"]:
        console.print(f"  Categories: [cyan]{', '.join(result_summary['categories'])}[/cyan]")
    console.print()

    for finding in result["findings"]:
        risk_label = get_risk_label(finding["risk"])

        # Scope indicator: * for wildcard, ~ for scoped
        if finding["resource_scope"] == "ALL":
            scope = "[bold red]*[/bold red]"
        else:
            scope = "[green]~[/green]"

        console.print(f"  {risk_label} {scope} {finding['action']}")
        console.print(f"           [dim]{finding['explanation']}[/dim]")
        console.print(f"           Source: [cyan]{finding['source']}[/cyan]")

        if finding["resource_scope"] == "SCOPED" and finding["resources"]:
            res = finding["resources"][0]
            if len(res) > 50:
                res = res[:47] + "..."
            console.print(f"           Resource: [dim]{res}[/dim]")

        if finding["conditions"]:
            cond_keys = list(finding["conditions"].keys())
            console.print(f"           [green]+ Conditions: {', '.join(cond_keys)}[/green]")

        # Verbose: show remediation
        if verbose:
            remediation = _get_egress_remediation(finding)
            if remediation:
                console.print(f"           [cyan]Remediation:[/cyan] [dim]{remediation}[/dim]")

        console.print()

    return None


def _get_egress_remediation(finding: dict) -> str | None:
    """Get remediation hint for egress finding."""
    action = finding.get("action", "")
    risk = finding.get("risk", "")
    scope = finding.get("resource_scope", "")

    if scope == "ALL":
        if "iam:" in action:
            return "Scope to specific IAM resources or remove if not needed"
        if "s3:" in action:
            return "Scope to specific buckets with Resource constraints"
        return "Add Resource constraints to limit scope"

    if risk == "CRITICAL":
        return "Review necessity - this permission enables privilege escalation"

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
        console.print(f"[red]Error:[/red] {result.get('message', 'Unknown error')}")
        return None

    if result.get("status") == "not_applicable":
        console.print(f"[dim]  {result.get('message', 'Not applicable')}[/dim]")
        return None

    direct = result.get("direct_escalations", [])
    combos = result.get("combination_escalations", [])
    potential = result.get("potential_escalations", [])

    # No escalation paths found
    if not direct and not combos:
        console.print()
        console.print("  [green]No escalation paths detected[/green]")

        if verbose and potential:
            console.print()
            console.print("  [dim]Potential (requires additional access):[/dim]")
            for p in potential[:5]:
                console.print(
                    f"  [dim]  - {p['action']} -> {p['escalation_path']}[/dim]"
                )
        console.print()
        return None

    if summary:
        summary.add_from_mutation(result)

    console.print()

    # Build display paths
    all_paths: list[dict] = []

    for esc in direct:
        all_paths.append({
            "display": esc["action"],
            "target": _truncate(esc["escalation_path"], 28),
            "risk": esc["risk"],
            "description": esc["description"],
            "category": esc.get("category", ""),
        })

    for combo in combos:
        all_paths.append({
            "display": " + ".join(combo["actions"]),
            "target": _truncate(combo["escalation_path"], 28),
            "risk": combo["risk"],
            "description": combo["description"],
            "category": "COMBINATION",
        })

    # Sort by risk (CRITICAL first)
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_paths.sort(key=lambda p: risk_order.get(p["risk"], 99))

    # Render tree
    for i, path in enumerate(all_paths):
        is_last = i == len(all_paths) - 1
        prefix = "└──" if is_last else "├──"
        continuation = "   " if is_last else "│  "

        # Build display and calculate dots
        display_text = f"{path['display']} -> {path['target']}"
        total_width = 48
        dots_needed = max(3, total_width - len(display_text))
        dots = "." * dots_needed

        # Risk style
        style = RISK_STYLES.get(path["risk"], "white")

        # Main line
        console.print(
            f"  {prefix} {display_text} [dim]{dots}[/dim] [{style}]{path['risk']}[/{style}]"
        )

        # Verbose: show details
        if verbose:
            console.print(f"  {continuation}     [dim]{path['description']}[/dim]")
            if path.get("category"):
                console.print(
                    f"  {continuation}     [dim]Category: {path['category']}[/dim]"
                )

        # Spacing
        if not is_last:
            console.print("  │")

    # Potential escalations (verbose only)
    if verbose and potential:
        console.print()
        console.print("  [dim]Potential (requires additional access):[/dim]")
        for p in potential[:5]:
            console.print(
                f"  [dim]  - {p['action']} -> {p['escalation_path']}[/dim]"
            )
        if len(potential) > 5:
            console.print(f"  [dim]  ... and {len(potential) - 5} more[/dim]")

    console.print()

    # Verdict
    verdict = result.get("verdict", "")
    if verdict:
        overall = result.get("overall_risk", "LOW")
        style = RISK_STYLES.get(overall, "white")
        console.print(f"  [{style}]{verdict}[/{style}]")
        console.print()

    return None


def _truncate(text: str, max_len: int) -> str:
    """Truncate text with ellipsis if too long."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 2] + ".."


if __name__ == "__main__":
    app()
