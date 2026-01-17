"""iamwho CLI - IAM principal security analyzer."""

import json

import typer
from rich.console import Console

from iamwho.models import RiskLevel

app = typer.Typer(help="Analyze AWS IAM principals for security insights.")
console = Console()


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
    output_json: bool = typer.Option(
        False, "--json", "-j", help="Output results as JSON"
    ),
):
    """Analyze the specified IAM principal."""
    if not is_valid_arn(principal_arn):
        console.print("[red]Invalid ARN format.[/red]")
        raise typer.Exit(code=1)

    results: dict = {}

    if check in ("ingress", "all"):
        result = perform_ingress_check(principal_arn, output_json)
        if output_json:
            results["ingress"] = result

    if check in ("egress", "all"):
        result = perform_egress_check(principal_arn, output_json)
        if output_json:
            results["egress"] = result

    if check in ("mutation", "all"):
        result = perform_privilege_mutation_check(principal_arn, output_json)
        if output_json:
            results["mutation"] = result

    if check not in ("ingress", "egress", "mutation", "all"):
        console.print(f"[red]Unsupported check type: {check}[/red]")
        raise typer.Exit(code=1)

    if output_json:
        console.print(json.dumps(results, indent=2))


def is_valid_arn(arn: str) -> bool:
    """Basic ARN format validation."""
    return arn.startswith("arn:aws:iam::")


def get_risk_style(risk: RiskLevel | str) -> str:
    """Return Rich style for risk level."""
    risk_str = risk.value if isinstance(risk, RiskLevel) else risk
    styles = {
        "CRITICAL": "white on red bold",
        "HIGH": "red bold",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFO": "dim",
    }
    return styles.get(risk_str, "white")


def perform_ingress_check(principal_arn: str, output_json: bool = False) -> dict | None:
    """Run the INGRESS check and display results."""
    from iamwho.checks.ingress import analyze_ingress

    result = analyze_ingress(principal_arn)

    if output_json:
        return result.to_dict()

    console.print(f"\n[bold blue]INGRESS Analysis: {result.role_arn}[/bold blue]")
    console.print("=" * 60)

    if result.error:
        console.print(f"[red]Error:[/red] {result.error}")
        return None

    if not result.findings:
        console.print("[dim](No trust relationships found)[/dim]\n")
        return None

    overall_style = get_risk_style(result.highest_risk)
    console.print(
        f"Overall Risk: [{overall_style}]{result.highest_risk.value}[/{overall_style}] "
        f"| Findings: {len(result.findings)}"
    )
    console.print()

    sorted_findings = sorted(result.findings, key=lambda f: f.risk, reverse=True)

    for finding in sorted_findings:
        risk_style = get_risk_style(finding.risk)

        console.print(
            f"  [{risk_style}][{finding.risk.value}][/{risk_style}] "
            f"{finding.principal}"
        )

        details = (
            f"        Type: [cyan]{finding.principal_type.value}[/cyan] | "
            f"Assume: [cyan]{finding.assume_type.value}[/cyan]"
        )
        if finding.statement_id:
            details += f" | Sid: {finding.statement_id}"
        console.print(details)

        for reason in finding.reasons:
            console.print(f"        [dim]{reason}[/dim]")

        protections = _get_protection_summary(finding.conditions)
        if protections:
            console.print(f"        Conditions: [green]{', '.join(protections)}[/green]")

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


def perform_egress_check(principal_arn: str, output_json: bool = False) -> dict | None:
    """Run the EGRESS check and display results."""
    from iamwho.checks.egress import analyze_egress

    result = analyze_egress(principal_arn)

    if output_json:
        return result

    console.print("\n[bold blue]EGRESS Analysis[/bold blue]")
    console.print("=" * 60)

    if result["status"] == "error":
        console.print(f"[red]Error:[/red] {result['message']}")
        return None

    if result["status"] == "not_applicable":
        console.print(f"[dim]{result['message']}[/dim]\n")
        return None

    summary = result["summary"]

    if not summary or summary["total_findings"] == 0:
        console.print("[dim](No dangerous permissions detected)[/dim]\n")
        return None

    verdict_style = get_risk_style(summary["verdict"])
    console.print(
        f"Verdict: [{verdict_style}]{summary['verdict']}[/{verdict_style}] "
        f"| Findings: {summary['total_findings']}"
    )
    console.print(f"  [dim]{summary['verdict_explanation']}[/dim]")

    if summary["categories"]:
        console.print(f"  Categories: [cyan]{', '.join(summary['categories'])}[/cyan]")

    # Risk breakdown
    if summary["risk_counts"]:
        counts = [f"{k}: {v}" for k, v in sorted(summary["risk_counts"].items())]
        console.print(f"  Breakdown: {', '.join(counts)}")

    console.print()

    for finding in result["findings"]:
        risk_style = get_risk_style(finding["risk"])
        scope_label = "[ALL]" if finding["resource_scope"] == "ALL" else "[SCOPED]"
        scope_style = "red" if finding["resource_scope"] == "ALL" else "green"

        console.print(
            f"  [{risk_style}][{finding['risk']}][/{risk_style}] "
            f"[{scope_style}]{scope_label}[/{scope_style}] "
            f"[white]{finding['action']}[/white]"
        )
        console.print(f"        [dim]{finding['explanation']}[/dim]")
        console.print(f"        Source: [cyan]{finding['source']}[/cyan]")

        if finding["resource_scope"] == "SCOPED" and finding["resources"]:
            res = finding["resources"][0]
            if len(res) > 60:
                res = res[:57] + "..."
            console.print(f"        Resource: [dim]{res}[/dim]")

        if finding["conditions"]:
            cond_keys = list(finding["conditions"].keys())
            console.print(f"        Conditions: [green]{', '.join(cond_keys)}[/green]")

        console.print()

    return None


def perform_privilege_mutation_check(principal_arn: str, output_json: bool = False) -> dict | None:
    """Run the PRIVILEGE MUTATION check (stub)."""
    if output_json:
        return {"status": "not_implemented", "message": "MUTATION check not yet implemented"}

    console.print("\n[bold blue]PRIVILEGE MUTATION Analysis[/bold blue]")
    console.print("=" * 60)
    console.print("[yellow]Not yet implemented[/yellow]")
    console.print("[dim]Will analyze: iam:*, sts:*, escalation primitives, dangerous combinations[/dim]")
    console.print()
    return None


if __name__ == "__main__":
    app()
