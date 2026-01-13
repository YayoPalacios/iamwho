# src/iamwho/cli.py
"""
iamwho CLI - IAM principal security analyzer
"""

import typer
from rich.console import Console

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
):
    """Analyze the specified IAM principal."""

    if not is_valid_arn(principal_arn):
        console.print("[red]Invalid ARN format.[/red]")
        raise typer.Exit(code=1)

    if check == "all":
        perform_ingress_check(principal_arn)
        perform_egress_check(principal_arn)
        perform_privilege_mutation_check(principal_arn)
    elif check == "ingress":
        perform_ingress_check(principal_arn)
    elif check == "egress":
        perform_egress_check(principal_arn)
    elif check == "mutation":
        perform_privilege_mutation_check(principal_arn)
    else:
        console.print(f"[red]Unsupported check type: {check}[/red]")
        raise typer.Exit(code=1)


def is_valid_arn(arn: str) -> bool:
    """Basic ARN format validation."""
    return arn.startswith("arn:aws:iam::")


def get_risk_style(risk: str) -> str:
    """Return Rich style for risk level."""
    styles = {
        "CRITICAL": "white on red bold",
        "HIGH": "red bold",
        "MEDIUM": "yellow",
        "LOW": "green",
        "INFO": "dim",
    }
    return styles.get(risk, "white")


def perform_ingress_check(principal_arn: str) -> None:
    """Run the INGRESS check and display results."""
    from iamwho.checks import ingress

    result = ingress.run(principal_arn)

    if result["status"] == "error":
        console.print(f"[red]Error:[/red] {result['message']}")
        return

    if result["status"] == "not_applicable":
        console.print(f"[yellow]{result['message']}[/yellow]")
        return

    console.print(f"\n[bold blue]{result['message']}[/bold blue]\n")

    if not result["findings"]:
        console.print("  [dim](No trust principals found)[/dim]\n")
        return

    for f in result["findings"]:
        risk = f["risk"]
        style = get_risk_style(risk)

        console.print(f"  [{style}][{risk}][/{style}] {f['trusted_entity']}")

        details = f"        Type: [cyan]{f['type']}[/cyan] | Assume: [cyan]{f['assume_type']}[/cyan]"
        if f.get("sid") and f["sid"] != "(no Sid)":
            details += f" | Sid: {f['sid']}"
        console.print(details)

        console.print(f"        [dim]{f['explanation']}[/dim]")

        if f.get("conditions"):
            cond_keys = list(f["conditions"].keys())
            console.print(f"        Conditions: {cond_keys}")

        console.print()


def perform_egress_check(principal_arn: str) -> None:
    """Run the EGRESS check and display results."""
    from iamwho.checks import egress

    result = egress.run(principal_arn)

    if result["status"] == "error":
        console.print(f"[red]Error:[/red] {result['message']}")
        return

    if result["status"] == "not_applicable":
        console.print(f"[yellow]{result['message']}[/yellow]")
        return

    console.print(f"\n[bold blue]{result['message']}[/bold blue]")

    summary = result.get("summary")
    if summary:
        verdict = summary["verdict"]
        verdict_style = get_risk_style(verdict)
        console.print(f"  Overall: [{verdict_style}][{verdict}][/{verdict_style}] {summary['verdict_explanation']}")
        if summary["categories"]:
            console.print(f"  Categories: {', '.join(summary['categories'])}")
    console.print()

    if not result["findings"]:
        console.print("  [dim](No dangerous permissions detected)[/dim]\n")
        return

    for risk_level in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        level_findings = [f for f in result["findings"] if f["risk"] == risk_level]
        if not level_findings:
            continue

        style = get_risk_style(risk_level)
        console.print(f"  [{style}]-- {risk_level} ({len(level_findings)}) --[/{style}]")

        for f in level_findings:
            scope_tag = "[red](ALL)[/red]" if f["resource_scope"] == "ALL" else "[green](SCOPED)[/green]"
            console.print(f"    {scope_tag} [bold]{f['action']}[/bold]")
            console.print(f"       {f['explanation']}")
            console.print(f"       [dim]Source: {f['source']}[/dim]")
        console.print()


def perform_privilege_mutation_check(principal_arn: str) -> None:
    """Run the PRIVILEGE MUTATION check and display results."""
    from iamwho.checks import privilege_mutation

    result = privilege_mutation.run(principal_arn)

    if result["status"] == "error":
        console.print(f"[red]Error:[/red] {result['message']}")
        return

    if result["status"] == "not_applicable":
        console.print(f"[yellow]{result['message']}[/yellow]")
        return

    console.print(f"\n[bold blue]{result['message']}[/bold blue]")

    # Overall verdict
    overall_risk = result.get("overall_risk", "LOW")
    verdict = result.get("verdict", "No escalation paths found")
    verdict_style = get_risk_style(overall_risk)
    console.print(f"  [{verdict_style}]{verdict}[/{verdict_style}]")
    console.print()

    # Direct escalation paths
    direct = result.get("direct_escalations", [])
    if direct:
        console.print("  [bold]Direct Escalation Paths:[/bold]")
        for f in direct:
            style = get_risk_style(f["risk"])
            scope_tag = "[red](ALL)[/red]" if f["resource_scope"] == "ALL" else "[green](SCOPED)[/green]"
            console.print(f"    [{style}][{f['risk']}][/{style}] {scope_tag} [bold]{f['action']}[/bold]")
            console.print(f"       Category: {f['category']}")
            console.print(f"       Attack: {f['escalation_path']}")
            console.print(f"       [dim]Source: {f['source_policy']}[/dim]")
        console.print()

    # Dangerous combinations
    combos = result.get("combination_escalations", [])
    if combos:
        console.print("  [bold]Dangerous Combinations:[/bold]")
        for c in combos:
            style = get_risk_style(c["risk"])
            actions_str = " + ".join(c["actions"])
            console.print(f"    [{style}][{c['risk']}][/{style}] [bold]{actions_str}[/bold]")
            console.print(f"       Attack: {c['escalation_path']}")
        console.print()

    # Potential escalations (require combinations but only one piece found)
    potential = result.get("potential_escalations", [])
    if potential:
        console.print("  [bold dim]Potential Escalations (require additional access):[/bold dim]")
        for f in potential:
            console.print(f"    [dim][{f['risk']}] {f['action']} - {f['description']}[/dim]")
        console.print()

    # Summary
    summary = result.get("summary", {})
    console.print(
        f"  [dim]Escalation paths: "
        f"{summary.get('critical_count', 0)} critical, "
        f"{summary.get('high_count', 0)} high, "
        f"{summary.get('medium_count', 0)} potential[/dim]"
    )
    console.print()


if __name__ == "__main__":
    app()
