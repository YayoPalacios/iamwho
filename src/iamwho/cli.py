# src/iamwho/cli.py
"""IAMWho CLI - AWS IAM Role Security Analyzer"""

import json
import re
from typing import Optional

import typer
from rich.console import Console
from rich.panel import Panel
from rich.text import Text

# ═══════════════════════════════════════════════════════════════════════════════
# App Setup
# ═══════════════════════════════════════════════════════════════════════════════
app = typer.Typer(
    name="iamwho",
    help="AWS IAM Role Security Analyzer - Analyze trust policies, permissions, and privilege escalation paths.",
    add_completion=False,
    no_args_is_help=True,
)

console = Console()

# ═══════════════════════════════════════════════════════════════════════════════
# Constants
# ═══════════════════════════════════════════════════════════════════════════════
ARN_PATTERN = re.compile(r"^arn:aws:iam::\d{12}:(role|user)(\/[\w+=,.@\/-]+)+$")

# Background-style severity badge (used for individual findings)
SEVERITY_STYLES = {
    "CRITICAL": ("bold white on red", "CRIT"),
    "HIGH": ("bold white on purple", "HIGH"),
    "MEDIUM": ("bold black on bright_yellow", "MED"),
    "LOW": ("bold black on bright_blue", "LOW"),
    "INFO": ("bold white on cyan", "INFO"),
    "PASS": ("bold white on green", "PASS"),
}

# Text-only styles (used in the summary to be calmer)
SEVERITY_TEXT_STYLES = {
    "CRITICAL": "bold red",
    "HIGH": "bold purple",
    "MEDIUM": "bold yellow",
    "LOW": "bold bright_blue",
    "INFO": "bold cyan",
    "PASS": "bold green",
}

SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO", "PASS"]
VALID_FAIL_ON = {"critical", "high", "medium", "low", "any"}

# ═══════════════════════════════════════════════════════════════════════════════
# Severity Helpers
# ═══════════════════════════════════════════════════════════════════════════════
def get_severity_text(severity: str) -> Text:
    """Return styled severity badge for findings (compact label, colored background)."""
    style, label = SEVERITY_STYLES.get(severity.upper(), ("dim", severity[:4].upper()))
    return Text(f"[{label}]", style=style)


def get_severity_symbol(severity: str) -> Text:
    """Return colored symbol for severity."""
    symbols = {
        "CRITICAL": ("✗", "red bold"),
        "HIGH": ("!", "purple bold"),
        "MEDIUM": ("~", "yellow bold"),
        "LOW": ("·", "bright_blue"),
        "INFO": ("i", "cyan"),
        "PASS": ("✓", "green bold"),
    }
    symbol, style = symbols.get(severity.upper(), ("?", "dim"))
    return Text(symbol, style=style)


def get_section_severity(findings: list) -> str:
    """Get the highest severity from a list of findings."""
    if not findings:
        return "PASS"
    for sev in SEVERITY_ORDER:
        if any(str(f.get("severity", "")).upper() == sev for f in findings):
            return sev
    return "PASS"


# ═══════════════════════════════════════════════════════════════════════════════
# Output Rendering
# ═══════════════════════════════════════════════════════════════════════════════
def print_banner():
    """Print the IAMWho banner."""
    banner = Text()
    banner.append("╦", style="cyan bold")
    banner.append("╔═╗", style="blue bold")
    banner.append("╔╦╗", style="magenta bold")
    banner.append("╦ ╦", style="red bold")
    banner.append("╦ ╦", style="yellow bold")
    banner.append("╔═╗\n", style="green bold")

    banner.append("║", style="cyan bold")
    banner.append("╠═╣", style="blue bold")
    banner.append("║║║", style="magenta bold")
    banner.append("║║║", style="red bold")
    banner.append("╠═╣", style="yellow bold")
    banner.append("║ ║\n", style="green bold")

    banner.append("╩", style="cyan bold")
    banner.append("╩ ╩", style="blue bold")
    banner.append("╩ ╩", style="magenta bold")
    banner.append("╚╩╝", style="red bold")
    banner.append("╩ ╩", style="yellow bold")
    banner.append("╚═╝", style="green bold")

    console.print(banner)
    console.print("[dim]AWS IAM Role Security Analyzer[/dim]\n")


def print_target(role_arn: str):
    """Print the target role being analyzed."""
    console.print(
        Panel(
            Text(role_arn, style="bold cyan"),
            title="[bold white]TARGET[/bold white]",
            title_align="left",
            border_style="cyan",
            padding=(0, 2),
        )
    )


def print_section_header(title: str, subtitle: str, color: str):
    """Print a section header with light framing."""
    console.print()
    console.print(f"┌─ {title} ───────────────────────────────────────────────")
    console.print(f"│ {subtitle}")
    console.print("└─────────────────────────────────────────────────────────")


def print_finding(finding: dict, verbose: bool = False):
    severity = str(finding.get("severity", "LOW")).upper()
    resource = finding.get("resource", finding.get("principal", "*"))
    action = finding.get("action", "")
    description = finding.get("description", "")
    is_combo = finding.get("is_combo", False)
    finding_id = finding.get("id")

    line = Text()
    line.append(get_severity_text(severity))
    line.append(" ")
    line.append_text(get_severity_symbol(severity))
    line.append(" ")
    line.append(str(resource), style="bold white")

    if action and action != resource:
        line.append(" ")
        line.append(str(action), style="cyan")

    if is_combo:
        line.append(" [", style="dim")
        line.append("COMBO", style="bold magenta")
        line.append("]", style="dim")

    if finding_id:
        line.append(f"  id:{finding_id}", style="dim")

    console.print(line)

    if description:
        desc_text = Text()
        desc_text.append("           -> ", style="dim")
        desc_text.append(str(description), style="italic dim")
        console.print(desc_text)

    if verbose:
        source = finding.get("source") or finding.get("source_policy")
        if source:
            src_text = Text()
            src_text.append("           ", style="dim")
            src_text.append("Source: ", style="dim")
            src_text.append(str(source), style="cyan")
            console.print(src_text)

        scope = finding.get("resource_scope")
        if scope:
            scope_text = Text()
            scope_text.append("           ", style="dim")
            scope_text.append("Scope: ", style="dim")
            scope_style = "red" if str(scope) == "ALL" else "cyan"
            scope_text.append(str(scope), style=scope_style)
            console.print(scope_text)

        remediation = finding.get("remediation")
        if remediation:
            rem_text = Text()
            rem_text.append("           ", style="dim")
            rem_text.append("Fix: ", style="dim")
            rem_text.append(str(remediation), style="italic cyan")
            console.print(rem_text)

        conditions = finding.get("conditions", {})
        if conditions:
            cond_text = Text()
            cond_text.append("           ", style="dim")
            cond_text.append("Conditions: ", style="dim")
            cond_text.append("present", style="green")
            console.print(cond_text)

        # Evidence block (policy-only, deterministic)
        evidence = finding.get("evidence") or []
        if isinstance(evidence, list) and evidence:
            ev_text = Text()
            ev_text.append("           ", style="dim")
            ev_text.append("Evidence:", style="dim")
            console.print(ev_text)

            # Collect unique policy labels deterministically
            policies = set()

            for ev in evidence:
                if not isinstance(ev, dict):
                    continue

                policy_type = str(ev.get("policy_type", "")).strip()
                policy_name = str(ev.get("policy_name", "")).strip()
                policy_arn = ev.get("policy_arn")

                if policy_type and policy_name:
                    label = f"{policy_type}:{policy_name}"
                elif policy_name:
                    label = policy_name
                elif policy_type:
                    label = policy_type
                elif policy_arn:
                    label = str(policy_arn)
                else:
                    label = "(unknown policy)"

                policies.add(label)

            for label in sorted(policies):
                bullet = Text("             - ", style="dim")
                bullet.append(label, style="cyan")
                console.print(bullet)

def print_no_findings(message: str = "No findings detected"):
    """Print a no-findings message."""
    text = Text()
    text.append("  + ", style="green bold")
    text.append(message, style="green")
    console.print(text)


def print_summary(ingress_findings: list, egress_findings: list, mutation_findings: list):
    """Print the summary table with better spacing and organization."""
    console.print()
    console.print("━" * 60, style="bold")

    sections = [
        ("INGRESS", ingress_findings, "cyan"),
        ("EGRESS", egress_findings, "yellow"),
        ("MUTATION", mutation_findings, "magenta"),
    ]

    for name, findings, color in sections:
        count = len(findings)
        max_sev = get_section_severity(findings)
        text_style = SEVERITY_TEXT_STYLES.get(max_sev, "dim")
        label = SEVERITY_STYLES.get(max_sev, ("dim", max_sev))[1]

        line = Text()
        line.append(f"  {name.ljust(14)}", style=f"bold {color}")
        line.append(f"{count:>5} findings".ljust(18), style="white")
        line.append(f" {label} ", style=text_style)
        console.print(line)

    console.print("━" * 60, style="bold")

    all_findings = ingress_findings + egress_findings + mutation_findings
    total = len(all_findings)

    counts = {}
    for f in all_findings:
        sev = str(f.get("severity", "LOW")).upper()
        counts[sev] = counts.get(sev, 0) + 1

    breakdown_parts = []
    for sev in SEVERITY_ORDER:
        if sev in counts:
            breakdown_parts.append(f"{counts[sev]} {sev.lower()}")

    breakdown = ", ".join(breakdown_parts)

    summary_line = Text()
    summary_line.append("-> ", style="bold white")
    summary_line.append(f"{total} findings", style="bold white")
    if breakdown:
        summary_line.append(f" ({breakdown})", style="dim")

    console.print(summary_line)
    console.print()


# ═══════════════════════════════════════════════════════════════════════════════
# Result Normalizers
# ═══════════════════════════════════════════════════════════════════════════════
def normalize_ingress_findings(result) -> list[dict]:
    """Convert IngressResult dataclass to list of finding dicts."""
    findings = []
    if hasattr(result, "error") and result.error:
        return []

    raw_findings = getattr(result, "findings", [])
    for f in raw_findings:
        risk = getattr(f, "risk", "LOW")
        if hasattr(risk, "value"):
            risk = risk.value

        principal = getattr(f, "principal", "*")
        assume_type = getattr(f, "assume_type", "")
        if hasattr(assume_type, "value"):
            assume_type = assume_type.value

        description = getattr(f, "description", "")
        if not description:
            principal_type = getattr(f, "principal_type", "")
            if hasattr(principal_type, "value"):
                principal_type = principal_type.value
            description = f"{principal_type} can assume via {assume_type}"

        findings.append(
            {
                "severity": str(risk).upper(),
                "resource": str(principal),
                "action": str(assume_type) if assume_type else "",
                "description": str(description),
                "is_combo": False,
                "conditions": getattr(getattr(f, "conditions", None), "raw_conditions", {}),
            }
        )

    return findings


def normalize_egress_findings(result) -> list[dict]:
    """Convert egress result to list of finding dicts."""
    if not isinstance(result, dict):
        return []

    if "error" in result:
        return []

    findings = []
    raw_findings = result.get("findings", [])
    for f in raw_findings:
        findings.append(
            {
                "severity": str(f.get("risk", f.get("severity", "LOW"))).upper(),
                "resource": f.get("resource", "*"),
                "action": f.get("action", ""),
                "description": f.get("description", f.get("explanation", "")),
                "is_combo": f.get("is_combo", False),
                "resource_scope": f.get("resource_scope"),
                "conditions": f.get("conditions", {}),
                "source": f.get("source"),
                "evidence": f.get("evidence", []),
            }
        )

    return findings


def normalize_mutation_findings(result) -> list[dict]:
    """Convert mutation result to list of finding dicts."""
    if not isinstance(result, dict):
        return []

    if "error" in result:
        return []

    findings = []
    raw_findings = result.get("findings", [])
    for f in raw_findings:
        action = f.get("action", "")
        remediation = f.get("remediation", "")
        finding_id = f.get("id")
        if f.get("actions"):
            action = " + ".join(f.get("actions", []))

        findings.append(
            {
                "id": finding_id,
                "severity": str(f.get("risk", f.get("severity", "LOW"))).upper(),
                "resource": action or f.get("name", "*"),
                "action": "",
                "description": f.get("description", f.get("explanation", "")),
                "is_combo": f.get("is_combo", len(f.get("actions", [])) > 1),
                "resource_scope": f.get("resource_scope"),
                "conditions": f.get("conditions", {}),
                "source": f.get("source_policy") or f.get("source"),
                "source_policy": f.get("source_policy"),
                "remediation": remediation,
                "evidence": f.get("evidence", []),
            }
        )

    return findings


# ═══════════════════════════════════════════════════════════════════════════════
# Validators
# ═══════════════════════════════════════════════════════════════════════════════
def is_valid_arn(arn: str) -> bool:
    """Validate AWS IAM ARN format."""
    return bool(ARN_PATTERN.match(arn))


def validate_fail_on(value: Optional[str]) -> Optional[str]:
    """Validate --fail-on option."""
    if value is None:
        return None
    value_lower = value.lower()
    if value_lower not in VALID_FAIL_ON:
        raise typer.BadParameter(
            f"Invalid value '{value}'. Must be one of: {', '.join(sorted(VALID_FAIL_ON))}"
        )
    return value_lower


# ═══════════════════════════════════════════════════════════════════════════════
# Exit Code Logic
# ═══════════════════════════════════════════════════════════════════════════════
def calculate_exit_code(all_findings: list[dict], fail_on: Optional[str]) -> int:
    """Calculate exit code based on findings and --fail-on threshold."""
    if not fail_on:
        if any(str(f.get("severity", "")).upper() == "CRITICAL" for f in all_findings):
            return 2
        if any(str(f.get("severity", "")).upper() == "HIGH" for f in all_findings):
            return 1
        return 0

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in all_findings:
        sev = str(f.get("severity", "LOW")).upper()
        counts[sev] += 1

    fail_on = fail_on.lower()

    if fail_on == "any":
        if any(counts.values()):
            return 2 if counts.get("CRITICAL", 0) > 0 else 1
    elif fail_on == "critical" and counts.get("CRITICAL", 0) > 0:
        return 2
    elif fail_on == "high":
        if counts.get("CRITICAL", 0) > 0:
            return 2
        if counts.get("HIGH", 0) > 0:
            return 1
    elif fail_on == "medium":
        if counts.get("CRITICAL", 0) > 0:
            return 2
        if counts.get("HIGH", 0) > 0 or counts.get("MEDIUM", 0) > 0:
            return 1
    elif fail_on == "low":
        if counts.get("CRITICAL", 0) > 0:
            return 2
        if (
            counts.get("HIGH", 0) > 0
            or counts.get("MEDIUM", 0) > 0
            or counts.get("LOW", 0) > 0
        ):
            return 1

    return 0


# ═══════════════════════════════════════════════════════════════════════════════
# CLI Commands
# ═══════════════════════════════════════════════════════════════════════════════
@app.command()
def analyze(
    principal_arn: str = typer.Argument(..., help="AWS IAM Role or User ARN to analyze"),
    check: str = typer.Option(
        "all", "--check", "-c", help="Check type: ingress, egress, mutation, or all"
    ),
    output_json: bool = typer.Option(False, "--json", "-j", help="Output as JSON"),
    verbose: bool = typer.Option(False, "--verbose", "-v", help="Show verbose output"),
    no_banner: bool = typer.Option(False, "--no-banner", help="Hide the banner"),
    fail_on: Optional[str] = typer.Option(
        None,
        "--fail-on",
        "-f",
        help="Exit non-zero if findings at or above: critical, high, medium, low, any",
        callback=lambda ctx, param, value: validate_fail_on(value),
    ),
):
    """
    Analyze an IAM role for security issues.

    Examples:
        iamwho analyze arn:aws:iam::123456789012:role/MyRole
        iamwho analyze arn:aws:iam::123456789012:role/MyRole --check egress
        iamwho analyze arn:aws:iam::123456789012:role/MyRole --json
        iamwho analyze arn:aws:iam::123456789012:role/MyRole --fail-on high
    """
    if not is_valid_arn(principal_arn):
        console.print(f"\n[red bold]Error:[/red bold] Invalid ARN format: {principal_arn}\n")
        raise typer.Exit(code=1)

    check = check.lower()
    if check not in {"ingress", "egress", "mutation", "all"}:
        console.print(f"\n[red bold]Error:[/red bold] Invalid check type: {check}\n")
        raise typer.Exit(code=1)

    ingress_findings, egress_findings, mutation_findings = [], [], []
    json_results = {}

    try:
        if check in ("ingress", "all"):
            from iamwho.checks.ingress import analyze_ingress

            result = analyze_ingress(principal_arn)
            ingress_findings = normalize_ingress_findings(result)
            if output_json:
                json_results["ingress"] = _serialize_result(result)

        if check in ("egress", "all"):
            from iamwho.checks.egress import analyze_egress

            result = analyze_egress(principal_arn)
            egress_findings = normalize_egress_findings(result)
            if output_json:
                json_results["egress"] = result

        if check in ("mutation", "all"):
            from iamwho.checks.privilege_mutation import analyze_privilege_mutation

            result = analyze_privilege_mutation(principal_arn)
            mutation_findings = normalize_mutation_findings(result)
            if output_json:
                json_results["mutation"] = result

    except Exception as e:
        console.print(f"\n[red bold]Error:[/red bold] {e}\n")
        if verbose:
            console.print_exception()
        raise typer.Exit(code=1)

    if output_json:
        output = {"principal_arn": principal_arn, "checks": json_results}
        console.print(json.dumps(output, indent=2, default=str))
        raise typer.Exit(code=0)

    if not no_banner:
        print_banner()

    print_target(principal_arn)

    if check in ("ingress", "all"):
        print_section_header("INGRESS", "Who can assume this role?", "cyan")
        if ingress_findings:
            for finding in ingress_findings:
                print_finding(finding, verbose=verbose)
        else:
            print_no_findings("No risky trust relationships detected")

    if check in ("egress", "all"):
        print_section_header("EGRESS", "What can this role do?", "yellow")
        if egress_findings:
            for finding in egress_findings:
                print_finding(finding, verbose=verbose)
        else:
            print_no_findings("No dangerous permissions detected")

    if check in ("mutation", "all"):
        print_section_header("MUTATION", "How could privileges escalate?", "magenta")
        if mutation_findings:
            for finding in mutation_findings:
                print_finding(finding, verbose=verbose)
        else:
            print_no_findings("No escalation paths detected")

    print_summary(ingress_findings, egress_findings, mutation_findings)

    all_findings = ingress_findings + egress_findings + mutation_findings
    exit_code = calculate_exit_code(all_findings, fail_on)

    if exit_code != 0 and fail_on:
        console.print(f"[dim]Exiting with code {exit_code} (--fail-on {fail_on})[/dim]\n")

    raise typer.Exit(code=exit_code)


@app.command()
def version():
    """Show version information."""
    from importlib.metadata import version as get_version

    try:
        ver = get_version("iamwho")
    except Exception:
        ver = "dev"

    console.print(f"[bold]iamwho[/bold] version [cyan]{ver}[/cyan]")


@app.command()
def checks():
    """List available security checks."""
    console.print()
    console.print("[bold]Available Security Checks[/bold]")
    console.print()

    info = [
        ("ingress", "Trust Policy Analysis", "Who/what can assume this role"),
        ("egress", "Permission Analysis", "What the principal can do"),
        ("mutation", "Privilege Escalation", "Paths to escalate privileges"),
    ]

    for name, title, desc in info:
        console.print(f"  [cyan]{name}[/cyan] - [bold]{title}[/bold]")
        console.print(f"    [dim]{desc}[/dim]")
        console.print()


# ═══════════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════════
def _serialize_result(result) -> dict:
    """Convert dataclass result to JSON-serializable dict."""
    from dataclasses import asdict, is_dataclass
    from enum import Enum

    def convert(obj):
        if is_dataclass(obj):
            return {k: convert(v) for k, v in asdict(obj).items()}
        elif isinstance(obj, Enum):
            return obj.value
        elif isinstance(obj, list):
            return [convert(i) for i in obj]
        elif isinstance(obj, dict):
            return {k: convert(v) for k, v in obj.items()}
        return obj

    return convert(result)


if __name__ == "__main__":
    app()
