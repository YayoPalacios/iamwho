# src/iamwho/checks/privilege_mutation.py
"""
PRIVILEGE MUTATION check - identifies privilege escalation paths.
"""

from typing import Any

from rich.console import Console

from iamwho.checks import egress

console = Console()


ESCALATION_PATHS: dict[str, dict[str, Any]] = {
    # Direct policy attachment
    "iam:AttachUserPolicy": {
        "risk": "CRITICAL",
        "category": "DIRECT_POLICY_ATTACH",
        "description": "Can attach any managed policy to a user",
        "escalation": "Attach AdministratorAccess to self or controlled user",
    },
    "iam:AttachRolePolicy": {
        "risk": "CRITICAL",
        "category": "DIRECT_POLICY_ATTACH",
        "description": "Can attach any managed policy to a role",
        "escalation": "Attach AdministratorAccess to assumable role",
    },
    "iam:AttachGroupPolicy": {
        "risk": "CRITICAL",
        "category": "DIRECT_POLICY_ATTACH",
        "description": "Can attach any managed policy to a group",
        "escalation": "Attach AdministratorAccess to group you belong to",
    },
    # Inline policy creation
    "iam:PutUserPolicy": {
        "risk": "CRITICAL",
        "category": "INLINE_POLICY_WRITE",
        "description": "Can write inline policy on a user",
        "escalation": "Grant self any permission via inline policy",
    },
    "iam:PutRolePolicy": {
        "risk": "CRITICAL",
        "category": "INLINE_POLICY_WRITE",
        "description": "Can write inline policy on a role",
        "escalation": "Grant assumable role any permission",
    },
    "iam:PutGroupPolicy": {
        "risk": "CRITICAL",
        "category": "INLINE_POLICY_WRITE",
        "description": "Can write inline policy on a group",
        "escalation": "Grant your group any permission",
    },
    # Policy version manipulation
    "iam:CreatePolicyVersion": {
        "risk": "CRITICAL",
        "category": "POLICY_EDIT",
        "description": "Can create new version of managed policy",
        "escalation": "Modify existing policy to grant admin access",
    },
    "iam:SetDefaultPolicyVersion": {
        "risk": "HIGH",
        "category": "POLICY_EDIT",
        "description": "Can set default version of managed policy",
        "escalation": "Revert policy to older, more permissive version",
    },
    # Credential creation
    "iam:CreateAccessKey": {
        "risk": "HIGH",
        "category": "CREDENTIAL_CREATE",
        "description": "Can create access keys for IAM users",
        "escalation": "Create keys for more privileged user",
    },
    "iam:CreateLoginProfile": {
        "risk": "HIGH",
        "category": "CREDENTIAL_CREATE",
        "description": "Can create console login for IAM users",
        "escalation": "Enable console access for privileged user",
    },
    "iam:UpdateLoginProfile": {
        "risk": "HIGH",
        "category": "CREDENTIAL_CREATE",
        "description": "Can reset console password for IAM users",
        "escalation": "Take over another user's console access",
    },
    # Trust policy manipulation
    "iam:UpdateAssumeRolePolicy": {
        "risk": "HIGH",
        "category": "TRUST_POLICY_EDIT",
        "description": "Can modify role trust policies",
        "escalation": "Backdoor role to trust attacker-controlled principal",
    },
    # Role passing (requires combination)
    "iam:PassRole": {
        "risk": "MEDIUM",
        "category": "ROLE_PASS",
        "description": "Can pass roles to AWS services",
        "escalation": "Pass high-privilege role to Lambda/EC2 you control",
        "requires_combination": True,
    },
    # Role assumption
    "sts:AssumeRole": {
        "risk": "MEDIUM",
        "category": "ROLE_ASSUME",
        "description": "Can assume other IAM roles",
        "escalation": "Pivot to more privileged role",
        "requires_combination": True,
    },
    # Lambda code update
    "lambda:UpdateFunctionCode": {
        "risk": "MEDIUM",
        "category": "CODE_INJECT",
        "description": "Can modify Lambda function code",
        "escalation": "Inject code into Lambda with privileged role",
        "requires_combination": True,
    },
    # Service creation with role
    "lambda:CreateFunction": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can create Lambda functions",
        "escalation": "Create Lambda with passed privileged role",
        "requires_combination": True,
    },
    "ec2:RunInstances": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can launch EC2 instances",
        "escalation": "Launch instance with passed privileged role",
        "requires_combination": True,
    },
    "glue:CreateDevEndpoint": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can create Glue dev endpoints",
        "escalation": "Create endpoint with passed privileged role",
        "requires_combination": True,
    },
    "glue:UpdateDevEndpoint": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can update Glue dev endpoints",
        "escalation": "Update endpoint SSH key for access",
        "requires_combination": True,
    },
    "cloudformation:CreateStack": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can create CloudFormation stacks",
        "escalation": "Create stack with passed privileged role",
        "requires_combination": True,
    },
    "datapipeline:CreatePipeline": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can create Data Pipeline",
        "escalation": "Create pipeline with passed privileged role",
        "requires_combination": True,
    },
    "sagemaker:CreateNotebookInstance": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can create SageMaker notebook",
        "escalation": "Create notebook with passed privileged role",
        "requires_combination": True,
    },
}

ESCALATION_COMBOS: list[dict[str, Any]] = [
    {
        "actions": ["iam:PassRole", "lambda:CreateFunction"],
        "risk": "HIGH",
        "description": "Can create Lambda with arbitrary role",
        "escalation": "Create Lambda with admin role, invoke to get credentials",
    },
    {
        "actions": ["iam:PassRole", "lambda:UpdateFunctionCode"],
        "risk": "HIGH",
        "description": "Can modify Lambda code and pass new role",
        "escalation": "Update existing Lambda to exfiltrate role credentials",
    },
    {
        "actions": ["iam:PassRole", "ec2:RunInstances"],
        "risk": "HIGH",
        "description": "Can launch EC2 with arbitrary role",
        "escalation": "Launch instance with admin role, SSH to get credentials",
    },
    {
        "actions": ["iam:PassRole", "glue:CreateDevEndpoint"],
        "risk": "HIGH",
        "description": "Can create Glue endpoint with arbitrary role",
        "escalation": "Create Glue endpoint with admin role",
    },
    {
        "actions": ["iam:PassRole", "cloudformation:CreateStack"],
        "risk": "HIGH",
        "description": "Can create CloudFormation stack with arbitrary role",
        "escalation": "Create stack that provisions admin resources",
    },
    {
        "actions": ["iam:PassRole", "datapipeline:CreatePipeline"],
        "risk": "HIGH",
        "description": "Can create Data Pipeline with arbitrary role",
        "escalation": "Create pipeline that runs with admin role",
    },
    {
        "actions": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
        "risk": "HIGH",
        "description": "Can create SageMaker notebook with arbitrary role",
        "escalation": "Create notebook with admin role for credential access",
    },
    {
        "actions": ["iam:CreateAccessKey", "sts:AssumeRole"],
        "risk": "HIGH",
        "description": "Can create keys and assume roles",
        "escalation": "Create persistent access then pivot to privileged roles",
    },
]


def run(principal_arn: str) -> dict[str, Any]:
    """
    Run privilege mutation check on a principal.

    Args:
        principal_arn: The ARN of the IAM principal

    Returns:
        Dictionary with mutation analysis results
    """
    # Get permissions from egress check
    egress_result = egress.run(principal_arn)

    if egress_result["status"] == "error":
        return egress_result

    if egress_result["status"] == "not_applicable":
        return {
            "status": "not_applicable",
            "message": egress_result["message"],
        }

    # Egress findings are already "Allow" permissions - no effect field
    permissions = egress_result.get("findings", [])

    if not permissions:
        return {
            "status": "success",
            "message": "PRIVILEGE MUTATION - No permissions to analyze",
            "overall_risk": "LOW",
            "verdict": "No permissions found",
            "direct_escalations": [],
            "combination_escalations": [],
            "potential_escalations": [],
            "summary": {"critical_count": 0, "high_count": 0, "medium_count": 0},
        }

    result = check_mutation(permissions)
    result["status"] = "success"
    result["message"] = "PRIVILEGE MUTATION - Escalation path analysis"

    return result


def check_mutation(permissions: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyze permissions for privilege escalation paths.

    Args:
        permissions: List of permission dicts from egress check.
                    Each has: action, resource_scope, explanation, source

    Returns:
        Dictionary with escalation findings
    """
    findings: list[dict[str, Any]] = []
    found_actions: set[str] = set()
    action_details: dict[str, dict[str, Any]] = {}

    # Collect all actions with their details
    for perm in permissions:
        action = perm.get("action", "")
        found_actions.add(action)
        action_details[action] = perm

        # Handle wildcards - expand to all known escalation actions
        _expand_wildcards(action, perm, found_actions, action_details)

    # Check for escalation paths
    for action in found_actions:
        if action in ESCALATION_PATHS:
            path_info = ESCALATION_PATHS[action]
            perm = action_details.get(action, {})

            # Get resource scope from egress finding
            resource_scope = perm.get("resource_scope", "ALL")

            finding = {
                "action": action,
                "risk": path_info["risk"],
                "category": path_info["category"],
                "description": path_info["description"],
                "escalation_path": path_info["escalation"],
                "resource_scope": resource_scope,
                "source_policy": perm.get("source", "Unknown"),
                "requires_combination": path_info.get("requires_combination", False),
            }
            findings.append(finding)

    # Check for dangerous combinations
    combo_findings: list[dict[str, Any]] = []
    for combo in ESCALATION_COMBOS:
        required_actions = combo["actions"]
        if all(action in found_actions for action in required_actions):
            combo_findings.append({
                "actions": required_actions,
                "risk": combo["risk"],
                "description": combo["description"],
                "escalation_path": combo["escalation"],
            })

    # Determine overall risk
    direct_escalations = [f for f in findings if not f.get("requires_combination")]
    potential_escalations = [f for f in findings if f.get("requires_combination")]

    direct_risks = [f["risk"] for f in direct_escalations]
    combo_risks = [c["risk"] for c in combo_findings]
    all_risks = direct_risks + combo_risks

    overall_risk, verdict = _determine_verdict(all_risks, findings)

    return {
        "overall_risk": overall_risk,
        "verdict": verdict,
        "direct_escalations": direct_escalations,
        "combination_escalations": combo_findings,
        "potential_escalations": potential_escalations,
        "summary": {
            "critical_count": sum(1 for f in direct_escalations if f["risk"] == "CRITICAL"),
            "high_count": (
                    sum(1 for f in direct_escalations if f["risk"] == "HIGH")
                    + sum(1 for c in combo_findings if c["risk"] == "HIGH")
            ),
            "medium_count": sum(1 for f in findings if f["risk"] == "MEDIUM"),
        },
    }


def _expand_wildcards(
        action: str,
        perm: dict[str, Any],
        found_actions: set[str],
        action_details: dict[str, dict[str, Any]],
) -> None:
    """Expand wildcard actions to all matching escalation paths."""

    # Full wildcard - matches everything
    if action == "*":
        for esc_action in ESCALATION_PATHS:
            found_actions.add(esc_action)
            if esc_action not in action_details:
                action_details[esc_action] = perm
        return

    # Service wildcard (e.g., "iam:*", "lambda:*")
    if action.endswith(":*"):
        service = action.split(":")[0]
        for esc_action in ESCALATION_PATHS:
            if esc_action.startswith(f"{service}:"):
                found_actions.add(esc_action)
                if esc_action not in action_details:
                    action_details[esc_action] = perm


def _determine_verdict(
        all_risks: list[str], findings: list[dict[str, Any]]
) -> tuple[str, str]:
    """Determine overall risk level and verdict message."""
    if "CRITICAL" in all_risks:
        return "CRITICAL", "CRITICAL: Direct privilege escalation possible"
    if "HIGH" in all_risks:
        return "HIGH", "HIGH: Privilege escalation paths detected"
    if "MEDIUM" in all_risks:
        return "MEDIUM", "MEDIUM: Potential escalation with additional access"
    if findings:
        return "LOW", "LOW: Limited escalation potential"
    return "LOW", "LOW: No obvious privilege escalation paths"


# =============================================================================
# RENDERING
# =============================================================================

RISK_COLORS: dict[str, str] = {
    "CRITICAL": "red bold",
    "HIGH": "red",
    "MEDIUM": "yellow",
    "LOW": "green",
}

RISK_ORDER: dict[str, int] = {
    "CRITICAL": 0,
    "HIGH": 1,
    "MEDIUM": 2,
    "LOW": 3,
}


def render(result: dict[str, Any], verbose: bool = False) -> None:
    """
    Render MUTATION results with tree-style ASCII diagram.

    Args:
        result: Dictionary from run() or check_mutation()
        verbose: Show detailed explanations and remediations
    """
    console.print()
    console.print(
        f"[bold][ MUTATION ][/bold] {result.get('message', 'Privilege escalation paths')}"
    )
    console.print("-" * 60)

    # Handle errors or not applicable
    if result.get("status") == "error":
        console.print()
        console.print(f"  [red]Error: {result.get('error', 'Unknown error')}[/red]")
        console.print()
        return

    if result.get("status") == "not_applicable":
        console.print()
        console.print(f"  [dim]{result.get('message', 'Not applicable')}[/dim]")
        console.print()
        return

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
                    f"  [dim]  - {p['action']} → {p['escalation_path']}[/dim]"
                )

        console.print()
        console.print("-" * 60)
        _render_summary(result)
        return

    console.print()

    # Build display paths from direct escalations and combos
    all_paths: list[dict[str, Any]] = []

    for esc in direct:
        all_paths.append({
            "display": esc["action"],
            "target": _truncate(esc["escalation_path"], 30),
            "risk": esc["risk"],
            "description": esc["description"],
            "category": esc.get("category", ""),
            "source": esc.get("source_policy", ""),
            "resource_scope": esc.get("resource_scope", ""),
        })

    for combo in combos:
        all_paths.append({
            "display": " + ".join(combo["actions"]),
            "target": _truncate(combo["escalation_path"], 30),
            "risk": combo["risk"],
            "description": combo["description"],
            "category": "COMBINATION",
            "source": "",
            "resource_scope": "",
        })

    # Sort by risk (CRITICAL first)
    all_paths.sort(key=lambda p: RISK_ORDER.get(p["risk"], 99))

    # Render tree
    for i, path in enumerate(all_paths):
        is_last = i == len(all_paths) - 1
        prefix = "└──" if is_last else "├──"
        continuation = "   " if is_last else "│  "

        # Build display text and calculate dots
        display_text = f"{path['display']} → {path['target']}"
        total_width = 50
        dots_needed = max(3, total_width - len(display_text))
        dots = "." * dots_needed

        # Get risk color
        style = RISK_COLORS.get(path["risk"], "white")

        # Main line
        console.print(
            f"  {prefix} {display_text} [dim]{dots}[/dim] [{style}]{path['risk']}[/{style}]"
        )

        # Verbose details
        if verbose:
            console.print(f"  {continuation}     [dim]{path['description']}[/dim]")
            if path.get("category"):
                console.print(
                    f"  {continuation}     [dim]Category: {path['category']}[/dim]"
                )
            if path.get("resource_scope") and path["resource_scope"] != "ALL":
                console.print(
                    f"  {continuation}     [cyan]Scope:[/cyan] [dim]{path['resource_scope']}[/dim]"
                )

        # Spacing between entries
        if not is_last:
            console.print("  │")

    # Show potential escalations in verbose mode
    if verbose and potential:
        console.print()
        console.print("  [dim]Potential (requires additional access):[/dim]")
        for p in potential[:5]:
            console.print(
                f"  [dim]  - {p['action']} → {p['escalation_path']}[/dim]"
            )
        if len(potential) > 5:
            console.print(f"  [dim]  ... and {len(potential) - 5} more[/dim]")

    # Footer
    console.print()
    console.print("-" * 60)
    _render_summary(result)


def _render_summary(result: dict[str, Any]) -> None:
    """Render the summary footer."""
    summary = result.get("summary", {})
    overall = result.get("overall_risk", "LOW")
    direct = result.get("direct_escalations", [])
    combos = result.get("combination_escalations", [])

    style = RISK_COLORS.get(overall, "white")
    total_paths = len(direct) + len(combos)

    console.print(
        f"  Paths: {total_paths} | "
        f"Highest: [{style}]{overall}[/{style}] | "
        f"[red]C:{summary.get('critical_count', 0)}[/red] "
        f"[red]H:{summary.get('high_count', 0)}[/red] "
        f"[yellow]M:{summary.get('medium_count', 0)}[/yellow]"
    )
    console.print()

    # Verdict
    verdict = result.get("verdict", "")
    if verdict:
        verdict_style = RISK_COLORS.get(overall, "white")
        console.print(f"  [{verdict_style}]{verdict}[/{verdict_style}]")
        console.print()


def _truncate(text: str, max_len: int) -> str:
    """Truncate text with ellipsis if too long."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 2] + ".."
