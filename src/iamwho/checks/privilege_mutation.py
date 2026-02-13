# src/iamwho/checks/privilege_mutation.py
"""
PRIVILEGE MUTATION check - identifies privilege escalation paths.

Security Focus:
- Direct escalation paths (single action grants admin)
- Combination escalations (multiple actions chain together)
- Resource scope awareness (wildcard vs scoped)
- PassRole pivot chains
"""

from typing import Any

from iamwho.checks import egress

# =============================================================================
# ESCALATION DEFINITIONS
# =============================================================================

# Actions that become CRITICAL when Resource is "*"
WILDCARD_ESCALATES_TO_CRITICAL: set[str] = {
    "iam:PassRole",
    "iam:UpdateAssumeRolePolicy",
    "sts:AssumeRole",
    "iam:CreateAccessKey",
    "iam:UpdateLoginProfile",
    "iam:CreateLoginProfile",
}

ESCALATION_PATHS: dict[str, dict[str, Any]] = {
    # =========================================================================
    # DIRECT POLICY ATTACHMENT - Always dangerous
    # =========================================================================
    "iam:AttachUserPolicy": {
        "risk": "CRITICAL",
        "category": "DIRECT_POLICY_ATTACH",
        "description": "Can attach any managed policy to a user",
        "escalation": "Attach AdministratorAccess to self or controlled user",
        "remediation": "Scope Resource to specific policy ARNs, never allow arn:aws:iam::*:policy/*",
    },
    "iam:AttachRolePolicy": {
        "risk": "CRITICAL",
        "category": "DIRECT_POLICY_ATTACH",
        "description": "Can attach any managed policy to a role",
        "escalation": "Attach AdministratorAccess to assumable role",
        "remediation": "Scope Resource to specific policy ARNs and role ARNs",
    },
    "iam:AttachGroupPolicy": {
        "risk": "CRITICAL",
        "category": "DIRECT_POLICY_ATTACH",
        "description": "Can attach any managed policy to a group",
        "escalation": "Attach AdministratorAccess to group you belong to",
        "remediation": "Scope Resource to specific policy ARNs and group ARNs",
    },
    # =========================================================================
    # INLINE POLICY CREATION - Can grant arbitrary permissions
    # =========================================================================
    "iam:PutUserPolicy": {
        "risk": "CRITICAL",
        "category": "INLINE_POLICY_WRITE",
        "description": "Can write inline policy on a user",
        "escalation": "Grant self any permission via inline policy",
        "remediation": "Remove this permission or scope to specific users with permission boundary",
    },
    "iam:PutRolePolicy": {
        "risk": "CRITICAL",
        "category": "INLINE_POLICY_WRITE",
        "description": "Can write inline policy on a role",
        "escalation": "Grant assumable role any permission",
        "remediation": "Remove this permission or scope to specific roles",
    },
    "iam:PutGroupPolicy": {
        "risk": "CRITICAL",
        "category": "INLINE_POLICY_WRITE",
        "description": "Can write inline policy on a group",
        "escalation": "Grant your group any permission",
        "remediation": "Remove this permission or scope to specific groups",
    },
    # =========================================================================
    # POLICY VERSION MANIPULATION
    # =========================================================================
    "iam:CreatePolicyVersion": {
        "risk": "CRITICAL",
        "category": "POLICY_EDIT",
        "description": "Can create new version of managed policy",
        "escalation": "Modify existing policy to grant admin access",
        "remediation": "Scope to specific policy ARNs that are not attached to privileged principals",
    },
    "iam:SetDefaultPolicyVersion": {
        "risk": "HIGH",
        "category": "POLICY_EDIT",
        "description": "Can set default version of managed policy",
        "escalation": "Revert policy to older, more permissive version",
        "remediation": "Scope to specific policy ARNs, audit policy version history",
    },
    # =========================================================================
    # CREDENTIAL CREATION - Persistence and takeover
    # =========================================================================
    "iam:CreateAccessKey": {
        "risk": "HIGH",
        "category": "CREDENTIAL_CREATE",
        "description": "Can create access keys for IAM users",
        "escalation": "Create keys for more privileged user",
        "remediation": "Scope Resource to specific user ARNs (ideally only self)",
    },
    "iam:CreateLoginProfile": {
        "risk": "HIGH",
        "category": "CREDENTIAL_CREATE",
        "description": "Can create console login for IAM users",
        "escalation": "Enable console access for privileged user",
        "remediation": "Scope Resource to specific user ARNs",
    },
    "iam:UpdateLoginProfile": {
        "risk": "HIGH",
        "category": "CREDENTIAL_CREATE",
        "description": "Can reset console password for IAM users",
        "escalation": "Take over another user's console access",
        "remediation": "Scope Resource to self only (arn:aws:iam::*:user/${aws:username})",
    },
    # =========================================================================
    # TRUST POLICY MANIPULATION - Backdoor roles
    # =========================================================================
    "iam:UpdateAssumeRolePolicy": {
        "risk": "HIGH",
        "category": "TRUST_POLICY_EDIT",
        "description": "Can modify role trust policies",
        "escalation": "Backdoor any role to trust attacker-controlled principal",
        "remediation": "Never grant on Resource:* - scope to specific non-privileged roles",
    },
    # =========================================================================
    # ROLE PASSING - Pivot point (requires service to use the role)
    # =========================================================================
    "iam:PassRole": {
        "risk": "MEDIUM",
        "category": "ROLE_PASS",
        "description": "Can pass roles to AWS services",
        "escalation": "Pass high-privilege role to Lambda/EC2/Glue you control",
        "requires_combination": True,
        "remediation": "Scope Resource to specific role ARNs with least privilege",
    },
    # =========================================================================
    # ROLE ASSUMPTION - Lateral movement
    # =========================================================================
    "sts:AssumeRole": {
        "risk": "MEDIUM",
        "category": "ROLE_ASSUME",
        "description": "Can assume other IAM roles",
        "escalation": "Pivot to any assumable role in the account",
        "requires_combination": True,
        "remediation": "Scope Resource to specific role ARNs needed for the workload",
    },
    # =========================================================================
    # LAMBDA ABUSE - Code execution with role credentials
    # =========================================================================
    "lambda:CreateFunction": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can create Lambda functions",
        "escalation": "Create Lambda with passed privileged role, invoke to get creds",
        "requires_combination": True,
        "remediation": "Require specific role ARNs via iam:PassRole scope",
    },
    "lambda:UpdateFunctionCode": {
        "risk": "MEDIUM",
        "category": "CODE_INJECT",
        "description": "Can modify Lambda function code",
        "escalation": "Inject code into Lambda with privileged role to exfiltrate creds",
        "requires_combination": True,
        "remediation": "Scope to specific function ARNs, monitor for code changes",
    },
    "lambda:UpdateFunctionConfiguration": {
        "risk": "MEDIUM",
        "category": "CODE_INJECT",
        "description": "Can modify Lambda configuration including execution role",
        "escalation": "Change Lambda role to privileged one, invoke to get creds",
        "requires_combination": True,
        "remediation": "Scope to specific function ARNs, separate from invoke permission",
    },
    "lambda:InvokeFunction": {
        "risk": "LOW",
        "category": "SERVICE_INVOKE",
        "description": "Can invoke Lambda functions",
        "escalation": "Trigger Lambda to perform privileged actions",
        "requires_combination": True,
        "remediation": "Scope to specific function ARNs",
    },
    "lambda:AddPermission": {
        "risk": "MEDIUM",
        "category": "RESOURCE_POLICY",
        "description": "Can add resource-based policy to Lambda",
        "escalation": "Allow external principal to invoke Lambda with privileged role",
        "requires_combination": True,
        "remediation": "Scope to specific function ARNs",
    },
    # =========================================================================
    # EC2 ABUSE - Instance with role
    # =========================================================================
    "ec2:RunInstances": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can launch EC2 instances",
        "escalation": "Launch instance with privileged instance profile, SSH in",
        "requires_combination": True,
        "remediation": "Restrict via ec2:InstanceProfile condition key",
    },
    # =========================================================================
    # GLUE ABUSE - Dev endpoints with role
    # =========================================================================
    "glue:CreateDevEndpoint": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can create Glue dev endpoints",
        "escalation": "Create endpoint with privileged role, SSH to get creds",
        "requires_combination": True,
        "remediation": "Avoid granting this permission, use Glue jobs instead",
    },
    "glue:UpdateDevEndpoint": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can update Glue dev endpoints",
        "escalation": "Update endpoint SSH key to gain access",
        "requires_combination": True,
        "remediation": "Scope to specific endpoint ARNs",
    },
    # =========================================================================
    # CLOUDFORMATION - Infrastructure as code abuse
    # =========================================================================
    "cloudformation:CreateStack": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can create CloudFormation stacks",
        "escalation": "Create stack with privileged role that provisions admin resources",
        "requires_combination": True,
        "remediation": "Scope iam:PassRole to specific CloudFormation service roles",
    },
    "cloudformation:UpdateStack": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can update CloudFormation stacks",
        "escalation": "Modify stack to add backdoor resources",
        "requires_combination": True,
        "remediation": "Scope to specific stack ARNs",
    },
    # =========================================================================
    # DATA PIPELINE - Legacy but dangerous
    # =========================================================================
    "datapipeline:CreatePipeline": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can create Data Pipeline",
        "escalation": "Create pipeline that runs with privileged role",
        "requires_combination": True,
        "remediation": "Prefer Step Functions or other modern alternatives",
    },
    # =========================================================================
    # SAGEMAKER - Notebooks with role
    # =========================================================================
    "sagemaker:CreateNotebookInstance": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can create SageMaker notebook",
        "escalation": "Create notebook with privileged role, open Jupyter for cred access",
        "requires_combination": True,
        "remediation": "Scope iam:PassRole to specific SageMaker execution roles",
    },
    "sagemaker:CreatePresignedNotebookInstanceUrl": {
        "risk": "MEDIUM",
        "category": "SERVICE_ACCESS",
        "description": "Can create presigned URL to existing notebook",
        "escalation": "Access notebook with privileged role without SSH",
        "requires_combination": True,
        "remediation": "Scope to specific notebook instance ARNs",
    },
    # =========================================================================
    # SSM - Command execution on EC2
    # =========================================================================
    "ssm:SendCommand": {
        "risk": "MEDIUM",
        "category": "CODE_INJECT",
        "description": "Can send commands to EC2 instances via SSM",
        "escalation": "Execute commands on instances with privileged instance profiles",
        "requires_combination": True,
        "remediation": "Scope to specific instance ARNs or tags",
    },
    "ssm:StartSession": {
        "risk": "MEDIUM",
        "category": "CODE_INJECT",
        "description": "Can start SSM session on EC2 instances",
        "escalation": "Interactive shell on instances with privileged roles",
        "requires_combination": True,
        "remediation": "Scope to specific instance ARNs or tags",
    },
    # =========================================================================
    # ECS - Container execution with role
    # =========================================================================
    "ecs:RunTask": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can run ECS tasks",
        "escalation": "Run task with privileged task role",
        "requires_combination": True,
        "remediation": "Scope to specific task definition ARNs",
    },
    "ecs:RegisterTaskDefinition": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can register new task definitions",
        "escalation": "Create task definition with privileged role, run it",
        "requires_combination": True,
        "remediation": "Restrict iam:PassRole to specific ECS task roles",
    },
    # =========================================================================
    # CODESTAR / CODEBUILD - CI/CD abuse
    # =========================================================================
    "codebuild:CreateProject": {
        "risk": "MEDIUM",
        "category": "SERVICE_CREATE",
        "description": "Can create CodeBuild projects",
        "escalation": "Create project with privileged role, run build to get creds",
        "requires_combination": True,
        "remediation": "Scope iam:PassRole to specific CodeBuild service roles",
    },
    "codebuild:StartBuild": {
        "risk": "LOW",
        "category": "SERVICE_INVOKE",
        "description": "Can start CodeBuild builds",
        "escalation": "Trigger build that runs with privileged role",
        "requires_combination": True,
        "remediation": "Scope to specific project ARNs",
    },
}


ESCALATION_COMBOS: list[dict[str, Any]] = [
    # =========================================================================
    # PASSROLE COMBINATIONS - The classic pivots
    # =========================================================================
    {
        "actions": ["iam:PassRole", "lambda:CreateFunction"],
        "risk": "HIGH",
        "description": "Can create Lambda with arbitrary role",
        "escalation": "Create Lambda with admin role, invoke to exfiltrate credentials",
        "requires_passrole_wildcard_for_critical": True,
    },
    {
        "actions": ["iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"],
        "risk": "HIGH",
        "description": "Full Lambda exploitation chain",
        "escalation": "Create Lambda with admin role and invoke it directly",
        "requires_passrole_wildcard_for_critical": True,
    },
    {
        "actions": ["iam:PassRole", "lambda:UpdateFunctionCode"],
        "risk": "HIGH",
        "description": "Can modify Lambda code with role pass capability",
        "escalation": "Inject credential exfiltration code into existing Lambda",
        "requires_passrole_wildcard_for_critical": True,
    },
    {
        "actions": ["lambda:UpdateFunctionConfiguration", "lambda:InvokeFunction"],
        "risk": "HIGH",
        "description": "Can change Lambda role and invoke it",
        "escalation": "Point Lambda at privileged role, invoke, exfiltrate credentials",
        "requires_passrole_wildcard_for_critical": False,
    },
    {
        "actions": ["iam:PassRole", "ec2:RunInstances"],
        "risk": "HIGH",
        "description": "Can launch EC2 with arbitrary instance profile",
        "escalation": "Launch instance with admin role, SSH/SSM to get credentials",
        "requires_passrole_wildcard_for_critical": True,
    },
    {
        "actions": ["iam:PassRole", "glue:CreateDevEndpoint"],
        "risk": "HIGH",
        "description": "Can create Glue endpoint with arbitrary role",
        "escalation": "Create Glue dev endpoint with admin role, SSH in",
        "requires_passrole_wildcard_for_critical": True,
    },
    {
        "actions": ["iam:PassRole", "cloudformation:CreateStack"],
        "risk": "HIGH",
        "description": "Can create CloudFormation stack with arbitrary role",
        "escalation": "Deploy stack that creates backdoor IAM resources",
        "requires_passrole_wildcard_for_critical": True,
    },
    {
        "actions": ["iam:PassRole", "datapipeline:CreatePipeline"],
        "risk": "HIGH",
        "description": "Can create Data Pipeline with arbitrary role",
        "escalation": "Create pipeline that executes with admin role",
        "requires_passrole_wildcard_for_critical": True,
    },
    {
        "actions": ["iam:PassRole", "sagemaker:CreateNotebookInstance"],
        "risk": "HIGH",
        "description": "Can create SageMaker notebook with arbitrary role",
        "escalation": "Create notebook with admin role, access via Jupyter",
        "requires_passrole_wildcard_for_critical": True,
    },
    {
        "actions": ["iam:PassRole", "ecs:RegisterTaskDefinition", "ecs:RunTask"],
        "risk": "HIGH",
        "description": "Can register and run ECS tasks with arbitrary role",
        "escalation": "Run container with admin task role",
        "requires_passrole_wildcard_for_critical": True,
    },
    {
        "actions": ["iam:PassRole", "codebuild:CreateProject"],
        "risk": "HIGH",
        "description": "Can create CodeBuild project with arbitrary role",
        "escalation": "Create build project with admin role, run build",
        "requires_passrole_wildcard_for_critical": True,
    },
    # =========================================================================
    # CREDENTIAL + ASSUME CHAINS
    # =========================================================================
    {
        "actions": ["iam:CreateAccessKey", "sts:AssumeRole"],
        "risk": "HIGH",
        "description": "Can create persistent keys and pivot",
        "escalation": "Create long-lived credentials, then assume privileged roles",
        "requires_passrole_wildcard_for_critical": False,
    },
    # =========================================================================
    # SSM CHAINS
    # =========================================================================
    {
        "actions": ["ssm:SendCommand", "ec2:DescribeInstances"],
        "risk": "HIGH",
        "description": "Can enumerate and execute on EC2 instances",
        "escalation": "Find instances with privileged roles, execute commands",
        "requires_passrole_wildcard_for_critical": False,
    },
    # =========================================================================
    # POLICY VERSION CHAIN
    # =========================================================================
    {
        "actions": ["iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion"],
        "risk": "CRITICAL",
        "description": "Full control over managed policy content",
        "escalation": "Create malicious policy version and activate it",
        "requires_passrole_wildcard_for_critical": False,
    },
]


# =============================================================================
# MAIN ANALYSIS FUNCTION
# =============================================================================


def analyze_privilege_mutation(principal_arn: str) -> dict[str, Any]:
    """
    Run privilege mutation check on a principal.

    Args:
        principal_arn: The ARN of the IAM principal

    Returns:
        Dictionary with mutation analysis results
    """
    egress_result = egress.run(principal_arn)

    if egress_result["status"] == "error":
        return {
            "status": "error",
            "message": egress_result.get("message", "Failed to get permissions"),
            "error": egress_result.get("message"),
        }

    if egress_result["status"] == "not_applicable":
        return {
            "status": "not_applicable",
            "message": egress_result["message"],
        }

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
            "findings": [],
            "summary": {
                "critical_count": 0,
                "high_count": 0,
                "medium_count": 0,
                "verdict": "LOW",
                "verdict_explanation": "No permissions found",
            },
        }

    result = _check_mutation(permissions)
    result["status"] = "success"
    result["message"] = "PRIVILEGE MUTATION - Escalation path analysis"

    return result


def _check_mutation(permissions: list[dict[str, Any]]) -> dict[str, Any]:
    """
    Analyze permissions for privilege escalation paths.

    Args:
        permissions: List of permission dicts from egress check.
                    Each has: action, resource_scope, resources, explanation, source

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
        _expand_wildcards(action, perm, found_actions, action_details)

    # Check for escalation paths
    for action in found_actions:
        if action not in ESCALATION_PATHS:
            continue

        path_info = ESCALATION_PATHS[action]
        perm = action_details.get(action, {})
        resource_scope = perm.get("resource_scope", "ALL")
        is_wildcard = resource_scope == "ALL"

        # Determine effective risk based on resource scope
        base_risk = path_info["risk"]
        requires_combo = path_info.get("requires_combination", False)

        if is_wildcard and action in WILDCARD_ESCALATES_TO_CRITICAL:
            effective_risk = "CRITICAL"
            # Wildcard on these actions makes them direct escalation
            requires_combo = False
        else:
            effective_risk = base_risk

        finding = {
            "action": action,
            "actions": [action],  # For consistent rendering
            "risk": effective_risk,
            "base_risk": base_risk,
            "category": path_info["category"],
            "description": path_info["description"],
            "escalation_path": path_info["escalation"],
            "remediation": path_info.get("remediation", ""),
            "resource_scope": resource_scope,
            "resources": perm.get("resources", []),
            "source_policy": perm.get("source", "Unknown"),
            "requires_combination": requires_combo,
            "escalated_due_to_wildcard": (effective_risk != base_risk),
            "is_combo": False,
        }
        findings.append(finding)

    # Check for dangerous combinations
    combo_findings = _check_combos(found_actions, action_details)

    # Mark combos
    for cf in combo_findings:
        cf["is_combo"] = True

    # Categorize findings
    direct_escalations = [f for f in findings if not f.get("requires_combination")]
    potential_escalations = [f for f in findings if f.get("requires_combination")]

    # Calculate risk from direct + combo (not potential)
    all_risks = [f["risk"] for f in direct_escalations] + [
        c["risk"] for c in combo_findings
    ]

    overall_risk, verdict = _determine_verdict(all_risks, findings)

    # Build unified findings list for rendering (direct + combos)
    all_findings = direct_escalations + combo_findings

    # Sort by risk level
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
    all_findings.sort(key=lambda f: risk_order.get(f["risk"], 99))

    return {
        "overall_risk": overall_risk,
        "verdict": verdict,
        "direct_escalations": direct_escalations,
        "combination_escalations": combo_findings,
        "potential_escalations": potential_escalations,
        "findings": all_findings,  # Unified list for rendering
        "summary": {
            "critical_count": (
                sum(1 for f in direct_escalations if f["risk"] == "CRITICAL")
                + sum(1 for c in combo_findings if c["risk"] == "CRITICAL")
            ),
            "high_count": (
                sum(1 for f in direct_escalations if f["risk"] == "HIGH")
                + sum(1 for c in combo_findings if c["risk"] == "HIGH")
            ),
            "medium_count": sum(1 for f in findings if f["risk"] == "MEDIUM"),
            "verdict": overall_risk,
            "verdict_explanation": verdict,
        },
    }


def _check_combos(
    found_actions: set[str],
    action_details: dict[str, dict[str, Any]],
) -> list[dict[str, Any]]:
    """Check for dangerous action combinations with scope awareness."""
    combo_findings: list[dict[str, Any]] = []

    for combo in ESCALATION_COMBOS:
        required_actions = combo["actions"]
        if not all(action in found_actions for action in required_actions):
            continue

        # Check PassRole scope for combos that depend on it
        passrole_scope = action_details.get("iam:PassRole", {}).get(
            "resource_scope", "SCOPED"
        )
        passrole_is_wildcard = passrole_scope == "ALL"

        # Determine effective risk
        base_risk = combo["risk"]
        if passrole_is_wildcard and combo.get(
            "requires_passrole_wildcard_for_critical", False
        ):
            effective_risk = "CRITICAL"
        else:
            effective_risk = base_risk

        combo_findings.append(
            {
                "actions": required_actions,
                "risk": effective_risk,
                "base_risk": base_risk,
                "description": combo["description"],
                "escalation_path": combo["escalation"],
                "passrole_is_wildcard": passrole_is_wildcard,
                "escalated_due_to_wildcard": (effective_risk != base_risk),
                "is_combo": True,
            }
        )

    return combo_findings


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
        return

    # Partial wildcard (e.g., "iam:Attach*", "lambda:Create*")
    if "*" in action:
        prefix = action.replace("*", "")
        for esc_action in ESCALATION_PATHS:
            if esc_action.startswith(prefix):
                found_actions.add(esc_action)
                if esc_action not in action_details:
                    action_details[esc_action] = perm


def _determine_verdict(
    all_risks: list[str],
    findings: list[dict[str, Any]],
) -> tuple[str, str]:
    """Determine overall risk level and verdict message."""
    if "CRITICAL" in all_risks:
        return "CRITICAL", "Direct privilege escalation possible"
    if "HIGH" in all_risks:
        return "HIGH", "Privilege escalation paths detected"
    if "MEDIUM" in all_risks:
        return "MEDIUM", "Potential escalation with additional access"
    if findings:
        return "LOW", "Limited escalation potential"
    return "LOW", "No obvious privilege escalation paths"


# =============================================================================
# RENDERING (with escape() for bulletproof output)
# =============================================================================

RISK_COLORS: dict[str, str] = {
    "CRITICAL": "red1",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim",
}


def format_mutation(result: dict[str, Any], verbose: bool = False) -> None:
    """Render mutation analysis results to console."""
    from rich.console import Console
    from rich.markup import escape
    from rich.text import Text

    console = Console(highlight=False)

    console.print()
    console.print("[bold][ MUTATION ][/bold] How could privileges escalate?")
    console.print("-" * 60)

    if result.get("status") == "error":
        console.print(
            f"  [red]Error: {escape(result.get('message', 'Unknown error'))}[/red]"
        )
        console.print()
        return

    if result.get("status") == "not_applicable":
        console.print(f"  [dim]{escape(result.get('message', 'Not applicable'))}[/dim]")
        console.print()
        return

    findings = result.get("findings", [])

    if not findings:
        console.print("  [green]No privilege escalation paths detected[/green]")
        console.print()
        return

    console.print()

    for finding in findings:
        _render_mutation_finding(console, finding, verbose)

    # Verdict
    summary = result.get("summary", {})
    console.print("-" * 60)

    verdict = summary.get("verdict", "LOW")
    verdict_explanation = summary.get("verdict_explanation", "Analysis complete")
    verdict_style = RISK_COLORS.get(verdict, "white")

    verdict_line = Text()
    verdict_line.append("  Verdict: ", style="bold")
    verdict_line.append(f"{verdict}: ", style=f"bold {verdict_style}")
    verdict_line.append(escape(verdict_explanation), style="white")  # ESCAPED
    console.print(verdict_line)

    console.print()


def _render_mutation_finding(console, finding: dict[str, Any], verbose: bool) -> None:
    """Render a single mutation finding with escape() for safety."""
    from rich.markup import escape
    from rich.text import Text

    risk = finding.get("risk", "MEDIUM")
    risk_color = RISK_COLORS.get(risk, "white")

    # First line: Risk + Action(s)
    header = Text()
    header.append("  ")
    header.append(f"{risk:8}", style=risk_color)

    # Show action(s)
    actions = finding.get("actions", [])
    if actions:
        header.append("  ")
        # ESCAPED: Join and escape all actions
        header.append(escape(" + ".join(actions)), style="bold white")

    # Combo indicator
    if finding.get("is_combo"):
        header.append("  ")
        header.append("[COMBO]", style="bold magenta")

    console.print(header)

    # Second line: Tree connector + Escalation path
    path_line = Text()
    path_line.append("        └─> ", style="dim")
    # ESCAPED: Escalation path
    path_line.append(
        escape(finding.get("escalation_path", "Unknown escalation")), style="white"
    )
    console.print(path_line)

    # Verbose: show resource scope and remediation
    if verbose:
        if finding.get("resource_scope"):
            scope_line = Text()
            scope_line.append("            Scope: ", style="dim")
            scope = finding["resource_scope"]
            scope_style = "red" if scope == "ALL" else "cyan"
            scope_line.append(escape(scope), style=scope_style)  # ESCAPED
            console.print(scope_line)

        if finding.get("remediation"):
            rem_line = Text()
            rem_line.append("            Fix: ", style="dim")
            # ESCAPED: Remediation text
            rem_line.append(escape(finding["remediation"]), style="dim green")
            console.print(rem_line)

        if finding.get("source_policy"):
            src_line = Text()
            src_line.append("            Source: ", style="dim")
            # ESCAPED: Source policy
            src_line.append(escape(finding["source_policy"]), style="dim cyan")
            console.print(src_line)

    console.print()


# =============================================================================
# MODULE ALIASES
# =============================================================================

# Primary entry point
run = analyze_privilege_mutation
