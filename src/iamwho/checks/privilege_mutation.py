# src/iamwho/checks/privilege_mutation.py
"""
PRIVILEGE MUTATION check - identifies privilege escalation paths.
"""

from typing import Any

from iamwho.checks import egress


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
    # Note: egress findings are already allowed permissions (no effect field)
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


def _determine_verdict(all_risks: list[str], findings: list[dict[str, Any]]) -> tuple[str, str]:
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
