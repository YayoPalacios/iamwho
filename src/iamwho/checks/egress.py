# src/iamwho/checks/egress.py
"""
EGRESS check - analyzes what permissions a role has.

Security Focus:
- Dangerous action patterns (iam:*, s3:*, etc.)
- Resource scope (wildcard vs scoped)
- NotAction/NotResource handling (implicit grants)
- Condition presence
"""

from typing import Any

import boto3
from botocore.exceptions import ClientError


# =============================================================================
# DANGEROUS ACTION PATTERNS
# =============================================================================

CRITICAL_ACTIONS: set[str] = {
    "*",
    "iam:*",
    "iam:CreateUser",
    "iam:CreateRole",
    "iam:AttachUserPolicy",
    "iam:AttachRolePolicy",
    "iam:AttachGroupPolicy",
    "iam:PutUserPolicy",
    "iam:PutRolePolicy",
    "iam:PutGroupPolicy",
    "iam:CreatePolicyVersion",
    "iam:SetDefaultPolicyVersion",
    "iam:UpdateAssumeRolePolicy",
    "sts:*",
}

HIGH_RISK_ACTIONS: set[str] = {
    "iam:CreateAccessKey",
    "iam:CreateLoginProfile",
    "iam:UpdateLoginProfile",
    "sts:AssumeRole",
    "sts:AssumeRoleWithSAML",
    "sts:AssumeRoleWithWebIdentity",
    "s3:*",
    "s3:GetObject",
    "s3:PutObject",
    "rds:*",
    "dynamodb:*",
    "secretsmanager:GetSecretValue",
    "ssm:GetParameter",
    "ssm:GetParameters",
    "kms:Decrypt",
    "lambda:*",
    "lambda:CreateFunction",
    "lambda:UpdateFunctionCode",
    "lambda:InvokeFunction",
    "ec2:RunInstances",
    "ecs:RunTask",
    "ecs:RegisterTaskDefinition",
}

MEDIUM_RISK_ACTIONS: set[str] = {
    "iam:PassRole",
    "lambda:UpdateFunctionConfiguration",
    "glue:CreateDevEndpoint",
    "glue:UpdateDevEndpoint",
    "sagemaker:CreateNotebookInstance",
    "cloudformation:CreateStack",
    "cloudformation:UpdateStack",
    "codebuild:CreateProject",
    "codebuild:StartBuild",
    "datapipeline:CreatePipeline",
    "ssm:SendCommand",
    "ssm:StartSession",
    "ec2:AuthorizeSecurityGroupIngress",
    "ec2:AuthorizeSecurityGroupEgress",
    "ec2:CreateSecurityGroup",
}

DANGEROUS_SERVICE_WILDCARDS: dict[str, str] = {
    "iam:*": "Full IAM control - can escalate to admin",
    "sts:*": "Full STS control - can assume any role",
    "s3:*": "Full S3 control - data exfiltration risk",
    "ec2:*": "Full EC2 control - compute abuse",
    "lambda:*": "Full Lambda control - code execution",
    "rds:*": "Full RDS control - database access",
    "dynamodb:*": "Full DynamoDB control - data access",
    "secretsmanager:*": "Full Secrets Manager - credential theft",
    "kms:*": "Full KMS control - encryption key access",
    "organizations:*": "Full Organizations control - account manipulation",
}

ACTION_CATEGORIES: dict[str, list[str]] = {
    "Identity & Access": ["iam:", "sts:", "sso:"],
    "Compute": ["lambda:", "ec2:", "ecs:", "eks:", "batch:"],
    "Data Access": ["s3:", "rds:", "dynamodb:", "redshift:", "athena:"],
    "Secrets & Encryption": ["secretsmanager:", "ssm:", "kms:"],
    "Networking": ["vpc:", "ec2:Authorize", "ec2:Create"],
    "Management": ["organizations:", "cloudformation:", "cloudtrail:"],
}


# =============================================================================
# MAIN ANALYSIS FUNCTION
# =============================================================================

def analyze_egress(role_arn: str) -> dict[str, Any]:
    """Analyze a role's permissions for security risks."""
    if ":role/" not in role_arn:
        return {
            "status": "not_applicable",
            "message": "EGRESS analysis only applies to IAM roles",
        }

    role_name = _extract_role_name(role_arn)
    if not role_name:
        return {
            "status": "error",
            "message": f"Could not extract role name from ARN: {role_arn}",
        }

    policies = _fetch_role_policies(role_name)
    if isinstance(policies, str):
        return {"status": "error", "message": policies}

    if not policies:
        return {
            "status": "success",
            "message": "No policies attached to role",
            "findings": [],
            "summary": {"total_findings": 0, "by_risk": {}, "categories": []},
        }

    findings: list[dict[str, Any]] = []

    for policy in policies:
        policy_name = policy["name"]
        policy_type = policy["type"]
        document = policy["document"]

        statements = document.get("Statement", [])
        if not isinstance(statements, list):
            statements = [statements]

        for statement in statements:
            if statement.get("Effect") != "Allow":
                continue
            statement_findings = _analyze_statement(statement, policy_name, policy_type)
            findings.extend(statement_findings)

    findings = _deduplicate_findings(findings)

    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    findings.sort(key=lambda f: risk_order.get(f["risk"], 99))

    summary = _build_summary(findings)

    return {"status": "success", "findings": findings, "summary": summary}


# =============================================================================
# POLICY FETCHING
# =============================================================================

def _extract_role_name(role_arn: str) -> str | None:
    """Extract role name from ARN."""
    if ":role/" not in role_arn:
        return None
    try:
        role_path = role_arn.split(":role/")[1]
        return role_path.split("/")[-1]
    except IndexError:
        return None


def _fetch_role_policies(role_name: str) -> list[dict[str, Any]] | str:
    """Fetch all policies (inline + attached) for a role."""
    try:
        iam = boto3.client("iam")
        policies: list[dict[str, Any]] = []

        inline_response = iam.list_role_policies(RoleName=role_name)
        for policy_name in inline_response.get("PolicyNames", []):
            policy_response = iam.get_role_policy(RoleName=role_name, PolicyName=policy_name)
            policies.append({
                "name": policy_name,
                "type": "inline",
                "document": policy_response["PolicyDocument"],
            })

        attached_response = iam.list_attached_role_policies(RoleName=role_name)
        for policy in attached_response.get("AttachedPolicies", []):
            policy_arn = policy["PolicyArn"]
            policy_name = policy["PolicyName"]
            policy_info = iam.get_policy(PolicyArn=policy_arn)
            version_id = policy_info["Policy"]["DefaultVersionId"]
            version_response = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
            policies.append({
                "name": policy_name,
                "type": "managed",
                "arn": policy_arn,
                "document": version_response["PolicyVersion"]["Document"],
            })

        return policies

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchEntity":
            return f"Role not found: {role_name}"
        if code == "AccessDenied":
            return f"Access denied fetching policies for: {role_name}"
        return f"AWS error: {code}"
    except Exception as e:
        return f"Unexpected error: {e}"


# =============================================================================
# STATEMENT ANALYSIS
# =============================================================================

def _analyze_statement(
    statement: dict[str, Any],
    policy_name: str,
    policy_type: str,
) -> list[dict[str, Any]]:
    """Analyze a single policy statement for dangerous permissions."""
    findings: list[dict[str, Any]] = []

    actions = statement.get("Action", [])
    not_actions = statement.get("NotAction", [])
    if isinstance(actions, str):
        actions = [actions]
    if isinstance(not_actions, str):
        not_actions = [not_actions]

    resources = statement.get("Resource", [])
    not_resources = statement.get("NotResource", [])
    if isinstance(resources, str):
        resources = [resources]
    if isinstance(not_resources, str):
        not_resources = [not_resources]

    conditions = statement.get("Condition", {})
    resource_scope = _determine_resource_scope(resources, not_resources)
    source = f"{policy_type}:{policy_name}"

    for action in actions:
        finding = _assess_action(
            action=action,
            resource_scope=resource_scope,
            resources=resources,
            conditions=conditions,
            source=source,
            via_not_action=False,
        )
        if finding:
            findings.append(finding)

    if not_actions and not actions:
        not_action_findings = _analyze_not_action(
            not_actions=not_actions,
            resource_scope=resource_scope,
            resources=resources,
            conditions=conditions,
            source=source,
        )
        findings.extend(not_action_findings)

    return findings


def _determine_resource_scope(resources: list[str], not_resources: list[str]) -> str:
    """Determine if resources are wildcarded or scoped."""
    if not_resources:
        return "ALL"
    for res in resources:
        if res == "*":
            return "ALL"
        if res.endswith(":*") or res.endswith("/*"):
            return "ALL"
    return "SCOPED" if resources else "ALL"


def _assess_action(
    action: str,
    resource_scope: str,
    resources: list[str],
    conditions: dict[str, Any],
    source: str,
    via_not_action: bool = False,
) -> dict[str, Any] | None:
    """Assess risk of a single action."""
    risk = "INFO"
    explanation = ""
    via_wildcard = False

    if action == "*":
        risk = "CRITICAL"
        explanation = "Full admin - allows ALL actions on ALL services"
        via_wildcard = True
    elif action in CRITICAL_ACTIONS:
        risk = "CRITICAL"
        explanation = _get_action_explanation(action)
    elif action in HIGH_RISK_ACTIONS:
        risk = "HIGH"
        explanation = _get_action_explanation(action)
    elif action in MEDIUM_RISK_ACTIONS:
        risk = "MEDIUM"
        explanation = _get_action_explanation(action)
    elif action.endswith(":*"):
        service = action.split(":")[0]
        if action in DANGEROUS_SERVICE_WILDCARDS:
            risk = "CRITICAL"
            explanation = DANGEROUS_SERVICE_WILDCARDS[action]
        else:
            risk = "MEDIUM"
            explanation = f"Full {service} service access"
        via_wildcard = True
    elif "*" in action:
        risk = "LOW"
        explanation = "Wildcard action pattern"
        via_wildcard = True
    else:
        return None

    if resource_scope == "SCOPED" and risk in ("HIGH", "MEDIUM"):
        explanation += " (scoped to specific resources)"

    if conditions and risk != "CRITICAL":
        explanation += " [conditions present]"

    return {
        "action": action,
        "risk": risk,
        "explanation": explanation,
        "resource_scope": resource_scope,
        "resources": resources,
        "conditions": conditions,
        "source": source,
        "via_not_action": via_not_action,
        "via_wildcard_action": via_wildcard,
        "original_action": action,
    }


def _analyze_not_action(
    not_actions: list[str],
    resource_scope: str,
    resources: list[str],
    conditions: dict[str, Any],
    source: str,
) -> list[dict[str, Any]]:
    """Analyze NotAction statements."""
    findings: list[dict[str, Any]] = []
    excluded_patterns = set(not_actions)
    all_dangerous = CRITICAL_ACTIONS | HIGH_RISK_ACTIONS | MEDIUM_RISK_ACTIONS
    # =========================================================================
    # FIX: NotAction grants specific actions, not the literal "*" wildcard.
    # A policy with NotAction:["iam:*"] allows everything EXCEPT iam:*,
    # but that's not the same as allowing Action:"*" (full admin).
    # We enumerate specific allowed actions below, so exclude "*" from the set.
    # =========================================================================
    all_dangerous = all_dangerous - {"*"}
    for action in all_dangerous:
        if _action_matches_any_pattern(action, excluded_patterns):
            continue
        finding = _assess_action(
            action=action,
            resource_scope=resource_scope,
            resources=resources,
            conditions=conditions,
            source=source,
            via_not_action=True,
        )
        if finding:
            findings.append(finding)

    if resource_scope == "ALL":
        findings.append({
            "action": f"NotAction:{','.join(not_actions[:3])}{'...' if len(not_actions) > 3 else ''}",
            "risk": "HIGH",
            "explanation": f"Grants all actions EXCEPT {len(not_actions)} pattern(s) - review carefully",
            "resource_scope": resource_scope,
            "resources": resources,
            "conditions": conditions,
            "source": source,
            "via_not_action": True,
            "via_wildcard_action": False,
            "original_action": "NotAction",
        })

    return findings


def _action_matches_any_pattern(action: str, patterns: set[str]) -> bool:
    """Check if an action matches any pattern (including wildcards)."""
    for pattern in patterns:
        if pattern == "*":
            return True
        if pattern == action:
            return True
        if pattern.endswith(":*"):
            service = pattern.split(":")[0]
            if action.startswith(f"{service}:"):
                return True
        if "*" in pattern:
            prefix = pattern.replace("*", "")
            if action.startswith(prefix):
                return True
    return False


def _get_action_explanation(action: str) -> str:
    """Get human-readable explanation for an action."""
    explanations = {
        "*": "Full admin access to all AWS services",
        "iam:*": "Full IAM control - can escalate to admin",
        "iam:CreateUser": "Can create new IAM users",
        "iam:CreateRole": "Can create new IAM roles",
        "iam:AttachUserPolicy": "Can attach policies to users",
        "iam:AttachRolePolicy": "Can attach policies to roles",
        "iam:AttachGroupPolicy": "Can attach policies to groups",
        "iam:PutUserPolicy": "Can write inline policies on users",
        "iam:PutRolePolicy": "Can write inline policies on roles",
        "iam:PutGroupPolicy": "Can write inline policies on groups",
        "iam:CreatePolicyVersion": "Can modify managed policies",
        "iam:SetDefaultPolicyVersion": "Can activate policy versions",
        "iam:UpdateAssumeRolePolicy": "Can modify role trust policies",
        "iam:CreateAccessKey": "Can create access keys for users",
        "iam:CreateLoginProfile": "Can create console passwords",
        "iam:UpdateLoginProfile": "Can reset console passwords",
        "iam:PassRole": "Can pass roles to AWS services",
        "sts:*": "Full STS control",
        "sts:AssumeRole": "Can assume other roles",
        "sts:AssumeRoleWithSAML": "Can assume roles via SAML",
        "sts:AssumeRoleWithWebIdentity": "Can assume roles via OIDC",
        "s3:*": "Full S3 access - data exfiltration risk",
        "s3:GetObject": "Can read S3 objects",
        "s3:PutObject": "Can write S3 objects",
        "lambda:*": "Full Lambda control",
        "lambda:CreateFunction": "Can create Lambda functions",
        "lambda:UpdateFunctionCode": "Can modify Lambda code",
        "lambda:InvokeFunction": "Can invoke Lambda functions",
        "lambda:UpdateFunctionConfiguration": "Can modify Lambda config/role",
        "ec2:RunInstances": "Can launch EC2 instances",
        "secretsmanager:GetSecretValue": "Can read secrets",
        "ssm:GetParameter": "Can read SSM parameters",
        "ssm:GetParameters": "Can read SSM parameters",
        "ssm:SendCommand": "Can run commands on EC2",
        "ssm:StartSession": "Can start SSM sessions",
        "kms:Decrypt": "Can decrypt with KMS keys",
        "glue:CreateDevEndpoint": "Can create Glue dev endpoints",
        "glue:UpdateDevEndpoint": "Can modify Glue dev endpoints",
        "sagemaker:CreateNotebookInstance": "Can create SageMaker notebooks",
        "cloudformation:CreateStack": "Can create CloudFormation stacks",
        "cloudformation:UpdateStack": "Can update CloudFormation stacks",
        "codebuild:CreateProject": "Can create CodeBuild projects",
        "codebuild:StartBuild": "Can start CodeBuild builds",
        "ecs:RunTask": "Can run ECS tasks",
        "ecs:RegisterTaskDefinition": "Can register ECS task definitions",
    }
    return explanations.get(action, "Potentially dangerous action")


def _deduplicate_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Deduplicate findings by action, keeping highest risk."""
    seen: dict[str, dict[str, Any]] = {}
    risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

    for finding in findings:
        action = finding["action"]
        if action not in seen:
            seen[action] = finding
        else:
            existing_risk = risk_order.get(seen[action]["risk"], 99)
            new_risk = risk_order.get(finding["risk"], 99)
            if new_risk < existing_risk:
                seen[action] = finding

    return list(seen.values())


def _build_summary(findings: list[dict[str, Any]]) -> dict[str, Any]:
    """Build summary statistics."""
    by_risk: dict[str, int] = {}
    categories: set[str] = set()

    for finding in findings:
        risk = finding["risk"]
        by_risk[risk] = by_risk.get(risk, 0) + 1

        action = finding["action"]
        for category, prefixes in ACTION_CATEGORIES.items():
            if any(action.startswith(prefix) for prefix in prefixes):
                categories.add(category)
                break

    return {
        "total_findings": len(findings),
        "by_risk": by_risk,
        "categories": sorted(categories),
    }


# =============================================================================
# RENDERING (Text.assemble - fully isolated styles)
# =============================================================================

RISK_COLORS: dict[str, str] = {
    "CRITICAL": "red1",
    "HIGH": "orange1",
    "MEDIUM": "yellow",
    "LOW": "green",
    "INFO": "dim",
}


def format_egress(result: dict[str, Any], verbose: bool = False) -> None:
    """Render egress results to console."""
    from rich.console import Console
    from rich.text import Text

    console = Console(highlight=False)  # Disable auto-highlighting

    console.print()
    console.print(Text.assemble(
        ("[bold][ EGRESS ][/bold] What can this role do?", ""),
    ))
    console.print("-" * 60)

    if result.get("status") == "error":
        msg = result.get("message", "Unknown error")
        console.print(Text.assemble(("  Error: ", "red"), (msg, "red")))
        console.print()
        return

    if result.get("status") == "not_applicable":
        msg = result.get("message", "Not applicable")
        console.print(Text.assemble(("  ", ""), (msg, "dim")))
        console.print()
        return

    summary = result.get("summary", {})
    findings = result.get("findings", [])

    if not findings:
        console.print(Text.assemble(("  No dangerous permissions detected", "green")))
        console.print()
        return

    categories = summary.get("categories", [])
    if categories:
        console.print(Text.assemble(
            ("  Categories: ", "dim"),
            (", ".join(categories), "dim cyan"),
        ))
        console.print()

    for finding in findings:
        _render_egress_finding(console, finding, verbose)

    console.print()


def _render_egress_finding(console, finding: dict[str, Any], verbose: bool) -> None:
    """Render a single egress finding with Text.assemble for style isolation."""
    from rich.text import Text

    risk = str(finding.get("risk", "INFO"))
    action = str(finding.get("action", "unknown"))
    risk_color = RISK_COLORS.get(risk, "white")

    resource_scope = finding.get("resource_scope", "ALL")
    scope_char = "*" if resource_scope == "ALL" else "~"

    # === LINE 1: Risk + Scope + Action ===
    parts: list[tuple[str, str]] = [
        (f"  {risk:8}", risk_color),
        (f" {scope_char} ", "dim"),
        (action, "bold white"),
    ]

    if finding.get("via_not_action"):
        parts.append((" (NotAction)", "dim italic"))

    console.print(Text.assemble(*parts))

    # === LINE 2: Explanation ===
    explanation = finding.get("explanation", "")
    if explanation:
        console.print(Text.assemble(
            ("           ", ""),
            (str(explanation), "dim"),
        ))

    # === VERBOSE DETAILS ===
    if verbose:
        source = finding.get("source", "")
        if source:
            console.print(Text.assemble(
                ("           Source: ", "dim"),
                (str(source), "cyan"),
            ))

        if resource_scope == "SCOPED":
            resources = finding.get("resources", [])
            if resources:
                res_str = resources[0] if len(resources) == 1 else f"{resources[0]} (+{len(resources)-1})"
                if len(res_str) > 50:
                    res_str = res_str[:47] + "..."
                console.print(Text.assemble(
                    ("           Resource: ", "dim"),
                    (str(res_str), "cyan"),
                ))

        conditions = finding.get("conditions", {})
        if conditions:
            console.print(Text.assemble(
                ("           Conditions: ", "dim"),
                ("present (may reduce risk)", "green"),
            ))

    console.print()


# =============================================================================
# MODULE ALIASES
# =============================================================================

run = analyze_egress
