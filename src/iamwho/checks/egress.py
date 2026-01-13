# src/iamwho/checks/egress.py
"""
EGRESS Check - Analyze what actions a principal can perform.

Security Focus:
- Identify overly permissive policies
- Flag privilege escalation paths
- Detect data exfiltration risks
- Highlight lateral movement capabilities
"""

import boto3
import json
import re
from typing import Any

# === DANGEROUS PERMISSION PATTERNS ===

CRITICAL_PATTERNS = [
    # Full admin
    (r"^\*$", "*", "Full admin access to all AWS services"),
    (r"^iam:\*$", "iam:*", "Full IAM control - can escalate to admin"),

    # Privilege escalation via IAM
    (r"^iam:CreateUser$", "iam:CreateUser", "Can create backdoor users"),
    (r"^iam:CreateAccessKey$", "iam:CreateAccessKey", "Can create persistent credentials"),
    (r"^iam:AttachUserPolicy$", "iam:AttachUserPolicy", "Can grant any permission to users"),
    (r"^iam:AttachRolePolicy$", "iam:AttachRolePolicy", "Can grant any permission to roles"),
    (r"^iam:PutUserPolicy$", "iam:PutUserPolicy", "Can grant any permission inline"),
    (r"^iam:PutRolePolicy$", "iam:PutRolePolicy", "Can grant any permission inline"),
    (r"^iam:CreatePolicyVersion$", "iam:CreatePolicyVersion", "Can modify managed policies"),
    (r"^iam:SetDefaultPolicyVersion$", "iam:SetDefaultPolicyVersion", "Can activate malicious policy versions"),
    (r"^iam:PassRole$", "iam:PassRole", "Can pass roles to services (pivot point)"),
    (r"^iam:UpdateAssumeRolePolicy$", "iam:UpdateAssumeRolePolicy", "Can backdoor role trust policies"),

    # STS abuse
    (r"^sts:AssumeRole$", "sts:AssumeRole", "Can assume other roles (check Resource)"),
]

HIGH_PATTERNS = [
    # Data exfiltration
    (r"^s3:\*$", "s3:*", "Full S3 access - data exfiltration risk"),
    (r"^s3:GetObject$", "s3:GetObject", "Can read S3 data (check Resource scope)"),
    (r"^s3:PutObject$", "s3:PutObject", "Can write/overwrite S3 data"),

    # Secrets access
    (r"^secretsmanager:GetSecretValue$", "secretsmanager:GetSecretValue", "Can read secrets"),
    (r"^secretsmanager:\*$", "secretsmanager:*", "Full secrets access"),
    (r"^ssm:GetParameter.*$", "ssm:GetParameter*", "Can read SSM parameters (often contain secrets)"),
    (r"^kms:Decrypt$", "kms:Decrypt", "Can decrypt data (enables secret access)"),

    # Compute abuse
    (r"^ec2:RunInstances$", "ec2:RunInstances", "Can launch instances (crypto mining, pivot)"),
    (r"^lambda:CreateFunction$", "lambda:CreateFunction", "Can create Lambda (code execution)"),
    (r"^lambda:InvokeFunction$", "lambda:InvokeFunction", "Can invoke Lambdas (check Resource)"),
    (r"^lambda:\*$", "lambda:*", "Full Lambda access"),

    # Database access
    (r"^rds:\*$", "rds:*", "Full RDS access"),
    (r"^dynamodb:\*$", "dynamodb:*", "Full DynamoDB access"),
    (r"^dynamodb:GetItem$", "dynamodb:GetItem", "Can read DynamoDB data"),
    (r"^dynamodb:Scan$", "dynamodb:Scan", "Can scan entire DynamoDB tables"),
]

MEDIUM_PATTERNS = [
    # Reconnaissance
    (r"^iam:List.*$", "iam:List*", "IAM enumeration"),
    (r"^iam:Get.*$", "iam:Get*", "IAM enumeration"),
    (r"^ec2:Describe.*$", "ec2:Describe*", "Infrastructure enumeration"),
    (r"^s3:ListBucket$", "s3:ListBucket", "Bucket enumeration"),
    (r"^s3:ListAllMyBuckets$", "s3:ListAllMyBuckets", "Account bucket discovery"),

    # Log manipulation (covering tracks)
    (r"^logs:DeleteLogGroup$", "logs:DeleteLogGroup", "Can delete CloudWatch logs"),
    (r"^logs:DeleteLogStream$", "logs:DeleteLogStream", "Can delete log streams"),
    (r"^cloudtrail:StopLogging$", "cloudtrail:StopLogging", "Can disable CloudTrail"),
    (r"^cloudtrail:DeleteTrail$", "cloudtrail:DeleteTrail", "Can delete CloudTrail"),
]


def run(principal_arn: str) -> dict[str, Any]:
    """
    Analyze EGRESS permissions for an IAM principal.

    Returns:
        dict with status, message, findings, and summary
    """
    # Parse ARN to determine principal type
    arn_parts = principal_arn.split(":")
    if len(arn_parts) < 6:
        return {
            "status": "error",
            "message": f"Invalid ARN format: {principal_arn}",
            "findings": [],
            "summary": None,
        }

    resource_part = arn_parts[5]  # e.g., "role/MyRole" or "user/MyUser"

    if resource_part.startswith("role/"):
        principal_type = "role"
        principal_name = resource_part[5:]  # Remove "role/" prefix
    elif resource_part.startswith("user/"):
        principal_type = "user"
        principal_name = resource_part[5:]  # Remove "user/" prefix
    else:
        return {
            "status": "not_applicable",
            "message": f"EGRESS check only supports roles and users, got: {resource_part}",
            "findings": [],
            "summary": None,
        }

    try:
        iam = boto3.client("iam")
        findings = []
        all_statements = []

        if principal_type == "role":
            # Get attached managed policies
            attached = iam.list_attached_role_policies(RoleName=principal_name)
            for policy in attached.get("AttachedPolicies", []):
                policy_statements = get_policy_statements(iam, policy["PolicyArn"])
                for stmt in policy_statements:
                    stmt["_source"] = f"Managed: {policy['PolicyName']}"
                    all_statements.append(stmt)

            # Get inline policies
            inline_names = iam.list_role_policies(RoleName=principal_name)
            for policy_name in inline_names.get("PolicyNames", []):
                policy_doc = iam.get_role_policy(RoleName=principal_name, PolicyName=policy_name)
                for stmt in policy_doc["PolicyDocument"].get("Statement", []):
                    stmt["_source"] = f"Inline: {policy_name}"
                    all_statements.append(stmt)

        else:  # user
            # Get attached managed policies
            attached = iam.list_attached_user_policies(UserName=principal_name)
            for policy in attached.get("AttachedPolicies", []):
                policy_statements = get_policy_statements(iam, policy["PolicyArn"])
                for stmt in policy_statements:
                    stmt["_source"] = f"Managed: {policy['PolicyName']}"
                    all_statements.append(stmt)

            # Get inline policies
            inline_names = iam.list_user_policies(UserName=principal_name)
            for policy_name in inline_names.get("PolicyNames", []):
                policy_doc = iam.get_user_policy(UserName=principal_name, PolicyName=policy_name)
                for stmt in policy_doc["PolicyDocument"].get("Statement", []):
                    stmt["_source"] = f"Inline: {policy_name}"
                    all_statements.append(stmt)

        # Analyze each statement
        for stmt in all_statements:
            if stmt.get("Effect") != "Allow":
                continue  # Only analyze Allow statements for egress risk

            stmt_findings = analyze_statement(stmt)
            findings.extend(stmt_findings)

        # Sort by risk level
        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: risk_order.get(x["risk"], 99))

        # Generate summary
        summary = generate_summary(findings)

        return {
            "status": "success",
            "message": f"EGRESS analysis for {principal_name}",
            "findings": findings,
            "summary": summary,
        }

    except iam.exceptions.NoSuchEntityException:
        return {
            "status": "error",
            "message": f"Principal not found: {principal_name}",
            "findings": [],
            "summary": None,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error analyzing {principal_name}: {str(e)}",
            "findings": [],
            "summary": None,
        }


def get_policy_statements(iam, policy_arn: str) -> list[dict]:
    """Fetch statements from a managed policy."""
    policy = iam.get_policy(PolicyArn=policy_arn)
    version_id = policy["Policy"]["DefaultVersionId"]
    version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    return version["PolicyVersion"]["Document"].get("Statement", [])


def analyze_statement(stmt: dict) -> list[dict]:
    """
    Analyze a single policy statement for security risks.

    Returns a list of findings (one per dangerous action found).
    """
    findings = []

    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]

    resources = stmt.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]

    conditions = stmt.get("Condition", {})
    source = stmt.get("_source", "Unknown")

    # Check if resources are wildcarded
    is_wildcard_resource = any(r == "*" or r.endswith(":*") for r in resources)

    for action in actions:
        finding = classify_action(action, resources, conditions, source, is_wildcard_resource)
        if finding:
            findings.append(finding)

    return findings


def classify_action(
    action: str,
    resources: list[str],
    conditions: dict,
    source: str,
    is_wildcard_resource: bool
) -> dict | None:
    """
    Classify a single action's risk level.

    Returns a finding dict or None if the action is benign.
    """
    action_lower = action.lower()

    # Check CRITICAL patterns
    for pattern, name, description in CRITICAL_PATTERNS:
        if re.match(pattern, action, re.IGNORECASE):
            risk = "CRITICAL"

            # Downgrade sts:AssumeRole if scoped to specific resources
            if action_lower == "sts:assumerole" and not is_wildcard_resource:
                risk = "MEDIUM"
                description = "Can assume specific roles (scoped)"

            # Downgrade iam:PassRole if scoped
            if action_lower == "iam:passrole" and not is_wildcard_resource:
                risk = "HIGH"
                description = "Can pass specific roles to services"

            return {
                "action": action,
                "risk": risk,
                "category": "Privilege Escalation" if "iam:" in action_lower else "Critical Access",
                "resources": resources,
                "resource_scope": "ALL" if is_wildcard_resource else "SCOPED",
                "conditions": conditions if conditions else None,
                "source": source,
                "explanation": description,
            }

    # Check HIGH patterns
    for pattern, name, description in HIGH_PATTERNS:
        if re.match(pattern, action, re.IGNORECASE):
            risk = "HIGH"

            # Downgrade if scoped to specific resources
            if not is_wildcard_resource:
                risk = "MEDIUM"
                description += " (scoped to specific resources)"

            return {
                "action": action,
                "risk": risk,
                "category": categorize_action(action),
                "resources": resources,
                "resource_scope": "ALL" if is_wildcard_resource else "SCOPED",
                "conditions": conditions if conditions else None,
                "source": source,
                "explanation": description,
            }

    # Check MEDIUM patterns
    for pattern, name, description in MEDIUM_PATTERNS:
        if re.match(pattern, action, re.IGNORECASE):
            return {
                "action": action,
                "risk": "MEDIUM",
                "category": categorize_action(action),
                "resources": resources,
                "resource_scope": "ALL" if is_wildcard_resource else "SCOPED",
                "conditions": conditions if conditions else None,
                "source": source,
                "explanation": description,
            }

    # Not a flagged action
    return None


def categorize_action(action: str) -> str:
    """Categorize an action by its security domain."""
    action_lower = action.lower()

    if action_lower.startswith("iam:"):
        return "Identity & Access"
    elif action_lower.startswith("s3:"):
        return "Data Access"
    elif action_lower.startswith(("secretsmanager:", "ssm:", "kms:")):
        return "Secrets Access"
    elif action_lower.startswith(("ec2:", "lambda:", "ecs:")):
        return "Compute"
    elif action_lower.startswith(("rds:", "dynamodb:")):
        return "Database"
    elif action_lower.startswith(("logs:", "cloudtrail:", "cloudwatch:")):
        return "Logging & Monitoring"
    elif action_lower.startswith("sts:"):
        return "Lateral Movement"
    else:
        return "Other"


def generate_summary(findings: list[dict]) -> dict:
    """Generate a risk summary from findings."""
    if not findings:
        return {
            "total_findings": 0,
            "risk_counts": {},
            "categories": [],
            "verdict": "MINIMAL",
            "verdict_explanation": "No dangerous permissions detected",
        }

    risk_counts = {}
    categories = set()

    for f in findings:
        risk = f["risk"]
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        categories.add(f["category"])

    # Determine overall verdict
    if risk_counts.get("CRITICAL", 0) > 0:
        verdict = "CRITICAL"
        verdict_explanation = "Principal has privilege escalation or admin-level access"
    elif risk_counts.get("HIGH", 0) >= 3:
        verdict = "HIGH"
        verdict_explanation = "Multiple high-risk permissions detected"
    elif risk_counts.get("HIGH", 0) > 0:
        verdict = "HIGH"
        verdict_explanation = "High-risk permissions present"
    elif risk_counts.get("MEDIUM", 0) >= 5:
        verdict = "MEDIUM"
        verdict_explanation = "Several medium-risk permissions detected"
    elif risk_counts.get("MEDIUM", 0) > 0:
        verdict = "MEDIUM"
        verdict_explanation = "Some reconnaissance or moderate access detected"
    else:
        verdict = "LOW"
        verdict_explanation = "Only low-risk permissions detected"

    return {
        "total_findings": len(findings),
        "risk_counts": risk_counts,
        "categories": sorted(categories),
        "verdict": verdict,
        "verdict_explanation": verdict_explanation,
    }
