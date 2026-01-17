"""
EGRESS Check - Analyze what actions a principal can perform.

Security Focus:
- Identify overly permissive policies
- Flag privilege escalation paths
- Detect data exfiltration risks
- Highlight lateral movement capabilities
"""

import re
from typing import Any

import boto3
from botocore.exceptions import ClientError

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


def analyze_egress(principal_arn: str) -> dict[str, Any]:
    """
    Analyze EGRESS permissions for an IAM principal.

    Returns:
        dict with status, message, findings, and summary
    """
    arn_parts = principal_arn.split(":")
    if len(arn_parts) < 6:
        return {
            "status": "error",
            "message": f"Invalid ARN format: {principal_arn}",
            "findings": [],
            "summary": None,
        }

    resource_part = arn_parts[5]

    if resource_part.startswith("role/"):
        principal_type = "role"
        principal_name = resource_part.split("/")[-1]
    elif resource_part.startswith("user/"):
        principal_type = "user"
        principal_name = resource_part.split("/")[-1]
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
            attached = iam.list_attached_role_policies(RoleName=principal_name)
            for policy in attached.get("AttachedPolicies", []):
                policy_statements = _get_policy_statements(iam, policy["PolicyArn"])
                for stmt in policy_statements:
                    stmt["_source"] = f"Managed: {policy['PolicyName']}"
                    all_statements.append(stmt)

            inline_names = iam.list_role_policies(RoleName=principal_name)
            for policy_name in inline_names.get("PolicyNames", []):
                policy_doc = iam.get_role_policy(RoleName=principal_name, PolicyName=policy_name)
                for stmt in policy_doc["PolicyDocument"].get("Statement", []):
                    stmt["_source"] = f"Inline: {policy_name}"
                    all_statements.append(stmt)

        else:  # user
            attached = iam.list_attached_user_policies(UserName=principal_name)
            for policy in attached.get("AttachedPolicies", []):
                policy_statements = _get_policy_statements(iam, policy["PolicyArn"])
                for stmt in policy_statements:
                    stmt["_source"] = f"Managed: {policy['PolicyName']}"
                    all_statements.append(stmt)

            inline_names = iam.list_user_policies(UserName=principal_name)
            for policy_name in inline_names.get("PolicyNames", []):
                policy_doc = iam.get_user_policy(UserName=principal_name, PolicyName=policy_name)
                for stmt in policy_doc["PolicyDocument"].get("Statement", []):
                    stmt["_source"] = f"Inline: {policy_name}"
                    all_statements.append(stmt)

        for stmt in all_statements:
            if stmt.get("Effect") != "Allow":
                continue

            stmt_findings = _analyze_statement(stmt)
            findings.extend(stmt_findings)

        risk_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        findings.sort(key=lambda x: risk_order.get(x["risk"], 99))

        summary = _generate_summary(findings)

        return {
            "status": "success",
            "message": f"Analyzed {len(all_statements)} policy statements",
            "findings": findings,
            "summary": summary,
        }

    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchEntity":
            return {
                "status": "error",
                "message": f"Principal not found: {principal_name}",
                "findings": [],
                "summary": None,
            }
        if code == "AccessDenied":
            return {
                "status": "error",
                "message": f"Access denied fetching policies for: {principal_name}",
                "findings": [],
                "summary": None,
            }
        return {
            "status": "error",
            "message": f"AWS error: {code}",
            "findings": [],
            "summary": None,
        }
    except Exception as e:
        return {
            "status": "error",
            "message": f"Error analyzing {principal_name}: {e}",
            "findings": [],
            "summary": None,
        }


def _get_policy_statements(iam, policy_arn: str) -> list[dict]:
    """Fetch statements from a managed policy."""
    policy = iam.get_policy(PolicyArn=policy_arn)
    version_id = policy["Policy"]["DefaultVersionId"]
    version = iam.get_policy_version(PolicyArn=policy_arn, VersionId=version_id)
    return version["PolicyVersion"]["Document"].get("Statement", [])


def _analyze_statement(stmt: dict) -> list[dict]:
    """Analyze a single policy statement for security risks."""
    findings = []

    actions = stmt.get("Action", [])
    if isinstance(actions, str):
        actions = [actions]

    resources = stmt.get("Resource", [])
    if isinstance(resources, str):
        resources = [resources]

    conditions = stmt.get("Condition", {})
    source = stmt.get("_source", "Unknown")

    is_wildcard_resource = any(r == "*" or r.endswith(":*") for r in resources)

    for action in actions:
        finding = _classify_action(action, resources, conditions, source, is_wildcard_resource)
        if finding:
            findings.append(finding)

    return findings


def _classify_action(
    action: str,
    resources: list[str],
    conditions: dict,
    source: str,
    is_wildcard_resource: bool,
) -> dict | None:
    """Classify a single action's risk level."""
    action_lower = action.lower()

    # Check CRITICAL patterns
    for pattern, name, description in CRITICAL_PATTERNS:
        if re.match(pattern, action, re.IGNORECASE):
            risk = "CRITICAL"

            if action_lower == "sts:assumerole" and not is_wildcard_resource:
                risk = "MEDIUM"
                description = "Can assume specific roles (scoped)"

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

            if not is_wildcard_resource:
                risk = "MEDIUM"
                description += " (scoped to specific resources)"

            return {
                "action": action,
                "risk": risk,
                "category": _categorize_action(action),
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
                "category": _categorize_action(action),
                "resources": resources,
                "resource_scope": "ALL" if is_wildcard_resource else "SCOPED",
                "conditions": conditions if conditions else None,
                "source": source,
                "explanation": description,
            }

    return None


def _categorize_action(action: str) -> str:
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


def _generate_summary(findings: list[dict]) -> dict:
    """Generate a risk summary from findings."""
    if not findings:
        return {
            "total_findings": 0,
            "risk_counts": {},
            "categories": [],
            "verdict": "MINIMAL",
            "verdict_explanation": "No dangerous permissions detected",
        }

    risk_counts: dict[str, int] = {}
    categories: set[str] = set()

    for f in findings:
        risk = f["risk"]
        risk_counts[risk] = risk_counts.get(risk, 0) + 1
        categories.add(f["category"])

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


def format_egress(result: dict[str, Any]) -> str:
    """Format egress results for CLI output."""
    lines: list[str] = []

    lines.append("EGRESS Analysis")
    lines.append("=" * 60)

    if result["status"] == "error":
        lines.append(f"ERROR: {result['message']}")
        return "\n".join(lines)

    if result["status"] == "not_applicable":
        lines.append(result["message"])
        return "\n".join(lines)

    summary = result["summary"]
    lines.append(f"Verdict: {summary['verdict']} | Findings: {summary['total_findings']}")
    lines.append(f"  {summary['verdict_explanation']}")

    if summary["categories"]:
        lines.append(f"  Categories: {', '.join(summary['categories'])}")

    lines.append("")

    for finding in result["findings"]:
        scope_label = "[ALL]" if finding["resource_scope"] == "ALL" else "[SCOPED]"
        lines.append(f"  [{finding['risk']}] {scope_label} {finding['action']}")
        lines.append(f"        {finding['explanation']}")
        lines.append(f"        Source: {finding['source']}")
        if finding["resource_scope"] == "SCOPED":
            res = finding["resources"][0] if finding["resources"] else "N/A"
            if len(res) > 60:
                res = res[:57] + "..."
            lines.append(f"        Resource: {res}")
        lines.append("")

    return "\n".join(lines)

# Alias for module consistency
run = analyze_egress
