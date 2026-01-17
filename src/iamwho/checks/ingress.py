"""INGRESS check: Analyze who/what can assume a role via trust policy."""
from typing import Any

import boto3
from botocore.exceptions import ClientError

from iamwho.models import (
    AssumeType,
    ConditionAnalysis,
    IngressResult,
    PrincipalType,
    RiskLevel,
    TrustFinding,
)


def analyze_ingress(role_arn: str) -> IngressResult:
    """
    Analyze a role's trust policy for security issues.

    Examines:
    - Who can assume the role (principals)
    - How they assume it (action type)
    - What restrictions exist (conditions)

    Args:
        role_arn: Full ARN of the IAM role to analyze

    Returns:
        IngressResult with findings and overall risk assessment
    """
    result = IngressResult(role_arn=role_arn)

    role_name = _extract_role_name(role_arn)
    if role_name is None:
        result.error = f"Invalid role ARN format: {role_arn}"
        return result

    trust_policy = _fetch_trust_policy(role_name)
    if trust_policy is None:
        result.error = f"Could not fetch trust policy for {role_name}"
        return result

    if isinstance(trust_policy, str):
        # Error message returned
        result.error = trust_policy
        return result

    statements = trust_policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        # Skip Deny statements for now (they reduce risk, not add it)
        if statement.get("Effect") != "Allow":
            continue

        findings = _analyze_statement(statement)
        result.findings.extend(findings)

    # Calculate highest risk
    if result.findings:
        result.highest_risk = max(f.risk for f in result.findings)

    return result


def _extract_role_name(role_arn: str) -> str | None:
    """Extract role name from ARN."""
    # Format: arn:aws:iam::ACCOUNT:role/ROLE_NAME
    # Or: arn:aws:iam::ACCOUNT:role/path/to/ROLE_NAME
    if ":role/" not in role_arn:
        return None
    try:
        role_path = role_arn.split(":role/")[1]
        # Handle paths: take the last segment
        return role_path.split("/")[-1]
    except IndexError:
        return None


def _fetch_trust_policy(role_name: str) -> dict[str, Any] | str | None:
    """Fetch trust policy from AWS."""
    try:
        iam = boto3.client("iam")
        response = iam.get_role(RoleName=role_name)
        return response["Role"]["AssumeRolePolicyDocument"]
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code == "NoSuchEntity":
            return f"Role not found: {role_name}"
        if code == "AccessDenied":
            return f"Access denied fetching role: {role_name}"
        return f"AWS error: {code}"
    except Exception as e:
        return f"Unexpected error: {e}"


def _analyze_statement(statement: dict[str, Any]) -> list[TrustFinding]:
    """Analyze a single trust policy statement."""
    findings: list[TrustFinding] = []

    statement_id = statement.get("Sid")
    actions = _normalize_to_list(statement.get("Action", []))
    conditions = _analyze_conditions(statement.get("Condition", {}))

    # Determine assume type from actions
    assume_type = _classify_assume_type(actions)

    # Extract and analyze principals
    principals = _extract_principals(statement)

    for principal in principals:
        principal_type = _classify_principal(principal)
        risk, reasons = _assess_risk(
            principal=principal,
            principal_type=principal_type,
            assume_type=assume_type,
            conditions=conditions,
        )

        findings.append(TrustFinding(
            statement_id=statement_id,
            principal=principal,
            principal_type=principal_type,
            assume_type=assume_type,
            risk=risk,
            conditions=conditions,
            reasons=reasons,
        ))

    return findings


def _normalize_to_list(value: Any) -> list[str]:
    """Normalize a string or list to a list."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return value
    return []


def _classify_assume_type(actions: list[str]) -> AssumeType:
    """Classify the assume action type."""
    # Check for specific assume types (more specific first)
    for action in actions:
        action_lower = action.lower()
        if "assumerolewithwebidentity" in action_lower:
            return AssumeType.ASSUME_ROLE_OIDC
        if "assumerolewithsaml" in action_lower:
            return AssumeType.ASSUME_ROLE_SAML
        if "assumerole" in action_lower:
            return AssumeType.ASSUME_ROLE

    # Wildcard action
    if "*" in actions or "sts:*" in actions:
        return AssumeType.ASSUME_ROLE  # Assume worst case

    return AssumeType.UNKNOWN


def _extract_principals(statement: dict[str, Any]) -> list[str]:
    """Extract all principals from a statement."""
    principal_field = statement.get("Principal", {})
    principals: list[str] = []

    # Handle Principal: "*"
    if principal_field == "*":
        return ["*"]

    # Handle Principal: {"AWS": "*"} or {"AWS": ["arn:..."]}
    if isinstance(principal_field, dict):
        for key, value in principal_field.items():
            if isinstance(value, str):
                principals.append(value)
            elif isinstance(value, list):
                principals.extend(value)

    return principals


def _classify_principal(principal: str) -> PrincipalType:
    """Classify the type of principal."""
    if principal == "*":
        return PrincipalType.WILDCARD

    # Service principals: service.amazonaws.com
    if principal.endswith(".amazonaws.com") or principal.endswith(".aws.internal"):
        return PrincipalType.SERVICE

    # SAML providers
    if ":saml-provider/" in principal:
        return PrincipalType.FEDERATED_SAML

    # OIDC providers
    if ":oidc-provider/" in principal:
        return PrincipalType.FEDERATED_OIDC

    # AWS principals
    if principal.startswith("arn:aws:iam::"):
        if ":root" in principal:
            return PrincipalType.AWS_ROOT
        if ":role/" in principal:
            return PrincipalType.AWS_ROLE
        if ":user/" in principal:
            return PrincipalType.AWS_USER

    # Account ID only (e.g., "123456789012")
    if principal.isdigit() and len(principal) == 12:
        return PrincipalType.AWS_ACCOUNT

    return PrincipalType.UNKNOWN


def _analyze_conditions(raw_conditions: dict[str, Any]) -> ConditionAnalysis:
    """Analyze conditions for security-relevant keys."""
    analysis = ConditionAnalysis(raw_conditions=raw_conditions)

    # Flatten all condition keys for analysis
    all_keys: set[str] = set()
    for operator_block in raw_conditions.values():
        if isinstance(operator_block, dict):
            all_keys.update(operator_block.keys())

    # Check for specific condition keys
    for key in all_keys:
        key_lower = key.lower()

        if key_lower == "sts:externalid":
            analysis.has_external_id = True
        elif key_lower == "aws:sourcearn":
            analysis.has_source_arn = True
        elif key_lower == "aws:sourceaccount":
            analysis.has_source_account = True
        elif key_lower == "aws:principalorgid":
            analysis.has_principal_org_id = True
        elif key_lower == "aws:principalarn":
            analysis.has_principal_arn = True
        # OIDC-specific conditions
        elif ":sub" in key_lower:
            analysis.has_oidc_sub_claim = True
        elif ":aud" in key_lower:
            analysis.has_oidc_aud_claim = True
        elif key_lower == "saml:aud":
            analysis.has_saml_aud = True

    return analysis


def _assess_risk(
        principal: str,
        principal_type: PrincipalType,
        assume_type: AssumeType,
        conditions: ConditionAnalysis,
) -> tuple[RiskLevel, list[str]]:
    """
    Assess risk level based on principal, assume type, and conditions.

    Returns:
        Tuple of (risk_level, list_of_reasons)
    """
    reasons: list[str] = []

    # CRITICAL: Wildcard without meaningful restrictions
    if principal_type == PrincipalType.WILDCARD:
        # These conditions actually restrict WHO can assume
        if conditions.has_principal_org_id:
            reasons.append("Wildcard principal restricted by PrincipalOrgID")
            return RiskLevel.HIGH, reasons
        if conditions.has_principal_arn:
            reasons.append("Wildcard principal restricted by PrincipalArn")
            return RiskLevel.HIGH, reasons

        # ExternalId exists but isn't sufficient for wildcards
        if conditions.has_external_id:
            reasons.append(
                "Wildcard principal with only ExternalId protection "
                "(ExternalId can be leaked/guessed - insufficient for '*')"
            )
            reasons.append(
                "Remediation: Add aws:PrincipalOrgID or aws:PrincipalArn condition, "
                "or replace '*' with specific principal ARNs"
            )
            return RiskLevel.CRITICAL, reasons

        # No meaningful protection at all
        reasons.append("Wildcard principal with no meaningful restriction")
        reasons.append(
            "Remediation: Add Condition with aws:PrincipalOrgID or aws:PrincipalArn, "
            "or replace '*' with specific principal ARNs"
        )
        return RiskLevel.CRITICAL, reasons

    # Service principals: check confused deputy protection
    if principal_type == PrincipalType.SERVICE:
        if not conditions.has_confused_deputy_protection:
            reasons.append(
                f"Service principal '{principal}' missing SourceArn/SourceAccount "
                "(confused deputy risk)"
            )
            reasons.append(
                "Remediation: Add Condition with aws:SourceArn and/or aws:SourceAccount"
            )
            return RiskLevel.MEDIUM, reasons
        reasons.append("Service principal with confused deputy protection")
        return RiskLevel.INFO, reasons

    # OIDC federation: check claim restrictions
    if principal_type == PrincipalType.FEDERATED_OIDC:
        if not conditions.has_oidc_claim_restriction:
            reasons.append(
                "OIDC federation without sub/aud claim restriction "
                "(any token from this IdP can assume)"
            )
            reasons.append(
                "Remediation: Add Condition restricting the 'sub' claim "
                "(e.g., token.actions.githubusercontent.com:sub for GitHub Actions)"
            )
            return RiskLevel.HIGH, reasons
        reasons.append("OIDC federation with claim restrictions")
        return RiskLevel.LOW, reasons

    # SAML federation
    if principal_type == PrincipalType.FEDERATED_SAML:
        reasons.append("SAML federation (verify IdP is trusted)")
        return RiskLevel.LOW, reasons

    # AWS root account trust
    if principal_type == PrincipalType.AWS_ROOT:
        if not conditions.has_cross_account_protection:
            reasons.append(
                "Trusts entire AWS account (root). Any principal in that account "
                "with sts:AssumeRole permission can assume this role."
            )
            reasons.append(
                "Remediation: Replace :root with specific role/user ARNs, "
                "or add sts:ExternalId condition for third-party access"
            )
            return RiskLevel.MEDIUM, reasons
        reasons.append("AWS account trust with conditions")
        return RiskLevel.LOW, reasons

    # AWS role/user trust
    if principal_type in (PrincipalType.AWS_ROLE, PrincipalType.AWS_USER):
        reasons.append(f"Trusts specific {principal_type.value}")
        return RiskLevel.LOW, reasons

    # AWS account (12-digit)
    if principal_type == PrincipalType.AWS_ACCOUNT:
        reasons.append("Trusts entire AWS account by ID")
        reasons.append(
            "Remediation: Consider restricting to specific role/user ARNs "
            "instead of entire account"
        )
        return RiskLevel.MEDIUM, reasons

    # Unknown/unclassified
    reasons.append("Unclassified principal type - review manually")
    return RiskLevel.MEDIUM, reasons


def format_findings(result: IngressResult) -> str:
    """Format findings for CLI output."""
    lines: list[str] = []

    lines.append(f"INGRESS Analysis: {result.role_arn}")
    lines.append("=" * 60)

    if result.error:
        lines.append(f"ERROR: {result.error}")
        return "\n".join(lines)

    if not result.findings:
        lines.append("No trust relationships found.")
        return "\n".join(lines)

    lines.append(f"Overall Risk: {result.highest_risk.value}")
    lines.append(f"Findings: {len(result.findings)}")
    lines.append("")

    # Sort by risk (highest first)
    sorted_findings = sorted(result.findings, key=lambda f: f.risk, reverse=True)

    for i, finding in enumerate(sorted_findings, 1):
        lines.append(f"[{i}] {finding.risk.value}: {finding.principal}")
        lines.append(f"    Type: {finding.principal_type.value}")
        lines.append(f"    Assume: {finding.assume_type.value}")
        if finding.statement_id:
            lines.append(f"    Statement: {finding.statement_id}")
        for reason in finding.reasons:
            lines.append(f"    - {reason}")

        # Show relevant condition info
        cond = finding.conditions
        protections: list[str] = []
        if cond.has_external_id:
            protections.append("ExternalId")
        if cond.has_source_arn:
            protections.append("SourceArn")
        if cond.has_source_account:
            protections.append("SourceAccount")
        if cond.has_principal_org_id:
            protections.append("PrincipalOrgID")
        if cond.has_principal_arn:
            protections.append("PrincipalArn")
        if cond.has_oidc_sub_claim:
            protections.append("OIDC:sub")
        if cond.has_oidc_aud_claim:
            protections.append("OIDC:aud")

        if protections:
            lines.append(f"    Conditions: {', '.join(protections)}")
        lines.append("")

    return "\n".join(lines)
