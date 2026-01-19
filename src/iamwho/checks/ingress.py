# src/iamwho/checks/ingress.py
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


# =============================================================================
# MAIN ANALYSIS
# =============================================================================

def analyze_ingress(role_arn: str) -> IngressResult:
    """Analyze a role's trust policy for security issues."""
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
        result.error = trust_policy
        return result

    statements = trust_policy.get("Statement", [])
    if not isinstance(statements, list):
        statements = [statements]

    for statement in statements:
        if statement.get("Effect") != "Allow":
            continue
        findings = _analyze_statement(statement)
        result.findings.extend(findings)

    if result.findings:
        result.highest_risk = max(f.risk for f in result.findings)

    return result


# =============================================================================
# HELPERS
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
    assume_type = _classify_assume_type(actions)
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
    for action in actions:
        action_lower = action.lower()
        if "assumerolewithwebidentity" in action_lower:
            return AssumeType.ASSUME_ROLE_OIDC
        if "assumerolewithsaml" in action_lower:
            return AssumeType.ASSUME_ROLE_SAML
        if "assumerole" in action_lower:
            return AssumeType.ASSUME_ROLE

    if "*" in actions or "sts:*" in actions:
        return AssumeType.ASSUME_ROLE

    return AssumeType.UNKNOWN


def _extract_principals(statement: dict[str, Any]) -> list[str]:
    """Extract all principals from a statement."""
    principal_field = statement.get("Principal", {})
    principals: list[str] = []

    if principal_field == "*":
        return ["*"]

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

    if principal.endswith(".amazonaws.com") or principal.endswith(".aws.internal"):
        return PrincipalType.SERVICE

    if ":saml-provider/" in principal:
        return PrincipalType.FEDERATED_SAML

    if ":oidc-provider/" in principal:
        return PrincipalType.FEDERATED_OIDC

    if principal.startswith("arn:aws:iam::"):
        if ":root" in principal:
            return PrincipalType.AWS_ROOT
        if ":role/" in principal:
            return PrincipalType.AWS_ROLE
        if ":user/" in principal:
            return PrincipalType.AWS_USER

    if principal.isdigit() and len(principal) == 12:
        return PrincipalType.AWS_ACCOUNT

    return PrincipalType.UNKNOWN


def _analyze_conditions(raw_conditions: dict[str, Any]) -> ConditionAnalysis:
    """Analyze conditions for security-relevant keys."""
    analysis = ConditionAnalysis(raw_conditions=raw_conditions)

    all_keys: set[str] = set()
    for operator_block in raw_conditions.values():
        if isinstance(operator_block, dict):
            all_keys.update(operator_block.keys())

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
    """Assess risk level based on principal, assume type, and conditions."""
    reasons: list[str] = []

    if principal_type == PrincipalType.WILDCARD:
        if conditions.has_principal_org_id:
            reasons.append("Wildcard principal restricted by PrincipalOrgID")
            return RiskLevel.HIGH, reasons
        if conditions.has_principal_arn:
            reasons.append("Wildcard principal restricted by PrincipalArn")
            return RiskLevel.HIGH, reasons

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

        reasons.append("Wildcard principal with no meaningful restriction")
        reasons.append(
            "Remediation: Add Condition with aws:PrincipalOrgID or aws:PrincipalArn, "
            "or replace '*' with specific principal ARNs"
        )
        return RiskLevel.CRITICAL, reasons

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

    if principal_type == PrincipalType.FEDERATED_SAML:
        reasons.append("SAML federation (verify IdP is trusted)")
        return RiskLevel.LOW, reasons

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

    if principal_type in (PrincipalType.AWS_ROLE, PrincipalType.AWS_USER):
        reasons.append(f"Trusts specific {principal_type.value}")
        return RiskLevel.LOW, reasons

    if principal_type == PrincipalType.AWS_ACCOUNT:
        reasons.append("Trusts entire AWS account by ID")
        reasons.append(
            "Remediation: Consider restricting to specific role/user ARNs "
            "instead of entire account"
        )
        return RiskLevel.MEDIUM, reasons

    reasons.append("Unclassified principal type - review manually")
    return RiskLevel.MEDIUM, reasons


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


def format_ingress(result: IngressResult, verbose: bool = False) -> None:
    """Render ingress analysis to console."""
    from rich.console import Console
    from rich.markup import escape
    from rich.text import Text

    console = Console()

    console.print()
    console.print("[bold][ INGRESS ][/bold] Who can assume this role?")
    console.print("-" * 60)

    if result.error:
        console.print(f"  [red]Error: {escape(result.error)}[/red]")
        console.print()
        return

    if not result.findings:
        console.print("  [green]No trust relationships found[/green]")
        console.print()
        return

    sorted_findings = sorted(result.findings, key=lambda f: f.risk, reverse=True)

    for finding in sorted_findings:
        _render_ingress_finding(console, finding, verbose)

    console.print()


def _render_ingress_finding(console, finding: TrustFinding, verbose: bool) -> None:
    """Render a single ingress finding with escape() for safety."""
    from rich.markup import escape
    from rich.text import Text

    risk = finding.risk.value
    risk_color = RISK_COLORS.get(risk, "white")

    # Line 1: Risk + Principal
    line = Text()
    line.append("  ")
    line.append(f"{risk:8}", style=risk_color)
    line.append(" ")
    line.append(escape(finding.principal), style="bold white")  # ESCAPED
    console.print(line)

    # Line 2: Type info
    type_line = Text()
    type_line.append("           Type: ", style="dim")
    type_line.append(escape(finding.principal_type.value), style="cyan")  # ESCAPED
    type_line.append(" | Assume: ", style="dim")
    type_line.append(escape(finding.assume_type.value), style="white")  # ESCAPED
    console.print(type_line)

    # Reasons
    for reason in finding.reasons:
        reason_line = Text()
        reason_line.append("           > ", style="dim")

        if reason.startswith("Remediation:"):
            reason_line.append(escape(reason), style="dim green")  # ESCAPED
        else:
            reason_line.append(escape(reason), style="dim")  # ESCAPED

        console.print(reason_line)

    if verbose:
        _render_condition_details(console, finding.conditions)

    console.print()


def _render_condition_details(console, conditions: ConditionAnalysis) -> None:
    """Render condition details for verbose output."""
    from rich.markup import escape
    from rich.text import Text

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

    if protections:
        cond_line = Text()
        cond_line.append("           Conditions: ", style="dim")
        cond_line.append(", ".join(protections), style="dim cyan")
        console.print(cond_line)

    if conditions.raw_conditions and protections:
        raw_line = Text()
        raw_line.append("           Raw: ", style="dim")
        raw_str = str(conditions.raw_conditions)
        if len(raw_str) > 60:
            raw_str = raw_str[:57] + "..."
        raw_line.append(escape(raw_str), style="dim")  # ESCAPED
        console.print(raw_line)


def format_findings(result: IngressResult) -> str:
    """Format findings for CLI output (legacy text format)."""
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

    sorted_findings = sorted(result.findings, key=lambda f: f.risk, reverse=True)

    for i, finding in enumerate(sorted_findings, 1):
        lines.append(f"[{i}] {finding.risk.value}: {finding.principal}")
        lines.append(f"    Type: {finding.principal_type.value}")
        lines.append(f"    Assume: {finding.assume_type.value}")
        if finding.statement_id:
            lines.append(f"    Statement: {finding.statement_id}")
        for reason in finding.reasons:
            lines.append(f"    - {reason}")

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


# =============================================================================
# MODULE ALIASES
# =============================================================================

run = analyze_ingress
