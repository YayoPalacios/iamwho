# src/iamwho/checks/ingress.py
"""
INGRESS Check: Who is trusted to become this principal?

Analyzes IAM role trust policies to identify:
- Who can assume the role (principals)
- What assume path they use (Action)
- Whether conditions meaningfully restrict access
- Risk level based on real-world attack patterns
"""

import boto3
from botocore.exceptions import ClientError, NoCredentialsError


def extract_role_name(arn: str) -> str | None:
    """Extract role name from ARN. Returns None if not a role ARN."""
    # arn:aws:iam::123456789012:role/MyAppRole → MyAppRole
    # arn:aws:iam::123456789012:role/path/to/MyRole → path/to/MyRole
    if ":role/" not in arn:
        return None
    return arn.split(":role/")[-1]


def get_principal_type(arn: str) -> str:
    """Determine if ARN is a role, user, or unknown."""
    if ":role/" in arn:
        return "role"
    elif ":user/" in arn:
        return "user"
    else:
        return "unknown"


def run(principal_arn: str) -> dict:
    """
    Analyze INGRESS for the given principal.

    Returns:
        dict with keys: status, message, findings
    """
    # Step 1: Determine principal type
    principal_type = get_principal_type(principal_arn)

    if principal_type == "user":
        return {
            "status": "not_applicable",
            "message": "INGRESS: N/A — Users don't have trust policies."
                       " Try --check egress instead.",
            "findings": [],
        }

    if principal_type == "unknown":
        return {
            "status": "error",
            "message": f"Cannot determine principal type from ARN: {principal_arn}",
            "findings": [],
        }

    # Step 2: It's a role — fetch the trust policy
    role_name = extract_role_name(principal_arn)

    try:
        iam = boto3.client("iam")
        response = iam.get_role(RoleName=role_name)
        trust_policy = response["Role"]["AssumeRolePolicyDocument"]

    except NoCredentialsError:
        return {
            "status": "error",
            "message": "AWS credentials not found. "
                       "Configure via AWS_PROFILE, aws sso login, or env vars.",
            "findings": [],
        }

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "NoSuchEntity":
            return {
                "status": "error",
                "message": f"Role not found: {role_name}",
                "findings": [],
            }
        elif error_code == "AccessDenied":
            return {
                "status": "error",
                "message": "Access denied. Ensure you have iam:GetRole permission.",
                "findings": [],
            }
        else:
            return {
                "status": "error",
                "message": f"AWS error: {e}",
                "findings": [],
            }

    # Step 3: Parse the trust policy
    findings = parse_trust_policy(trust_policy)

    return {
        "status": "success",
        "message": f"INGRESS analysis for {role_name}",
        "findings": findings,
    }


def is_meaningful_condition(conditions: dict, principal_type: str) -> tuple[bool, list[str]]:
    """
    Evaluate if conditions actually restrict access meaningfully.

    Args:
        conditions: The Condition block from the statement
        principal_type: "AWS", "Service", or "Federated"

    Returns:
        (is_meaningful, list_of_reasons)

    Security context:
        - Some conditions are cosmetic (attacker can satisfy them)
        - Different principal types need different conditions to be "safe"
        - Service: needs SourceArn/SourceAccount (confused deputy protection)
        - AWS: benefits from ExternalId, PrincipalOrgID, PrincipalArn
        - Federated: needs claim restrictions (sub, aud for OIDC)
    """
    if not conditions:
        return False, ["No conditions present"]

    found_protections = []

    # Flatten all condition keys across operators (StringEquals, ArnLike, etc.)
    all_condition_keys = set()
    for operator, key_values in conditions.items():
        if isinstance(key_values, dict):
            all_condition_keys.update(key_values.keys())

    # --- Service principal protections (confused deputy) ---
    if principal_type == "Service":
        if "aws:SourceArn" in all_condition_keys:
            found_protections.append("aws:SourceArn restricts source resource")
        if "aws:SourceAccount" in all_condition_keys:
            found_protections.append("aws:SourceAccount restricts source account")

        if found_protections:
            return True, found_protections
        return False, ["Missing aws:SourceArn/SourceAccount (confused deputy risk)"]

    # --- AWS principal protections ---
    if principal_type == "AWS":
        if "sts:ExternalId" in all_condition_keys:
            found_protections.append("sts:ExternalId required (third-party pattern)")
        if "aws:PrincipalOrgID" in all_condition_keys:
            found_protections.append("aws:PrincipalOrgID restricts to AWS Organization")
        if "aws:PrincipalArn" in all_condition_keys:
            found_protections.append("aws:PrincipalArn restricts specific principals")

    # --- Federated principal protections ---
    if principal_type == "Federated":
        oidc_claims = [k for k in all_condition_keys if ":sub" in k or ":aud" in k]
        if oidc_claims:
            found_protections.append(f"OIDC claims restricted: {', '.join(oidc_claims)}")

        saml_attrs = [k for k in all_condition_keys if k.startswith("SAML:")]
        if saml_attrs:
            found_protections.append(f"SAML attributes restricted: {', '.join(saml_attrs)}")

    # --- Universal protections ---
    if "aws:PrincipalOrgID" in all_condition_keys:
        org_note = "aws:PrincipalOrgID restricts to AWS Organization"
        if org_note not in found_protections:
            found_protections.append(org_note)

    if found_protections:
        return True, found_protections

    return False, ["Conditions present but none provide meaningful restriction"]


def classify_assume_action(actions: str | list[str] | None) -> tuple[str, str]:
    """
    Classify the type of assume operation.

    Returns:
        (assume_type, description)
    """
    if actions is None:
        return "UNKNOWN", "No Action specified (implicit allow)"

    if isinstance(actions, str):
        actions = [actions]

    actions_lower = [a.lower() for a in actions]

    if "sts:*" in actions_lower or "*" in actions:
        return "ALL_STS", "Allows all STS actions"

    assume_types = []
    if "sts:assumerole" in actions_lower:
        assume_types.append("AssumeRole")
    if "sts:assumerolewithsaml" in actions_lower:
        assume_types.append("SAML")
    if "sts:assumerolewithwebidentity" in actions_lower:
        assume_types.append("OIDC")

    if not assume_types:
        return "OTHER", f"STS actions: {', '.join(actions)}"

    return "+".join(assume_types), f"Assume via: {', '.join(assume_types)}"


def classify_risk(
        principal_type: str,
        value: str,
        conditions: dict,
        actions: list[str] | None = None,
) -> tuple[str, str]:
    """
    Classify risk level of a trust relationship.

    Returns:
        (risk_level, explanation)
    """
    is_meaningful, protection_notes = is_meaningful_condition(conditions, principal_type)
    notes_str = "; ".join(protection_notes)

    # Wildcard in AWS field {"AWS": "*"}
    if principal_type == "AWS" and value == "*":
        if is_meaningful:
            return "HIGH", f"Wildcard AWS principal with restrictions: {notes_str}"
        return "CRITICAL", f"Wildcard AWS principal: {notes_str}"

    # Service principals
    if principal_type == "Service":
        if is_meaningful:
            return "INFO", f"Service trust protected: {notes_str}"
        return "MEDIUM", f"Service trust: {notes_str}"

    # AWS principals
    if principal_type == "AWS":
        if ":root" in value:
            if is_meaningful:
                return "MEDIUM", f"Account root trust with restrictions: {notes_str}"
            return "HIGH", f"Account root trust (any principal in account): {notes_str}"

        if is_meaningful:
            return "LOW", f"Specific principal with restrictions: {notes_str}"
        return "LOW", "Specific principal trust"

    # Federated principals
    if principal_type == "Federated":
        if is_meaningful:
            return "LOW", f"Federated trust with restrictions: {notes_str}"
        return "MEDIUM", f"Federated trust: {notes_str}"

    return "MEDIUM", "Unknown trust pattern"


def parse_trust_policy(policy: dict) -> list[dict]:
    """
    Parse trust policy into structured findings.

    Each finding includes:
        - sid: Statement ID
        - type: Principal type (AWS, Service, Federated, Wildcard)
        - trusted_entity: The principal value
        - assume_type: How assumption happens (AssumeRole, SAML, OIDC)
        - risk: Risk level (CRITICAL, HIGH, MEDIUM, LOW, INFO)
        - explanation: Why this risk level
    """
    findings = []

    for statement in policy.get("Statement", []):
        if statement.get("Effect") != "Allow":
            continue

        sid = statement.get("Sid", "(no Sid)")
        principal = statement.get("Principal", {})
        conditions = statement.get("Condition", {})
        actions = statement.get("Action")

        assume_type, assume_desc = classify_assume_action(actions)

        # Handle "Principal": "*"
        if principal == "*":
            risk, explanation = classify_risk("AWS", "*", conditions, actions)
            findings.append({
                "sid": sid,
                "type": "Wildcard",
                "trusted_entity": "*",
                "assume_type": assume_type,
                "assume_desc": assume_desc,
                "conditions": conditions or None,
                "risk": risk,
                "explanation": explanation,
            })
            continue

        # Handle structured Principal
        for principal_type, values in principal.items():
            if isinstance(values, str):
                values = [values]

            for value in values:
                # Handle {"AWS": "*"}
                if principal_type == "AWS" and value == "*":
                    risk, explanation = classify_risk("AWS", "*", conditions, actions)
                    findings.append({
                        "sid": sid,
                        "type": "Wildcard",
                        "trusted_entity": "* (via AWS: *)",
                        "assume_type": assume_type,
                        "assume_desc": assume_desc,
                        "conditions": conditions or None,
                        "risk": risk,
                        "explanation": explanation,
                    })
                else:
                    risk, explanation = classify_risk(principal_type, value, conditions, actions)
                    findings.append({
                        "sid": sid,
                        "type": principal_type,
                        "trusted_entity": value,
                        "assume_type": assume_type,
                        "assume_desc": assume_desc,
                        "conditions": conditions or None,
                        "risk": risk,
                        "explanation": explanation,
                    })

    return findings
