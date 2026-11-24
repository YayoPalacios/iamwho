# src/iamwho/checks/ingress.py
"""INGRESS check: Analyze who/what can assume a role via trust policy."""

import re
from enum import Enum
from typing import Any

from iamwho.checks import _client
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

    try:
        trust_policy = _client.get_trust_policy(role_arn)
    except _client.IamFetchError as e:
        result.error = e.message
        return result

    for statement in _statements(trust_policy):
        if statement.get("Effect") == "Deny":
            # Deny is not evaluated: listed, never credited as narrowing.
            result.deny_statements.append(statement)
            continue
        if statement.get("Effect") != "Allow":
            continue
        findings = _analyze_statement(statement)
        result.findings.extend(findings)

    if result.findings:
        result.highest_risk = max(f.risk for f in result.findings)

    return result


def web_identity_entry_findings(trust_policy: dict[str, Any]) -> list[TrustFinding]:
    """The findings that make a role a web-identity entry, with ingress's
    own verdict on each.

    An Allow statement admits external OIDC subjects when it trusts a
    federated OIDC principal (whatever its action), or a wildcard principal
    (``"*"``, ``{"AWS": "*"}``) whose ``Action`` matches
    ``sts:AssumeRoleWithWebIdentity``, or whose ``NotAction`` doesn't
    exclude it. SAML is not OIDC and never counts.
    """
    findings: list[TrustFinding] = []
    for statement in _statements(trust_policy):
        if statement.get("Effect") != "Allow":
            continue
        web_identity_action = _allows_web_identity(statement)
        for finding in _analyze_statement(statement):
            if finding.principal_type == PrincipalType.FEDERATED_OIDC or (
                finding.principal_type == PrincipalType.WILDCARD and web_identity_action
            ):
                findings.append(finding)
    return findings


def _statements(trust_policy: dict[str, Any]) -> list[dict[str, Any]]:
    statements = trust_policy.get("Statement", [])
    return statements if isinstance(statements, list) else [statements]


def _allows_web_identity(statement: dict[str, Any]) -> bool:
    """Whether the statement allows sts:AssumeRoleWithWebIdentity: one of
    its ``Action`` patterns matches it, or, for ``NotAction``, none of the
    excluded patterns does. IAM action names are case-insensitive."""
    if "NotAction" in statement:
        return not _matches_web_identity_action(statement["NotAction"])
    return _matches_web_identity_action(statement.get("Action", []))


def _matches_web_identity_action(patterns: Any) -> bool:
    return any(
        isinstance(pattern, str)
        and _glob_matches(pattern.lower(), "sts:assumerolewithwebidentity")
        for pattern in _normalize_to_list(patterns)
    )


# =============================================================================
# HELPERS
# =============================================================================


_extract_role_name = _client.extract_role_name


def _analyze_statement(statement: dict[str, Any]) -> list[TrustFinding]:
    """Analyze a single trust policy statement."""
    findings: list[TrustFinding] = []

    statement_id = statement.get("Sid")
    actions = _normalize_to_list(statement.get("Action", []))
    raw_conditions = statement.get("Condition", {})
    assume_type = _classify_assume_type(actions)
    principals = _extract_principals(statement)

    for principal in principals:
        principal_type = _classify_principal(principal)
        conditions = _analyze_conditions(raw_conditions, principal, principal_type)
        subject: dict[str, Any] = {}
        provider = _web_identity_provider(principal, principal_type)
        if provider == "github":
            risk, reasons, subject = _assess_github(conditions)
        elif provider == "saml":
            risk, reasons, subject = _assess_saml(conditions)
        elif provider is not None:
            risk, reasons, subject = _assess_key_presence(
                principal, provider, conditions
            )
        else:
            risk, reasons = _assess_risk(
                principal=principal,
                principal_type=principal_type,
                assume_type=assume_type,
                conditions=conditions,
            )

        findings.append(
            TrustFinding(
                statement_id=statement_id,
                principal=principal,
                principal_type=principal_type,
                assume_type=assume_type,
                risk=risk,
                conditions=conditions,
                reasons=reasons,
                **subject,
            )
        )

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

    # Cognito identity pools federate through web identity; checked before
    # the service rule, which its ".amazonaws.com" suffix would otherwise hit.
    if principal.lower() == "cognito-identity.amazonaws.com":
        return PrincipalType.FEDERATED_OIDC

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


def _analyze_conditions(
    raw_conditions: dict[str, Any], principal: str, principal_type: PrincipalType
) -> ConditionAnalysis:
    """Analyze conditions for security-relevant keys, as seen by one principal.

    The OIDC claim flags count only conditions on the principal's own issuer
    (``<issuer>:sub``, ``<issuer>:aud``) that scope something: a negated,
    ``Null: false`` or ``StringLike "*"`` block is not a protection.
    """
    analysis = ConditionAnalysis(raw_conditions=raw_conditions)
    if principal_type == PrincipalType.FEDERATED_OIDC:
        issuer = _oidc_issuer(principal)
        analysis.has_oidc_sub_claim = bool(
            _scoping_blocks(raw_conditions, f"{issuer}:sub")
        )
        analysis.has_oidc_aud_claim = bool(
            _scoping_blocks(raw_conditions, f"{issuer}:aud")
        )

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

    # Federated OIDC and SAML principals never reach here: they are rated by
    # provider (_assess_github, _assess_key_presence, _assess_saml).

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


# Only the public GitHub issuer. GitHub Enterprise custom issuers
# (token.actions.githubusercontent.com/<enterprise>) are deliberately not
# treated as GitHub (ADR-0001) and keep the generic OIDC verdict.
GITHUB_OIDC_PROVIDER_SUFFIX = ":oidc-provider/token.actions.githubusercontent.com"


def _is_github(principal: str) -> bool:
    return principal.lower().endswith(GITHUB_OIDC_PROVIDER_SUFFIX)


def _web_identity_provider(principal: str, principal_type: PrincipalType) -> str | None:
    """The stable ``provider`` value of a federated principal, or None."""
    if principal_type == PrincipalType.FEDERATED_SAML:
        return "saml"
    if principal_type != PrincipalType.FEDERATED_OIDC:
        return None
    if _is_github(principal):
        return "github"
    if principal.lower() == COGNITO_PRINCIPAL:
        return "cognito"
    issuer = _oidc_issuer(principal)
    if issuer.startswith(GITHUB_ENTERPRISE_ISSUER_PREFIX):
        # Tagged, but rated as a generic provider (ADR-0001).
        return "github_enterprise"
    if issuer.startswith("oidc.eks."):
        return "eks"
    return "generic_oidc"


GITHUB_ENTERPRISE_ISSUER_PREFIX = "token.actions.githubusercontent.com/"


COGNITO_PRINCIPAL = "cognito-identity.amazonaws.com"


def _oidc_issuer(principal: str) -> str:
    """The issuer a federated OIDC principal names, lowercased: the prefix of
    its condition keys (``<issuer>:sub``)."""
    if principal.lower() == COGNITO_PRINCIPAL:
        return COGNITO_PRINCIPAL
    return principal.lower().partition(":oidc-provider/")[2]


def _identifying_key(principal: str, provider: str) -> str:
    """The condition key that identifies who may assume: the identity pool
    (``aud``) for Cognito, the subject (``sub``) for every other provider."""
    claim = "aud" if provider == "cognito" else "sub"
    return f"{_oidc_issuer(principal)}:{claim}"


def _assess_key_presence(
    principal: str, provider: str, conditions: ConditionAnalysis
) -> tuple[RiskLevel, list[str], dict[str, Any]]:
    """Rate a web-identity trust whose condition values iamwho doesn't evaluate.

    Only the presence of the identifying key is checked (ADR-0001): without
    it, any token from the IdP (for Cognito, from any identity pool in any
    account) can assume the role. A key that only appears under negated
    operators, ``Null: false`` or ``StringLike "*"`` scopes nothing, so it
    counts as absent.

    For Cognito, a literal identity ID in ``sub`` also pins the trust:
    Cognito generates identity IDs, so an attacker can't pick a matching one.
    """
    key = _identifying_key(principal, provider)
    present = _scoping_blocks(conditions.raw_conditions, key)
    sub_blocks: list[tuple[str, Any]] = []
    if provider == "cognito" and not present:
        sub_key = f"{COGNITO_PRINCIPAL}:sub"
        sub_blocks = _scoping_blocks(conditions.raw_conditions, sub_key)
        if any(_is_literal_identity(op, value) for op, value in sub_blocks):
            key, present = sub_key, sub_blocks
    if not present:
        if provider == "cognito":
            risk = RiskLevel.CRITICAL
            pins = "the identity pool ID"
            if sub_blocks:
                admits = (
                    f"its '{COGNITO_PRINCIPAL}:sub' condition is not a literal "
                    "identity ID under StringEquals, so it is not credited as "
                    "pinning who can assume"
                )
            else:
                admits = "any identity pool, in any AWS account, can mint a token"
        else:
            risk = RiskLevel.HIGH
            admits = "any token from this IdP can assume"
            pins = "the expected subject"
        reasons = [
            f"Web-identity trust without a '{key}' condition that scopes it "
            f"({admits}; negated operators, Null: false and StringLike '*' "
            "don't scope)",
            f"Remediation: Add a StringEquals condition on {key} pinning {pins}",
        ]
        return risk, reasons, _subject_fields(provider, risk.value, True)
    reasons = [
        f"Web-identity '{key}' condition present but not evaluated "
        "(iamwho evaluates condition values for GitHub Actions only); "
        "review manually"
    ]
    return RiskLevel.MEDIUM, reasons, _subject_fields(provider, NOT_EVALUATED, False)


def _assess_saml(
    conditions: ConditionAnalysis,
) -> tuple[RiskLevel, list[str], dict[str, Any]]:
    """SAML stays LOW: iamwho evaluates no SAML assertion attributes. It only
    notes a missing ``saml:aud``, which never changes the risk."""
    notes = []
    if not conditions.has_saml_aud:
        notes.append(
            _info(
                "saml_aud_missing",
                "No 'saml:aud' condition; add one pinning the AWS sign-in "
                "endpoint as defense in depth",
            )
        )
    return (
        RiskLevel.LOW,
        ["SAML federation (verify IdP is trusted)"],
        {**_subject_fields("saml", None, False), "audience_notes": notes},
    )


def _scoping_blocks(raw_conditions: dict[str, Any], key: str) -> list[tuple[str, Any]]:
    """``(operator, value)`` for every condition on ``key`` (matched
    case-insensitively) that isn't unscoping."""
    return [
        (operator, value)
        for operator, block in raw_conditions.items()
        if isinstance(block, dict)
        for k, value in block.items()
        if k.lower() == key and not _is_unscoping(operator, value)
    ]


def _is_unscoping(operator: str, value: Any) -> bool:
    """Whether a condition block admits every token carrying the claim: a
    negated operator, ``Null: false``, or a ``StringLike`` value of exactly
    ``*`` (values are ORed, so one is enough) (ADR-0001)."""
    base = _operator_base(operator)
    if base == "null":
        return _null_sub_verdict(value) is SubVerdict.UNSCOPED
    if base in _GLOB_OPERATORS:
        return "*" in _sub_values(value)
    return base in _NON_SCOPING_OPERATORS


def _is_literal_identity(operator: str, value: Any) -> bool:
    """A ``StringEquals``/``StringEqualsIgnoreCase`` block whose values are all
    strings with no ``*`` or ``?``."""
    values = _sub_values(value)
    return (
        _operator_base(operator) in _LITERAL_OPERATORS
        and bool(values)
        and all(isinstance(v, str) and not set(v) & {"*", "?"} for v in values)
    )


def _subject_fields(
    provider: str, verdict: str | None, evaluated: bool
) -> dict[str, Any]:
    return {
        "provider": provider,
        "subject_verdict": verdict,
        "subject_evaluated": evaluated,
    }


def _assess_github(
    conditions: ConditionAnalysis,
) -> tuple[RiskLevel, list[str], dict[str, Any]]:
    """Rate a GitHub Actions trust and report what was not evaluated.

    Returns the risk, the reasons and the GitHub fields of the finding.
    """
    sub_blocks = _github_sub_blocks(conditions.raw_conditions)
    verdicts = [_github_sub_block_verdict(op, value) for op, _, value in sub_blocks]
    risk, reasons, verdict = _rate_github_sub(sub_blocks, verdicts)

    unevaluated: dict[str, dict[str, Any]] = {}
    for (op, key, value), v in zip(sub_blocks, verdicts):
        # A rated block can still hold unrated values (["repo:my-org/*", 42]).
        partly_rated = (
            isinstance(v, RiskLevel) and _rate_sub_values(_operator_base(op), value)[1]
        )
        if v is SubVerdict.NOT_EVALUATED or partly_rated:
            unevaluated.setdefault(op, {})[key] = value

    return (
        risk,
        reasons,
        {
            "provider": "github",
            "subject_verdict": verdict,
            "subject_evaluated": verdict != NOT_EVALUATED,
            "unevaluated_sub_condition": unevaluated or None,
            "unevaluated_condition_keys": _github_unevaluated_keys(
                conditions.raw_conditions
            ),
            "audience_notes": _github_audience_notes(conditions.raw_conditions),
        },
    )


GITHUB_AUDIENCE = "sts.amazonaws.com"


def _github_audience_notes(raw_conditions: dict[str, Any]) -> list[dict[str, str]]:
    """INFO notes on a GitHub trust's ``aud``. They never change the ``sub``
    verdict: any workflow can mint a token with the default audience.

    Only positive string operators are read, with their semantics (literal,
    case-insensitive literal, case-sensitive glob). ``aud`` under any other
    operator gets no note; it is listed under ``unevaluated_condition_keys``.
    """
    aud_blocks = [
        (operator, value)
        for operator, block in raw_conditions.items()
        if isinstance(block, dict)
        for key, value in block.items()
        if key.lower() == GITHUB_AUD_KEY
    ]
    if not aud_blocks:
        return [
            _info(
                "aud_missing",
                f"No 'aud' condition; add {GITHUB_AUDIENCE} as defense in "
                "depth (it does not scope who can assume)",
            )
        ]
    unexpected = [
        str(v)
        for operator, value in aud_blocks
        if _is_positive_string(operator)
        for v in _sub_values(value)
        if not _admits_default_audience(_operator_base(operator), v)
    ]
    if unexpected:
        return [
            _info(
                "aud_unexpected",
                f"'aud' {', '.join(unexpected)} is not {GITHUB_AUDIENCE}: it may "
                "be a custom audience, or a role nobody can assume",
            )
        ]
    return []


def _admits_default_audience(base: str, value: Any) -> bool:
    """Whether one ``aud`` value matches ``sts.amazonaws.com``."""
    if not isinstance(value, str):
        return False
    if base in _GLOB_OPERATORS:
        return _glob_matches(value, GITHUB_AUDIENCE)
    if base.endswith("ignorecase"):
        return value.lower() == GITHUB_AUDIENCE
    return value == GITHUB_AUDIENCE


def _glob_matches(pattern: str, text: str) -> bool:
    """IAM ``StringLike``: case-sensitive, ``*`` and ``?`` only."""
    regex = "".join(
        ".*" if c == "*" else "." if c == "?" else re.escape(c) for c in pattern
    )
    return re.fullmatch(regex, text, re.DOTALL) is not None


def _info(code: str, message: str) -> dict[str, str]:
    return {"code": code, "severity": RiskLevel.INFO.value, "message": message}


def _github_unevaluated_keys(raw_conditions: dict[str, Any]) -> list[str]:
    """Condition keys iamwho did not evaluate, as written: every key other than
    GitHub ``sub`` and ``aud``, plus ``aud`` under an operator other than a
    positive string operator. (``sub`` blocks iamwho can't evaluate are
    attached whole as ``unevaluated_sub_condition``.)

    iamwho lists them but never credits them as narrowing (ADR-0001).
    """
    keys: set[str] = set()
    for operator, block in raw_conditions.items():
        if not isinstance(block, dict):
            continue
        for key in block:
            name = key.lower()
            if name == GITHUB_SUB_KEY:
                continue
            if name == GITHUB_AUD_KEY and _is_positive_string(operator):
                continue
            keys.add(key)
    return sorted(keys)


def _is_positive_string(operator: str) -> bool:
    return _operator_base(operator) in _LITERAL_OPERATORS | _GLOB_OPERATORS


def _rate_github_sub(
    sub_blocks: list[tuple[str, str, Any]],
    verdicts: list["RiskLevel | SubVerdict"],
) -> tuple[RiskLevel, list[str], str]:
    """Rate a GitHub Actions trust by who can satisfy its ``sub`` condition.

    Returns the risk, the reasons and the subject verdict: the risk's value,
    or ``NOT_EVALUATED``.

    ``aud`` never counts: every GitHub token minted for AWS carries
    ``sts.amazonaws.com``, so it does not narrow who can assume the role.
    """
    if not sub_blocks:
        return _rated(
            RiskLevel.CRITICAL,
            "GitHub OIDC trust without a 'sub' condition "
            "(any GitHub Actions workflow, in any repository, can assume)",
        )

    # Condition blocks are ANDed, so the narrowest scoping block decides.
    scoping = [
        v for v in verdicts if isinstance(v, RiskLevel) and v < RiskLevel.CRITICAL
    ]
    if scoping:
        risk = min(scoping)
        if risk == RiskLevel.HIGH:
            return _rated(
                risk,
                "GitHub OIDC 'sub' condition pins an organization but not a "
                "repository (any GitHub Actions workflow in any repository of "
                "that organization can assume)",
            )
        if risk == RiskLevel.MEDIUM:
            return _rated(
                risk,
                "GitHub OIDC 'sub' condition pins a repository but not a ref or "
                "environment (any workflow run in that repository can assume)",
            )
        return risk, ["GitHub OIDC federation with 'sub' restriction"], risk.value
    not_evaluated = sorted(
        _not_evaluated_label(op, value)
        for (op, _, value), v in zip(sub_blocks, verdicts)
        if v is SubVerdict.NOT_EVALUATED
    )
    # A positive block that admits all of GitHub is evaluated; a block beside
    # it that iamwho can't evaluate is never credited as narrowing it.
    if not_evaluated and RiskLevel.CRITICAL not in verdicts:
        return (
            RiskLevel.MEDIUM,
            [
                "GitHub OIDC 'sub' condition not evaluated "
                f"({'; '.join(not_evaluated)}); review manually",
            ],
            NOT_EVALUATED,
        )
    return _rated(
        RiskLevel.CRITICAL,
        "GitHub OIDC 'sub' condition does not pin an organization "
        "(any GitHub Actions workflow, in any repository, can assume)",
    )


NOT_EVALUATED = "NOT_EVALUATED"

_GITHUB_REMEDIATION = (
    "Remediation: Add a StringEquals condition on "
    "token.actions.githubusercontent.com:sub pinning the repository "
    "and ref or environment (e.g. repo:my-org/app:ref:refs/heads/main)"
)


def _rated(risk: RiskLevel, reason: str) -> tuple[RiskLevel, list[str], str]:
    """An evaluated, overbroad GitHub subject: reason plus remediation."""
    return risk, [reason, _GITHUB_REMEDIATION], risk.value


GITHUB_SUB_KEY = "token.actions.githubusercontent.com:sub"
GITHUB_AUD_KEY = "token.actions.githubusercontent.com:aud"

# Operator base names (lowercased, without ForAnyValue:/ForAllValues: or
# IfExists). Positive operators can scope ``sub``; negated operators admit
# everything they don't name, so they never scope it. Null is split by value
# in _github_sub_block_verdict.
_LITERAL_OPERATORS = {"stringequals", "stringequalsignorecase"}
_GLOB_OPERATORS = {"stringlike"}
_NON_SCOPING_OPERATORS = {
    "stringnotequals",
    "stringnotequalsignorecase",
    "stringnotlike",
}


class SubVerdict(Enum):
    """A ``sub`` condition block that doesn't rate the subject.

    Blocks that do rate it (positive operators with string values) return a
    :class:`RiskLevel` instead.
    """

    UNSCOPED = "unscoped"  # negated operators, Null: false
    NOT_EVALUATED = "not_evaluated"


def _github_sub_blocks(
    raw_conditions: dict[str, Any],
) -> list[tuple[str, str, Any]]:
    """Return ``(operator, key, value)`` for every condition on the GitHub sub
    key.

    Key names match case-insensitively; keys and values are left as written.
    """
    blocks: list[tuple[str, str, Any]] = []
    for operator, block in raw_conditions.items():
        if not isinstance(block, dict):
            continue
        for key, value in block.items():
            if key.lower() == GITHUB_SUB_KEY:
                blocks.append((operator, key, value))
    return blocks


def _operator_base(operator: str) -> str:
    base = operator.lower()
    for qualifier in ("foranyvalue:", "forallvalues:"):
        base = base.removeprefix(qualifier)
    return base.removesuffix("ifexists")


def _github_sub_block_verdict(operator: str, value: Any) -> RiskLevel | SubVerdict:
    """Rate one condition block on ``sub``.

    ``StringEquals`` values are literal; ``StringLike`` values are
    case-sensitive globs. The values in one block are ORed, so the block takes
    the risk of its broadest value. A value iamwho can't rate (not a string, or
    not in the ``repo:`` subject format) is never assumed narrow: the block is
    not evaluated unless another value already rates it HIGH or CRITICAL.
    """
    base = _operator_base(operator)
    if base == "null":
        return _null_sub_verdict(value)
    if base in _NON_SCOPING_OPERATORS:
        return SubVerdict.UNSCOPED
    if base not in _LITERAL_OPERATORS | _GLOB_OPERATORS:
        return SubVerdict.NOT_EVALUATED

    # No ratable values (an empty list, a number, an object): nothing iamwho
    # can rate. With some unratable values, only a HIGH or CRITICAL one rates
    # the block, since the rest could admit anything.
    risks, unrated = _rate_sub_values(base, value)
    if not risks or (unrated and max(risks) < RiskLevel.HIGH):
        return SubVerdict.NOT_EVALUATED
    return max(risks)


def _sub_values(value: Any) -> list[Any]:
    return _normalize_to_list(value) if isinstance(value, (str, list)) else [value]


def _rate_sub_values(base: str, value: Any) -> tuple[list[RiskLevel], bool]:
    """The risks of a positive block's ratable values, and whether any value
    could not be rated."""
    glob = base in _GLOB_OPERATORS
    risks: list[RiskLevel] = []
    unrated = False
    for entry in _sub_values(value):
        if not isinstance(entry, str):
            unrated = True
            continue
        if base.endswith("ignorecase"):
            # Case-insensitive literal: "Repo:My-Org/App" is "repo:my-org/app".
            entry = entry.lower()
        risk = _github_sub_value_risk(entry, glob)
        if isinstance(risk, RiskLevel):
            risks.append(risk)
        else:
            unrated = True
    return risks, unrated


def _github_sub_value_risk(value: str, glob: bool) -> RiskLevel | SubVerdict:
    """Rate one ``sub`` value by who can satisfy it.

    Only the text before the first wildcard is pinned; a literal pins all of
    it. The subject template is assumed to be the worst case: a value with no
    context suffix (``repo:my-org/app``) is satisfied by every ref under a
    repo-only custom template. Only a literal ``ref:`` or ``environment:``
    context pins the trust; ``pull_request`` admits every pull-request run.
    A value outside the ``repo:`` format (a custom claim template such as
    ``repository_owner:my-org``) is not evaluated.
    """
    literal = _literal_prefix(value) if glob else value
    wildcard = literal != value
    if wildcard and _pins_no_org(literal):
        return RiskLevel.CRITICAL
    if not literal.startswith("repo:"):
        return SubVerdict.NOT_EVALUATED
    _org, slash, repo = literal.removeprefix("repo:").partition("/")
    if not slash:
        # A literal such as "repo:*": no GitHub subject has this form.
        return RiskLevel.LOW
    _name, colon, context = repo.partition(":")
    if not colon:
        # Repo name not complete (wildcard) or no context suffix (literal).
        return RiskLevel.HIGH if wildcard else RiskLevel.MEDIUM
    if wildcard or not _pins_ref_or_environment(context):
        # Any ref, pull_request, or a context iamwho doesn't know.
        return RiskLevel.MEDIUM
    return RiskLevel.LOW


def _pins_ref_or_environment(context: str) -> bool:
    """True for a literal ``ref:<name>`` or ``environment:<name>`` context."""
    kind, _, name = context.partition(":")
    return kind in ("ref", "environment") and bool(name)


def _literal_prefix(pattern: str) -> str:
    """The text of a glob before its first ``*`` or ``?``."""
    wildcards = [i for i in (pattern.find("*"), pattern.find("?")) if i != -1]
    return pattern[: min(wildcards)] if wildcards else pattern


def _not_evaluated_label(operator: str, value: Any) -> str:
    base = _operator_base(operator)
    if base == "null":
        return f"{operator}: true"
    if base not in _LITERAL_OPERATORS | _GLOB_OPERATORS:
        return f"unrecognised operator {operator}"
    entries = _sub_values(value)
    if not any(isinstance(v, str) for v in entries):
        return f"{operator} with no string values"
    if not all(isinstance(v, str) for v in entries):
        return f"{operator} with a non-string value"
    return f"{operator} value outside the 'repo:' subject format"


def _null_sub_verdict(value: Any) -> SubVerdict:
    """``Null: false`` only asserts the claim exists, and every GitHub token
    carries ``sub``, so it scopes nothing. ``Null: true`` requires the claim to
    be absent, which no GitHub token satisfies: not overbroad, but not a
    scoping iamwho evaluates either. Values are ORed, so one ``false`` wins.
    """
    values = value if isinstance(value, list) else [value]
    if any(str(v).lower() == "false" for v in values):
        return SubVerdict.UNSCOPED
    return SubVerdict.NOT_EVALUATED


def _pins_no_org(literal: str) -> bool:
    """True when a glob's literal prefix leaves the org open to an attacker.

    That is: the wildcard falls inside ``repo:`` itself (``*``, ``repo:*``)
    or inside the org name (``repo:my-org*``, ``repo:my-or?/*``), so anyone
    can register a matching org. Values that don't use the ``repo:`` template
    are not rated here.
    """
    if "repo:".startswith(literal):
        return True
    return literal.startswith("repo:") and "/" not in literal


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
        if cond.has_saml_aud:
            protections.append("SAML:aud")

        if protections:
            lines.append(f"    Conditions: {', '.join(protections)}")
        lines.append("")

    return "\n".join(lines)


# =============================================================================
# MODULE ALIASES
# =============================================================================

run = analyze_ingress
