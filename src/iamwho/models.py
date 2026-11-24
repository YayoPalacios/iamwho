"""Data models for iamwho findings."""

from dataclasses import dataclass, field
from enum import Enum
from functools import total_ordering
from typing import Any


@total_ordering
class RiskLevel(Enum):
    """Risk classification levels."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        order = [
            RiskLevel.INFO,
            RiskLevel.LOW,
            RiskLevel.MEDIUM,
            RiskLevel.HIGH,
            RiskLevel.CRITICAL,
        ]
        return order.index(self) < order.index(other)

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, RiskLevel):
            return NotImplemented
        return self.value == other.value

    def __hash__(self) -> int:
        # Defining __eq__ sets __hash__ to None, which makes the enum
        # unusable in sets and as a dict key.
        return hash(self.value)


class AssumeType(Enum):
    """STS assume action classification."""

    ASSUME_ROLE = "AssumeRole"
    ASSUME_ROLE_SAML = "AssumeRoleWithSAML"
    ASSUME_ROLE_OIDC = "AssumeRoleWithWebIdentity"
    UNKNOWN = "Unknown"


class PrincipalType(Enum):
    """Trust policy principal classification."""

    AWS_ACCOUNT = "AWSAccount"
    AWS_ROLE = "AWSRole"
    AWS_USER = "AWSUser"
    AWS_ROOT = "AWSRoot"
    SERVICE = "Service"
    FEDERATED_SAML = "FederatedSAML"
    FEDERATED_OIDC = "FederatedOIDC"
    WILDCARD = "Wildcard"
    UNKNOWN = "Unknown"


@dataclass
class ConditionAnalysis:
    """Analysis of a statement's conditions."""

    has_external_id: bool = False
    has_source_arn: bool = False
    has_source_account: bool = False
    has_principal_org_id: bool = False
    has_principal_arn: bool = False
    has_oidc_sub_claim: bool = False
    has_oidc_aud_claim: bool = False
    has_saml_aud: bool = False
    raw_conditions: dict[str, Any] = field(default_factory=dict)

    @property
    def has_confused_deputy_protection(self) -> bool:
        """Check if conditions protect against confused deputy."""
        return self.has_source_arn or self.has_source_account

    @property
    def has_cross_account_protection(self) -> bool:
        """Check if conditions protect cross-account access."""
        return self.has_external_id or self.has_principal_org_id


@dataclass
class TrustFinding:
    """A single finding from trust policy analysis."""

    statement_id: str | None
    principal: str
    principal_type: PrincipalType
    assume_type: AssumeType
    risk: RiskLevel
    conditions: ConditionAnalysis
    reasons: list[str] = field(default_factory=list)
    # Set for federated principals. provider is a stable machine value:
    # github, github_enterprise, eks, cognito, generic_oidc or saml.
    # subject_verdict is a RiskLevel value, "NOT_EVALUATED", or None (SAML).
    provider: str | None = None
    subject_verdict: str | None = None
    subject_evaluated: bool | None = None
    # GitHub only: the sub condition blocks iamwho could not evaluate, in
    # Condition shape, or None when every block was evaluated.
    unevaluated_sub_condition: dict[str, Any] | None = None
    # GitHub only: condition keys present but not evaluated (never credited
    # as narrowing).
    unevaluated_condition_keys: list[str] | None = None
    # GitHub and SAML: INFO notes on aud, [{"code", "severity", "message"}].
    audience_notes: list[dict[str, str]] | None = None

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "statement_id": self.statement_id,
            "principal": self.principal,
            "principal_type": self.principal_type.value,
            "assume_type": self.assume_type.value,
            "risk": self.risk.value,
            "reasons": self.reasons,
            "conditions": {
                "confused_deputy_protected": self.conditions.has_confused_deputy_protection,
                "cross_account_protected": self.conditions.has_cross_account_protection,
                "raw": self.conditions.raw_conditions,
            },
            "provider": self.provider,
            "subject_verdict": self.subject_verdict,
            "subject_evaluated": self.subject_evaluated,
            "unevaluated_sub_condition": self.unevaluated_sub_condition,
            "unevaluated_condition_keys": self.unevaluated_condition_keys,
            "audience_notes": self.audience_notes,
        }


@dataclass
class IngressResult:
    """Complete INGRESS analysis result."""

    role_arn: str
    findings: list[TrustFinding] = field(default_factory=list)
    highest_risk: RiskLevel = field(default_factory=lambda: RiskLevel.INFO)
    error: str | None = None
    # Trust-policy Deny statements, raw. Not evaluated: they are listed but
    # never lower a finding's risk.
    deny_statements: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        """Convert to dictionary for JSON output."""
        return {
            "role_arn": self.role_arn,
            "highest_risk": self.highest_risk.value,
            "finding_count": len(self.findings),
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
            "deny_statements": self.deny_statements,
        }
