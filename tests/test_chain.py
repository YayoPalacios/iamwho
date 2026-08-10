"""Tests for the bounded PassRole/AssumeRole chain walk.

_resolve_hop_targets reads resources already captured in an egress
finding's evidence during the normal scan - no new AWS calls - to find the
role(s) a PassRole/AssumeRole grant points at.
"""

from iamwho.checks.egress import _resolve_hop_targets

from .conftest import role_arn

ADMIN_ARN = role_arn("Admin")
DEPLOYER_ARN = role_arn("Deployer")


def _finding(action: str, evidence: list[dict]) -> dict:
    return {"action": action, "evidence": evidence}


def _evidence(resources: list[str]) -> dict:
    return {"resources": resources, "normalized_resources": resources}


# =============================================================================
# _resolve_hop_targets
# =============================================================================


def test_concrete_passrole_target_is_resolved():
    finding = _finding("iam:PassRole", [_evidence([ADMIN_ARN])])

    assert _resolve_hop_targets(finding) == [ADMIN_ARN]


def test_concrete_assumerole_target_is_resolved():
    finding = _finding("sts:AssumeRole", [_evidence([ADMIN_ARN])])

    assert _resolve_hop_targets(finding) == [ADMIN_ARN]


def test_wildcard_resource_is_not_resolved():
    """A bare "*" can't be resolved to a role without enumerating the account."""
    finding = _finding("iam:PassRole", [_evidence(["*"])])

    assert _resolve_hop_targets(finding) == []


def test_globbed_role_resource_is_not_resolved():
    finding = _finding("iam:PassRole", [_evidence([f"{ADMIN_ARN[:-2]}*"])])

    assert _resolve_hop_targets(finding) == []


def test_non_role_resource_is_ignored():
    finding = _finding("iam:PassRole", [_evidence(["arn:aws:s3:::bucket/*"])])

    assert _resolve_hop_targets(finding) == []


def test_non_hop_action_resolves_nothing():
    finding = _finding("s3:GetObject", [_evidence([ADMIN_ARN])])

    assert _resolve_hop_targets(finding) == []


def test_targets_are_deduped_and_sorted_across_evidence_entries():
    finding = _finding(
        "iam:PassRole",
        [_evidence([ADMIN_ARN]), _evidence([DEPLOYER_ARN, ADMIN_ARN])],
    )

    assert _resolve_hop_targets(finding) == sorted([ADMIN_ARN, DEPLOYER_ARN])


def test_missing_evidence_resolves_nothing():
    assert _resolve_hop_targets({"action": "iam:PassRole"}) == []
