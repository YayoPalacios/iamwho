"""Tests for the bounded PassRole/AssumeRole chain walk.

_resolve_hop_targets reads resources already captured in an egress
finding's evidence during the normal scan - no new AWS calls - to find the
role(s) a PassRole/AssumeRole grant points at. chain.walk follows those
targets, bounded by max_depth.
"""

from iamwho.checks import chain
from iamwho.checks.egress import _resolve_hop_targets

from .conftest import allow, role_arn

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


# =============================================================================
# walk
# =============================================================================


def test_walk_reports_a_lone_node_when_there_are_no_hop_actions(iam):
    arn = iam.add_role("Solo", inline={"p": {"Statement": [allow("s3:ListBucket")]}})

    result = chain.walk(arn)

    assert result["role_arn"] == arn
    assert result["depth"] == 0
    assert result["status"] == "success"
    assert result["hops"] == []
    assert result["truncated"] is False
    assert result["unexplored"] == []


def test_walk_follows_a_passrole_target_one_hop(iam):
    target = iam.add_role(
        "Target", inline={"p": {"Statement": [allow("s3:ListBucket")]}}
    )
    start = iam.add_role(
        "Start", inline={"p": {"Statement": [allow("iam:PassRole", target)]}}
    )

    result = chain.walk(start)

    assert len(result["hops"]) == 1
    hop = result["hops"][0]
    assert hop["role_arn"] == target
    assert hop["depth"] == 1


def test_walk_reuses_the_client_cache_for_a_role_reached_via_two_paths(iam):
    """A role reached via two PassRole grants must be fetched only once."""
    shared = iam.add_role(
        "Shared", inline={"p": {"Statement": [allow("s3:ListBucket")]}}
    )
    branch_a = iam.add_role(
        "BranchA", inline={"p": {"Statement": [allow("iam:PassRole", shared)]}}
    )
    branch_b = iam.add_role(
        "BranchB", inline={"p": {"Statement": [allow("iam:PassRole", shared)]}}
    )
    start = iam.add_role(
        "Start",
        inline={
            "p": {
                "Statement": [
                    allow("iam:PassRole", [branch_a, branch_b]),
                ]
            }
        },
    )

    chain.walk(start)

    assert iam.count("list_role_policies") == 4  # Start, BranchA, BranchB, Shared once


def test_walk_visited_guard_stops_a_cycle(iam):
    """A passes to B, B passes back to A: the walk must terminate."""
    a_arn = role_arn("A")
    b_arn = role_arn("B")
    iam.add_role("A", inline={"p": {"Statement": [allow("iam:PassRole", b_arn)]}})
    iam.add_role("B", inline={"p": {"Statement": [allow("iam:PassRole", a_arn)]}})

    result = chain.walk(a_arn)

    assert result["role_arn"] == a_arn
    assert len(result["hops"]) == 1
    assert result["hops"][0]["role_arn"] == b_arn
    # B's PassRole back to A is a cycle: A is already visited, so it's not re-walked.
    assert result["hops"][0]["hops"] == []
