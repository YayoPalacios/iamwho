"""Tests for the bounded PassRole/AssumeRole chain walk.

_resolve_hop_targets reads resources already captured in an egress
finding's evidence during the normal scan - no new AWS calls - to find the
role(s) a PassRole/AssumeRole grant points at. chain.walk follows those
targets, bounded by max_depth.
"""

from iamwho.checks import chain
from iamwho.checks.egress import _resolve_hop_targets, _unresolved_hop_targets

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


def test_globbed_role_resource_is_reported_as_unresolved():
    glob = f"{ADMIN_ARN[:-2]}*"
    finding = _finding("iam:PassRole", [_evidence([glob])])

    assert _resolve_hop_targets(finding) == []
    assert _unresolved_hop_targets(finding) == [glob]


def test_question_mark_wildcard_role_resource_is_reported_as_unresolved():
    """The ? character is IAM's single-character wildcard, same as * for
    any sequence - a resource ending in ? can't be resolved either."""
    glob = f"{ADMIN_ARN}?"
    finding = _finding("iam:PassRole", [_evidence([glob])])

    assert _resolve_hop_targets(finding) == []
    assert _unresolved_hop_targets(finding) == [glob]


def test_bare_wildcard_is_reported_as_unresolved():
    finding = _finding("iam:PassRole", [_evidence(["*"])])

    assert _unresolved_hop_targets(finding) == ["*"]


def test_unrelated_resource_type_is_not_reported_as_unresolved():
    """A non-role resource on a PassRole statement isn't a skipped hop -
    it never referred to a role in the first place."""
    finding = _finding("iam:PassRole", [_evidence(["arn:aws:s3:::bucket/*"])])

    assert _unresolved_hop_targets(finding) == []


def test_non_hop_action_reports_no_unresolved_targets():
    finding = _finding("s3:GetObject", [_evidence(["*"])])

    assert _unresolved_hop_targets(finding) == []


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


def test_walk_records_a_skipped_wildcard_target_as_unresolved(iam):
    """A PassRole grant to role/app-* can't be resolved to a specific role;
    it must show up as unresolved, not just vanish from the target list."""
    glob_arn = role_arn("app-*")
    start = iam.add_role(
        "Start", inline={"p": {"Statement": [allow("iam:PassRole", glob_arn)]}}
    )

    result = chain.walk(start)

    assert result["hops"] == []
    assert result["truncated"] is False
    assert result["unexplored"] == []
    assert result["unresolved_targets"] == [glob_arn]


def test_walk_reports_a_shared_target_at_its_shortest_depth(iam):
    """Target is reachable directly from Start (1 hop) and via Mid (2 hops).
    It must be reported once, at the shorter depth, regardless of which
    path the traversal considers first."""
    target_arn = iam.add_role(
        "Target", inline={"p": {"Statement": [allow("s3:ListBucket")]}}
    )
    mid_arn = iam.add_role(
        "Mid", inline={"p": {"Statement": [allow("iam:PassRole", target_arn)]}}
    )
    start_arn = iam.add_role(
        "Start",
        inline={"p": {"Statement": [allow("iam:PassRole", [mid_arn, target_arn])]}},
    )

    result = chain.walk(start_arn)

    occurrences = [
        node["depth"] for node in _flatten(result) if node["role_arn"] == target_arn
    ]
    assert occurrences == [1]  # reported exactly once, at the shortest depth

    mid_node = next(n for n in _flatten(result) if n["role_arn"] == mid_arn)
    assert mid_node["hops"] == []  # not re-embedded as Mid's child


def test_walk_reports_a_genuine_cycle_at_correct_shortest_depths(iam):
    """A -> B -> A: the walk must terminate, not loop, and place A and B
    each at their true shortest depth (A at 0, since it's the start)."""
    a_arn = role_arn("A")
    b_arn = role_arn("B")
    iam.add_role("A", inline={"p": {"Statement": [allow("iam:PassRole", b_arn)]}})
    iam.add_role("B", inline={"p": {"Statement": [allow("iam:PassRole", a_arn)]}})

    result = chain.walk(a_arn)  # must return, not recurse forever

    nodes = list(_flatten(result))
    assert len(nodes) == 2  # A and B each appear exactly once
    depths_by_arn = {node["role_arn"]: node["depth"] for node in nodes}
    assert depths_by_arn == {a_arn: 0, b_arn: 1}

    b_node = next(n for n in nodes if n["role_arn"] == b_arn)
    assert b_node["hops"] == []
    assert b_node["unexplored"] == []  # A is already covered, not "beyond the cap"
    assert b_node["truncated"] is False


def test_walk_reports_a_diamond_target_at_the_in_cap_depth(iam):
    """Target is reachable two ways: Start -> A -> Target (depth 2, within
    the default max_depth=2 cap) and Start -> B -> C -> Target (depth 3,
    past the cap). It must be reported once, fully resolved, at depth 2 -
    not marked truncated/unexplored because of the longer path via C."""
    target_arn = iam.add_role(
        "Target", inline={"p": {"Statement": [allow("s3:ListBucket")]}}
    )
    a_arn = iam.add_role(
        "A", inline={"p": {"Statement": [allow("iam:PassRole", target_arn)]}}
    )
    c_arn = iam.add_role(
        "C", inline={"p": {"Statement": [allow("iam:PassRole", target_arn)]}}
    )
    b_arn = iam.add_role(
        "B", inline={"p": {"Statement": [allow("iam:PassRole", c_arn)]}}
    )
    start_arn = iam.add_role(
        "Start",
        inline={"p": {"Statement": [allow("iam:PassRole", [a_arn, b_arn])]}},
    )

    result = chain.walk(start_arn)  # max_depth defaults to 2

    nodes = list(_flatten(result))
    target_nodes = [n for n in nodes if n["role_arn"] == target_arn]
    assert len(target_nodes) == 1  # reported exactly once
    assert target_nodes[0]["depth"] == 2  # at the shorter, in-cap depth

    c_node = next(n for n in nodes if n["role_arn"] == c_arn)
    assert c_node["hops"] == []  # Target not re-embedded here
    assert c_node["unexplored"] == []  # already resolved via A, not truncated
    assert c_node["truncated"] is False

    assert not any(node["truncated"] for node in nodes)
    assert iam.count("list_role_policies") == 5  # Start,A,B,C,Target each once


def test_walk_paths_follow_the_shortest_resolved_route(iam):
    """Same diamond as above: Target's real path is via A (depth 2), not
    via B -> C (depth 3). The top-level `paths` field must reflect that -
    ["Start", "A", "Target"] and ["Start", "B", "C"], never
    ["Start", "B", "C", "Target"]."""
    target_arn = iam.add_role(
        "Target", inline={"p": {"Statement": [allow("s3:ListBucket")]}}
    )
    a_arn = iam.add_role(
        "A", inline={"p": {"Statement": [allow("iam:PassRole", target_arn)]}}
    )
    c_arn = iam.add_role(
        "C", inline={"p": {"Statement": [allow("iam:PassRole", target_arn)]}}
    )
    b_arn = iam.add_role(
        "B", inline={"p": {"Statement": [allow("iam:PassRole", c_arn)]}}
    )
    start_arn = iam.add_role(
        "Start",
        inline={"p": {"Statement": [allow("iam:PassRole", [a_arn, b_arn])]}},
    )

    result = chain.walk(start_arn)  # max_depth defaults to 2

    assert result["paths"] == [
        [start_arn, a_arn, target_arn],
        [start_arn, b_arn, c_arn],
    ]
    assert [start_arn, b_arn, c_arn, target_arn] not in result["paths"]

    # `paths` is a top-level summary, not part of the tree itself.
    assert "paths" not in result["hops"][0]


# =============================================================================
# AGENT-IDENTITY FIXTURES
# =============================================================================


def _flatten(node):
    """Yield node and all its descendants, depth-first."""
    yield node
    for hop in node["hops"]:
        yield from _flatten(hop)


def test_walk_reports_the_full_path_to_admin_two_hops_away(iam):
    """agent -> deployer -> admin: the walk must surface the admin hop and
    its full-admin finding, not just the roles closer to the start."""
    admin_arn = iam.add_role("Admin", inline={"p": {"Statement": [allow("*")]}})
    deployer_arn = iam.add_role(
        "Deployer",
        inline={"p": {"Statement": [allow("iam:PassRole", admin_arn)]}},
    )
    agent_arn = iam.add_role(
        "Agent",
        inline={"p": {"Statement": [allow("iam:PassRole", deployer_arn)]}},
    )

    result = chain.walk(agent_arn)

    assert result["role_arn"] == agent_arn
    deployer_node = result["hops"][0]
    assert deployer_node["role_arn"] == deployer_arn
    assert deployer_node["depth"] == 1

    admin_node = deployer_node["hops"][0]
    assert admin_node["role_arn"] == admin_arn
    assert admin_node["depth"] == 2

    admin_actions = {f["action"] for f in admin_node["egress"]["findings"]}
    assert "*" in admin_actions

    # Nothing was truncated: the whole path fit inside the default max_depth.
    assert not any(node["truncated"] for node in _flatten(result))


def test_walk_finds_no_escalation_when_every_hop_is_safe(iam):
    """agent -> deployer -> viewer, none of which grant anything dangerous
    beyond the PassRole hop itself: no CRITICAL/HIGH finding anywhere."""
    viewer_arn = iam.add_role(
        "Viewer", inline={"p": {"Statement": [allow("s3:ListBucket")]}}
    )
    deployer_arn = iam.add_role(
        "Deployer",
        inline={"p": {"Statement": [allow("iam:PassRole", viewer_arn)]}},
    )
    agent_arn = iam.add_role(
        "Agent",
        inline={"p": {"Statement": [allow("iam:PassRole", deployer_arn)]}},
    )

    result = chain.walk(agent_arn)

    all_findings = [
        f for node in _flatten(result) for f in node["egress"].get("findings", [])
    ]
    assert not any(f["risk"] in ("CRITICAL", "HIGH") for f in all_findings)
    assert not any(node["truncated"] for node in _flatten(result))

    viewer_node = result["hops"][0]["hops"][0]
    assert viewer_node["role_arn"] == viewer_arn
    assert viewer_node["egress"]["findings"] == []


def test_walk_stops_at_max_depth_and_reports_truncation(iam):
    """A chain deeper than max_depth must stop at the cap and say so,
    rather than pretending the chain ends there or fetching past it."""
    admin_arn = iam.add_role("Admin", inline={"p": {"Statement": [allow("*")]}})
    hop3_arn = iam.add_role(
        "Hop3", inline={"p": {"Statement": [allow("iam:PassRole", admin_arn)]}}
    )
    hop2_arn = iam.add_role(
        "Hop2", inline={"p": {"Statement": [allow("iam:PassRole", hop3_arn)]}}
    )
    hop1_arn = iam.add_role(
        "Hop1", inline={"p": {"Statement": [allow("iam:PassRole", hop2_arn)]}}
    )
    start_arn = iam.add_role(
        "Start", inline={"p": {"Statement": [allow("iam:PassRole", hop1_arn)]}}
    )

    result = chain.walk(start_arn)  # max_depth defaults to 2

    hop1_node = result["hops"][0]
    hop2_node = hop1_node["hops"][0]

    assert hop2_node["role_arn"] == hop2_arn
    assert hop2_node["depth"] == 2
    assert hop2_node["truncated"] is True
    assert hop2_node["max_depth"] == 2
    assert hop2_node["unexplored"] == [hop3_arn]
    assert hop2_node["hops"] == []  # not walked

    # Admin, beyond the cap, was never fetched at all.
    assert iam.count("list_role_policies") == 3  # Start, Hop1, Hop2 only
