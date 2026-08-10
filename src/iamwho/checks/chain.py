# src/iamwho/checks/chain.py
"""
CHAIN WALK - follows PassRole/AssumeRole grants across roles.

A role's own egress findings only show what it can do directly. If it can
pass or assume another role, that role's permissions are reachable too.
This walks that graph, bounded by max_depth, reusing the same cached reads
egress already uses so a role reached by two paths is fetched once.

The walk is breadth-first: every reachable role is placed in the output
tree at the shortest depth from the start, even if a longer path to it
happens to be discovered before a shorter one. Shortest distance is a BFS
invariant - it does not depend on which edge is considered first.
"""

from typing import Any

from iamwho.checks import egress


def _hop_targets(role_arn: str) -> tuple[Any, list[str], list[str]]:
    """Run analyze_egress on a role and pull its PassRole/AssumeRole hop
    targets and unresolved (wildcarded) targets out of the findings."""
    egress_result = egress.analyze_egress(role_arn)
    findings = (
        egress_result.get("findings", []) if isinstance(egress_result, dict) else []
    )

    targets: set[str] = set()
    unresolved_targets: set[str] = set()
    for finding in findings:
        targets.update(egress._resolve_hop_targets(finding))
        unresolved_targets.update(egress._unresolved_hop_targets(finding))

    return egress_result, sorted(targets), sorted(unresolved_targets)


def _shortest_depths(
    role_arn: str, depth: int, max_depth: int, seed_visited: set[str]
) -> dict[str, int]:
    """BFS the PassRole/AssumeRole graph from role_arn, returning the
    shortest depth at which every role within max_depth is first reached.

    Processing a whole frontier (one depth level) before moving to the next
    is what guarantees a node is recorded at its true shortest distance,
    regardless of which edge into it happens to be considered first.
    """
    depths: dict[str, int] = {role_arn: depth}
    frontier = [role_arn]
    current_depth = depth

    while frontier:
        next_frontier: list[str] = []
        for arn in frontier:
            _, targets, _ = _hop_targets(arn)
            if current_depth >= max_depth:
                continue
            for target in targets:
                if target in depths or target in seed_visited:
                    continue
                depths[target] = current_depth + 1
                next_frontier.append(target)
        frontier = next_frontier
        current_depth += 1

    return depths


def _build_node(
    role_arn: str,
    depth: int,
    max_depth: int,
    depths: dict[str, int],
    placed: set[str],
) -> dict[str, Any]:
    """Build one node of the walk's output tree, recursing only into
    targets whose precomputed shortest depth is exactly depth + 1 - so a
    target reachable by a second, longer path is never re-embedded."""
    placed.add(role_arn)

    egress_result, targets, unresolved_targets = _hop_targets(role_arn)

    children = sorted(
        target
        for target in targets
        if depths.get(target) == depth + 1 and target not in placed
    )
    unexplored = sorted(target for target in targets if target not in depths)

    hops = [
        _build_node(target, depth + 1, max_depth, depths, placed) for target in children
    ]

    egress_is_dict = isinstance(egress_result, dict)

    return {
        "role_arn": role_arn,
        "depth": depth,
        "status": egress_result.get("status") if egress_is_dict else "error",
        # Mirrors egress's error contract (AGENTS.md): populate both message
        # and error on failure, so callers keying off either field see it.
        "message": egress_result.get("message") if egress_is_dict else None,
        "error": egress_result.get("error") if egress_is_dict else None,
        "egress": egress_result,
        "hops": hops,
        "truncated": bool(unexplored),
        "max_depth": max_depth,
        "unexplored": unexplored,
        "unresolved_targets": unresolved_targets,
    }


def _collect_paths(node: dict[str, Any]) -> list[list[str]]:
    """List every root-to-terminal path of role ARNs through the walk's
    tree, one per node with no further hops.

    Since the tree already embeds each role exactly once, at its shortest
    depth (see _build_node), this is a plain traversal - a role reachable
    by a second, longer path only ever appears in the path of its shorter
    one.
    """
    if not node["hops"]:
        return [[node["role_arn"]]]

    return [
        [node["role_arn"], *sub_path]
        for hop in node["hops"]
        for sub_path in _collect_paths(hop)
    ]


def walk(
    role_arn: str,
    depth: int = 0,
    max_depth: int = 2,
    visited: set[str] | None = None,
) -> dict[str, Any]:
    """Walk the PassRole/AssumeRole chain reachable from a role.

    Runs analyze_egress on ``role_arn``, then follows any role its
    PassRole/AssumeRole findings point at (via egress._resolve_hop_targets),
    up to ``max_depth`` hops from the starting role. A role reachable via
    two paths at different depths is reported once, at the shorter one -
    never at whichever depth this run's traversal order happened to reach
    it first.

    ``visited`` pre-seeds roles to treat as already accounted for (a cycle
    guard: a role that passes back to one of its own ancestors is not
    re-walked). Hop targets found at ``max_depth`` are not walked either,
    but unlike a cycle this is a real limitation of the scan: the node
    reports ``truncated: True`` and lists those targets under
    ``unexplored`` rather than silently dropping them. A PassRole/
    AssumeRole grant to a wildcarded resource (e.g. role/app-*) can't be
    resolved to a specific role at all; those are listed under
    ``unresolved_targets`` instead of just vanishing from the target list.

    The returned dict also carries a top-level ``paths`` field: a flat
    list of role-ARN lists, one per distinct path from ``role_arn`` to
    each terminal node in the tree above - a derived summary alongside
    the tree, not a restructuring of it.
    """
    if visited is None:
        visited = set()

    depths = _shortest_depths(role_arn, depth, max_depth, visited)
    result = _build_node(role_arn, depth, max_depth, depths, set(visited))
    result["paths"] = _collect_paths(result)
    return result


# =============================================================================
# MODULE ALIASES
# =============================================================================

run = walk
