# src/iamwho/checks/chain.py
"""
CHAIN WALK - follows PassRole/AssumeRole grants across roles.

A role's own egress findings only show what it can do directly. If it can
pass or assume another role, that role's permissions are reachable too.
This walks that graph, bounded by max_depth, reusing the same cached reads
egress already uses so a role reached by two paths is fetched once.
"""

from typing import Any

from iamwho.checks import egress


def walk(
    role_arn: str,
    depth: int = 0,
    max_depth: int = 2,
    visited: set[str] | None = None,
) -> dict[str, Any]:
    """Walk the PassRole/AssumeRole chain reachable from a role.

    Runs analyze_egress on ``role_arn``, then recurses into any role its
    PassRole/AssumeRole findings point at (via egress._resolve_hop_targets),
    up to ``max_depth`` hops from the starting role.

    ``visited`` guards against cycles (a role that passes back to one of its
    own ancestors in the walk is not re-walked). Hop targets found at
    ``max_depth`` are not walked either, but unlike a cycle this is a real
    limitation of the scan: the node reports ``truncated: True`` and lists
    those targets under ``unexplored`` rather than silently dropping them.
    """
    if visited is None:
        visited = set()
    visited.add(role_arn)

    egress_result = egress.analyze_egress(role_arn)
    findings = (
        egress_result.get("findings", []) if isinstance(egress_result, dict) else []
    )

    targets: set[str] = set()
    for finding in findings:
        targets.update(egress._resolve_hop_targets(finding))

    unvisited_targets = sorted(target for target in targets if target not in visited)

    can_recurse = depth < max_depth
    to_explore = unvisited_targets if can_recurse else []
    unexplored = [] if can_recurse else unvisited_targets

    hops = [walk(target, depth + 1, max_depth, visited) for target in to_explore]

    return {
        "role_arn": role_arn,
        "depth": depth,
        "status": egress_result.get("status")
        if isinstance(egress_result, dict)
        else "error",
        "egress": egress_result,
        "hops": hops,
        "truncated": bool(unexplored),
        "max_depth": max_depth,
        "unexplored": unexplored,
    }


# =============================================================================
# MODULE ALIASES
# =============================================================================

run = walk
