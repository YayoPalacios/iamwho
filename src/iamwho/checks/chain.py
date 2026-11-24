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

Every walked role's trust policy is also run through the ingress evaluator,
so a role that admits an external OIDC subject is marked as a web-identity
entry, and each resolved path reports the worst entry on it beside the
egress severity of its last role. The two are reported side by side, never
combined into one score.
"""

from typing import Any

from iamwho.checks import _client, egress, ingress
from iamwho.models import RiskLevel, serialize


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


def _web_identity_entry(role_arn: str) -> dict[str, Any] | None:
    """The ingress evaluator's verdict on a role as a web-identity entry.

    None when no trust statement admits external OIDC subjects (see
    ingress.web_identity_entry_findings). Otherwise the worst
    statement's severity, those statements' findings serialized exactly as
    ``--check ingress --json`` emits them, and the trust policy's Deny
    statements, listed and never credited. A failed trust-policy read is an
    error object, never None, so it can't be mistaken for "not an entry".
    """
    result = ingress.analyze_ingress(role_arn)
    if result.error:
        return {"status": "error", "message": result.error, "error": result.error}

    # Served from the client cache: analyze_ingress just read it.
    findings = ingress.web_identity_entry_findings(_client.get_trust_policy(role_arn))
    if not findings:
        return None

    return {
        "severity": max(f.risk for f in findings).value,
        "findings": serialize(findings),
        "deny_statements": result.deny_statements,
    }


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
    status = egress_result.get("status") if egress_is_dict else "error"
    # Mirrors egress's error contract (AGENTS.md): populate both message
    # and error on failure, so callers keying off either field see it.
    message = egress_result.get("message") if egress_is_dict else None
    error = egress_result.get("error") if egress_is_dict else None

    entry = _web_identity_entry(role_arn)
    if _entry_failed(entry) and status != "error":
        # Egress read fine but the trust policy didn't: the node is still an
        # error. When both fail, the egress failure stays the node's message
        # and the trust failure is carried by web_identity_entry.
        status, message, error = "error", entry["message"], entry["error"]

    return {
        "role_arn": role_arn,
        "depth": depth,
        "status": status,
        "message": message,
        "error": error,
        "egress": egress_result,
        "web_identity_entry": entry,
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


_RISK_VALUES = {level.value for level in RiskLevel}


def _entry_failed(entry: dict[str, Any] | None) -> bool:
    return entry is not None and entry.get("status") == "error"


def _egress_failed(node: dict[str, Any]) -> bool:
    egress_result = node["egress"]
    return not isinstance(egress_result, dict) or egress_result.get("status") == "error"


def _highest_egress_severity(node: dict[str, Any]) -> str | None:
    """The highest risk among a node's egress findings, or None when it has
    none (including when its egress read failed)."""
    egress_result = node["egress"]
    findings = (
        egress_result.get("findings", []) if isinstance(egress_result, dict) else []
    )
    risks = [RiskLevel(f["risk"]) for f in findings if f.get("risk") in _RISK_VALUES]
    return max(risks).value if risks else None


def _path_severities(root: dict[str, Any]) -> list[dict[str, Any]]:
    """One entry per resolved path, index-aligned with ``paths``.

    ``entry_severity`` is the worst web-identity entry on the path and
    ``entry_role_arn`` names it (on a tie, the one nearest the start).
    If any node on the path failed its trust-policy read, the worst entry
    can't be known: ``entry_unknown`` is true and both fields are None.
    ``last_role_severity`` is the highest egress severity of the path's last
    role; ``last_role_unknown`` is true when that role's policies couldn't
    be read, so a null severity isn't mistaken for "no findings". Every
    entry on a path reaches that same last role.
    """
    nodes = {node["role_arn"]: node for node in _flatten(root)}
    summaries = []
    for path in _collect_paths(root):
        path_nodes = [nodes[arn] for arn in path]
        entries = [
            (node["role_arn"], RiskLevel(node["web_identity_entry"]["severity"]))
            for node in path_nodes
            if node["web_identity_entry"] is not None
            and not _entry_failed(node["web_identity_entry"])
        ]
        unknown = any(_entry_failed(node["web_identity_entry"]) for node in path_nodes)
        worst = None
        if entries and not unknown:
            worst = max(entries, key=lambda e: e[1])  # max keeps the first on a tie
        summaries.append(
            {
                "roles": list(path),
                "entry_severity": worst[1].value if worst else None,
                "entry_role_arn": worst[0] if worst else None,
                "entry_unknown": unknown,
                "last_role_arn": path[-1],
                "last_role_severity": _highest_egress_severity(path_nodes[-1]),
                "last_role_unknown": _egress_failed(path_nodes[-1]),
            }
        )
    return summaries


def _flatten(node: dict[str, Any]):
    yield node
    for hop in node["hops"]:
        yield from _flatten(hop)


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
    the tree, not a restructuring of it - and ``path_severities``, index-
    aligned with ``paths``: per path, the worst web-identity entry on it
    and the highest egress severity of its last role, side by side.

    Every node carries ``web_identity_entry`` (see _web_identity_entry).
    """
    if visited is None:
        visited = set()

    depths = _shortest_depths(role_arn, depth, max_depth, visited)
    result = _build_node(role_arn, depth, max_depth, depths, set(visited))
    result["paths"] = _collect_paths(result)
    result["path_severities"] = _path_severities(result)
    return result


# =============================================================================
# MODULE ALIASES
# =============================================================================

run = walk
