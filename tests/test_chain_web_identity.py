"""Web-identity entries along the chain walk (#11), through the CLI JSON seam.

The chain walk followed PassRole/AssumeRole grants but never read a walked
role's trust policy, so a GitHub org-wildcard trust one hop away from a
``*:*`` role read as two unrelated facts. Every walked node now carries
``web_identity_entry`` (the shared ingress evaluator's verdict, or null),
and each resolved path gets a ``path_severities`` entry with the worst entry
on it beside the egress severity of its last role. There is no combined
score.
"""

import json

import pytest
from typer.testing import CliRunner

from iamwho.cli import app

from .conftest import ACCOUNT, allow, role_arn

runner = CliRunner()

GITHUB = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
GITHUB_SUB = "token.actions.githubusercontent.com:sub"


def github_statement(sub, operator="StringLike"):
    return {
        "Effect": "Allow",
        "Principal": {"Federated": GITHUB},
        "Action": "sts:AssumeRoleWithWebIdentity",
        "Condition": {operator: {GITHUB_SUB: sub}},
    }


def role_statement(name):
    """Trust the upstream role, so the hop stays valid once #25 checks it."""
    return {
        "Effect": "Allow",
        "Principal": {"AWS": role_arn(name)},
        "Action": "sts:AssumeRole",
    }


def trust(*statements):
    return {"Version": "2012-10-17", "Statement": list(statements)}


def policy(*statements):
    return {"p": {"Statement": list(statements)}}


def run_chain(arn, *extra):
    result = runner.invoke(app, ["analyze", arn, "--json", "--check", "chain", *extra])
    return result.exit_code, json.loads(result.output)["checks"]["chain"]


def flatten(node):
    yield node
    for hop in node["hops"]:
        yield from flatten(hop)


def node_for(chain, arn):
    [node] = [n for n in flatten(chain) if n["role_arn"] == arn]
    return node


# =============================================================================
# MOTIVATING CASE: ORG-WILDCARD ENTRY -> ADMIN ONE HOP LATER
# =============================================================================


def test_org_wildcard_entry_reaching_admin_reads_as_one_chain(iam):
    admin = iam.add_role(
        "Admin", trust_policy=trust(role_statement("Deploy")), inline=policy(allow("*"))
    )
    deploy = iam.add_role(
        "Deploy",
        trust_policy=trust(github_statement("repo:my-org/*")),
        inline=policy(allow("sts:AssumeRole", admin)),
    )

    _, chain = run_chain(deploy)

    entry = chain["web_identity_entry"]
    assert entry["severity"] == "HIGH"
    [finding] = entry["findings"]
    assert finding["provider"] == "github"
    assert finding["subject_verdict"] == "HIGH"
    assert entry["deny_statements"] == []

    assert chain["path_severities"] == [
        {
            "roles": [deploy, admin],
            "entry_severity": "HIGH",
            "entry_role_arn": deploy,
            "entry_unknown": False,
            "last_role_arn": admin,
            "last_role_severity": "CRITICAL",
            "last_role_unknown": False,
        }
    ]


# =============================================================================
# SEVERAL ENTRIES ON ONE PATH
# =============================================================================


def two_entry_chain(iam):
    """Start (one repo, any ref: MEDIUM) -> Mid (not an entry) ->
    Deep (any repo on GitHub: CRITICAL), a role two hops in that also trusts
    GitHub."""
    deep = iam.add_role(
        "Deep",
        trust_policy=trust(role_statement("Mid"), github_statement("repo:*")),
        inline=policy(allow("s3:ListBucket")),
    )
    mid = iam.add_role(
        "Mid",
        trust_policy=trust(role_statement("Start")),
        inline=policy(allow("sts:AssumeRole", deep)),
    )
    start = iam.add_role(
        "Start",
        trust_policy=trust(github_statement("repo:my-org/app:*")),
        inline=policy(allow("sts:AssumeRole", mid)),
    )
    return start, mid, deep


def test_second_entry_at_depth_two_is_marked_on_its_own_node(iam):
    start, mid, deep = two_entry_chain(iam)

    _, chain = run_chain(start)

    assert chain["web_identity_entry"]["severity"] == "MEDIUM"
    assert node_for(chain, mid)["web_identity_entry"] is None
    deep_node = node_for(chain, deep)
    assert deep_node["depth"] == 2
    assert deep_node["web_identity_entry"]["severity"] == "CRITICAL"
    # Only the federated statement is an entry finding, not the role trust.
    [finding] = deep_node["web_identity_entry"]["findings"]
    assert finding["principal"] == GITHUB


def test_path_with_two_entries_carries_the_worst_and_names_its_node(iam):
    start, mid, deep = two_entry_chain(iam)

    _, chain = run_chain(start)

    [summary] = chain["path_severities"]
    assert summary["roles"] == [start, mid, deep]
    assert summary["entry_severity"] == "CRITICAL"
    assert summary["entry_role_arn"] == deep
    assert summary["entry_unknown"] is False
    assert summary["last_role_arn"] == deep
    # s3:ListBucket raises no egress finding: no severity, not a guessed one.
    assert summary["last_role_severity"] is None
    assert summary["last_role_unknown"] is False


# =============================================================================
# NO ENTRIES: OUTPUT UNCHANGED APART FROM NULL FIELDS
# =============================================================================

# The node and top-level keys the walk emitted before #11.
PRE_11_NODE_KEYS = {
    "role_arn",
    "depth",
    "status",
    "message",
    "error",
    "egress",
    "hops",
    "truncated",
    "max_depth",
    "unexplored",
    "unresolved_targets",
}


def test_walk_with_no_entries_only_adds_null_fields(iam):
    admin = iam.add_role(
        "Admin", trust_policy=trust(role_statement("Deploy")), inline=policy(allow("*"))
    )
    deploy = iam.add_role(
        "Deploy",
        trust_policy=trust(role_statement("Ci")),
        inline=policy(allow("sts:AssumeRole", admin)),
    )

    _, chain = run_chain(deploy)

    for node in flatten(chain):
        assert set(node) - {"paths", "path_severities"} == PRE_11_NODE_KEYS | {
            "web_identity_entry"
        }
        assert node["web_identity_entry"] is None
    assert chain["paths"] == [[deploy, admin]]
    assert chain["path_severities"] == [
        {
            "roles": [deploy, admin],
            "entry_severity": None,
            "entry_role_arn": None,
            "entry_unknown": False,
            "last_role_arn": admin,
            "last_role_severity": "CRITICAL",
            "last_role_unknown": False,
        }
    ]


def test_saml_trust_is_not_a_web_identity_entry(iam):
    saml = {
        "Effect": "Allow",
        "Principal": {"Federated": f"arn:aws:iam::{ACCOUNT}:saml-provider/Okta"},
        "Action": "sts:AssumeRoleWithSAML",
    }
    arn = iam.add_role("Sso", trust_policy=trust(saml), inline=policy())

    _, chain = run_chain(arn)

    assert chain["web_identity_entry"] is None


# =============================================================================
# DEPTH CAP, TRUNCATION AND SHORTEST DEPTH UNCHANGED WITH ENTRIES PRESENT
# =============================================================================


def test_entries_do_not_change_cap_truncation_or_unresolved_targets(iam):
    """Start -> Hop1 -> Hop2 -> Hop3: every role is an entry. Hop2 sits at
    the cap, so Hop3 is unexplored, never fetched, and gets no verdict."""
    hop3 = role_arn("Hop3")
    iam.add_role(
        "Hop3", trust_policy=trust(github_statement("repo:*")), inline=policy()
    )
    hop2 = iam.add_role(
        "Hop2",
        trust_policy=trust(role_statement("Hop1"), github_statement("repo:*")),
        inline=policy(allow("sts:AssumeRole", [hop3, role_arn("app-*")])),
    )
    hop1 = iam.add_role(
        "Hop1",
        trust_policy=trust(role_statement("Start"), github_statement("repo:*")),
        inline=policy(allow("sts:AssumeRole", hop2)),
    )
    start = iam.add_role(
        "Start",
        trust_policy=trust(github_statement("repo:my-org/*")),
        inline=policy(allow("sts:AssumeRole", hop1)),
    )

    _, chain = run_chain(start)

    hop2_node = node_for(chain, hop2)
    assert hop2_node["depth"] == 2
    assert hop2_node["truncated"] is True
    assert hop2_node["max_depth"] == 2
    assert hop2_node["unexplored"] == [hop3]
    assert hop2_node["unresolved_targets"] == [role_arn("app-*")]
    assert hop2_node["hops"] == []
    assert chain["paths"] == [[start, hop1, hop2]]
    assert [s["roles"] for s in chain["path_severities"]] == chain["paths"]
    # Hop3, past the cap, was never read at all - not even its trust policy.
    assert iam.count("get_role") == 3
    assert iam.count("list_role_policies") == 3


def test_entries_do_not_change_shortest_depth_placement(iam):
    """Diamond: Target is reachable via A (depth 2) and via B -> C (depth 3).
    With every role an entry, Target is still placed once, at depth 2."""
    target = iam.add_role(
        "Target",
        trust_policy=trust(
            role_statement("A"), role_statement("C"), github_statement("repo:*")
        ),
        inline=policy(allow("*")),
    )
    a = iam.add_role(
        "A",
        trust_policy=trust(role_statement("Start"), github_statement("repo:*")),
        inline=policy(allow("sts:AssumeRole", target)),
    )
    c = iam.add_role(
        "C",
        trust_policy=trust(role_statement("B"), github_statement("repo:*")),
        inline=policy(allow("sts:AssumeRole", target)),
    )
    b = iam.add_role(
        "B",
        trust_policy=trust(role_statement("Start"), github_statement("repo:*")),
        inline=policy(allow("sts:AssumeRole", c)),
    )
    start = iam.add_role(
        "Start",
        trust_policy=trust(github_statement("repo:my-org/*")),
        inline=policy(allow("sts:AssumeRole", [a, b])),
    )

    _, chain = run_chain(start)

    assert [n["depth"] for n in flatten(chain) if n["role_arn"] == target] == [2]
    assert not any(n["truncated"] for n in flatten(chain))
    assert chain["paths"] == [[start, a, target], [start, b, c]]
    assert [s["roles"] for s in chain["path_severities"]] == chain["paths"]
    assert [s["last_role_arn"] for s in chain["path_severities"]] == [target, c]


# =============================================================================
# READS
# =============================================================================


def test_each_walked_role_trust_policy_is_read_once(iam):
    """Shared is reached via BranchA and BranchB; Start is also the CLI's
    starting role. Every role's get_role runs exactly once."""
    shared = iam.add_role(
        "Shared",
        trust_policy=trust(
            role_statement("BranchA"),
            role_statement("BranchB"),
            github_statement("repo:*"),
        ),
        inline=policy(),
    )
    branch_a = iam.add_role(
        "BranchA",
        trust_policy=trust(role_statement("Start")),
        inline=policy(allow("sts:AssumeRole", shared)),
    )
    branch_b = iam.add_role(
        "BranchB",
        trust_policy=trust(role_statement("Start")),
        inline=policy(allow("sts:AssumeRole", shared)),
    )
    start = iam.add_role(
        "Start",
        trust_policy=trust(github_statement("repo:my-org/*")),
        inline=policy(allow("sts:AssumeRole", [branch_a, branch_b])),
    )

    _, chain = run_chain(start)

    assert node_for(chain, shared)["web_identity_entry"]["severity"] == "CRITICAL"
    assert iam.count("get_role") == 4  # Start, BranchA, BranchB, Shared


# =============================================================================
# TRUST-POLICY READ ERRORS
# =============================================================================


def chain_with_unreadable_mid(iam):
    """Start (entry) -> Mid -> Leaf, where Mid's get_role is denied but its
    policy reads succeed, so the walk still reaches Leaf through it."""
    leaf = iam.add_role(
        "Leaf", trust_policy=trust(role_statement("Mid")), inline=policy(allow("*"))
    )
    mid = iam.add_role(
        "Mid",
        trust_policy=trust(role_statement("Start")),
        inline=policy(allow("sts:AssumeRole", leaf)),
    )
    start = iam.add_role(
        "Start",
        trust_policy=trust(github_statement("repo:my-org/*")),
        inline=policy(allow("sts:AssumeRole", mid)),
    )
    iam.fail_for_role("get_role", "Mid", "AccessDenied")
    return start, mid, leaf


def test_trust_read_error_is_an_error_not_a_missing_entry(iam):
    start, mid, leaf = chain_with_unreadable_mid(iam)

    exit_code, chain = run_chain(start)

    mid_node = node_for(chain, mid)
    assert mid_node["status"] == "error"
    assert mid_node["message"] == "Access denied fetching role: Mid"
    assert mid_node["error"] == "Access denied fetching role: Mid"
    assert mid_node["web_identity_entry"] == {
        "status": "error",
        "message": "Access denied fetching role: Mid",
        "error": "Access denied fetching role: Mid",
    }
    # The walk still went through Mid: its policies were readable.
    assert node_for(chain, leaf)["depth"] == 2

    for summary in chain["path_severities"]:
        assert mid in summary["roles"]
        assert summary["entry_unknown"] is True
        assert summary["entry_severity"] is None
        assert summary["entry_role_arn"] is None
    assert exit_code != 0


def test_trust_read_error_is_reported_in_errors_and_exits_non_zero(iam):
    start, _, _ = chain_with_unreadable_mid(iam)

    result = runner.invoke(app, ["analyze", start, "--json", "--check", "chain"])

    payload = json.loads(result.output)
    assert payload["errors"] == [
        {"check": "chain", "message": "Access denied fetching role: Mid"}
    ]
    assert result.exit_code != 0


def test_egress_failure_stays_the_node_message_when_both_reads_fail(iam):
    start, mid, _ = chain_with_unreadable_mid(iam)
    iam.fail_for_role("list_role_policies", "Mid", "AccessDenied")

    _, chain = run_chain(start)

    mid_node = node_for(chain, mid)
    assert mid_node["status"] == "error"
    assert mid_node["message"] == "Access denied fetching policies for: Mid"
    assert mid_node["web_identity_entry"]["message"] == (
        "Access denied fetching role: Mid"
    )


# =============================================================================
# EXIT CODE: MAX OF EGRESS AND ENTRY SEVERITIES
# =============================================================================


@pytest.mark.parametrize(
    "sub,fail_on,expected",
    [
        pytest.param("repo:*", [], 2, id="critical-entry-fails-default-gate"),
        pytest.param("repo:my-org/*", [], 1, id="high-entry-fails-default-gate"),
        pytest.param("repo:my-org/app:*", [], 0, id="medium-entry-passes-default"),
        pytest.param(
            "repo:my-org/app:*",
            ["--fail-on", "medium"],
            1,
            id="medium-entry-fails-fail-on-medium",
        ),
        pytest.param(
            "repo:my-org/app:ref:refs/heads/main",
            ["--fail-on", "medium"],
            0,
            id="low-entry-passes-fail-on-medium",
        ),
    ],
)
def test_entry_severity_gates_the_chain_exit_code(iam, sub, fail_on, expected):
    """The starting role reaches nothing and has no risky egress, so the
    entry is the only thing that can fail the gate."""
    arn = iam.add_role(
        "Deploy",
        trust_policy=trust(github_statement(sub)),
        inline=policy(allow("s3:ListBucket")),
    )

    exit_code, chain = run_chain(arn, *fail_on)

    assert chain["egress"]["findings"] == []
    assert exit_code == expected


def test_egress_severity_still_gates_when_it_is_the_higher_one(iam):
    arn = iam.add_role(
        "Deploy",
        trust_policy=trust(github_statement("repo:my-org/app:*")),
        inline=policy(allow("*")),
    )

    exit_code, _ = run_chain(arn)

    assert exit_code == 2


def test_unreadable_last_role_is_unknown_not_harmless(iam):
    """A failed policy read on the last role must not read as "no egress
    findings": last_role_severity stays null, and last_role_unknown says why."""
    leaf = iam.add_role(
        "Leaf", trust_policy=trust(role_statement("Start")), inline=policy(allow("*"))
    )
    start = iam.add_role(
        "Start",
        trust_policy=trust(github_statement("repo:*")),
        inline=policy(allow("sts:AssumeRole", leaf)),
    )
    iam.fail_for_role("list_role_policies", "Leaf", "AccessDenied")

    exit_code, chain = run_chain(start)

    [summary] = chain["path_severities"]
    assert summary["last_role_arn"] == leaf
    assert summary["last_role_severity"] is None
    assert summary["last_role_unknown"] is True
    assert summary["entry_severity"] == "CRITICAL"
    assert exit_code != 0


# =============================================================================
# WILDCARD PRINCIPAL ALLOWING sts:AssumeRoleWithWebIdentity
# =============================================================================


def wildcard_statement(action, **extra):
    return {"Effect": "Allow", "Principal": "*", "Action": action, **extra}


@pytest.mark.parametrize(
    "principal_statement",
    [
        pytest.param(
            wildcard_statement("sts:AssumeRoleWithWebIdentity"), id="bare-star"
        ),
        pytest.param(
            {
                **wildcard_statement("sts:AssumeRoleWithWebIdentity"),
                "Principal": {"AWS": "*"},
            },
            id="aws-star",
        ),
        pytest.param(
            wildcard_statement(["sts:AssumeRole", "sts:AssumeRoleWithWebIdentity"]),
            id="among-other-actions",
        ),
        pytest.param(wildcard_statement("sts:AssumeRoleWith*"), id="action-glob"),
    ],
)
def test_wildcard_principal_allowing_web_identity_is_an_entry(iam, principal_statement):
    arn = iam.add_role(
        "Open",
        trust_policy=trust(principal_statement),
        inline=policy(allow("s3:ListBucket")),
    )

    exit_code, chain = run_chain(arn)

    entry = chain["web_identity_entry"]
    # Ingress's own verdict for an unrestricted "*" principal.
    assert entry["severity"] == "CRITICAL"
    [finding] = entry["findings"]
    assert finding["principal"] == "*"
    assert finding["principal_type"] == "Wildcard"
    assert chain["path_severities"][0]["entry_role_arn"] == arn
    assert exit_code == 2


def test_wildcard_principal_entry_keeps_ingress_verdict_when_org_restricted(iam):
    statement = wildcard_statement(
        "sts:AssumeRoleWithWebIdentity",
        Condition={"StringEquals": {"aws:PrincipalOrgID": "o-example"}},
    )
    arn = iam.add_role("Open", trust_policy=trust(statement), inline=policy())

    _, chain = run_chain(arn)

    assert chain["web_identity_entry"]["severity"] == "HIGH"


def test_wildcard_principal_without_web_identity_action_is_not_an_entry(iam):
    arn = iam.add_role(
        "Open",
        trust_policy=trust(wildcard_statement("sts:AssumeRole")),
        inline=policy(),
    )

    _, chain = run_chain(arn)

    assert chain["web_identity_entry"] is None


def test_wildcard_principal_with_notaction_not_excluding_web_identity_is_an_entry(
    iam,
):
    """NotAction excluding only sts:AssumeRole still allows
    sts:AssumeRoleWithWebIdentity."""
    statement = {"Effect": "Allow", "Principal": "*", "NotAction": "sts:AssumeRole"}
    arn = iam.add_role("Open", trust_policy=trust(statement), inline=policy())

    exit_code, chain = run_chain(arn)

    entry = chain["web_identity_entry"]
    assert entry["severity"] == "CRITICAL"
    [finding] = entry["findings"]
    assert finding["principal"] == "*"
    assert exit_code == 2


@pytest.mark.parametrize(
    "not_action",
    [
        pytest.param("sts:AssumeRoleWithWebIdentity", id="exact"),
        pytest.param("STS:assumerolewithwebidentity", id="case-insensitive"),
        pytest.param("sts:AssumeRoleWith*", id="glob"),
        pytest.param(["sts:AssumeRole", "sts:*"], id="list-with-service-glob"),
    ],
)
def test_wildcard_principal_with_notaction_excluding_web_identity_is_not_an_entry(
    iam, not_action
):
    statement = {"Effect": "Allow", "Principal": "*", "NotAction": not_action}
    arn = iam.add_role("Open", trust_policy=trust(statement), inline=policy())

    _, chain = run_chain(arn)

    assert chain["web_identity_entry"] is None
