"""Tests for the shared IAM client: pagination, caching, retries, single client.

Before ``checks/_client.py`` existed, each check built its own
``boto3.client("iam")`` inline, called ``list_role_policies`` and
``list_attached_role_policies`` without a paginator, and cached nothing. The
tests below fail against that behavior.
"""

import json

import boto3
import pytest
from typer.testing import CliRunner

from iamwho.checks import _client, egress
from iamwho.checks.privilege_mutation import analyze_privilege_mutation
from iamwho.cli import app

from .conftest import allow

runner = CliRunner()

# =============================================================================
# PAGINATION
# =============================================================================


def test_inline_policies_past_the_first_page_are_not_dropped(iam):
    """Unpaginated list_role_policies returned only the first page."""
    iam.page_size = 2
    inline = {
        f"policy-{i}": {"Statement": [allow(f"s3:GetObject{i}")]} for i in range(5)
    }
    arn = iam.add_role("Wide", inline=inline)

    policies = _client.get_role_policies(arn)

    assert len(policies) == 5
    assert iam.count("list_role_policies") == 1  # one paginate call, three pages
    assert iam.count("get_role_policy") == 5


def test_attached_policies_past_the_first_page_are_not_dropped(iam):
    iam.page_size = 2
    attached = [
        iam.add_managed_policy(f"managed-{i}", {"Statement": [allow("iam:PassRole")]})
        for i in range(5)
    ]
    arn = iam.add_role("Wide", attached=attached)

    policies = _client.get_role_policies(arn)

    assert len(policies) == 5
    assert {p["type"] for p in policies} == {"managed"}


def test_paginated_policies_reach_the_egress_check(iam):
    """The truncation was silent: findings simply went missing."""
    iam.page_size = 1
    arn = iam.add_role(
        "Wide",
        inline={
            "a": {"Statement": [allow("s3:GetObject")]},
            "b": {"Statement": [allow("iam:PutRolePolicy")]},
        },
    )

    result = egress.analyze_egress(arn)
    actions = {f["action"] for f in result["findings"]}

    assert actions == {"s3:GetObject", "iam:PutRolePolicy"}


# =============================================================================
# CACHING
# =============================================================================


def test_repeated_reads_of_a_role_hit_the_cache(iam):
    arn = iam.add_role("Cached", inline={"p": {"Statement": [allow("s3:GetObject")]}})

    for _ in range(3):
        _client.get_role_policies(arn)

    assert iam.count("list_role_policies") == 1
    assert iam.count("get_role_policy") == 1


def test_trust_policy_reads_are_cached(iam):
    arn = iam.add_role("Cached")

    _client.get_trust_policy(arn)
    _client.get_trust_policy(arn)

    assert iam.count("get_role") == 1


def test_managed_policy_shared_by_two_roles_is_fetched_once(iam):
    """Chain walks re-encounter the same managed policy on many roles."""
    shared = iam.add_managed_policy("Shared", {"Statement": [allow("iam:PassRole")]})
    first = iam.add_role("First", attached=[shared])
    second = iam.add_role("Second", attached=[shared])

    _client.get_role_policies(first)
    _client.get_role_policies(second)

    assert iam.count("get_policy_version") == 1


def test_cached_documents_are_isolated_from_caller_mutation(iam):
    arn = iam.add_role("Cached", inline={"p": {"Statement": [allow("s3:GetObject")]}})

    first = _client.get_role_policies(arn)
    first[0]["document"]["Statement"].append(allow("iam:*"))
    second = _client.get_role_policies(arn)

    assert len(second[0]["document"]["Statement"]) == 1


def test_clear_cache_forces_a_refetch(iam):
    arn = iam.add_role("Cached")

    _client.get_trust_policy(arn)
    _client.clear_cache()
    _client.get_trust_policy(arn)

    assert iam.count("get_role") == 2


def test_failures_are_not_cached(iam):
    """A throttled or transient read must be retried, not remembered."""
    arn = iam.add_role("Flaky")
    iam.fail("get_role", "Throttling")

    with pytest.raises(_client.IamFetchError):
        _client.get_trust_policy(arn)

    iam.errors.clear()
    assert _client.get_trust_policy(arn) == {"Version": "2012-10-17", "Statement": []}


# =============================================================================
# DOUBLE FETCH
# =============================================================================


def test_mutation_reuses_a_supplied_egress_result(iam):
    """Mutation used to call egress.run again, doubling the API reads."""
    arn = iam.add_role(
        "Agent",
        inline={"p": {"Statement": [allow(["iam:PassRole", "lambda:CreateFunction"])]}},
    )

    egress_result = egress.analyze_egress(arn)
    reads_after_egress = len(iam.calls)
    mutation = analyze_privilege_mutation(arn, egress_result=egress_result)

    assert len(iam.calls) == reads_after_egress
    assert mutation["status"] == "success"
    assert mutation["overall_risk"] == "CRITICAL"


def test_mutation_still_fetches_when_called_standalone(iam):
    arn = iam.add_role("Agent", inline={"p": {"Statement": [allow("iam:PassRole")]}})

    mutation = analyze_privilege_mutation(arn)

    assert mutation["status"] == "success"
    assert iam.count("list_role_policies") == 1


def test_standalone_mutation_check_finds_the_same_escalation_as_check_all(iam):
    """`--check mutation` alone must surface the same findings as `--check all`.

    If mutation ever went back to requiring a caller-supplied egress_result
    (the double-fetch fix's failure mode), a standalone `--check mutation`
    run would come back empty while `--check all` still found the real
    escalation.
    """
    arn = iam.add_role(
        "Agent",
        inline={"p": {"Statement": [allow(["iam:PassRole", "lambda:CreateFunction"])]}},
    )

    standalone = runner.invoke(app, ["analyze", arn, "--json", "--check", "mutation"])
    combined = runner.invoke(app, ["analyze", arn, "--json", "--check", "all"])

    standalone_mutation = json.loads(standalone.output)["checks"]["mutation"]
    combined_mutation = json.loads(combined.output)["checks"]["mutation"]

    assert standalone_mutation == combined_mutation
    assert standalone_mutation["overall_risk"] == "CRITICAL"
    assert standalone_mutation["findings"], (
        "expected the known PassRole+CreateFunction combo"
    )


# =============================================================================
# CLIENT CONFIGURATION
# =============================================================================


def test_every_check_shares_one_client(iam):
    assert _client.get_client() is iam
    assert _client.get_client() is _client.get_client()


def test_real_client_is_configured_with_adaptive_retries(monkeypatch):
    captured = {}

    class _Session:
        def client(self, name, config=None):
            captured["name"] = name
            captured["config"] = config
            return object()

    monkeypatch.setattr(boto3, "Session", _Session)
    _client.set_client(None)
    try:
        _client.get_client()
    finally:
        _client.set_client(None)

    assert captured["name"] == "iam"
    assert captured["config"].retries["mode"] == "adaptive"
    assert captured["config"].retries["max_attempts"] == 10


# =============================================================================
# ERROR TRANSLATION
# =============================================================================


@pytest.mark.parametrize(
    "code,expected",
    [
        ("NoSuchEntity", "Role not found: Gone"),
        ("AccessDenied", "Access denied fetching role: Gone"),
        ("AccessDeniedException", "Access denied fetching role: Gone"),
        ("Throttling", "AWS error: Throttling"),
    ],
)
def test_client_errors_become_user_facing_messages(iam, code, expected):
    arn = iam.add_role("Gone")
    iam.fail("get_role", code)

    with pytest.raises(_client.IamFetchError) as excinfo:
        _client.get_trust_policy(arn)

    assert excinfo.value.message == expected


def test_invalid_role_arn_is_rejected_before_any_api_call(iam):
    with pytest.raises(_client.IamFetchError):
        _client.get_role_policies("arn:aws:iam::123456789012:user/alice")

    assert iam.calls == []
