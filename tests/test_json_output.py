"""Tests that --json emits raw, uncorrupted JSON.

The payload used to go through ``console.print``, which routes it through
rich. Rich does two things to a JSON string that machine-readable output
cannot tolerate:

- it parses ``[...]`` as style markup and strips it, so a value containing
  square brackets comes out silently altered but still parses as JSON;
- it hard-wraps at the console width, inserting a newline inside the string
  literal and producing invalid JSON.

Policy documents carry arbitrary strings — condition values, resource ARNs,
external IDs — so both are reachable.
"""

import json

from typer.testing import CliRunner

from iamwho.cli import app

from .conftest import allow

runner = CliRunner()

LONG_RESOURCE = "arn:aws:s3:::" + ("a" * 120) + "/*"
BRACKETED = "arn:aws:s3:::bucket/[red]prefix[/red]/*"


def run_json(arn, *args):
    result = runner.invoke(app, ["analyze", arn, "--json", *args])
    return result, json.loads(result.output)


def test_long_values_do_not_wrap_into_invalid_json(iam):
    """Rich hard-wrapped past the console width, breaking the string literal."""
    arn = iam.add_role(
        "Long", inline={"p": {"Statement": [allow("s3:GetObject", LONG_RESOURCE)]}}
    )

    result, payload = run_json(arn, "--check", "egress")

    assert result.exit_code in (0, 1, 2)
    resources = payload["checks"]["egress"]["findings"][0]["resources"]
    assert resources == [LONG_RESOURCE]


def test_square_brackets_in_values_survive_intact(iam):
    """Rich stripped markup, corrupting the value while still parsing."""
    arn = iam.add_role(
        "Bracketed", inline={"p": {"Statement": [allow("s3:GetObject", BRACKETED)]}}
    )

    _, payload = run_json(arn, "--check", "egress")

    assert payload["checks"]["egress"]["findings"][0]["resources"] == [BRACKETED]


def test_bracketed_condition_values_survive_intact(iam):
    """Trust policy conditions are echoed raw into the ingress payload."""
    external_id = "[bold]tenant-42[/bold]"
    arn = iam.add_role(
        "Vendor",
        trust_policy={
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"AWS": "arn:aws:iam::999988887777:root"},
                    "Action": "sts:AssumeRole",
                    "Condition": {"StringEquals": {"sts:ExternalId": external_id}},
                }
            ]
        },
    )

    _, payload = run_json(arn, "--check", "ingress")

    raw = payload["checks"]["ingress"]["findings"][0]["conditions"]["raw_conditions"]
    assert raw["StringEquals"]["sts:ExternalId"] == external_id


def test_no_findings_payload_is_valid_json(iam):
    arn = iam.add_role("Clean")

    result, payload = run_json(arn, "--check", "all")

    assert result.exit_code == 0
    assert payload["errors"] == []


def test_error_payload_is_valid_json(iam):
    arn = iam.add_role("Denied")
    iam.fail("list_role_policies", "AccessDenied")

    result, payload = run_json(arn, "--check", "egress")

    assert result.exit_code == 1
    assert payload["errors"][0]["check"] == "egress"


def test_output_is_exactly_one_json_document(iam):
    """Nothing else may be written to stdout in --json mode."""
    arn = iam.add_role("Admin", inline={"p": {"Statement": [allow("*")]}})

    result = runner.invoke(app, ["analyze", arn, "--json", "--check", "all"])

    assert result.output.strip().startswith("{")
    assert result.output.strip().endswith("}")
    json.loads(result.output)


# =============================================================================
# CHAIN (opt-in, JSON only for now)
# =============================================================================


def test_check_chain_returns_the_walk_structure(iam):
    target_arn = iam.add_role(
        "Target", inline={"p": {"Statement": [allow("s3:ListBucket")]}}
    )
    arn = iam.add_role(
        "Agent", inline={"p": {"Statement": [allow("iam:PassRole", target_arn)]}}
    )

    result, payload = run_json(arn, "--check", "chain")

    assert result.exit_code == 0
    chain_result = payload["checks"]["chain"]
    assert chain_result["role_arn"] == arn
    assert chain_result["depth"] == 0
    assert chain_result["hops"][0]["role_arn"] == target_arn
    assert chain_result["paths"] == [[arn, target_arn]]


def test_check_all_does_not_include_chain(iam):
    """chain is opt-in only: more AWS reads than the other checks' single fetch."""
    arn = iam.add_role("Agent", inline={"p": {"Statement": [allow("s3:ListBucket")]}})

    _, payload = run_json(arn, "--check", "all")

    assert "chain" not in payload["checks"]


def test_chain_check_without_json_prints_a_placeholder(iam):
    """No console tree renderer yet (issue #2) - print a plain message."""
    arn = iam.add_role("Agent", inline={"p": {"Statement": [allow("s3:ListBucket")]}})

    result = runner.invoke(app, ["analyze", arn, "--check", "chain", "--no-banner"])

    assert result.exit_code == 0
    assert "requires --json" in result.output
    assert "issue #2" in result.output
