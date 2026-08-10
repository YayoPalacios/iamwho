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
