"""Tests for failed checks and for --json honouring --fail-on.

Two bugs are covered here.

The first was a fail-open: ``normalize_egress_findings`` guarded on
``"error" in result``, but the egress error shape puts the detail under
``message`` and the status under ``status``. The guard never matched, the
normalizer fell through to ``result.get("findings", [])``, and a role the
caller had no permission to read printed "No dangerous permissions detected"
in green and exited 0.

The second was in the same function's caller: ``--json`` raised
``typer.Exit(code=0)`` unconditionally, so ``--fail-on`` was ignored in exactly
the output mode CI uses.
"""

import json

import pytest
from botocore.exceptions import NoCredentialsError
from typer.testing import CliRunner

from iamwho.checks.egress import analyze_egress
from iamwho.cli import app, calculate_exit_code, check_error, normalize_egress_findings

from .conftest import allow

runner = CliRunner()

ADMIN = {"Statement": [allow("*")]}


def run(*args):
    return runner.invoke(app, ["analyze", *args])


# =============================================================================
# ERROR DETECTION
# =============================================================================


def test_egress_error_shape_is_detected():
    """The shape that used to slip past the guard."""
    result = {"status": "error", "message": "Access denied fetching policies for: R"}

    assert check_error(result) == "Access denied fetching policies for: R"
    assert normalize_egress_findings(result) == []


def test_ingress_error_shape_is_detected():
    class _Result:
        error = "Role not found: R"

    assert check_error(_Result()) == "Role not found: R"


def test_successful_results_are_not_treated_as_errors():
    assert check_error({"status": "success", "findings": []}) is None
    assert check_error(None) is None


def test_egress_fetch_failure_populates_both_message_and_error(iam):
    """AGENTS.md requires both keys on an error return; egress set only message."""
    arn = iam.add_role("Denied", inline={"p": ADMIN})
    iam.fail("list_role_policies", "AccessDenied")

    result = analyze_egress(arn)

    assert result["status"] == "error"
    assert result["error"] == result["message"]


def test_egress_unresolvable_role_name_populates_both_message_and_error():
    result = analyze_egress("arn:aws:iam::123456789012:role/")

    assert result["status"] == "error"
    assert result["error"] == result["message"]


# =============================================================================
# FAIL-OPEN
# =============================================================================


def test_access_denied_is_reported_not_rendered_as_clean(iam):
    arn = iam.add_role("Denied", inline={"p": ADMIN})
    iam.fail("list_role_policies", "AccessDenied")

    result = run(arn, "--check", "egress", "--no-banner")

    assert result.exit_code != 0
    assert "Check failed" in result.output
    assert "Access denied" in result.output
    assert "No dangerous permissions detected" not in result.output


def test_access_denied_exits_non_zero_without_fail_on(iam):
    """The CI gate ran without --fail-on and got a passing exit code."""
    arn = iam.add_role("Denied", inline={"p": ADMIN})
    iam.fail("list_role_policies", "AccessDenied")

    assert run(arn, "--check", "egress", "--no-banner").exit_code == 1


def test_access_denied_exits_non_zero_with_fail_on(iam):
    arn = iam.add_role("Denied", inline={"p": ADMIN})
    iam.fail("list_role_policies", "AccessDenied")

    result = run(arn, "--check", "egress", "--fail-on", "high", "--no-banner")

    assert result.exit_code != 0


def test_missing_role_is_reported(iam):
    result = run(
        "arn:aws:iam::123456789012:role/Ghost", "--check", "ingress", "--no-banner"
    )

    assert result.exit_code != 0
    assert "Role not found" in result.output


def test_partial_failure_still_reports_the_checks_that_worked(iam):
    """One denied check must not hide the findings from the others."""
    arn = iam.add_role(
        "Partial",
        trust_policy={
            "Statement": [
                {"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}
            ]
        },
    )
    iam.fail("list_role_policies", "AccessDenied")

    result = run(arn, "--check", "all", "--no-banner")

    assert result.exit_code != 0
    assert "check(s) failed" in result.output
    assert "results are incomplete" in result.output
    # The ingress finding still rendered.
    assert "CRIT" in result.output


def test_healthy_role_still_exits_zero(iam):
    arn = iam.add_role("Clean", inline={"p": {"Statement": [allow("s3:ListBucket")]}})

    result = run(arn, "--check", "egress", "--no-banner")

    assert result.exit_code == 0
    assert "Check failed" not in result.output


# =============================================================================
# JSON MODE
# =============================================================================


def test_json_reports_errors_and_exits_non_zero(iam):
    arn = iam.add_role("Denied", inline={"p": ADMIN})
    iam.fail("list_role_policies", "AccessDenied")

    result = run(arn, "--check", "egress", "--json")
    payload = json.loads(result.output)

    assert result.exit_code != 0
    assert payload["errors"] == [
        {"check": "egress", "message": "Access denied fetching policies for: Denied"}
    ]


def test_json_honours_fail_on(iam):
    """--json used to raise Exit(code=0) unconditionally."""
    arn = iam.add_role("Admin", inline={"p": ADMIN})

    result = run(arn, "--check", "egress", "--json", "--fail-on", "critical")

    assert result.exit_code == 2
    assert json.loads(result.output)["checks"]["egress"]["status"] == "success"


@pytest.mark.parametrize(
    "fail_on,expected",
    [("critical", 2), ("high", 2), ("medium", 2), ("any", 2)],
)
def test_json_exit_code_matches_text_mode(iam, fail_on, expected):
    arn = iam.add_role("Admin", inline={"p": ADMIN})

    as_json = run(arn, "--check", "egress", "--json", "--fail-on", fail_on)
    as_text = run(arn, "--check", "egress", "--no-banner", "--fail-on", fail_on)

    assert as_json.exit_code == expected
    assert as_json.exit_code == as_text.exit_code


def test_json_stays_zero_for_a_clean_role(iam):
    arn = iam.add_role("Clean", inline={"p": {"Statement": [allow("s3:ListBucket")]}})

    result = run(arn, "--check", "egress", "--json", "--fail-on", "high")

    assert result.exit_code == 0
    assert json.loads(result.output)["errors"] == []


def test_json_output_remains_parseable_with_errors(iam):
    arn = iam.add_role("Denied")
    iam.fail("get_role", "AccessDenied")
    iam.fail("list_role_policies", "AccessDenied")

    result = run(arn, "--check", "all", "--json")

    json.loads(result.output)  # must not raise


def test_json_stays_valid_when_an_unexpected_exception_escapes_a_check(iam):
    """A non-ClientError (e.g. missing credentials) used to print a Rich
    error to stdout instead of the JSON envelope, corrupting --json output.
    """
    arn = iam.add_role("Agent", inline={"p": {"Statement": [allow("s3:GetObject")]}})
    iam.raise_exception("get_role", NoCredentialsError())

    result = run(arn, "--check", "ingress", "--json")
    payload = json.loads(result.output)  # must not raise

    assert result.exit_code != 0
    assert payload["errors"] == [
        {"check": "fatal", "message": "Unable to locate credentials"}
    ]


def test_json_stays_valid_for_an_invalid_arn():
    result = run("not-an-arn", "--json")
    payload = json.loads(result.output)  # must not raise

    assert result.exit_code != 0
    assert payload["errors"][0]["check"] == "validation"


def test_json_stays_valid_for_an_invalid_check_type(iam):
    arn = iam.add_role("Agent")

    result = run(arn, "--check", "bogus", "--json")
    payload = json.loads(result.output)  # must not raise

    assert result.exit_code != 0
    assert payload["errors"][0]["check"] == "validation"


# =============================================================================
# EXIT CODE PLUMBING
# =============================================================================


def test_check_failure_does_not_downgrade_a_critical_finding(iam):
    """An error floor of 1 must not mask a CRITICAL exit of 2."""
    findings = [{"severity": "CRITICAL"}]

    assert max(calculate_exit_code(findings, "critical"), 1) == 2
