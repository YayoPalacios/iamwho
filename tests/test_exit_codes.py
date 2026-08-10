"""Tests for --fail-on exit codes.

calculate_exit_code seeded its counter with only CRITICAL/HIGH/MEDIUM/LOW and
then did ``counts[sev] += 1``. Ingress emits INFO for a service principal that
*does* carry confused-deputy protection — a well-configured role — so analyzing
one with --fail-on raised KeyError: 'INFO'. The raise happened outside the
command's try block, so it surfaced as an uncaught traceback.
"""

import pytest
from typer.testing import CliRunner

from iamwho.cli import app, calculate_exit_code

from .conftest import allow

runner = CliRunner()

FAIL_ON_VALUES = ["critical", "high", "medium", "low", "any", None]

# A service principal with SourceAccount set: ingress scores this INFO.
PROTECTED_SERVICE_TRUST = {
    "Statement": [
        {
            "Effect": "Allow",
            "Principal": {"Service": "lambda.amazonaws.com"},
            "Action": "sts:AssumeRole",
            "Condition": {"StringEquals": {"aws:SourceAccount": "123456789012"}},
        }
    ]
}


# =============================================================================
# THE CRASH
# =============================================================================


@pytest.mark.parametrize("fail_on", FAIL_ON_VALUES)
@pytest.mark.parametrize("severity", ["INFO", "PASS"])
def test_non_gating_severities_do_not_crash(severity, fail_on):
    assert calculate_exit_code([{"severity": severity}], fail_on) == 0


@pytest.mark.parametrize("fail_on", FAIL_ON_VALUES)
def test_unknown_severity_does_not_crash(fail_on):
    """Anything outside SEVERITY_ORDER used to raise KeyError too."""
    code = calculate_exit_code([{"severity": "BOGUS"}], fail_on)

    assert code in (0, 1)


def test_a_well_configured_role_does_not_crash_the_cli(iam):
    """End to end: the INFO finding reached calculate_exit_code and blew up."""
    arn = iam.add_role("Protected", trust_policy=PROTECTED_SERVICE_TRUST)

    result = runner.invoke(
        app, ["analyze", arn, "--check", "ingress", "--fail-on", "high", "--no-banner"]
    )

    assert result.exception is None
    assert result.exit_code == 0
    assert "INFO" in result.output


# =============================================================================
# NON-GATING SEVERITIES
# =============================================================================


def test_info_does_not_gate_even_on_fail_on_any():
    """INFO means the control is present; it must never fail a build."""
    assert calculate_exit_code([{"severity": "INFO"}], "any") == 0
    assert calculate_exit_code([{"severity": "PASS"}], "any") == 0


def test_info_alongside_a_real_finding_does_not_change_the_code():
    with_info = [{"severity": "HIGH"}, {"severity": "INFO"}]
    without_info = [{"severity": "HIGH"}]

    assert calculate_exit_code(with_info, "high") == calculate_exit_code(
        without_info, "high"
    )


def test_unknown_severity_counts_as_a_finding():
    assert calculate_exit_code([{"severity": "BOGUS"}], "any") == 1
    assert calculate_exit_code([{"severity": "BOGUS"}], "low") == 1
    assert calculate_exit_code([{"severity": "BOGUS"}], "high") == 0


# =============================================================================
# THRESHOLDS STILL BEHAVE
# =============================================================================


@pytest.mark.parametrize(
    "severity,fail_on,expected",
    [
        ("CRITICAL", None, 2),
        ("HIGH", None, 1),
        ("MEDIUM", None, 0),
        ("CRITICAL", "critical", 2),
        ("HIGH", "critical", 0),
        ("CRITICAL", "high", 2),
        ("HIGH", "high", 1),
        ("MEDIUM", "high", 0),
        ("MEDIUM", "medium", 1),
        ("LOW", "medium", 0),
        ("LOW", "low", 1),
        ("LOW", "any", 1),
        ("CRITICAL", "any", 2),
    ],
)
def test_thresholds(severity, fail_on, expected):
    assert calculate_exit_code([{"severity": severity}], fail_on) == expected


def test_no_findings_exits_zero():
    for fail_on in FAIL_ON_VALUES:
        assert calculate_exit_code([], fail_on) == 0


def test_missing_severity_defaults_to_low():
    assert calculate_exit_code([{}], "low") == 1
    assert calculate_exit_code([{}], "high") == 0


def test_critical_role_still_gates(iam):
    arn = iam.add_role("Admin", inline={"p": {"Statement": [allow("*")]}})

    result = runner.invoke(
        app, ["analyze", arn, "--check", "egress", "--fail-on", "high", "--no-banner"]
    )

    assert result.exit_code == 2
