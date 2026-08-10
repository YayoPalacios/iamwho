"""Tests for the summary table's handling of failed checks.

print_summary derived each row from get_section_severity(findings), which
returns "PASS" for any empty list and had no notion of a check that failed.
A denied check therefore rendered as "0 findings PASS" — a green clean
result — in the table directly beneath a section body that said
"Check failed", and beneath a run that exited non-zero.

The section bodies, the failure count line, and the exit code were all already
correct. The table alone lied, so these tests assert on the table rows
specifically, isolated from the rest of the output.
"""

from typer.testing import CliRunner

from iamwho.cli import app, console, print_summary

from .conftest import allow

runner = CliRunner()

WILDCARD_TRUST = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": "*", "Action": "sts:AssumeRole"}],
}


def summary_rows(output: str) -> dict[str, str]:
    """Extract only the summary table rows, keyed by section name.

    The table is the block between the first two heavy rules, which excludes
    the section bodies above it and the totals below.
    """
    lines = output.splitlines()
    rules = [i for i, line in enumerate(lines) if line.strip().startswith("━")]
    assert len(rules) >= 2, f"summary table not found in output:\n{output}"
    rows = {}
    for line in lines[rules[0] + 1 : rules[1]]:
        if line.strip():
            rows[line.split()[0]] = line
    return rows


def render_summary(**kwargs) -> str:
    with console.capture() as captured:
        print_summary(**kwargs)
    return captured.get()


# =============================================================================
# THE BUG
# =============================================================================


def test_failed_check_row_is_not_reported_as_pass(iam):
    """Scenario 3: egress denied, ingress succeeds."""
    arn = iam.add_role("AgentRole", trust_policy=WILDCARD_TRUST)
    iam.fail("list_role_policies", "AccessDenied")

    result = runner.invoke(app, ["analyze", arn, "--check", "all", "--no-banner"])
    rows = summary_rows(result.output)

    assert "PASS" not in rows["EGRESS"]
    assert "ERROR" in rows["EGRESS"]
    assert "0 findings" not in rows["EGRESS"]


def test_check_that_failed_downstream_is_also_not_pass(iam):
    """Mutation consumes egress, so a denied egress fails mutation too."""
    arn = iam.add_role("AgentRole", trust_policy=WILDCARD_TRUST)
    iam.fail("list_role_policies", "AccessDenied")

    rows = summary_rows(
        runner.invoke(app, ["analyze", arn, "--check", "all", "--no-banner"]).output
    )

    assert "ERROR" in rows["MUTATION"]
    assert "PASS" not in rows["MUTATION"]


def test_succeeding_check_still_reports_its_real_severity(iam):
    """The failure must not flatten the check that did work."""
    arn = iam.add_role("AgentRole", trust_policy=WILDCARD_TRUST)
    iam.fail("list_role_policies", "AccessDenied")

    rows = summary_rows(
        runner.invoke(app, ["analyze", arn, "--check", "all", "--no-banner"]).output
    )

    assert "CRIT" in rows["INGRESS"]
    assert "1 findings" in rows["INGRESS"]
    assert "ERROR" not in rows["INGRESS"]


def test_table_agrees_with_the_section_body(iam):
    """The two used to contradict each other."""
    arn = iam.add_role("AgentRole", trust_policy=WILDCARD_TRUST)
    iam.fail("list_role_policies", "AccessDenied")

    output = runner.invoke(
        app, ["analyze", arn, "--check", "all", "--no-banner"]
    ).output

    assert "Check failed" in output
    assert "ERROR" in summary_rows(output)["EGRESS"]


# =============================================================================
# UNCHANGED BEHAVIOR
# =============================================================================


def test_clean_run_still_reports_pass(iam):
    arn = iam.add_role(
        "Clean", inline={"p": {"Statement": [allow("s3:ListBucket", "arn:aws:s3:::b")]}}
    )

    rows = summary_rows(
        runner.invoke(app, ["analyze", arn, "--check", "all", "--no-banner"]).output
    )

    for section in ("INGRESS", "EGRESS", "MUTATION"):
        assert "PASS" in rows[section]
        assert "ERROR" not in rows[section]


def test_findings_run_still_reports_severity(iam):
    arn = iam.add_role("Admin", inline={"p": {"Statement": [allow("*")]}})

    rows = summary_rows(
        runner.invoke(app, ["analyze", arn, "--check", "egress", "--no-banner"]).output
    )

    assert "CRIT" in rows["EGRESS"]


def test_print_summary_without_check_errors_is_unchanged():
    """The parameter is optional; existing callers keep working."""
    without = render_summary(
        ingress_findings=[], egress_findings=[], mutation_findings=[]
    )
    with_empty = render_summary(
        ingress_findings=[], egress_findings=[], mutation_findings=[], check_errors={}
    )

    assert without == with_empty
    assert "PASS" in without


def test_print_summary_marks_only_the_named_checks():
    output = render_summary(
        ingress_findings=[{"severity": "HIGH"}],
        egress_findings=[],
        mutation_findings=[],
        check_errors={"egress": "Access denied"},
    )
    rows = summary_rows(output)

    assert "ERROR" in rows["EGRESS"]
    assert "HIGH" in rows["INGRESS"]
    assert "PASS" in rows["MUTATION"]
