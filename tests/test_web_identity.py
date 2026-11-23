"""Web-identity trust verdicts, through the CLI JSON seam.

An overbroad web-identity trust used to score LOW whenever *any* ``sub`` or
``aud`` key was present: an ``aud = sts.amazonaws.com`` condition (carried by
every GitHub token for AWS) or ``StringLike sub = "repo:*"`` (satisfied by
every workflow on GitHub) counted as "restricted". Cognito federated
principals were misclassified as AWS services.

Issue #7 fixed those verdicts; #8 rates a GitHub ``sub`` by who can satisfy
it: anyone on GitHub (CRITICAL), anyone in one org (HIGH), any ref in one
repository (MEDIUM), or a pinned ref or environment (LOW).
"""

import json

import pytest
from typer.testing import CliRunner

from iamwho.cli import app

from .conftest import ACCOUNT

runner = CliRunner()

GITHUB = f"arn:aws:iam::{ACCOUNT}:oidc-provider/token.actions.githubusercontent.com"
GITHUB_AUD = "token.actions.githubusercontent.com:aud"
GITHUB_SUB = "token.actions.githubusercontent.com:sub"
PINNED = "repo:my-org/app:ref:refs/heads/main"
ENVIRONMENT = "repo:my-org/app:environment:prod"


def web_identity_trust(federated, condition=None):
    statement = {
        "Effect": "Allow",
        "Principal": {"Federated": federated},
        "Action": "sts:AssumeRoleWithWebIdentity",
    }
    if condition is not None:
        statement["Condition"] = condition
    return {"Version": "2012-10-17", "Statement": [statement]}


def run_ingress(iam, trust_policy):
    arn = iam.add_role("Deploy", trust_policy=trust_policy)
    result = runner.invoke(app, ["analyze", arn, "--json", "--check", "ingress"])
    payload = json.loads(result.output)
    return result.exit_code, payload["checks"]["ingress"]["findings"]


def test_github_trust_with_only_aud_is_critical(iam):
    trust = web_identity_trust(
        GITHUB, {"StringEquals": {GITHUB_AUD: "sts.amazonaws.com"}}
    )

    exit_code, findings = run_ingress(iam, trust)

    assert [f["risk"] for f in findings] == ["CRITICAL"]
    assert exit_code == 2


def test_github_trust_with_no_conditions_is_critical(iam):
    exit_code, findings = run_ingress(iam, web_identity_trust(GITHUB))

    assert [f["risk"] for f in findings] == ["CRITICAL"]
    assert exit_code == 2


def test_github_trust_with_wildcard_only_sub_is_critical(iam):
    """``repo:*`` is satisfied by every workflow on GitHub."""
    trust = web_identity_trust(
        GITHUB,
        {
            "StringEquals": {GITHUB_AUD: "sts.amazonaws.com"},
            "StringLike": {GITHUB_SUB: "repo:*"},
        },
    )

    exit_code, findings = run_ingress(iam, trust)

    assert [f["risk"] for f in findings] == ["CRITICAL"]
    assert exit_code == 2


@pytest.mark.parametrize(
    "condition",
    [
        pytest.param(
            {"StringEquals": {GITHUB_SUB: "repo:my-org/app:ref:refs/heads/main"}},
            id="pinned-branch",
        ),
        pytest.param(
            {"StringEquals": {GITHUB_SUB: ENVIRONMENT}}, id="pinned-environment"
        ),
        pytest.param(
            {
                "StringEquals": {
                    GITHUB_AUD: "sts.amazonaws.com",
                    GITHUB_SUB: "repo:my-org/app:ref:refs/heads/main",
                }
            },
            id="pinned-branch-with-aud",
        ),
        pytest.param(
            {"StringEquals": {GITHUB_SUB: "repo:*"}},
            id="string-equals-is-literal",
        ),
        pytest.param(
            {
                "StringLike": {
                    "Token.Actions.GitHubUserContent.com:SUB": PINNED,
                }
            },
            id="key-name-case-insensitive",
        ),
    ],
)
def test_github_trust_with_scoped_sub_stays_low(iam, condition):
    exit_code, findings = run_ingress(iam, web_identity_trust(GITHUB, condition))

    assert [f["risk"] for f in findings] == ["LOW"]
    assert exit_code == 0


def test_one_broad_value_in_a_sub_list_makes_it_critical(iam):
    trust = web_identity_trust(
        GITHUB,
        {
            "StringLike": {
                GITHUB_SUB: ["repo:my-org/app:ref:refs/heads/main", "repo:*"],
            }
        },
    )

    exit_code, findings = run_ingress(iam, trust)

    assert [f["risk"] for f in findings] == ["CRITICAL"]
    assert exit_code == 2


@pytest.mark.parametrize(
    "condition",
    [
        pytest.param(
            {"StringLike": {GITHUB_SUB: "repo:my-org*"}},
            id="org-part-wildcard",  # matches the org my-org-evil
        ),
        pytest.param(
            {"StringLike": {GITHUB_SUB: "repo:my-or?/*"}},
            id="org-part-question-mark",
        ),
        pytest.param(
            {"StringNotLike": {GITHUB_SUB: "repo:evil-org/*"}},
            id="negated-operator",  # everyone except one org
        ),
        pytest.param(
            {"Null": {GITHUB_SUB: "false"}},
            id="null-false",  # only asserts the claim exists
        ),
        pytest.param(
            {"Null": {GITHUB_SUB: False}},
            id="null-false-bool",
        ),
        pytest.param(
            {"Null": {GITHUB_SUB: ["true", "false"]}},
            id="null-list-with-false",  # values are ORed
        ),
    ],
)
def test_github_sub_condition_that_does_not_pin_an_org_is_critical(iam, condition):
    exit_code, findings = run_ingress(iam, web_identity_trust(GITHUB, condition))

    assert [f["risk"] for f in findings] == ["CRITICAL"]
    assert exit_code == 2


def test_negated_sub_alongside_a_pinned_sub_stays_low(iam):
    """Condition blocks are ANDed: the pinned block alone scopes the trust."""
    trust = web_identity_trust(
        GITHUB,
        {
            "StringEquals": {GITHUB_SUB: "repo:my-org/app:ref:refs/heads/main"},
            "StringNotLike": {GITHUB_SUB: "repo:my-org/app:ref:refs/heads/dev*"},
        },
    )

    exit_code, findings = run_ingress(iam, trust)

    assert [f["risk"] for f in findings] == ["LOW"]
    assert exit_code == 0


@pytest.mark.parametrize(
    "condition",
    [
        # Null: true requires the claim to be absent; no GitHub token is.
        pytest.param({"Null": {GITHUB_SUB: "true"}}, id="null-true"),
        pytest.param({"Null": {GITHUB_SUB: True}}, id="null-true-bool"),
        # No string values: nothing a token's sub could match.
        pytest.param({"StringLike": {GITHUB_SUB: []}}, id="empty-value-list"),
        pytest.param({"StringEquals": {GITHUB_SUB: 42}}, id="non-string-value"),
        pytest.param(
            {"StringEquals": {GITHUB_SUB: [{"repo": "my-org"}]}},
            id="non-string-list",
        ),
        pytest.param({"ArnLike": {GITHUB_SUB: PINNED}}, id="unrecognised-operator"),
        pytest.param(
            {
                "ArnLike": {GITHUB_SUB: PINNED},
                "StringNotLike": {GITHUB_SUB: "repo:evil-org/*"},
            },
            id="unrecognised-operator-alongside-negation",
        ),
    ],
)
def test_github_sub_condition_iamwho_cannot_rate_is_not_evaluated(iam, condition):
    """Neither a false CRITICAL nor a reassuring LOW (ADR-0001)."""
    exit_code, findings = run_ingress(iam, web_identity_trust(GITHUB, condition))

    [finding] = findings
    assert finding["risk"] == "MEDIUM"
    assert any("not evaluated" in r for r in finding["reasons"])
    assert exit_code == 0


# =============================================================================
# SUBJECT TIERS: WHO CAN SATISFY THE PATTERN (#8)
# =============================================================================

ODD_CASE_SUB = "Token.Actions.GitHubUserContent.com:SUB"
GATE_EXIT = {"CRITICAL": 2, "HIGH": 1, "MEDIUM": 0}


def like(value, key=GITHUB_SUB):
    return {"StringLike": {key: value}}


def equals(value, key=GITHUB_SUB):
    return {"StringEquals": {key: value}}


# (overbroad condition, its tier, a tight counterpart that must stay LOW)
TIERS = [
    # CRITICAL: anyone on GitHub can register a matching org.
    pytest.param(like("repo:*"), "CRITICAL", like(PINNED), id="any-org"),
    pytest.param(
        like("repo:my-org*/*"), "CRITICAL", like(PINNED), id="org-part-wildcard"
    ),
    # HIGH: anyone who can push a workflow to a repository in the org. A
    # pinned ref does not lower it.
    pytest.param(like("repo:my-org/*"), "HIGH", like(PINNED), id="any-repo"),
    pytest.param(
        like("repo:my-org/*:ref:refs/heads/main"),
        "HIGH",
        like(PINNED),
        id="any-repo-pinned-ref",
    ),
    pytest.param(
        like("repo:my-org/app*"),  # matches my-org/app-evil
        "HIGH",
        like(PINNED),
        id="repo-prefix-no-colon",
    ),
    pytest.param(
        like("repo:my-org/ap?:*"),
        "HIGH",
        like(ENVIRONMENT),
        id="repo-name-question-mark",
    ),
    pytest.param(
        # Matches nothing under the default template, but a repo-only custom
        # template emits subjects without a context suffix.
        like("repo:my-org/ap?"),
        "HIGH",
        like(ENVIRONMENT),
        id="bare-repo-question-mark",
    ),
    pytest.param(
        like("repo:my-org/*", key=ODD_CASE_SUB),
        "HIGH",
        like(PINNED, key=ODD_CASE_SUB),
        id="key-name-case-insensitive",
    ),
    pytest.param(
        like([PINNED, ENVIRONMENT, "repo:my-org/*"]),
        "HIGH",
        like([PINNED, ENVIRONMENT]),
        id="broadest-value-in-list-wins",
    ),
    # MEDIUM: one repository, any ref.
    pytest.param(like("repo:my-org/app:*"), "MEDIUM", like(PINNED), id="any-ref"),
    pytest.param(
        like("repo:my-org/app:ref:refs/heads/*"),
        "MEDIUM",
        like(PINNED),
        id="any-branch",
    ),
    pytest.param(
        # Under a repo-only custom template this admits every ref.
        equals("repo:my-org/app"),
        "MEDIUM",
        equals(PINNED),
        id="literal-without-suffix",
    ),
    pytest.param(
        # Every pull_request workflow run in the repository.
        equals("repo:my-org/app:pull_request"),
        "MEDIUM",
        equals(PINNED),
        id="pull-request-context",
    ),
    pytest.param(
        # Assume the worst about a context iamwho doesn't know.
        equals("repo:my-org/app:job_workflow_ref:deploy.yml"),
        "MEDIUM",
        equals(ENVIRONMENT),
        id="unknown-context",
    ),
    pytest.param(
        equals("repo:my-org/app:ref:"),
        "MEDIUM",
        equals(PINNED),
        id="empty-ref",
    ),
    pytest.param(
        # IgnoreCase compares case-insensitively, so "Repo:" is "repo:".
        {"StringEqualsIgnoreCase": {GITHUB_SUB: "Repo:My-Org/App"}},
        "MEDIUM",
        {"StringEqualsIgnoreCase": {GITHUB_SUB: "Repo:My-Org/App:ref:refs/heads/main"}},
        id="ignore-case-literal-without-suffix",
    ),
]


@pytest.mark.parametrize("broad,tier,_tight", TIERS)
def test_github_sub_tier_reflects_who_can_satisfy_it(iam, broad, tier, _tight):
    exit_code, findings = run_ingress(iam, web_identity_trust(GITHUB, broad))

    [finding] = findings
    assert finding["risk"] == tier
    assert not any("not evaluated" in r for r in finding["reasons"])
    assert exit_code == GATE_EXIT[tier]


@pytest.mark.parametrize("_broad,_tier,tight", TIERS)
def test_tight_counterpart_of_each_broad_sub_is_low(iam, _broad, _tier, tight):
    exit_code, findings = run_ingress(iam, web_identity_trust(GITHUB, tight))

    assert [f["risk"] for f in findings] == ["LOW"]
    assert exit_code == 0


@pytest.mark.parametrize(
    "condition,tier",
    [
        pytest.param(
            {
                "StringLike": {GITHUB_SUB: "repo:my-org/*"},
                "StringEquals": {GITHUB_SUB: PINNED},
            },
            "LOW",
            id="any-repo-and-pinned",
        ),
        pytest.param(
            {
                "StringEquals": {GITHUB_SUB: PINNED},
                "StringLike": {GITHUB_SUB: "repo:my-org/*"},
            },
            "LOW",
            id="pinned-and-any-repo",  # block order doesn't matter
        ),
        pytest.param(
            {
                "StringLike": {GITHUB_SUB: "repo:my-org/*"},
                "StringEquals": {GITHUB_SUB: "repo:my-org/app:pull_request"},
            },
            "MEDIUM",
            id="any-repo-and-pull-request",
        ),
    ],
)
def test_narrowest_of_two_positive_sub_blocks_decides(iam, condition, tier):
    """Condition blocks are ANDed, so a token must satisfy both."""
    _, findings = run_ingress(iam, web_identity_trust(GITHUB, condition))

    [finding] = findings
    assert finding["risk"] == tier
    assert finding["subject_verdict"] == tier


def test_github_sub_values_are_not_lowercased(iam):
    """Globs are case-sensitive: ``REPO:*`` matches no GitHub subject, which
    always starts ``repo:``. Lowercasing it would make it CRITICAL."""
    _, findings = run_ingress(iam, web_identity_trust(GITHUB, like("REPO:*")))

    assert [f["risk"] for f in findings] != ["CRITICAL"]


@pytest.mark.parametrize(
    "condition,verdict,evaluated",
    [
        pytest.param(None, "CRITICAL", True, id="no-sub"),
        pytest.param(like("repo:my-org/*"), "HIGH", True, id="any-repo"),
        pytest.param(like("repo:my-org/app:*"), "MEDIUM", True, id="any-ref"),
        pytest.param(equals(PINNED), "LOW", True, id="pinned"),
        pytest.param(
            {"ArnLike": {GITHUB_SUB: PINNED}},
            "NOT_EVALUATED",
            False,
            id="unrecognised-operator",
        ),
    ],
)
def test_github_finding_reports_provider_and_subject_verdict(
    iam, condition, verdict, evaluated
):
    _, findings = run_ingress(iam, web_identity_trust(GITHUB, condition))

    [finding] = findings
    assert finding["provider"] == "github"
    assert finding["subject_verdict"] == verdict
    assert finding["subject_evaluated"] is evaluated


def test_subject_fields_leave_existing_fields_unchanged(iam):
    _, findings = run_ingress(iam, web_identity_trust(GITHUB, equals(PINNED)))

    [finding] = findings
    assert set(finding) == {
        "statement_id",
        "principal",
        "principal_type",
        "assume_type",
        "risk",
        "conditions",
        "reasons",
        "provider",
        "subject_verdict",
        "subject_evaluated",
    }
    assert finding["principal"] == GITHUB
    assert finding["principal_type"] == "FederatedOIDC"
    assert finding["assume_type"] == "AssumeRoleWithWebIdentity"
    assert finding["conditions"]["raw_conditions"] == equals(PINNED)


def test_non_github_findings_leave_subject_fields_unset(iam):
    """Other providers get their subject fields in #10."""
    _, findings = run_ingress(iam, web_identity_trust(EKS))

    [finding] = findings
    assert finding["provider"] is None
    assert finding["subject_verdict"] is None
    assert finding["subject_evaluated"] is None


def test_subject_evaluation_reads_only_the_trust_policy(iam):
    """Evaluation is offline: one get_role, nothing else."""
    run_ingress(iam, web_identity_trust(GITHUB, like([PINNED, "repo:my-org/*"])))

    assert iam.calls == ["get_role"]


# =============================================================================
# VERBOSE CONDITIONS LINE (text output; recorded seam exception in #8)
# =============================================================================


def verbose_conditions_line(iam, trust_policy):
    arn = iam.add_role("Deploy", trust_policy=trust_policy)
    result = runner.invoke(
        app, ["analyze", arn, "--check", "ingress", "-v", "--no-banner"]
    )
    lines = result.output.splitlines()
    [start] = [i for i, ln in enumerate(lines) if "Conditions:" in ln]
    # Rich wraps at the console width (80 here); rejoin up to the blank line
    # that ends the finding.
    wrapped = []
    for ln in lines[start:]:
        if not ln.strip():
            break
        wrapped.append(ln.strip())
    return " ".join(wrapped)


AUD_ONLY = {"StringEquals": {GITHUB_AUD: "sts.amazonaws.com"}}


def test_verbose_does_not_show_critical_github_conditions_as_scoping(iam):
    trust = web_identity_trust(
        GITHUB, {**AUD_ONLY, "StringLike": {GITHUB_SUB: "repo:*"}}
    )

    line = verbose_conditions_line(iam, trust)

    assert line == "Conditions: present, but they do not scope 'sub'"


def test_verbose_does_not_show_unevaluated_github_conditions_as_scoping(iam):
    trust = web_identity_trust(GITHUB, {**AUD_ONLY, "ArnLike": {GITHUB_SUB: PINNED}})

    line = verbose_conditions_line(iam, trust)

    assert line == "Conditions: present, but 'sub' was not evaluated"


def test_verbose_says_what_a_high_github_sub_still_admits(iam):
    trust = web_identity_trust(
        GITHUB, {**AUD_ONLY, "StringLike": {GITHUB_SUB: "repo:my-org/*"}}
    )

    line = verbose_conditions_line(iam, trust)

    assert line == "Conditions: present, but 'sub' admits any repository in the org"


def test_verbose_says_what_a_medium_github_sub_still_admits(iam):
    trust = web_identity_trust(
        GITHUB, {**AUD_ONLY, "StringLike": {GITHUB_SUB: "repo:my-org/app:*"}}
    )

    line = verbose_conditions_line(iam, trust)

    assert line == (
        "Conditions: present, but 'sub' admits more than a pinned ref or environment"
    )


def test_verbose_still_shows_low_github_conditions_as_present(iam):
    trust = web_identity_trust(
        GITHUB, {"StringEquals": {GITHUB_AUD: "sts.amazonaws.com", GITHUB_SUB: PINNED}}
    )

    line = verbose_conditions_line(iam, trust)

    assert line == "Conditions: present"
    assert "aud" not in line


# =============================================================================
# COGNITO
# =============================================================================


def test_cognito_is_federated_oidc_not_a_service(iam):
    """Cognito used to match the ``.amazonaws.com`` service rule and get a
    confused-deputy finding it can never satisfy."""
    trust = web_identity_trust(
        "cognito-identity.amazonaws.com",
        {
            "StringEquals": {
                "cognito-identity.amazonaws.com:aud": "us-east-1:pool-id",
            },
            "ForAnyValue:StringLike": {
                "cognito-identity.amazonaws.com:amr": "authenticated",
            },
        },
    )

    _, findings = run_ingress(iam, trust)

    [finding] = findings
    assert finding["principal_type"] == "FederatedOIDC"
    assert not any("confused deputy" in r.lower() for r in finding["reasons"])


# =============================================================================
# OTHER PROVIDERS: UNCHANGED UNTIL THEIR OWN TICKETS
# =============================================================================

EKS = (
    f"arn:aws:iam::{ACCOUNT}:oidc-provider/"
    "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE"
)
EKS_SUB = "oidc.eks.us-east-1.amazonaws.com/id/EXAMPLED539D4633E53DE1B71EXAMPLE:sub"
GITHUB_ENTERPRISE = f"{GITHUB}/my-enterprise"


@pytest.mark.parametrize(
    "federated,condition,expected_risk,expected_exit",
    [
        pytest.param(EKS, None, "HIGH", 1, id="eks-no-sub"),
        pytest.param(
            EKS,
            {"StringEquals": {EKS_SUB: "system:serviceaccount:app:deployer"}},
            "LOW",
            0,
            id="eks-with-sub",
        ),
        pytest.param(GITHUB_ENTERPRISE, None, "HIGH", 1, id="ghe-issuer-no-sub"),
    ],
)
def test_other_providers_keep_their_verdicts(
    iam, federated, condition, expected_risk, expected_exit
):
    trust = web_identity_trust(federated, condition)

    exit_code, findings = run_ingress(iam, trust)

    assert [f["risk"] for f in findings] == [expected_risk]
    assert exit_code == expected_exit
