"""Web-identity trust verdicts, through the CLI JSON seam.

An overbroad web-identity trust used to score LOW whenever *any* ``sub`` or
``aud`` key was present: an ``aud = sts.amazonaws.com`` condition (carried by
every GitHub token for AWS) or ``StringLike sub = "repo:*"`` (satisfied by
every workflow on GitHub) counted as "restricted". Cognito federated
principals were misclassified as AWS services.

This is the coarse fix (issue #7); full ``sub`` evaluation follows in #8.
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
                    "Token.Actions.GitHubUserContent.com:SUB": "repo:my-org/app:*"
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


PINNED = "repo:my-org/app:ref:refs/heads/main"


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
