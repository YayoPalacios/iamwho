"""Tests for the RiskLevel enum.

RiskLevel defines __eq__ for value comparison, which makes Python set
__hash__ to None. Any set of risk levels, or any dict keyed by one — the
obvious way to group findings by severity — raised
``TypeError: unhashable type: 'RiskLevel'``.
"""

import pytest

from iamwho.models import (
    AssumeType,
    ConditionAnalysis,
    PrincipalType,
    RiskLevel,
    TrustFinding,
)


def finding(risk: RiskLevel) -> TrustFinding:
    return TrustFinding(
        statement_id=None,
        principal="*",
        principal_type=PrincipalType.WILDCARD,
        assume_type=AssumeType.ASSUME_ROLE,
        risk=risk,
        conditions=ConditionAnalysis(),
    )


# =============================================================================
# HASHABILITY
# =============================================================================


def test_risk_levels_go_in_a_set():
    assert {RiskLevel.HIGH, RiskLevel.LOW, RiskLevel.HIGH} == {
        RiskLevel.HIGH,
        RiskLevel.LOW,
    }


def test_risk_levels_key_a_dict():
    counts = {level: 0 for level in RiskLevel}
    counts[RiskLevel.CRITICAL] += 1

    assert counts[RiskLevel.CRITICAL] == 1


def test_findings_group_by_risk():
    """The shape fixture assertions want."""
    findings = [
        finding(RiskLevel.HIGH),
        finding(RiskLevel.LOW),
        finding(RiskLevel.HIGH),
    ]

    grouped: dict[RiskLevel, int] = {}
    for f in findings:
        grouped[f.risk] = grouped.get(f.risk, 0) + 1

    assert grouped == {RiskLevel.HIGH: 2, RiskLevel.LOW: 1}


def test_equal_levels_hash_equal():
    assert hash(RiskLevel.HIGH) == hash(RiskLevel("HIGH"))


def test_hash_is_consistent_with_equality():
    for level in RiskLevel:
        other = RiskLevel(level.value)
        assert level == other
        assert hash(level) == hash(other)


# =============================================================================
# EXISTING BEHAVIOR IS UNCHANGED
# =============================================================================


def test_ordering_still_works():
    assert RiskLevel.CRITICAL > RiskLevel.HIGH > RiskLevel.MEDIUM
    assert RiskLevel.LOW > RiskLevel.INFO


def test_levels_order_by_severity_not_alphabetically():
    """Alphabetically, HIGH < INFO < LOW < MEDIUM; by severity it's the reverse
    for most of them."""
    shuffled = [
        RiskLevel.MEDIUM,
        RiskLevel.CRITICAL,
        RiskLevel.INFO,
        RiskLevel.HIGH,
        RiskLevel.LOW,
    ]

    assert sorted(shuffled) == [
        RiskLevel.INFO,
        RiskLevel.LOW,
        RiskLevel.MEDIUM,
        RiskLevel.HIGH,
        RiskLevel.CRITICAL,
    ]


def test_min_picks_the_lowest_risk():
    """ingress uses min() over ANDed sub blocks: the narrowest one decides."""
    assert min([RiskLevel.HIGH, RiskLevel.LOW]) == RiskLevel.LOW
    assert min([RiskLevel.HIGH, RiskLevel.MEDIUM]) == RiskLevel.MEDIUM


def test_max_picks_the_highest_risk():
    """ingress uses max() over finding risks."""
    levels = [RiskLevel.LOW, RiskLevel.CRITICAL, RiskLevel.MEDIUM]

    assert max(levels) == RiskLevel.CRITICAL


def test_comparison_with_a_non_risk_level_is_not_an_error():
    assert RiskLevel.HIGH != "HIGH"
    with pytest.raises(TypeError):
        RiskLevel.HIGH < "HIGH"
