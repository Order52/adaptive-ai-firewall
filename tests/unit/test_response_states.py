"""N6: response-policy states and the shared-address guard (ADR-043)."""

from __future__ import annotations

import datetime as dt
from ipaddress import IPv4Address

import pytest
from conftest import T0
from test_decision_behavior_only import AUTH, ML, STAT, ra

from afw.domain.events import AuthOutcome, HttpObservation
from afw.domain.policy import OperatingMode, PolicyKind, RateProfile
from afw.domain.risk import EvidenceCategory
from afw.policy.decision import DecisionEngine
from afw.policy.response import (
    SHARED_ADDRESS_GUARD,
    ResponseState,
    accounts_behind,
    response_state,
)
from afw.policy.validator import PolicyValidator

WAF = EvidenceCategory.WAF
SRC = IPv4Address("10.77.20.150")


@pytest.mark.parametrize(
    ("items", "cats", "state"),
    [
        ([(ML, 10.0)], [ML], ResponseState.NORMAL),
        ([(STAT, 20.0), (ML, 30.0)], [ML], ResponseState.UNFAMILIAR),
        ([(AUTH, 25.0), (ML, 25.0)], [AUTH], ResponseState.SUSPICIOUS),
        ([(AUTH, 30.0), (WAF, 30.0), (ML, 10.0)], [AUTH, WAF], ResponseState.STRONGLY_SUPPORTED),
        ([(AUTH, 30.0), (WAF, 30.0), (ML, 30.0)], [AUTH, WAF, ML], ResponseState.HIGH_RISK),
        # a high score from one category is not strong support
        ([(AUTH, 30.0), (ML, 35.0)], [AUTH], ResponseState.SUSPICIOUS),
    ],
)
def test_states(lab_cfg, items, cats, state):
    assert response_state(ra(items, cats), lab_cfg) is state


def test_every_intent_records_its_state(lab_cfg):
    it = DecisionEngine(lab_cfg).decide(ra([(AUTH, 25.0), (ML, 25.0)], [AUTH]), 0, T0)
    assert it is not None and "state:suspicious" in it.reason_codes


BLOCKABLE = ra([(AUTH, 30.0), (WAF, 30.0), (ML, 10.0)], [AUTH, WAF])


def test_block_on_a_private_address_is_unchanged(lab_cfg):
    it = DecisionEngine(lab_cfg).decide(BLOCKABLE, 0, T0, accounts_behind=1)
    assert it is not None and it.kind is PolicyKind.SOURCE_BLOCK


def test_shared_address_is_never_blocked_automatically(lab_cfg):
    it = DecisionEngine(lab_cfg).decide(BLOCKABLE, 0, T0, accounts_behind=5)
    assert it is not None and it.kind is PolicyKind.RATE_LIMIT
    assert it.rate_profile is RateProfile.STRICT
    assert SHARED_ADDRESS_GUARD in it.reason_codes and "accounts_behind_5" in it.reason_codes
    v = PolicyValidator(lab_cfg).validate(it, OperatingMode.AUTO, 0, T0)
    assert v.ok and not v.auto_eligible
    assert "shared address: requires human approval" in v.notes


def test_guard_does_not_touch_lower_responses(lab_cfg):
    low = ra([(AUTH, 25.0), (ML, 25.0)], [AUTH])
    it = DecisionEngine(lab_cfg).decide(low, 0, T0, accounts_behind=9)
    assert it is not None and SHARED_ADDRESS_GUARD not in it.reason_codes


def obs(i: int, user: str | None, outcome: AuthOutcome | None, age_s: float) -> HttpObservation:
    return HttpObservation(
        event_id=f"e{i}",
        request_id=f"r{i}",
        app_id="rental",
        observed_at=T0 - dt.timedelta(seconds=age_s),
        client_ip=SRC,
        method="POST",
        path="/login",
        route="/login",
        status=200,
        auth_outcome=outcome,
        username_hash=user,
    )


def test_accounts_behind_counts_recent_successful_distinct_accounts():
    hour = dt.timedelta(hours=1)
    ok, bad = AuthOutcome.SUCCESS, AuthOutcome.FAILURE
    evs = [
        obs(1, "u1", ok, 10),
        obs(2, "u1", ok, 20),  # same account twice
        obs(3, "u2", ok, 30),
        obs(4, "u3", bad, 40),  # failures do not prove a person is there
        obs(5, "u4", ok, 7200),  # too old
        obs(6, None, ok, 50),
    ]
    assert accounts_behind(evs, T0, hour) == 2
