"""A3: account-aware AUTH evidence and endpoint-scoped login controls (ADR-044)."""

from __future__ import annotations

import datetime as dt
from ipaddress import IPv4Address

import pytest
from conftest import T0
from test_decision_behavior_only import AUTH, ML, ra

from afw.correlation.auth import AuthTracker
from afw.correlation.engine import CorrelationEngine
from afw.domain.events import AuthOutcome, HttpObservation
from afw.domain.policy import OperatingMode, PolicyKind, RateProfile
from afw.domain.risk import EvidenceCategory
from afw.ml.experiments import refused_logins
from afw.policy.decision import DecisionEngine, LoginContext
from afw.policy.validator import PolicyValidator

SRC = IPv4Address("10.77.20.150")
WAF = EvidenceCategory.WAF
_n = 0


def login(at: float, user: str | None = "alice", ok: bool = False, status: int | None = None):
    """One POST /login at T0 + ``at`` s; ``status`` 429/403: refused by the WAF."""
    global _n
    _n += 1
    refused = status in (403, 429)
    return HttpObservation(
        event_id=f"e{_n}",
        request_id=f"r{_n}",
        app_id="rental",
        observed_at=T0 + dt.timedelta(seconds=at),
        client_ip=SRC,
        method="POST",
        path="/login",
        route="/login",
        status=status or (200 if ok else 401),
        app_joined=not refused,
        reached_backend=not refused,
        auth_outcome=None if refused else (AuthOutcome.SUCCESS if ok else AuthOutcome.FAILURE),
        username_hash=None if refused else user,
    )


def tracker(*obs: HttpObservation) -> AuthTracker:
    t = AuthTracker({"/login"})
    for o in obs:
        t.add(o)
    return t


def codes(t: AuthTracker, at: float) -> list[str]:
    return [e.code for e in t.evidence(SRC, T0 + dt.timedelta(seconds=at))]


# --------------------------------------------------------------- evidence
def test_typos_followed_by_a_login_build_no_evidence():
    # the P7 forgetful user: two quick logins with 3 typos each, 6 failures in 30 s
    ev = [login(i) for i in range(3)] + [login(4, ok=True)]
    ev += [login(10 + i) for i in range(3)] + [login(14, ok=True)]
    assert codes(tracker(*ev), 20) == []


def test_five_failures_on_one_account_is_guessing():
    t = tracker(*[login(i * 2) for i in range(5)])
    (item,) = t.evidence(SRC, T0 + dt.timedelta(seconds=10))
    assert item.code == "account_guessing" and item.points == 15.0
    assert item.category is EvidenceCategory.AUTH


def test_slow_guessing_is_seen_across_windows():
    t = tracker(*[login(i * 20) for i in range(8)])  # one guess every 20 s
    assert codes(t, 61) == []  # 4 failures so far
    assert codes(t, 81) == ["account_guessing"]
    assert codes(t, 141)[0] == "account_guessing"


def test_evidence_needs_recent_activity_and_expires():
    t = tracker(*[login(i) for i in range(6)])
    assert codes(t, 10) == ["account_guessing"]
    assert codes(t, 60) == []  # nothing in the last 30 s
    t.add(login(1000))
    assert codes(t, 1001) == []  # the earlier streak is outside the 900 s lookback


def test_spraying_three_accounts():
    t = tracker(login(0, "a"), login(1, "b"), login(2, "c"), login(3, "a"), login(4, "d"))
    assert codes(t, 5) == ["credential_spraying"]


def test_success_after_guessing_is_evidence():
    t = tracker(*[login(i) for i in range(6)], login(7, ok=True))
    (item,) = t.evidence(SRC, T0 + dt.timedelta(seconds=8))
    assert item.code == "success_after_guessing" and item.points == 25.0


def test_refused_requests_and_missing_usernames():
    t = tracker(*[login(i, status=429) for i in range(20)])
    assert codes(t, 21) == []  # refused attempts never reached the application
    t = tracker(*[login(i, user=None) for i in range(5)])
    assert codes(t, 6) == ["account_guessing"]  # missing telemetry cannot hide guessing


def test_failures_since_counts_answered_failures_only():
    t = tracker(*[login(i) for i in range(4)], login(5, status=429), login(6, ok=True))
    assert t.failures_since(SRC, T0, T0 + dt.timedelta(seconds=10)) == 4


def test_engine_uses_the_tracker_and_has_an_auth_only_view(lab_cfg):
    t = tracker(*[login(i * 20) for i in range(6)])
    eng = CorrelationEngine(lab_cfg.risk, auth=t)
    r = eng.assess_auth_only("rental", SRC, T0 + dt.timedelta(seconds=101))
    assert r is not None and r.view == "auth_only"
    assert r.corroborating_categories == (EvidenceCategory.AUTH,)
    assert eng.assess_auth_only("rental", SRC, T0 + dt.timedelta(seconds=500)) is None


# --------------------------------------------------------------- ladder
AUTH_ONLY = ra([(AUTH, 15.0)], [AUTH])
AUTH_ML = ra([(AUTH, 25.0), (ML, 30.0)], [AUTH])  # dependent behaviour points


def decide(lab_cfg, a=AUTH_ONLY, accounts=0, **ctx):
    return DecisionEngine(lab_cfg).decide(a, 0, T0, accounts, LoginContext(**ctx))


def test_first_response_is_a_login_throttle_never_a_site_wide_limit(lab_cfg):
    for a in (AUTH_ONLY, AUTH_ML):
        it = decide(lab_cfg, a)
        assert it is not None and it.kind is PolicyKind.LOGIN_CONTROL
        assert it.rate_profile is RateProfile.LOGIN_THROTTLE and it.duration_s == 900
        assert "login_scope_only" in it.reason_codes


def test_without_login_context_the_a2_behaviour_is_kept(lab_cfg):
    it = DecisionEngine(lab_cfg).decide(AUTH_ML, 0, T0)
    assert it is not None and it.kind is PolicyKind.RATE_LIMIT


def test_throttle_then_deny_on_persistence(lab_cfg):
    t = RateProfile.LOGIN_THROTTLE
    assert decide(lab_cfg, active=t, failures_since=9) is None
    it = decide(lab_cfg, active=t, failures_since=10)
    assert it is not None and it.rate_profile is RateProfile.LOGIN_DENY and it.duration_s == 900
    assert decide(lab_cfg, active=RateProfile.LOGIN_DENY, failures_since=50) is None


@pytest.mark.parametrize(("repeats", "duration"), [(1, 900), (2, 1800), (3, 3600), (6, 3600)])
def test_repeat_offender_is_denied_with_growing_duration(lab_cfg, repeats, duration):
    it = decide(lab_cfg, recent_repeats=repeats)
    assert it is not None and it.rate_profile is RateProfile.LOGIN_DENY
    assert it.duration_s == duration


def test_other_independent_evidence_keeps_the_block_path(lab_cfg):
    both = ra([(AUTH, 30.0), (WAF, 30.0), (ML, 10.0)], [AUTH, WAF])
    it = decide(lab_cfg, both)
    assert it is not None and it.kind is PolicyKind.SOURCE_BLOCK


def test_waf_evidence_below_block_keeps_the_site_wide_limit(lab_cfg):
    it = decide(lab_cfg, ra([(AUTH, 20.0), (WAF, 30.0)], [AUTH, WAF]))
    assert it is not None and it.kind is PolicyKind.RATE_LIMIT


def test_validator_bounds(lab_cfg):
    v = PolicyValidator(lab_cfg)
    thr = decide(lab_cfg)
    deny = decide(lab_cfg, recent_repeats=3)
    shared_deny = decide(lab_cfg, accounts=5, recent_repeats=1)
    assert thr is not None and deny is not None and shared_deny is not None
    assert v.validate(thr, OperatingMode.AUTO, 0, T0).auto_eligible
    assert v.validate(deny, OperatingMode.AUTO, 0, T0).auto_eligible  # 3600 s
    r = v.validate(shared_deny, OperatingMode.AUTO, 0, T0)
    assert r.ok and not r.auto_eligible and "shared address: requires human approval" in r.notes
    shared_thr = decide(lab_cfg, accounts=5)
    assert (
        shared_thr is not None and v.validate(shared_thr, OperatingMode.AUTO, 0, T0).auto_eligible
    )
    bad = thr.model_copy(update={"rate_profile": RateProfile.STRICT})
    assert not v.validate(bad, OperatingMode.AUTO, 0, T0).ok


# --------------------------------------------------------------- limiter
def ts(*secs: float) -> list[dt.datetime]:
    return [T0 + dt.timedelta(seconds=s) for s in secs]


def test_limiter_matches_nginx_limit_req():
    thr = [(T0, T0 + dt.timedelta(seconds=900), RateProfile.LOGIN_THROTTLE)]
    # 1 + burst 4 at once, then one per 20 s
    assert refused_logins(ts(0, 0, 0, 0, 0, 0), thr) == [False] * 5 + [True]
    assert refused_logins(ts(0, 0, 0, 0, 0, 20, 21), thr) == [False] * 6 + [True]
    deny = [(T0, T0 + dt.timedelta(seconds=900), RateProfile.LOGIN_DENY)]
    assert refused_logins(ts(1, 2, 1000), deny) == [True, True, False]
    assert refused_logins(ts(1, 2), []) == [False, False]


# --------------------------------------------------------------- live runtime
def test_runtime_assesses_a_slow_guesser_without_any_http_window(settings):
    """One attempt every 20 s never fills a window (>= 3 requests in 30 s); the
    AUTH-only view still assesses it and proposes a login throttle."""
    from conftest import FakeClock

    from afw.container import build_container

    c = build_container(settings, simulated=True)
    clock = FakeClock(T0)
    c.policy_service.clock = clock
    c.controller.clock = clock
    guesser = IPv4Address("10.77.10.23")
    t = T0
    for i in range(10):
        o = login(i * 20.0).model_copy(update={"client_ip": guesser})
        while o.observed_at > t:
            c.controller.tick(t)
            t += dt.timedelta(seconds=1)
            clock.now = t
        c.controller.ingest_observations([o])
    c.controller.tick(t)
    mine = [p for p in c.policies_repo.recent(100) if p.intent.target.source_ip == guesser]
    assert mine and all(p.kind is PolicyKind.LOGIN_CONTROL for p in mine)
    assert mine[-1].intent.rate_profile is RateProfile.LOGIN_THROTTLE
    assert c.stats.snapshot()["counts"]["auth_only_assessment"] >= 1
