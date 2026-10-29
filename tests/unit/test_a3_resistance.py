"""A3 §4.2 simulator mechanics (the AR families run once, recorded in evidence)."""

from __future__ import annotations

import datetime as dt
import random

from conftest import T0

from afw.domain.policy import RateProfile
from afw.ml import a3_resistance as ar
from afw.ml.experiments import LOGIN_BURST, LOGIN_RATE_PER_S, refused_logins


def test_limiter_agrees_with_the_replay_limiter():
    rng = random.Random(5)
    times = sorted(T0 + dt.timedelta(seconds=rng.uniform(0, 600)) for _ in range(200))
    ctl = [(T0, T0 + dt.timedelta(seconds=900), RateProfile.LOGIN_THROTTLE)]
    lim = ar.LimitReq(LOGIN_RATE_PER_S, LOGIN_BURST)
    assert [not lim.allow(t) for t in times] == refused_logins(times, ctl)


def test_four_typos_then_success_meets_no_control(lab_cfg):
    out = ar._loop(ar._A3(lab_cfg, {"/login"}), ar.friction_attempts(4, seed=1))
    assert out.controls == [] and out.refused == 0 and out.success_at_s is not None


def test_nothing_is_refused_before_the_first_decision(lab_cfg):
    arm = ar._A3(lab_cfg, {"/login"})
    out = ar._loop(arm, [(i * 0.1, "x", False) for i in range(40)])  # 40 in 4 s, no tick yet
    assert out.accepted == 40 and out.refused == 0
    assert arm.auth.failures_since(ar.SOURCE, ar.T0, ar.T0 + dt.timedelta(seconds=5)) == 40
