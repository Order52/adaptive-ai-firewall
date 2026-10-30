"""A3 attack resistance and login friction: SYNTHETIC, sequence level (protocol
``A3_AUTH_CONTROLS.md`` §4.2).

No traffic is sent. A scripted sequence of login attempts from one source is run in a
closed loop against the real A3 code (``AuthTracker``, the AUTH-only assessment,
``DecisionEngine`` with its login ladder) and the enforcement arithmetic of nginx
``limit_req``. An attempt refused by a control in force never reaches the application,
so it is not a failure and cannot feed escalation. Decisions run on the live tick (5 s).

The A2 baseline is modelled at its most favourable: a site-wide limit of 1 r/s, burst 5,
for 120 s, imposed at the first tick whose 30 s window holds >= 5 answered failures at
>= 50 %, and re-imposed whenever that recurs after it ends.

ML paths are left out of both arms, since they can only add protection: A3's numbers
are a lower bound on its protection and the baseline's an upper bound on A2's. These
results measure the controls' arithmetic and the decision logic, never detection of a
real attack tool.
"""

from __future__ import annotations

import random
from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta
from ipaddress import IPv4Address
from typing import Any

from afw.config import LabConfig
from afw.correlation.auth import AuthTracker
from afw.correlation.engine import CorrelationEngine
from afw.domain.events import AuthOutcome, HttpObservation
from afw.domain.policy import PolicyKind, RateProfile
from afw.ml.experiments import LOGIN_BURST, LOGIN_RATE_PER_S, _SourceTrack
from afw.policy.decision import DecisionEngine

SOURCE = IPv4Address("10.77.10.250")
T0 = datetime(2026, 10, 29, 12, 0, tzinfo=UTC)
TICK_S = 5.0
A2_WINDOW_S = 30.0
A2_MIN_FAILURES = 5
A2_FAIL_SHARE = 0.5
A2_RATE_PER_S = 1.0
A2_BURST = 5
A2_DURATION_S = 120.0
USER_RETRY_S = 10.0  # friction: a refused user tries the correct password again 10 s later
FRICTION_CAP_S = 7200.0

FAMILIES: dict[str, tuple[float, bool]] = {  # period s, new account per attempt
    "AR1": (1.0, False),
    "AR2": (20.0, False),
    "AR3": (1.0, True),
    "AR4": (60.0, True),
}
DURATION_S = 3600.0


class LimitReq:
    """nginx ``limit_req`` with ``nodelay`` for one key: ``excess = max(excess -
    rate*dt, 0) + 1``; refused if above the burst; a refused request leaves the state
    unchanged; the first request creates the key."""

    def __init__(self, rate_per_s: float, burst: int) -> None:
        self.rate, self.burst = rate_per_s, burst
        self.excess: float | None = None
        self.last: datetime | None = None

    def reset(self) -> None:
        self.excess, self.last = None, None

    def allow(self, t: datetime) -> bool:
        if self.excess is None or self.last is None:
            self.excess, self.last = 0.0, t
            return True
        new = max(self.excess - self.rate * (t - self.last).total_seconds(), 0.0) + 1.0
        if new > self.burst:
            return False
        self.excess, self.last = new, t
        return True


@dataclass
class Outcome:
    accepted: int = 0  # attempts answered by the application
    refused: int = 0
    first_control_s: float | None = None
    controls: list[dict[str, Any]] = field(default_factory=list)
    success_at_s: float | None = None  # friction only

    def as_dict(self) -> dict[str, Any]:
        return {
            "accepted": self.accepted,
            "refused": self.refused,
            "first_control_s": self.first_control_s,
            "controls": self.controls,
            "success_at_s": self.success_at_s,
        }


def _attempt(n: int, at: datetime, account: str, ok: bool) -> HttpObservation:
    return HttpObservation(
        event_id=f"syn{n}",
        request_id=f"syn{n}",
        app_id="rental",
        observed_at=at,
        client_ip=SOURCE,
        method="POST",
        path="/login",
        route="/login",
        status=200 if ok else 401,
        app_joined=True,
        reached_backend=True,
        auth_outcome=AuthOutcome.SUCCESS if ok else AuthOutcome.FAILURE,
        username_hash=account,
    )


class _A3:
    """The A3 loop: tracker, AUTH-only assessment, login ladder, login-route limiter."""

    def __init__(self, cfg: LabConfig, routes: set[str]) -> None:
        self.auth = AuthTracker(routes)
        self.corr = CorrelationEngine(cfg.risk, auth=self.auth)
        self.dec = DecisionEngine(cfg)
        self.track = _SourceTrack()
        self.limiter = LimitReq(LOGIN_RATE_PER_S, LOGIN_BURST)
        self.current: tuple[datetime, datetime, RateProfile] | None = None

    def tick(self, now: datetime, out: Outcome) -> None:
        self.auth.prune(now)
        ra = self.corr.assess_auth_only("rental", SOURCE, now)
        if ra is None:
            return
        login = self.track.login_context(now, self.auth, SOURCE)
        it = self.dec.decide(ra, 0, now, 0, login)
        if it is None or it.kind is not PolicyKind.LOGIN_CONTROL or it.rate_profile is None:
            return
        until = now + timedelta(seconds=it.duration_s or 0)
        if it.rate_profile is RateProfile.LOGIN_DENY:
            self.track.login = [(a, min(b, now), p) for a, b, p in self.track.login]
        self.track.login.append((now, until, it.rate_profile))
        out.controls.append(
            {
                "at_s": (now - T0).total_seconds(),
                "profile": it.rate_profile.value,
                "duration_s": it.duration_s,
            }
        )

    def allowed(self, t: datetime) -> bool:
        live = [c for c in self.track.login if c[0] <= t < c[1]]
        if not live:
            self.current = None
            self.limiter.reset()
            return True
        if any(c[2] is RateProfile.LOGIN_DENY for c in live):
            return False
        if live[-1] is not self.current:  # the WAF key exists only while throttled
            self.current = live[-1]
            self.limiter.reset()
        return self.limiter.allow(t)

    def answer(self, o: HttpObservation) -> None:
        self.auth.add(o)


class _A2:
    """The A2 baseline: window rule and a site-wide 1 r/s, burst 5 limit."""

    def __init__(self) -> None:
        self.answered: list[tuple[datetime, bool]] = []
        self.until: datetime | None = None
        self.limiter = LimitReq(A2_RATE_PER_S, A2_BURST)

    def tick(self, now: datetime, out: Outcome) -> None:
        if self.until is not None and now < self.until:
            return
        lo = now - timedelta(seconds=A2_WINDOW_S)
        recent = [ok for t, ok in self.answered if lo < t <= now]
        fails = sum(1 for ok in recent if not ok)
        if fails >= A2_MIN_FAILURES and fails / len(recent) >= A2_FAIL_SHARE:
            self.until = now + timedelta(seconds=A2_DURATION_S)
            self.limiter.reset()
            out.controls.append(
                {
                    "at_s": (now - T0).total_seconds(),
                    "profile": "strict_site_wide",
                    "duration_s": A2_DURATION_S,
                }
            )

    def allowed(self, t: datetime) -> bool:
        if self.until is None or t >= self.until:
            return True
        return self.limiter.allow(t)

    def answer(self, o: HttpObservation) -> None:
        self.answered.append((o.observed_at, o.auth_outcome is AuthOutcome.SUCCESS))


def _loop(arm: _A3 | _A2, attempts: list[tuple[float, str, bool]]) -> Outcome:
    """Run scripted (offset s, account, correct password) attempts. A refused correct
    attempt is retried every ``USER_RETRY_S`` until it is accepted (friction)."""
    out = Outcome()
    pending = sorted(attempts)
    tick = 0.0
    n = 0
    while pending:
        at, account, ok = pending.pop(0)
        if at > FRICTION_CAP_S:
            break
        while tick <= at:
            arm.tick(T0 + timedelta(seconds=tick), out)
            tick += TICK_S
        t = T0 + timedelta(seconds=at)
        if out.controls and out.first_control_s is None:
            out.first_control_s = out.controls[0]["at_s"]
        if not arm.allowed(t):
            out.refused += 1
            if ok:
                pending.append((at + USER_RETRY_S, account, ok))
                pending.sort()
            continue
        n += 1
        out.accepted += 1
        arm.answer(_attempt(n, t, account, ok))
        if ok and out.success_at_s is None:
            out.success_at_s = at
    if out.controls and out.first_control_s is None:
        out.first_control_s = out.controls[0]["at_s"]
    return out


def family_attempts(name: str) -> list[tuple[float, str, bool]]:
    period, spray = FAMILIES[name]
    n = int(DURATION_S / period)
    return [(i * period, f"acct{i}" if spray else "victim", False) for i in range(n)]


def friction_attempts(k: int, seed: int) -> list[tuple[float, str, bool]]:
    """A user who mistypes ``k`` times, 1-4 s apart, then enters the right password."""
    rng = random.Random(seed)
    t = 0.0
    out = []
    for _ in range(k):
        out.append((t, "user", False))
        t += rng.uniform(1.0, 4.0)
    out.append((t, "user", True))
    return out


def run(cfg: LabConfig, routes: set[str] | None = None) -> dict[str, Any]:
    routes = routes or {"/login"}
    report: dict[str, Any] = {"label": "SYNTHETIC", "families": {}, "friction": {}}
    for name in FAMILIES:
        attempts = family_attempts(name)
        a3 = _loop(_A3(cfg, routes), attempts)
        a2 = _loop(_A2(), attempts)
        report["families"][name] = {
            "raw": len(attempts),
            "a3": a3.as_dict() | {"accepted_share": round(a3.accepted / len(attempts), 4)},
            "a2_baseline": a2.as_dict() | {"accepted_share": round(a2.accepted / len(attempts), 4)},
        }
    for k in (4, 6, 8):
        attempts = friction_attempts(k, seed=k)
        report["friction"][f"k{k}"] = {
            "a3": _loop(_A3(cfg, routes), attempts).as_dict(),
            "a2_baseline": _loop(_A2(), attempts).as_dict(),
        }
    return report


CRITERIA = {"AR1": (0.25, 60.0), "AR2": (0.25, 300.0), "AR3": (0.25, 60.0), "AR4": (0.50, 600.0)}


def criterion5(report: dict[str, Any]) -> dict[str, Any]:
    """A3 §5 criterion 5, per family: accepted share, not worse than the baseline, time
    to first control."""
    out: dict[str, Any] = {}
    for name, (share, ttc) in CRITERIA.items():
        f = report["families"][name]
        a3, a2 = f["a3"], f["a2_baseline"]
        why = []
        if a3["accepted_share"] > share:
            why.append(f"accepted {a3['accepted_share']} > {share}")
        if a3["accepted"] > a2["accepted"]:
            why.append(f"accepted {a3['accepted']} > A2 baseline {a2['accepted']}")
        if a3["first_control_s"] is None or a3["first_control_s"] > ttc:
            why.append(f"first control {a3['first_control_s']} s > {ttc} s")
        out[name] = {"pass": not why, "why": why}
    out["pass"] = all(v["pass"] for v in out.values())
    return out
