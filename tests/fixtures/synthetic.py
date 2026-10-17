"""SYNTHETIC TEST FIXTURE — unit/integration tests only.

Generates plausible HttpObservation streams so the pipeline can be tested
without the lab. These data are never used for reported experimental results;
the evaluation uses captured GNS3 lab runs (see docs/AI_RESEARCH.md).
"""

from __future__ import annotations

import hashlib
import random
from datetime import datetime, timedelta
from ipaddress import IPv4Address

from afw.domain.events import AuthOutcome, HttpObservation

V1_PAGES = ["/", "/cars", "/cars/{car_id}", "/bookings", "/booking/{booking_id}"]
V2_PAGES = [*V1_PAGES, "/cars/{car_id}/reviews"]


def _obs(
    rng: random.Random,
    t: datetime,
    ip: str,
    method: str,
    route: str,
    status: int,
    *,
    auth: AuthOutcome | None = None,
    user: str | None = None,
    version: str = "1.0.0",
    waf_rules: tuple[int, ...] = (),
    blocked: bool = False,
    nbytes: int | None = None,
) -> HttpObservation:
    rid = f"{rng.getrandbits(64):016x}{rng.getrandbits(32):08x}"
    path = route.replace("{car_id}", str(rng.randint(1, 40))).replace(
        "{booking_id}", str(rng.randint(1, 500))
    )
    return HttpObservation(
        event_id=f"obs-{rid[:12]}",
        request_id=rid,
        app_id="rental",
        observed_at=t,
        client_ip=IPv4Address(ip),
        method=method,
        path=path,
        route=route,
        status=status,
        bytes_in=nbytes or rng.randint(350, 700),
        bytes_out=rng.randint(500, 4000),
        duration_ms=rng.uniform(3, 30),
        waf_rule_ids=waf_rules,
        waf_anomaly_score=5 * len(waf_rules),
        waf_blocked=blocked,
        app_joined=not blocked,
        auth_outcome=auth,
        username_hash=hashlib.sha256(user.encode()).hexdigest()[:16] if user else None,
        app_version=None if blocked else version,
        reached_backend=not blocked,
    )


def benign_user(
    rng: random.Random, ip: str, start: datetime, duration_s: float, *, v2: bool = False
) -> list[HttpObservation]:
    out: list[HttpObservation] = []
    t = start + timedelta(seconds=rng.uniform(0, 5))
    end = start + timedelta(seconds=duration_s)
    user = f"user{rng.randint(1, 50)}"
    version = "2.0.0" if v2 else "1.0.0"
    pages = V2_PAGES if v2 else V1_PAGES
    while t < end:
        r = rng.random()
        if r < 0.08:
            ok = rng.random() > 0.08
            out.append(
                _obs(
                    rng,
                    t,
                    ip,
                    "POST",
                    "/login",
                    200 if ok else 401,
                    auth=AuthOutcome.SUCCESS if ok else AuthOutcome.FAILURE,
                    user=user,
                    version=version,
                )
            )
        elif r < 0.14:
            out.append(_obs(rng, t, ip, "POST", "/booking", 201, version=version, nbytes=900))
        elif v2 and r < 0.22:
            out.append(_obs(rng, t, ip, "POST", "/reviews", 201, version=version, nbytes=800))
        else:
            out.append(_obs(rng, t, ip, "GET", rng.choice(pages), 200, version=version))
        t += timedelta(seconds=rng.expovariate(1 / 2.5))
    return out


def brute_force(
    rng: random.Random, ip: str, start: datetime, duration_s: float, rate: float = 4.0
) -> list[HttpObservation]:
    out = []
    t = start
    while t < start + timedelta(seconds=duration_s):
        user = f"user{rng.randint(1, 200)}"
        out.append(_obs(rng, t, ip, "POST", "/login", 401, auth=AuthOutcome.FAILURE, user=user))
        t += timedelta(seconds=rng.expovariate(rate))
    return out


def sqli_probe(rng: random.Random, ip: str, start: datetime, n: int = 12) -> list[HttpObservation]:
    return [
        _obs(
            rng,
            start + timedelta(seconds=i * 1.5),
            ip,
            "GET",
            "/cars",
            403,
            waf_rules=(942100, 942190, 949110),
            blocked=True,
        )
        for i in range(n)
    ]


def traffic(
    seed: int,
    start: datetime,
    duration_s: float,
    benign_ips: list[str],
    attack: dict[str, str] | None = None,
    v2_ips: list[str] | None = None,
) -> list[HttpObservation]:
    rng = random.Random(seed)
    obs: list[HttpObservation] = []
    for ip in benign_ips:
        obs += benign_user(rng, ip, start, duration_s)
    for ip in v2_ips or []:
        obs += benign_user(rng, ip, start, duration_s, v2=True)
    for ip, kind in (attack or {}).items():
        at = start + timedelta(seconds=duration_s / 3)
        if kind == "bruteforce":
            obs += brute_force(rng, ip, at, duration_s / 3)
        elif kind == "sqli":
            obs += sqli_probe(rng, ip, at)
    return sorted(obs, key=lambda o: o.observed_at)
