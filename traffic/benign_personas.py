#!/usr/bin/env python3
"""Benign legitimate-user traffic generator for the AFW lab (stdlib only).

Runs on a client guest (e.g. USR01) and performs *legitimate* user journeys
against the protected rental app through the WAF: browse cars, read reviews,
log in with valid credentials, view/make a booking, occasionally leave a
review, log out. It models normal variation — think-time, an occasional
mistyped password that is immediately corrected, a mix of browse-only and
authenticated sessions.

This is NOT an attack tool: it uses only valid app routes and valid
credentials, sends no injection/enumeration/brute-force patterns, and binds to
real local source addresses so the controller sees several ordinary users. Its
purpose is to produce *real* benign telemetry so the AI can learn a trusted
behavioural profile from genuine lab traffic (not synthetic fixtures).

Usage (on the guest):
    AFW_SOURCES=10.77.20.10,10.77.20.11 AFW_DURATION=300 python3 benign_personas.py

Modes (AFW_MODE):
    shared   one sequential loop; each session picks a random source (default,
             the original behaviour: per-source intensity falls as sources grow)
    personas one concurrent user per source, each with its own persona drawn
             from AFW_SEED: pacing, gaps between sessions, session depth,
             login habit and typo rate differ per user (realistic diversity)

Persona sets (AFW_PERSONA_SET, personas mode only):
    v1  the P1 personas (default; unchanged so P1 seeds stay reproducible)
    v2  P6 legitimate archetypes (casual, regular, forgetful, power, household,
        stale-link, slow reader, city searcher); AFW_ARCHETYPES=a,b restricts the
        draw. Still legitimate only: valid routes and credentials, at most 3
        mistyped passwords before the right one, an occasional outdated car link.
"""

from __future__ import annotations

import http.client
import json
import os
import random
import socket
import ssl
import time
from http.cookies import SimpleCookie

TARGET_IP = os.environ.get("AFW_TARGET_IP", "10.77.30.10")
TARGET_NAME = os.environ.get("AFW_TARGET_NAME", "rental.lab.afw")
CA = os.environ.get("AFW_LAB_CA", "/etc/afw/tls/lab-ca.pem")
SOURCES = [s for s in os.environ.get("AFW_SOURCES", "10.77.20.10").split(",") if s]
DURATION = float(os.environ.get("AFW_DURATION", "300"))
SEED = int(os.environ.get("AFW_SEED", "1"))
MODE = os.environ.get("AFW_MODE", "shared")
PERSONA_SET = os.environ.get("AFW_PERSONA_SET", "v1")
ARCHETYPES = [a for a in os.environ.get("AFW_ARCHETYPES", "").split(",") if a]
CITIES = ["Tripoli", "Benghazi", "Misrata", "Sabha"]
VALID_USERS = [(f"user{n}", f"pw-{n}") for n in range(1, 51)]

_ctx = ssl.create_default_context(cafile=CA)


def _request(
    source: str,
    method: str,
    path: str,
    cookie: str | None = None,
    body: dict | None = None,
) -> tuple[int, str | None]:
    """One HTTPS request bound to `source`; returns (status, set-cookie session)."""
    status, session, _ = _request_full(source, method, path, cookie, body)
    return status, session


def _request_full(
    source: str,
    method: str,
    path: str,
    cookie: str | None = None,
    body: dict | None = None,
) -> tuple[int, str | None, bytes]:
    """As ``_request``, also returning the response body."""
    # Bind the real source address, then set SNI/Host to the app hostname (matches
    # the lab cert and avoids CRS 920350 for a numeric Host).
    sock = socket.create_connection((TARGET_IP, 443), timeout=6.0, source_address=(source, 0))
    tls = _ctx.wrap_socket(sock, server_hostname=TARGET_NAME)
    conn = http.client.HTTPSConnection(TARGET_NAME, 443, timeout=6.0, context=_ctx)
    conn.sock = tls
    headers = {"Accept": "application/json"}
    payload = None
    if body is not None:
        payload = json.dumps(body)
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = f"session={cookie}"
    try:
        conn.request(method, path, body=payload, headers=headers)
        resp = conn.getresponse()
        session = None
        raw = resp.getheader("Set-Cookie")
        if raw:
            c = SimpleCookie()
            c.load(raw)
            if "session" in c:
                session = c["session"].value
        data = resp.read()
        return resp.status, session, data
    finally:
        conn.close()


DEFAULT_PERSONA = {
    "think": 1.0,
    "depth": 1,
    "auth": 0.65,
    "typo": 0.12,
    "book": 0.6,
    "review": 0.3,
    "user": None,
}


def persona(rng: random.Random) -> dict:
    """A legitimate user's habits (drawn once per user)."""
    return {
        "think": rng.choice([0.5, 1.0, 1.0, 2.0, 4.0]),  # reading speed multiplier
        "depth": rng.randint(1, 4),  # cars looked at per session
        "auth": rng.uniform(0.2, 0.95),
        "typo": rng.uniform(0.0, 0.15),
        "book": rng.uniform(0.2, 0.8),
        "review": rng.uniform(0.0, 0.4),
        "gap": rng.choice([2.0, 8.0, 30.0, 90.0]),  # mean seconds between sessions
        "user": rng.choice(VALID_USERS),  # a person mostly uses their own account
    }


def journey(rng: random.Random, source: str, p: dict = DEFAULT_PERSONA) -> None:
    """One legitimate user session."""
    t = p["think"]
    _request(source, "GET", "/")
    time.sleep(rng.uniform(0.3, 1.5) * t)
    _request(source, "GET", "/cars")
    time.sleep(rng.uniform(0.3, 1.5) * t)
    car_id = rng.randint(1, 40)
    for _ in range(p["depth"]):
        if rng.random() < 0.7:
            car_id = rng.randint(1, 40)
            _request(source, "GET", f"/cars/{car_id}")
            _request(source, "GET", f"/cars/{car_id}/reviews")
            time.sleep(rng.uniform(0.3, 1.2) * t)

    # Some sessions authenticate; the rest browse only.
    if rng.random() < p["auth"]:
        username, password = p["user"] or rng.choice(VALID_USERS)
        # Occasional mistyped password that the user immediately corrects.
        if rng.random() < p["typo"]:
            _request(source, "POST", "/login", body={"username": username, "password": "wrong"})
            time.sleep(rng.uniform(0.5, 1.5))
        _, session = _request(
            source, "POST", "/login", body={"username": username, "password": password}
        )
        if session:
            _request(source, "GET", "/bookings", cookie=session)
            time.sleep(rng.uniform(0.3, 1.2) * t)
            if rng.random() < p["book"]:
                _request(
                    source,
                    "POST",
                    "/booking",
                    cookie=session,
                    body={"car_id": car_id, "days": rng.randint(1, 7)},
                )
            if rng.random() < p["review"]:
                _request(
                    source,
                    "POST",
                    "/reviews",
                    cookie=session,
                    body={"car_id": car_id, "stars": rng.randint(3, 5), "text": "great car"},
                )
            _request(source, "POST", "/logout", cookie=session)


# P6 archetypes: name -> (draw weight, persona factory). Each is a kind of legitimate
# user the P1 personas did not cover; the values are habits, not attack parameters.
def _arch(rng: random.Random, name: str) -> dict:
    base = persona(rng)
    base.update({"archetype": name, "stale": 0.0, "max_typos": 1, "accounts": [base["user"]],
                 "city": 0.0, "detail": 0.3})
    match name:
        case "casual":  # mostly browsing, rarely logs in
            base.update(auth=rng.uniform(0.0, 0.25), depth=rng.randint(1, 3))
        case "regular":  # the P1 kind of user
            pass
        case "forgetful":  # often mistypes, retries up to 3 times, then succeeds
            base.update(typo=rng.uniform(0.3, 0.7), max_typos=3, auth=rng.uniform(0.6, 1.0))
        case "power":  # fast, deep sessions, books a lot (e.g. a fleet manager)
            base.update(think=rng.choice([0.25, 0.5]), depth=rng.randint(4, 8),
                        gap=rng.choice([2.0, 5.0]), auth=0.95, book=0.9, detail=0.8)
        case "household":  # one address, 2-4 people with their own accounts (home NAT)
            base.update(accounts=rng.sample(VALID_USERS, rng.randint(2, 4)), auth=0.8)
        case "stale":  # bookmarks to cars that no longer exist
            base.update(stale=rng.uniform(0.1, 0.3))
        case "slow":  # reads everything slowly, long pauses
            base.update(think=rng.choice([4.0, 6.0, 8.0]), gap=rng.choice([60.0, 120.0, 180.0]))
        case "city":  # filters the list by city before choosing
            base.update(city=rng.uniform(0.5, 1.0))
    return base


ARCHETYPE_WEIGHTS = {
    "casual": 3, "regular": 3, "forgetful": 1, "power": 1,
    "household": 1, "stale": 1, "slow": 1, "city": 1,
}


def persona_v2(rng: random.Random) -> dict:
    names = ARCHETYPES or list(ARCHETYPE_WEIGHTS)
    name = rng.choices(names, weights=[ARCHETYPE_WEIGHTS[n] for n in names])[0]
    return _arch(rng, name)


def journey_v2(rng: random.Random, source: str, p: dict) -> None:
    """One legitimate session of a P6 archetype."""
    t = p["think"]
    _request(source, "GET", "/")
    time.sleep(rng.uniform(0.3, 1.5) * t)
    if rng.random() < p["city"]:
        _request(source, "GET", f"/cars?city={rng.choice(CITIES)}")
    else:
        _request(source, "GET", "/cars")
    time.sleep(rng.uniform(0.3, 1.5) * t)
    car_id = rng.randint(1, 40)
    for _ in range(p["depth"]):
        if rng.random() < 0.7:
            if rng.random() < p["stale"]:
                _request(source, "GET", f"/cars/{rng.randint(41, 60)}")  # outdated link
                time.sleep(rng.uniform(0.5, 2.0) * t)
                continue
            car_id = rng.randint(1, 40)
            _request(source, "GET", f"/cars/{car_id}")
            _request(source, "GET", f"/cars/{car_id}/reviews")
            time.sleep(rng.uniform(0.3, 1.2) * t)
    if rng.random() >= p["auth"]:
        return
    username, password = rng.choice(p["accounts"])
    if rng.random() < p["typo"]:
        for _ in range(rng.randint(1, p["max_typos"])):
            _request(source, "POST", "/login", body={"username": username, "password": "wrong"})
            time.sleep(rng.uniform(1.0, 4.0))
    _, session = _request(source, "POST", "/login", body={"username": username, "password": password})
    if not session:
        return
    _request(source, "GET", "/bookings", cookie=session)
    time.sleep(rng.uniform(0.3, 1.2) * t)
    if rng.random() < p["book"]:
        status, _, data = _request_full(
            source, "POST", "/booking", cookie=session,
            # a valid body: v1 omits the required city, so every v1 booking is a 422
            body={"car_id": car_id, "days": rng.randint(1, 7),
                  "city": ["Tripoli", "Benghazi", "Misrata"][(car_id - 1) % 3]},
        )
        if status == 201 and rng.random() < p["detail"]:
            try:
                bid = json.loads(data).get("id")
            except ValueError:
                bid = None
            if bid is not None:
                time.sleep(rng.uniform(0.3, 1.0) * t)
                _request(source, "GET", f"/booking/{bid}", cookie=session)
    if rng.random() < p["review"]:
        _request(
            source, "POST", "/reviews", cookie=session,
            body={"car_id": car_id, "stars": rng.randint(3, 5), "text": "great car"},
        )
    _request(source, "POST", "/logout", cookie=session)


def _user(source: str, end: float, seed: int, counts: dict) -> None:
    rng = random.Random(seed)
    v2 = PERSONA_SET == "v2"
    p = persona_v2(rng) if v2 else persona(rng)
    print(f"persona {source}: {p}", flush=True)
    time.sleep(rng.uniform(0, p["gap"]))  # users do not all start together
    while time.time() < end:
        try:
            (journey_v2 if v2 else journey)(rng, source, p)
            counts[source] = counts.get(source, 0) + 1
        except Exception as exc:
            print(f"journey error from {source}: {exc}", flush=True)
        # never sleep past the end of the run (draw kept, so the sequence is unchanged)
        time.sleep(min(rng.expovariate(1 / p["gap"]), max(0.0, end - time.time())))


def main() -> None:
    if MODE == "personas":
        import threading

        end = time.time() + DURATION
        counts: dict = {}
        threads = [
            threading.Thread(target=_user, args=(s, end, SEED * 1000 + i, counts))
            for i, s in enumerate(SOURCES)
        ]
        for th in threads:
            th.start()
        for th in threads:
            th.join()
        print(
            f"done: {sum(counts.values())} legitimate sessions over {DURATION:.0f}s "
            f"from {len(SOURCES)} persona users: {counts}"
        )
        return
    rng = random.Random(SEED)
    end = time.time() + DURATION
    sent = 0
    while time.time() < end:
        source = rng.choice(SOURCES)
        try:
            journey(rng, source)
            sent += 1
        except Exception as exc:  # keep generating; report transient errors
            print(f"journey error from {source}: {exc}", flush=True)
        time.sleep(rng.expovariate(1 / 1.5))
    print(f"done: {sent} legitimate sessions over {DURATION:.0f}s from {len(SOURCES)} sources")


if __name__ == "__main__":
    main()
