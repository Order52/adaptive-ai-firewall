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
        resp.read()
        return resp.status, session
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


def _user(source: str, end: float, seed: int, counts: dict) -> None:
    rng = random.Random(seed)
    p = persona(rng)
    print(f"persona {source}: {p}", flush=True)
    time.sleep(rng.uniform(0, p["gap"]))  # users do not all start together
    while time.time() < end:
        try:
            journey(rng, source, p)
            counts[source] = counts.get(source, 0) + 1
        except Exception as exc:
            print(f"journey error from {source}: {exc}", flush=True)
        time.sleep(rng.expovariate(1 / p["gap"]))


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
