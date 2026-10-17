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


def journey(rng: random.Random, source: str) -> None:
    """One legitimate user session."""
    _request(source, "GET", "/")
    time.sleep(rng.uniform(0.3, 1.5))
    _request(source, "GET", "/cars")
    time.sleep(rng.uniform(0.3, 1.5))
    car_id = rng.randint(1, 40)
    if rng.random() < 0.7:
        _request(source, "GET", f"/cars/{car_id}")
        _request(source, "GET", f"/cars/{car_id}/reviews")
        time.sleep(rng.uniform(0.3, 1.2))

    # ~65% of sessions authenticate; the rest browse only.
    if rng.random() < 0.65:
        username, password = rng.choice(VALID_USERS)
        # Occasional mistyped password that the user immediately corrects.
        if rng.random() < 0.12:
            _request(source, "POST", "/login", body={"username": username, "password": "wrong"})
            time.sleep(rng.uniform(0.5, 1.5))
        _, session = _request(
            source, "POST", "/login", body={"username": username, "password": password}
        )
        if session:
            _request(source, "GET", "/bookings", cookie=session)
            time.sleep(rng.uniform(0.3, 1.2))
            if rng.random() < 0.6:
                _request(
                    source,
                    "POST",
                    "/booking",
                    cookie=session,
                    body={"car_id": car_id, "days": rng.randint(1, 7)},
                )
            if rng.random() < 0.3:
                _request(
                    source,
                    "POST",
                    "/reviews",
                    cookie=session,
                    body={"car_id": car_id, "stars": rng.randint(3, 5), "text": "great car"},
                )
            _request(source, "POST", "/logout", cookie=session)


def main() -> None:
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
