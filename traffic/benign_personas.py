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

Ordinary network activity besides the app (AFW_NET=1, NV1 protocol): each source
also gets a separate thread with its own random stream (the web journeys draw
exactly the same values with or without it) that does what a client on the USERS
segment legitimately does and the firewall allows: DNS lookups through public
resolvers (favourite and occasional new sites, plus the local-name lookups that
real machines leak, which answer NXDOMAIN), a visit to some looked-up sites
(HEAD / over HTTPS, rarely plain HTTP), NTP to the gateway, an occasional ping of
the gateway, and now and then an ``http://`` address typed for the app (port 80 is
closed, so the connection fails). Each user draws a light, normal or heavy habit.
No scanning, no guessing, nothing towards blocked lab zones.
"""

from __future__ import annotations

import http.client
import json
import os
import random
import socket
import ssl
import struct
import subprocess
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
NET = os.environ.get("AFW_NET", "0") == "1"
GATEWAY = os.environ.get("AFW_GATEWAY", "10.77.20.1")
CITIES = ["Tripoli", "Benghazi", "Misrata", "Sabha"]
# Review endpoints exist only in app 2.x. "auto" asks the app its version once, so
# legitimate users never request routes the deployed app does not serve (before
# 2026-10-28 every review request to the v1 app was a 404: 22-29 % of all generated
# legitimate requests, P6 amendment A2).
REVIEWS_SETTING = os.environ.get("AFW_APP_REVIEWS", "auto")
REVIEWS = REVIEWS_SETTING == "1"
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
            if REVIEWS:
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
            if rng.random() < p["review"] and REVIEWS:
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
    base.update(
        {
            "archetype": name,
            "stale": 0.0,
            "max_typos": 1,
            "accounts": [base["user"]],
            "city": 0.0,
            "detail": 0.3,
        }
    )
    match name:
        case "casual":  # mostly browsing, rarely logs in
            base.update(auth=rng.uniform(0.0, 0.25), depth=rng.randint(1, 3))
        case "regular":  # the P1 kind of user
            pass
        case "forgetful":  # often mistypes, retries up to 3 times, then succeeds
            base.update(typo=rng.uniform(0.3, 0.7), max_typos=3, auth=rng.uniform(0.6, 1.0))
        case "power":  # fast, deep sessions, books a lot (e.g. a fleet manager)
            base.update(
                think=rng.choice([0.25, 0.5]),
                depth=rng.randint(4, 8),
                gap=rng.choice([2.0, 5.0]),
                auth=0.95,
                book=0.9,
                detail=0.8,
            )
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
    "casual": 3,
    "regular": 3,
    "forgetful": 1,
    "power": 1,
    "household": 1,
    "stale": 1,
    "slow": 1,
    "city": 1,
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
            if REVIEWS:
                _request(source, "GET", f"/cars/{car_id}/reviews")
            time.sleep(rng.uniform(0.3, 1.2) * t)
    if rng.random() >= p["auth"]:
        return
    username, password = rng.choice(p["accounts"])
    if rng.random() < p["typo"]:
        for _ in range(rng.randint(1, p["max_typos"])):
            _request(source, "POST", "/login", body={"username": username, "password": "wrong"})
            time.sleep(rng.uniform(1.0, 4.0))
    _, session = _request(
        source, "POST", "/login", body={"username": username, "password": password}
    )
    if not session:
        return
    _request(source, "GET", "/bookings", cookie=session)
    time.sleep(rng.uniform(0.3, 1.2) * t)
    if rng.random() < p["book"]:
        status, _, data = _request_full(
            source,
            "POST",
            "/booking",
            cookie=session,
            # a valid body: v1 omits the required city, so every v1 booking is a 422
            body={
                "car_id": car_id,
                "days": rng.randint(1, 7),
                "city": ["Tripoli", "Benghazi", "Misrata"][(car_id - 1) % 3],
            },
        )
        if status == 201 and rng.random() < p["detail"]:
            try:
                bid = json.loads(data).get("id")
            except ValueError:
                bid = None
            if bid is not None:
                time.sleep(rng.uniform(0.3, 1.0) * t)
                _request(source, "GET", f"/booking/{bid}", cookie=session)
    if rng.random() < p["review"] and REVIEWS:
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


def _app_has_reviews(source: str) -> bool:
    status, _, data = _request_full(source, "GET", "/")
    try:
        version = str(json.loads(data).get("version", "")) if status == 200 else ""
    except ValueError:
        version = ""
    return version.startswith("2.")


# ------------------------------------------------------------- ordinary network use
RESOLVERS = ["1.1.1.1", "8.8.8.8"]
SITES = [
    "www.wikipedia.org", "www.debian.org", "www.python.org", "github.com",
    "www.mozilla.org", "ubuntu.com", "www.cloudflare.com", "example.com",
    "www.bbc.co.uk", "www.kernel.org", "pypi.org", "www.gnu.org",
    "www.openstreetmap.org", "stackoverflow.com", "www.apache.org", "nginx.org",
    "www.postgresql.org", "www.w3.org", "www.ietf.org", "www.rust-lang.org",
    "golang.org", "www.libreoffice.org", "www.gimp.org", "archive.org",
]
# names real machines ask public resolvers by mistake (search domains, discovery)
LOCAL_NAMES = ["wpad", "printer.home", "nas.lan", "router.home", "_ldap._tcp.dc.office",
               "fileserver.local.lan", "isatap", "laptop.home"]
NET_HABITS = {  # dns lookups/min, visit share, pings/h, typed http:// per h
    "light": ((0.2, 0.8), (0.3, 0.5), (0.0, 0.5), (0.0, 0.3)),
    "normal": ((0.8, 2.5), (0.4, 0.6), (0.0, 1.0), (0.0, 0.6)),
    "heavy": ((2.5, 6.0), (0.5, 0.7), (0.5, 2.0), (0.2, 1.0)),
}


def _dns(source: str, resolver: str, name: str, qtype: int = 1) -> tuple[int, str | None]:
    """One DNS query over UDP bound to ``source``; (rcode, first A address)."""
    qid = random.getrandbits(16)
    q = struct.pack(">HHHHHH", qid, 0x0100, 1, 0, 0, 0)
    q += b"".join(bytes([len(p)]) + p.encode() for p in name.rstrip(".").split(".")) + b"\0"
    q += struct.pack(">HH", qtype, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((source, 0))
        s.settimeout(3.0)
        s.sendto(q, (resolver, 53))
        data = s.recv(2048)
    rcode = data[3] & 0x0F
    an = struct.unpack(">H", data[6:8])[0]
    i = len(q)  # answers follow the echoed question
    for _ in range(an):
        if data[i] & 0xC0 == 0xC0:
            i += 2
        else:
            while data[i]:
                i += data[i] + 1
            i += 1
        rtype, _, _, rdlen = struct.unpack(">HHIH", data[i : i + 10])
        i += 10
        if rtype == 1 and rdlen == 4:
            return rcode, socket.inet_ntoa(data[i : i + 4])
        i += rdlen
    return rcode, None


def _visit(source: str, ip: str, name: str, tls: bool) -> None:
    sock = socket.create_connection((ip, 443 if tls else 80), timeout=6.0, source_address=(source, 0))
    try:
        if tls:
            sock = ssl.create_default_context().wrap_socket(sock, server_hostname=name)
        sock.sendall(f"HEAD / HTTP/1.1\r\nHost: {name}\r\nConnection: close\r\n\r\n".encode())
        sock.recv(512)
    finally:
        sock.close()


def _ntp(source: str) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.bind((source, 0))
        s.settimeout(3.0)
        s.sendto(b"\x23" + b"\0" * 47, (GATEWAY, 123))
        s.recv(128)


def _typed_http(source: str) -> None:
    """A user typing http:// for the app: port 80 is closed at the firewall."""
    try:
        socket.create_connection((TARGET_IP, 80), timeout=3.0, source_address=(source, 0)).close()
    except OSError:
        pass


def _net_user(source: str, end: float, seed: int, counts: dict) -> None:
    rng = random.Random(seed)
    habit = rng.choices(list(NET_HABITS), weights=[2, 3, 1])[0]
    (d0, d1), (v0, v1), (p0, p1), (h0, h1) = NET_HABITS[habit]
    dns_per_min, visit, pings_h, typed_h = (
        rng.uniform(d0, d1), rng.uniform(v0, v1), rng.uniform(p0, p1), rng.uniform(h0, h1)
    )
    resolver = rng.choice(RESOLVERS)
    favourites = rng.sample(SITES, rng.randint(4, 12))
    print(f"net {source}: {habit} dns/min={dns_per_min:.2f} visit={visit:.2f} "
          f"pings/h={pings_h:.2f} typed/h={typed_h:.2f} resolver={resolver}", flush=True)
    # one event stream: each activity's next time, exponential gaps
    rate = {"dns": dns_per_min / 60, "ntp": 1 / rng.uniform(256, 1024),
            "ping": pings_h / 3600, "typed": typed_h / 3600}
    nxt = {k: time.time() + (rng.expovariate(r) if r > 0 else 1e12) for k, r in rate.items()}
    while True:
        kind = min(nxt, key=nxt.get)
        if nxt[kind] >= end:
            return
        time.sleep(max(0.0, nxt[kind] - time.time()))
        nxt[kind] += rng.expovariate(rate[kind])
        try:
            if kind == "dns":
                r = rng.random()
                if r < 0.03:
                    _dns(source, resolver, rng.choice(LOCAL_NAMES))
                    continue
                name = rng.choice(favourites) if r < 0.85 else rng.choice(SITES)
                _, ip = _dns(source, resolver, name)
                if rng.random() < 0.3:
                    _dns(source, resolver, name, qtype=28)  # AAAA, as dual-stack clients do
                if ip and rng.random() < visit:
                    _visit(source, ip, name, tls=rng.random() < 0.95)
            elif kind == "ntp":
                _ntp(source)
            elif kind == "ping":
                subprocess.run(["ping", "-n", "-c", "1", "-W", "2", "-I", source, GATEWAY],
                               capture_output=True, timeout=5, check=False)
            else:
                _typed_http(source)
            counts[kind] = counts.get(kind, 0) + 1
        except (OSError, subprocess.SubprocessError, IndexError, struct.error) as exc:
            counts["error"] = counts.get("error", 0) + 1
            print(f"net error from {source} ({kind}): {exc}", flush=True)


def _start_net(end: float) -> list:
    import threading

    counts: dict = {}
    threads = [
        threading.Thread(target=_net_user, args=(s, end, SEED * 1000 + 500 + i, counts), daemon=True)
        for i, s in enumerate(SOURCES)
    ]
    for th in threads:
        th.start()
    return [threads, counts]


def main() -> None:
    global REVIEWS
    if REVIEWS_SETTING == "auto":
        REVIEWS = _app_has_reviews(SOURCES[0])
    state = "on" if REVIEWS else "off"
    print(f"app reviews: {state} (AFW_APP_REVIEWS={REVIEWS_SETTING})", flush=True)
    net = _start_net(time.time() + DURATION) if NET else None
    try:
        _web()
    finally:
        if net is not None:
            for th in net[0]:
                th.join()
            print(f"network activity: {net[1]}", flush=True)


def _web() -> None:
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
