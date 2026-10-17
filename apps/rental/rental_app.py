"""Protected test application: a small synthetic car-rental API.

Deployed on APP01 behind the WAF. All data is fake. It emits one JSON event per
request (route template, status, authentication outcome, version, WAF request
id) for the controller; passwords, tokens and bodies are never logged.

Version 2.0.0 (APP_VERSION) adds review endpoints — the legitimate behavioral
change used in Scenario C.

Identity rule: X-Request-ID / X-Real-IP are honored only when the TCP peer is
the configured WAF (TRUSTED_PROXY). Anything else is logged as untrusted.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import secrets
import time
from logging.handlers import WatchedFileHandler
from typing import Any

from fastapi import Cookie, FastAPI, HTTPException, Request, Response
from fastapi.routing import APIRoute
from pydantic import BaseModel, Field

APP_ID = "rental"
VERSION = os.environ.get("APP_VERSION", "1.0.0")
TRUSTED_PROXY = os.environ.get("TRUSTED_PROXY", "10.77.30.10")
EVENT_LOG = os.environ.get("EVENT_LOG", "/var/log/afw/app-events.log")
V2 = VERSION.startswith("2.")

event_log = logging.getLogger("afw.app.events")
event_log.setLevel(logging.INFO)
event_log.propagate = False
try:
    _h: logging.Handler = WatchedFileHandler(EVENT_LOG)  # rotation-safe for rsyslog imfile
except OSError:
    _h = logging.StreamHandler()
_h.setFormatter(logging.Formatter("%(message)s"))
event_log.addHandler(_h)

# ---------------------------------------------------------------- fake data
CARS = [
    {"id": i, "model": m, "daily_rate": 30 + (i * 7) % 90, "city": c}
    for i, (m, c) in enumerate(
        [
            (f"Model-{chr(65 + k % 26)}{k}", ["Tripoli", "Benghazi", "Misrata"][k % 3])
            for k in range(40)
        ],
        start=1,
    )
]
_SALT = b"afw-lab-static-salt"  # synthetic users only


def _pw_hash(pw: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), _SALT, 20_000).hex()


USERS = {f"user{n}": _pw_hash(f"pw-{n}") for n in range(1, 51)}
SESSIONS: dict[str, str] = {}
BOOKINGS: dict[int, dict[str, Any]] = {}
REVIEWS: dict[int, list[dict[str, Any]]] = {}

app = FastAPI(title="Rental (AFW protected app)", version=VERSION, docs_url=None, redoc_url=None)


def user_hash(username: str) -> str:
    return hashlib.sha256(f"afw:{username}".encode()).hexdigest()[:16]


@app.middleware("http")
async def telemetry(request: Request, call_next):  # type: ignore[no-untyped-def]
    peer = request.client.host if request.client else ""
    trusted = peer == TRUSTED_PROXY
    rid = request.headers.get("x-request-id", "") if trusted else ""
    request.state.auth = None
    request.state.user_h = None
    try:
        response = await call_next(request)
        status = response.status_code
    except Exception:
        status = 500
        raise
    finally:
        route = request.scope.get("route")
        template = route.path if isinstance(route, APIRoute) else "<unmatched>"
        event = {
            "type": "app_request",
            "rid": rid or None,
            "trusted_proxy": trusted,
            "app": APP_ID,
            "ver": VERSION,
            "route": template,
            "method": request.method,
            "status": status,
            "auth": request.state.auth,
            "user_h": request.state.user_h,
            "ts": round(time.time(), 6),
        }
        event_log.info(json.dumps(event, separators=(",", ":")))
    return response


class LoginBody(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=128)


class BookingBody(BaseModel):
    car_id: int = Field(ge=1, le=1000)
    days: int = Field(ge=1, le=30)
    city: str = Field(max_length=32)


class ReviewBody(BaseModel):
    car_id: int = Field(ge=1, le=1000)
    stars: int = Field(ge=1, le=5)
    text: str = Field(max_length=500)


def _session_user(session: str | None) -> str:
    user = SESSIONS.get(session or "")
    if user is None:
        raise HTTPException(401, "login required")
    return user


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok", "version": VERSION}


@app.get("/")
def index() -> dict[str, Any]:
    return {"app": "rental", "version": VERSION, "cars": len(CARS)}


@app.get("/cars")
def cars(city: str | None = None) -> list[dict[str, Any]]:
    return [c for c in CARS if city is None or c["city"] == city]


@app.get("/cars/{car_id}")
def car(car_id: int) -> dict[str, Any]:
    if not 1 <= car_id <= len(CARS):
        raise HTTPException(404, "no such car")
    return CARS[car_id - 1]


@app.post("/login")
def login(body: LoginBody, request: Request, response: Response) -> dict[str, str]:
    request.state.user_h = user_hash(body.username)
    expected = USERS.get(body.username)
    if expected is None or not secrets.compare_digest(expected, _pw_hash(body.password)):
        request.state.auth = "failure"
        raise HTTPException(401, "invalid credentials")
    request.state.auth = "success"
    token = secrets.token_urlsafe(24)
    SESSIONS[token] = body.username
    response.set_cookie("session", token, httponly=True, secure=True, samesite="strict")
    return {"status": "ok"}


@app.post("/logout")
def logout(session: str | None = Cookie(default=None)) -> dict[str, str]:
    SESSIONS.pop(session or "", None)
    return {"status": "bye"}


@app.get("/bookings")
def bookings(session: str | None = Cookie(default=None)) -> list[dict[str, Any]]:
    user = _session_user(session)
    return [b for b in BOOKINGS.values() if b["user"] == user]


@app.post("/booking", status_code=201)
def booking(body: BookingBody, session: str | None = Cookie(default=None)) -> dict[str, Any]:
    user = _session_user(session)
    if not 1 <= body.car_id <= len(CARS):
        raise HTTPException(404, "no such car")
    bid = len(BOOKINGS) + 1
    BOOKINGS[bid] = {"id": bid, "user": user, **body.model_dump()}
    return BOOKINGS[bid]


@app.get("/booking/{booking_id}")
def get_booking(booking_id: int, session: str | None = Cookie(default=None)) -> dict[str, Any]:
    user = _session_user(session)
    b = BOOKINGS.get(booking_id)
    if b is None or b["user"] != user:
        raise HTTPException(404, "not found")
    return b


if V2:

    @app.get("/cars/{car_id}/reviews")
    def reviews(car_id: int) -> list[dict[str, Any]]:
        return REVIEWS.get(car_id, [])

    @app.post("/reviews", status_code=201)
    def add_review(body: ReviewBody, session: str | None = Cookie(default=None)) -> dict[str, Any]:
        user = _session_user(session)
        item = {"user": user, **body.model_dump()}
        REVIEWS.setdefault(body.car_id, []).append(item)
        return item
