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
from store import make_store, pw_hash

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

# ------------------------------------------------------- data store (3-tier)
# Business data (catalogue, users, bookings, reviews) lives in the DB tier when
# DATABASE_URL is set (PostgreSQL on DB01, its own zone), else in-memory for
# tests/offline. Sessions are ephemeral auth state and stay in the app process.
STORE = make_store()
SESSIONS: dict[str, str] = {}

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
    return {"app": "rental", "version": VERSION, "cars": STORE.car_count()}


@app.get("/cars")
def cars(city: str | None = None) -> list[dict[str, Any]]:
    return STORE.cars(city)


@app.get("/cars/{car_id}")
def car(car_id: int) -> dict[str, Any]:
    c = STORE.car(car_id)
    if c is None:
        raise HTTPException(404, "no such car")
    return c


@app.post("/login")
def login(body: LoginBody, request: Request, response: Response) -> dict[str, str]:
    request.state.user_h = user_hash(body.username)
    expected = STORE.user_pw_hash(body.username)
    if expected is None or not secrets.compare_digest(expected, pw_hash(body.password)):
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
    return STORE.bookings(user)


@app.post("/booking", status_code=201)
def booking(body: BookingBody, session: str | None = Cookie(default=None)) -> dict[str, Any]:
    user = _session_user(session)
    if STORE.car(body.car_id) is None:
        raise HTTPException(404, "no such car")
    return STORE.add_booking(user, body.car_id, body.days, body.city)


@app.get("/booking/{booking_id}")
def get_booking(booking_id: int, session: str | None = Cookie(default=None)) -> dict[str, Any]:
    user = _session_user(session)
    b = STORE.booking(booking_id, user)
    if b is None:
        raise HTTPException(404, "not found")
    return b


if V2:

    @app.get("/cars/{car_id}/reviews")
    def reviews(car_id: int) -> list[dict[str, Any]]:
        return STORE.reviews(car_id)

    @app.post("/reviews", status_code=201)
    def add_review(body: ReviewBody, session: str | None = Cookie(default=None)) -> dict[str, Any]:
        user = _session_user(session)
        return STORE.add_review(user, body.car_id, body.stars, body.text)
