"""Rate limits, auth-failure lockout, body cap and security headers."""

from __future__ import annotations

import pytest
from fastapi import FastAPI, HTTPException
from fastapi.testclient import TestClient

from afw.api.hardening import CSP, HardeningMiddleware, SlidingWindow


class Clock:
    def __init__(self) -> None:
        self.t = 1000.0

    def __call__(self) -> float:
        return self.t


def test_sliding_window_limits_and_recovers():
    clk = Clock()
    w = SlidingWindow(3, window=60, clock=clk)
    assert [w.hit("k") for _ in range(4)] == [True, True, True, False]
    assert w.hit("other") is True  # keys are independent
    clk.t += 61
    assert w.hit("k") is True


def test_sliding_window_memory_is_released():
    clk = Clock()
    w = SlidingWindow(2, window=10, clock=clk)
    for i in range(50):
        w.hit(f"ip{i}")
    clk.t += 11
    w.blocked("ip0")
    w.hit("fresh")
    assert len(w._hits) <= 50  # stale keys are dropped when touched
    assert "ip0" not in w._hits


def _app(clk: Clock, **kw) -> TestClient:
    app = FastAPI()

    @app.get("/api/ok")
    def ok() -> dict[str, str]:
        return {"ok": "1"}

    @app.get("/api/deny")
    def deny() -> None:
        raise HTTPException(401, "nope")

    @app.post("/api/echo")
    def echo(body: dict) -> dict:
        return body

    @app.get("/page")
    def page() -> dict[str, str]:
        return {"page": "1"}

    app.add_middleware(HardeningMiddleware, clock=clk, **kw)
    return TestClient(app)


def test_general_rate_limit_returns_429_with_retry_after():
    clk = Clock()
    c = _app(clk, rate_per_min=3)
    assert [c.get("/api/ok").status_code for _ in range(3)] == [200, 200, 200]
    r = c.get("/api/ok")
    assert r.status_code == 429 and int(r.headers["retry-after"]) >= 1
    clk.t += 61
    assert c.get("/api/ok").status_code == 200


def test_mutations_have_their_own_stricter_limit():
    clk = Clock()
    c = _app(clk, rate_per_min=100, mutations_per_min=2)
    assert [c.post("/api/echo", json={"a": 1}).status_code for _ in range(3)] == [200, 200, 429]
    assert c.get("/api/ok").status_code == 200  # reads unaffected


def test_repeated_auth_failures_lock_the_client_out():
    clk = Clock()
    c = _app(clk, auth_failures_per_min=3)
    assert [c.get("/api/deny").status_code for _ in range(3)] == [401, 401, 401]
    r = c.get("/api/ok")  # even a valid request is refused while locked out
    assert r.status_code == 429 and "authentications" in r.json()["detail"]
    clk.t += 61
    assert c.get("/api/ok").status_code == 200


def test_non_api_paths_are_not_rate_limited():
    c = _app(Clock(), rate_per_min=1)
    assert all(c.get("/page").status_code == 200 for _ in range(5))


def test_body_size_cap():
    c = _app(Clock(), max_body_bytes=100)
    assert c.post("/api/echo", json={"a": "x" * 10}).status_code == 200
    r = c.post("/api/echo", json={"a": "x" * 500})
    assert r.status_code == 413


def test_chunked_upload_is_refused():
    c = _app(Clock())

    def gen():
        yield b'{"a": 1}'

    assert c.post("/api/echo", content=gen()).status_code == 411


@pytest.mark.parametrize("path", ["/api/ok", "/page"])
def test_security_headers_on_every_response(path):
    r = _app(Clock()).get(path)
    assert r.headers["x-content-type-options"] == "nosniff"
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["referrer-policy"] == "no-referrer"
    assert r.headers["content-security-policy"] == CSP
    assert ("cache-control" in r.headers) == path.startswith("/api")


def test_csp_forbids_external_and_inline_scripts():
    assert "script-src 'self'" in CSP and "frame-ancestors 'none'" in CSP
    script = next(d for d in CSP.split("; ") if d.startswith("script-src"))
    assert "unsafe-inline" not in script and "http" not in CSP
