"""Request hardening for the API: rate limits, body size cap, security headers.

Pure ASGI middleware (no extra dependency). State is in memory and per process, which is
right for the single-controller design. Clients are keyed by peer address; behind the SSH
tunnel every dashboard user shares one address, so the limits are deliberately generous.

* general limit - requests per minute per client (reads and writes);
* mutation limit - POST/PUT/PATCH/DELETE per minute per client;
* auth-failure lockout - after N responses with 401 a client gets 429 until the window ends
  (stops token guessing; tokens carry 256 bits, so this is defence in depth);
* body cap - bodies above ``max_body_bytes`` are refused with 413, chunked bodies with 411;
* headers - ``nosniff``, frame denial, no referrer, no caching of API responses, and a CSP
  that allows scripts only from this origin;
* request id - every response carries ``X-Request-ID`` (a safe incoming value is kept, else one
  is generated) and every log line written while handling the request includes it. Requests
  are logged as ``api_request`` events: 2xx/3xx at debug, 4xx at info (401/403/429 at warning),
  5xx at error.
"""

from __future__ import annotations

import json
import re
import threading
import time
import uuid
from collections import defaultdict, deque
from collections.abc import Callable, MutableMapping
from typing import Any

import structlog

log = structlog.get_logger(__name__)
_REQUEST_ID = re.compile(rb"^[A-Za-z0-9._-]{8,64}$")

Scope = MutableMapping[str, Any]
Message = MutableMapping[str, Any]

MUTATING = {"POST", "PUT", "PATCH", "DELETE"}
WINDOW_S = 60.0

# Scripts only from this origin. 'unsafe-inline' is allowed for styles only: the dashboard
# renders inline style attributes. No external hosts are used anywhere.
CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
    "img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
    "base-uri 'none'; form-action 'none'"
)


class SlidingWindow:
    """At most ``limit`` events per ``window`` seconds per key."""

    def __init__(
        self, limit: int, window: float = WINDOW_S, clock: Callable[[], float] = time.monotonic
    ) -> None:
        self.limit, self.window, self._clock = limit, window, clock
        self._hits: dict[str, deque[float]] = defaultdict(deque)
        self._lock = threading.Lock()

    def _trim(self, key: str, now: float) -> deque[float]:
        q = self._hits[key]
        while q and q[0] <= now - self.window:
            q.popleft()
        if not q:
            self._hits.pop(key, None)  # keep memory bounded by active clients
            return deque()
        return q

    def blocked(self, key: str) -> bool:
        with self._lock:
            return len(self._trim(key, self._clock())) >= self.limit

    def hit(self, key: str) -> bool:
        """Record one event; return False when it exceeds the limit."""
        with self._lock:
            now = self._clock()
            q = self._trim(key, now)
            if len(q) >= self.limit:
                return False
            self._hits[key].append(now)
            return True

    def retry_after(self, key: str) -> int:
        with self._lock:
            now = self._clock()
            q = self._trim(key, now)
            return max(1, int(q[0] + self.window - now) + 1) if q else 1


class HardeningMiddleware:
    def __init__(
        self,
        app: Any,
        *,
        rate_per_min: int = 3000,
        mutations_per_min: int = 60,
        auth_failures_per_min: int = 10,
        max_body_bytes: int = 64 * 1024,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.app = app
        self.max_body = max_body_bytes
        self.general = SlidingWindow(rate_per_min, clock=clock)
        self.mutations = SlidingWindow(mutations_per_min, clock=clock)
        self.failures = SlidingWindow(auth_failures_per_min, clock=clock)

    async def __call__(self, scope: Scope, receive: Any, send: Any) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        path: str = scope["path"]
        method: str = scope["method"]
        is_api = path.startswith("/api/")
        client = (scope.get("client") or ("?", 0))[0]
        headers = {k.lower(): v for k, v in scope.get("headers", [])}
        incoming = headers.get(b"x-request-id", b"")
        rid = incoming.decode() if _REQUEST_ID.match(incoming) else uuid.uuid4().hex[:16]
        started = time.perf_counter()
        structlog.contextvars.clear_contextvars()
        structlog.contextvars.bind_contextvars(request_id=rid)
        status_seen = 0

        async def reject(status: int, detail: str, retry_after: int | None = None) -> None:
            self._log(method, path, status, client, started)
            await self._reply(send, status, detail, is_api, rid, retry_after)

        if is_api:
            if self.failures.blocked(client):
                await reject(
                    429, "too many failed authentications", self.failures.retry_after(client)
                )
                return
            if not self.general.hit(client):
                await reject(429, "rate limit exceeded", self.general.retry_after(client))
                return
            if method in MUTATING and not self.mutations.hit(client):
                await reject(
                    429, "mutation rate limit exceeded", self.mutations.retry_after(client)
                )
                return
            if method in MUTATING:
                if b"chunked" in headers.get(b"transfer-encoding", b"").lower():
                    await reject(411, "Content-Length required")
                    return
                declared = headers.get(b"content-length")
                if declared is not None and (
                    not declared.isdigit() or int(declared) > self.max_body
                ):
                    await reject(413, "request body too large")
                    return

        async def send_wrapped(message: Message) -> None:
            nonlocal status_seen
            if message["type"] == "http.response.start":
                status_seen = message["status"]
                if is_api and status_seen == 401:
                    self.failures.hit(client)
                message["headers"] = [
                    *self._with_security(message.get("headers", []), is_api),
                    (b"x-request-id", rid.encode()),
                ]
            await send(message)

        try:
            await self.app(scope, receive, send_wrapped)
        finally:
            if is_api:
                self._log(method, path, status_seen, client, started)
            structlog.contextvars.clear_contextvars()

    @staticmethod
    def _log(method: str, path: str, status: int, client: str, started: float) -> None:
        ms = round((time.perf_counter() - started) * 1000, 1)
        fields = {"method": method, "path": path, "status": status, "client": client, "ms": ms}
        if status >= 500 or status == 0:
            log.error("api_request", **fields)
        elif status in (401, 403, 429):
            log.warning("api_request", **fields)
        elif status >= 400:
            log.info("api_request", **fields)
        else:
            log.debug("api_request", **fields)

    @staticmethod
    def _with_security(raw: list[tuple[bytes, bytes]], is_api: bool) -> list[tuple[bytes, bytes]]:
        extra = {
            b"x-content-type-options": b"nosniff",
            b"x-frame-options": b"DENY",
            b"referrer-policy": b"no-referrer",
            b"content-security-policy": CSP.encode(),
        }
        if is_api:
            extra[b"cache-control"] = b"no-store"
        present = {k.lower() for k, _ in raw}
        return [*raw, *((k, v) for k, v in extra.items() if k not in present)]

    async def _reply(
        self,
        send: Any,
        status: int,
        detail: str,
        is_api: bool,
        rid: str,
        retry_after: int | None = None,
    ) -> None:
        body = json.dumps({"detail": detail}).encode()
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(body)).encode()),
        ]
        headers.append((b"x-request-id", rid.encode()))
        if retry_after is not None:
            headers.append((b"retry-after", str(retry_after).encode()))
        await send(
            {
                "type": "http.response.start",
                "status": status,
                "headers": self._with_security(headers, is_api),
            }
        )
        await send({"type": "http.response.body", "body": body})
