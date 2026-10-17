#!/usr/bin/env python3
"""Enforcement verification probe agent (runs on USR01 / ATK01, stdlib only).

Exactly one operation: ``GET /v1/probe?source=<ip>`` makes ONE HTTPS
``GET /health`` request to the fixed, configured protected service, bound to
``source`` (which must be an address on this host), and reports whether a TCP
connection was established and what HTTP status came back.

It accepts no URL, host, port, path, payload or command, only callers from the
controller address may use it, and it requires a bearer token. It therefore
cannot be used as a general traffic generator or execution channel.
"""

from __future__ import annotations

import hmac
import http.client
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

LISTEN = os.environ.get("AFW_PROBE_LISTEN", "0.0.0.0")  # noqa: S104 - nftables + caller check
PORT = int(os.environ.get("AFW_PROBE_PORT", "9180"))
TARGET = os.environ.get("AFW_PROBE_TARGET", "10.77.30.10")
TARGET_NAME = os.environ.get("AFW_PROBE_TARGET_NAME", "rental.lab.afw")  # SNI/Host
TARGET_PORT = 443
TARGET_PATH = "/health"
CA = os.environ.get("AFW_LAB_CA", "/etc/afw/tls/lab-ca.pem")
ALLOWED_CALLERS = {os.environ.get("AFW_PROBE_CALLER", "10.77.50.10")}
TOKEN = Path(os.environ.get("AFW_PROBE_TOKEN_FILE", "/etc/afw/probe.token")).read_text().strip()
TIMEOUT_S = 4.0


def local_addresses() -> set[str]:
    out = subprocess.run(
        ["/usr/sbin/ip", "-4", "-o", "addr", "show"],
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return {line.split()[3].split("/")[0] for line in out.splitlines()}


def probe(source: str) -> dict[str, object]:
    ctx = ssl.create_default_context(cafile=CA)
    sock = socket.create_connection(
        (TARGET, TARGET_PORT), timeout=TIMEOUT_S, source_address=(source, 0)
    )
    result: dict[str, object] = {"source": source, "connected": True}
    try:
        tls = ctx.wrap_socket(sock, server_hostname=TARGET_NAME)
        conn = http.client.HTTPSConnection(TARGET_NAME, TARGET_PORT, timeout=TIMEOUT_S, context=ctx)
        conn.sock = tls
        conn.request("GET", TARGET_PATH, headers={"User-Agent": "afw-probe/1"})
        resp = conn.getresponse()
        resp.read(4096)
        result |= {
            "status": resp.status,
            "ok": resp.status == 200,
            "policy_rev": resp.getheader("X-AFW-Policy-Rev"),
        }
    except (OSError, http.client.HTTPException) as exc:
        result |= {"ok": False, "error": f"after_connect: {type(exc).__name__}"}
    finally:
        sock.close()
    return result


class Handler(BaseHTTPRequestHandler):
    server_version = "afw-probe"

    def _send(self, code: int, body: dict[str, object]) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.client_address[0] not in ALLOWED_CALLERS:
            return self._send(403, {"error": "caller_not_allowed"})
        got = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        if not hmac.compare_digest(got.encode(), TOKEN.encode()):
            return self._send(401, {"error": "unauthorized"})
        url = urlsplit(self.path)
        if url.path != "/v1/probe":
            return self._send(404, {"error": "not_found"})
        try:
            source = str(ipaddress.IPv4Address(parse_qs(url.query).get("source", [""])[0]))
        except ValueError:
            return self._send(400, {"error": "bad_source"})
        if source not in local_addresses():
            return self._send(200, {"source": source, "error": "source_not_local"})
        try:
            return self._send(200, probe(source))
        except OSError as exc:  # no TCP connection: filtered/refused/timeout
            return self._send(
                200,
                {"source": source, "connected": False, "ok": False, "error": type(exc).__name__},
            )

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("afw-probe %s\n" % (fmt % args))


if __name__ == "__main__":
    ThreadingHTTPServer((LISTEN, PORT), Handler).serve_forever()
