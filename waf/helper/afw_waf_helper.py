#!/usr/bin/env python3
"""AFW WAF policy helper (runs on WAF01; stdlib only).

Accepts ONLY the typed desired state from the controller:
    {"denied_sources": [ipv4...], "rate_limited": {ipv4: "strict"|"moderate"},
     "contracts": [{route, allowed_methods, allowed_content_types, max_body_bytes, revision}],
     "login_controls": {ipv4: "throttle"|"deny"}}            (optional; A3)
login_controls act on the application's login routes only (AFW_LOGIN_ROUTES): a
throttle limits them to LOGIN_RATE with LOGIN_BURST, a deny answers 403 there.
Renders reviewed templates, validates with `nginx -t` inside the running WAF
container (same image/modules), reloads, verifies the served revision through
an end-to-end request, and restores the previous configuration on any failure.
There is no input path for free-form Nginx or ModSecurity text.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

POLICY_DIR = Path(os.environ.get("AFW_POLICY_DIR", "/srv/afw-waf/policy"))
STATE_FILE = POLICY_DIR.parent / "state.json"
CONTAINER = os.environ.get("AFW_WAF_CONTAINER", "afw-waf")
LISTEN = os.environ.get("AFW_HELPER_LISTEN", "10.77.30.10")
PORT = int(os.environ.get("AFW_HELPER_PORT", "9443"))
SELFTEST_URL = os.environ.get("AFW_SELFTEST_URL", "https://10.77.30.10/__afw/selftest")
BACKEND_URL = os.environ.get("AFW_BACKEND_URL", "http://10.77.40.10:8000/health")
TOKEN = (
    Path(os.environ.get("AFW_HELPER_TOKEN_FILE", "/etc/afw/waf-helper.token")).read_text().strip()
)
CERT = os.environ.get("AFW_HELPER_CERT", "/etc/afw/tls/waf.crt")
KEY = os.environ.get("AFW_HELPER_KEY", "/etc/afw/tls/waf.key")
CA = os.environ.get("AFW_LAB_CA", "/etc/afw/tls/lab-ca.pem")
CLIENT_NETS = [
    ipaddress.ip_network(n)
    for n in os.environ.get("AFW_CLIENT_NETS", "10.77.10.0/24,10.77.20.0/24").split(",")
]

ROUTE_RE = re.compile(r"^/[A-Za-z0-9_\-/{}]{0,127}$")
PARAM_RE = re.compile(r"^\{[A-Za-z_][A-Za-z0-9_]*\}$")
METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD"}
CTYPES = {"application/json", "application/x-www-form-urlencoded", "text/plain"}
RATES = {"strict": ("1r/s", 5), "moderate": ("5r/s", 10)}
LOGIN_ROUTES = [r for r in os.environ.get("AFW_LOGIN_ROUTES", "/login").split(",") if r]
LOGIN_RATE, LOGIN_BURST = "3r/m", 4  # A3_AUTH_CONTROLS.md §2.2
LOGIN_LEVELS = {"throttle", "deny"}
LOCK = threading.Lock()


class Invalid(ValueError):
    pass


# ------------------------------------------------------------------ validation
def _client_ip(text: str) -> str:
    ip = ipaddress.ip_address(text)
    if not isinstance(ip, ipaddress.IPv4Address) or not any(ip in n for n in CLIENT_NETS):
        raise Invalid(f"{text} is not a client-zone IPv4 address")
    return str(ip)


def validate(doc: object) -> dict:
    base = {"denied_sources", "rate_limited", "contracts"}
    if not isinstance(doc, dict) or not base <= set(doc) <= base | {"login_controls"}:
        raise Invalid("expected denied_sources, rate_limited, contracts[, login_controls]")
    logins = {}
    raw_logins = doc.get("login_controls", {})
    if not isinstance(raw_logins, dict):
        raise Invalid("login_controls must be an object")
    for ip, level in raw_logins.items():
        if level not in LOGIN_LEVELS:
            raise Invalid(f"unknown login control {level!r}")
        logins[_client_ip(ip)] = level
    denied = sorted({_client_ip(x) for x in doc["denied_sources"]})
    if not isinstance(doc["rate_limited"], dict):
        raise Invalid("rate_limited must be an object")
    rates = {}
    for ip, prof in doc["rate_limited"].items():
        if prof not in RATES:
            raise Invalid(f"unknown rate profile {prof!r}")
        rates[_client_ip(ip)] = prof
    contracts = []
    for c in doc["contracts"]:
        keys = {
            "type",
            "route",
            "allowed_methods",
            "allowed_content_types",
            "max_body_bytes",
            "revision",
        }
        if not isinstance(c, dict) or not set(c) <= keys:
            raise Invalid("bad contract fields")
        route = c["route"]
        if not ROUTE_RE.match(route) or "//" in route:
            raise Invalid(f"bad route {route!r}")
        segs = route.split("/")
        if any(("{" in s or "}" in s) and not PARAM_RE.match(s) for s in segs):
            raise Invalid(f"bad route parameter in {route!r}")
        methods = sorted(set(c["allowed_methods"]))
        if not methods or not set(methods) <= METHODS:
            raise Invalid("bad methods")
        ctypes = sorted(set(c.get("allowed_content_types", [])))
        if not set(ctypes) <= CTYPES:
            raise Invalid("bad content types")
        size = int(c["max_body_bytes"])
        if not 0 <= size <= 1_048_576:
            raise Invalid("bad body size")
        contracts.append(
            {
                "type": "contract",
                "route": route,
                "allowed_methods": methods,
                "allowed_content_types": ctypes,
                "max_body_bytes": size,
                "revision": int(c["revision"]),
            }
        )
    out = {
        "denied_sources": denied,
        "rate_limited": dict(sorted(rates.items())),
        "contracts": sorted(contracts, key=lambda x: x["route"]),
    }
    if logins:
        out["login_controls"] = dict(sorted(logins.items()))
    return out


# ------------------------------------------------------------------ rendering
def render(state: dict, rev: int) -> dict[str, str]:
    http = [
        f"# AFW policy revision {rev} — generated, do not edit",
        f'map "" $afw_policy_rev {{ default "{rev}"; }}',
        "geo $afw_denied {",
        "    default 0;",
    ]
    http += [f"    {ip}/32 1;" for ip in state["denied_sources"]]
    http += ["}", "geo $afw_rate_class {", '    default "";']
    http += [f"    {ip}/32 {p};" for ip, p in state["rate_limited"].items()]
    http += ["}"]
    for name, (rate, _) in RATES.items():
        http += [
            f'map $afw_rate_class $afw_key_{name} {{ {name} $binary_remote_addr; default ""; }}',
            f"limit_req_zone $afw_key_{name} zone=afw_{name}:1m rate={rate};",
        ]
    logins = state.get("login_controls", {})
    http += ["geo $afw_login_class {", '    default "";']
    http += [f"    {ip}/32 {lvl};" for ip, lvl in logins.items()]
    http += [
        "}",
        'map $afw_login_class $afw_key_login { throttle $binary_remote_addr; default ""; }',
        f"limit_req_zone $afw_key_login zone=afw_login:1m rate={LOGIN_RATE};",
    ]
    http += ["limit_req_status 429;", ""]

    server = [
        f"# AFW policy revision {rev} — generated, do not edit",
        "if ($afw_denied) { return 403; }",
    ]
    server += [f"limit_req zone=afw_{n} burst={b} nodelay;" for n, (_, b) in RATES.items()]
    site_limits = [f"    limit_req zone=afw_{n} burst={b} nodelay;" for n, (_, b) in RATES.items()]
    # A3: every login route gets its own exact location (always rendered, so the shape
    # does not depend on the policy); nginx does not inherit limit_req into a location
    # that sets its own, so the site-wide zones are repeated there
    login_lines = [
        '    if ($afw_login_class = "deny") { return 403; }',
        *site_limits,
        f"    limit_req zone=afw_login burst={LOGIN_BURST} nodelay;",
    ]
    contract_routes = {c["route"] for c in state["contracts"]}
    for route in LOGIN_ROUTES:
        if route not in contract_routes:
            server += [
                f"location = {route} {{",
                *login_lines,
                "    include /etc/nginx/afw/proxy_backend.conf;",
                "}",
            ]
    for c in state["contracts"]:
        parts = ["[^/]+" if PARAM_RE.match(s) else re.escape(s) for s in c["route"].split("/")]
        loc = "~ ^" + "/".join(parts) + "$" if "{" in c["route"] else "= " + c["route"]
        server += [
            f"location {loc} {{",
            *(login_lines if c["route"] in LOGIN_ROUTES else []),
            f"    limit_except {' '.join(c['allowed_methods'])} {{ deny all; }}",
            f"    client_max_body_size {max(c['max_body_bytes'], 1)};",
        ]
        if c["allowed_content_types"]:
            alt = "|".join(re.escape(t) for t in c["allowed_content_types"])
            server += [
                '    if ($request_method !~ ^(GET|HEAD)$) { set $afw_ct_check "1"; }',
                f'    if ($content_type ~* "^({alt})") {{ set $afw_ct_check "0"; }}',
                '    if ($afw_ct_check = "1") { return 415; }',
            ]
        server += ["    include /etc/nginx/afw/proxy_backend.conf;", "}"]
    server.insert(1, 'set $afw_ct_check "0";')
    return {"http.conf": "\n".join(http) + "\n", "server.conf": "\n".join(server) + "\n"}


# ------------------------------------------------------------------ apply
def docker(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(  # noqa: S603 - fixed binary, validated arguments
        ["/usr/bin/docker", "exec", CONTAINER, *args],
        capture_output=True,
        text=True,
        timeout=20,
        check=False,
    )


def load_state() -> dict:
    if STATE_FILE.exists():
        return json.loads(STATE_FILE.read_text())
    return {"revision": 0, "desired": {"denied_sources": [], "rate_limited": {}, "contracts": []}}


def selftest(rev: int) -> dict:
    ctx = ssl.create_default_context(cafile=CA)
    out = {"expected_revision": rev}
    for _ in range(10):
        try:
            with urllib.request.urlopen(SELFTEST_URL, context=ctx, timeout=3) as r:  # noqa: S310
                out |= {"status": r.status, "served_revision": r.headers.get("X-AFW-Policy-Rev")}
        except urllib.error.HTTPError as e:
            out |= {"status": e.code, "served_revision": e.headers.get("X-AFW-Policy-Rev")}
        except OSError as e:
            out |= {"status": None, "error": str(e)}
        if out.get("served_revision") == str(rev):
            break
        time.sleep(0.3)
    out["revision_active"] = out.get("served_revision") == str(rev)
    out["waf_ok"] = out.get("status") == 204
    return out


def backend_ok() -> bool:
    """Direct WAF->app reachability (not through nginx, so it is not client telemetry)."""
    try:
        with urllib.request.urlopen(BACKEND_URL, timeout=3) as r:  # noqa: S310
            return r.status == 200
    except OSError:
        return False


def apply(desired: dict) -> tuple[int, dict]:
    with LOCK:
        cur = load_state()
        # A stored revision that nginx is not serving (e.g. stale reload) is re-applied.
        unchanged = cur["desired"] == desired and cur["revision"] > 0
        if unchanged and selftest(cur["revision"])["revision_active"]:
            return 200, {"ok": True, "revision": cur["revision"], "changed": False}
        rev = cur["revision"] + 1
        backup = POLICY_DIR.parent / "policy.prev"
        if backup.exists():
            shutil.rmtree(backup)
        shutil.copytree(POLICY_DIR, backup)
        for name, text in render(desired, rev).items():
            tmp = POLICY_DIR / f".{name}.tmp"
            tmp.write_text(text)
            tmp.replace(POLICY_DIR / name)
        test = docker("nginx", "-t")
        if test.returncode != 0:
            shutil.rmtree(POLICY_DIR)
            shutil.copytree(backup, POLICY_DIR)
            return 422, {
                "ok": False,
                "error": "nginx -t failed; previous policy restored",
                "detail": test.stderr[-800:],
            }
        reload = docker("nginx", "-s", "reload")
        if reload.returncode != 0:
            shutil.rmtree(POLICY_DIR)
            shutil.copytree(backup, POLICY_DIR)
            docker("nginx", "-s", "reload")
            return 500, {
                "ok": False,
                "error": "reload failed; restored",
                "detail": reload.stderr[-800:],
            }
        st = selftest(rev)
        st["backend_ok"] = backend_ok()  # direct check only on change (app logs it)
        if not st["revision_active"]:
            return 500, {
                "ok": False,
                "error": "new revision not observed in served traffic",
                "selftest": st,
                "revision": rev,
            }
        STATE_FILE.write_text(json.dumps({"revision": rev, "desired": desired, "selftest": st}))
        return 200, {"ok": True, "revision": rev, "changed": True, "selftest": st}


class Handler(BaseHTTPRequestHandler):
    server_version = "afw-waf-helper"

    def _send(self, code: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _authorized(self) -> bool:
        import hmac

        got = self.headers.get("Authorization", "").removeprefix("Bearer ").strip()
        return hmac.compare_digest(got.encode(), TOKEN.encode())

    def do_GET(self) -> None:
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        if self.path != "/v1/state":
            return self._send(404, {"error": "not found"})
        st = load_state()
        live = selftest(st["revision"]) if st["revision"] else {"revision_active": False}
        self._send(
            200,
            {
                **st["desired"],
                "revision": st["revision"],
                "revision_active": live["revision_active"],
                "waf_ok": live.get("waf_ok"),
                "backend_ok": st.get("selftest", {}).get("backend_ok"),
            },
        )

    def do_PUT(self) -> None:
        if not self._authorized():
            return self._send(401, {"error": "unauthorized"})
        if self.path != "/v1/state":
            return self._send(404, {"error": "not found"})
        length = int(self.headers.get("Content-Length", "0"))
        if length > 256_000:
            return self._send(413, {"error": "too large"})
        try:
            desired = validate(json.loads(self.rfile.read(length)))
        except (Invalid, ValueError, KeyError, TypeError) as e:
            return self._send(400, {"ok": False, "error": f"invalid desired state: {e}"})
        code, body = apply(desired)
        self._send(code, body)

    def log_message(self, fmt: str, *args: object) -> None:
        sys.stderr.write("afw-waf-helper %s\n" % (fmt % args))


def ensure_initial() -> None:
    POLICY_DIR.mkdir(parents=True, exist_ok=True)
    if not (POLICY_DIR / "http.conf").exists():
        empty = {"denied_sources": [], "rate_limited": {}, "contracts": []}
        for name, text in render(empty, 0).items():
            (POLICY_DIR / name).write_text(text)


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "init":
        ensure_initial()
        sys.exit(0)
    ensure_initial()
    httpd = ThreadingHTTPServer((LISTEN, PORT), Handler)
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(CERT, KEY)
    httpd.socket = tls.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()
