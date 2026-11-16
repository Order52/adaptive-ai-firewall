"""API security review (docs/SECURITY_CHECKLIST.md): authorization matrix, hardening, inputs.

ROLE_TABLE is the reviewed, intended minimum role of every API route. A new route that is not
in the table fails ``test_every_route_is_in_the_reviewed_table`` until someone decides its role.
"""

from __future__ import annotations

import os
import re
from datetime import UTC, datetime, timedelta

import pytest
import yaml
from fastapi.testclient import TestClient

from afw.api.app import create_app
from afw.api.auth import Role, TokenStore, write_entries
from afw.container import build_container

PUBLIC = {("GET", "/api/health"), ("GET", "/api/readyz")}

ROLE_TABLE: dict[tuple[str, str], Role] = {
    **{
        ("GET", p): Role.VIEWER
        for p in [
            "/api/adaptation",
            "/api/assessments/{assessment_id}",
            "/api/assessments",
            "/api/audit",
            "/api/config",
            "/api/detections",
            "/api/events",
            "/api/experiments",
            "/api/geo/lookup/{ip}",
            "/api/geo/preview/{country_code}",
            "/api/geo/status",
            "/api/learning/challenger",
            "/api/learning/shadow",
            "/api/models",
            "/api/network",
            "/api/overview",
            "/api/policies/{policy_id}/explain",
            "/api/policies/{policy_id}",
            "/api/policies",
            "/api/profiles/{app_id}/diff",
            "/api/profiles",
            "/api/resources",
            "/api/sources/{ip}",
            "/api/whoami",
        ]
    },
    ("GET", "/api/metrics"): Role.VIEWER,
    ("GET", "/api/geo/enforcement/{direction}"): Role.FIREWALL,
    **{
        ("POST", p): Role.OPERATOR
        for p in [
            "/api/feedback",
            "/api/policies",
            "/api/policies/{policy_id}/approve",
            "/api/policies/{policy_id}/reject",
            "/api/policies/{policy_id}/revoke",
            "/api/policies/simulate",
            "/api/profiles/{app_id}/candidates",
        ]
    },
    **{
        ("POST", p): Role.ADMIN
        for p in [
            "/api/learning/challenger/evaluate",
            "/api/learning/challenger/{evaluation_id}/promote",
            "/api/learning/challenger/rollback",
            "/api/mode",
            "/api/strategy",
            "/api/profiles/{app_id}/{version}/promote",
            "/api/profiles/{app_id}/{version}/reject",
            "/api/profiles/{app_id}/{version}/rollback",
        ]
    },
}


def _build(settings, tmp_path, **over):
    settings = settings.model_copy(
        update={
            "api_tokens_file": tmp_path / "tokens.yaml",
            # these tests deliberately make many unauthenticated calls
            "api_auth_failures_per_min": 10_000,
            "api_rate_per_min": 10_000,
            "api_mutations_per_min": 10_000,
            **over,
        }
    )
    tokens, entries = {}, []
    for role in ("firewall", "viewer", "operator", "admin"):
        tok, entry = TokenStore.issue(role, role)
        tokens[role] = {"Authorization": f"Bearer {tok}"}
        entries.append(entry)
    write_entries(settings.api_tokens_file, entries)
    c = build_container(settings, simulated=True)
    c.policy_service.reconcile()
    return TestClient(create_app(c), raise_server_exceptions=False), tokens, c, settings


@pytest.fixture
def api(settings, tmp_path):
    return _build(settings, tmp_path)


def _routes(client):
    for r in client.app.routes:
        path = getattr(r, "path", "")
        if path.startswith("/api"):
            for m in sorted(r.methods - {"HEAD", "OPTIONS"}):
                yield m, path


def _fill(path: str) -> str:
    return (
        path.replace("{ip}", "10.77.20.10")
        .replace("{version}", "1")
        .replace("{direction}", "inbound")
        .replace("{country_code}", "cn")
        .replace("{app_id}", "rental")
        .replace("{policy_id}", "pol-none")
        .replace("{assessment_id}", "x")
        .replace("{evaluation_id}", "x")
    )


def test_every_route_is_in_the_reviewed_table(api):
    client = api[0]
    actual = set(_routes(client))
    assert actual - PUBLIC == set(ROLE_TABLE), "route added/removed: review its role"


def test_every_protected_route_refuses_anonymous_and_garbage_tokens(api):
    client = api[0]
    for method, path in ROLE_TABLE:
        for headers in ({}, {"Authorization": "Bearer nonsense"}, {"Authorization": "Basic abc"}):
            r = client.request(method, _fill(path), headers=headers)
            assert r.status_code == 401, (method, path, headers, r.status_code)


def test_role_matrix_every_route_rejects_the_role_below_and_admits_the_minimum(api):
    client, tok, _, _ = api
    order = [Role.FIREWALL, Role.VIEWER, Role.OPERATOR, Role.ADMIN]
    for (method, path), need in ROLE_TABLE.items():
        for role in order:
            r = client.request(method, _fill(path), headers=tok[role.name.lower()], json={})
            if role < need:
                assert r.status_code == 403, (method, path, role.name, r.status_code)
            else:
                assert r.status_code not in (401, 403), (method, path, role.name, r.status_code)


def test_no_route_crashes_on_empty_or_unknown_input(api):
    client, tok, _, _ = api
    for method, path in ROLE_TABLE:
        h = tok["admin"]
        for body in ({}, {"app_id": "nope"}):
            r = client.request(method, _fill(path).replace("rental", "nope"), headers=h, json=body)
            # 503 is a deliberate 'dependency not installed' answer; 500 is an unhandled crash
            assert r.status_code != 500, (method, path, body, r.text[:200])


def test_unknown_app_is_404_not_500(api):
    client, tok, _, _ = api
    r = client.post(
        "/api/profiles/nope/candidates",
        json={"since": "2026-01-01T00:00:00Z", "until": "2026-01-02T00:00:00Z"},
        headers=tok["operator"],
    )
    assert r.status_code == 404


def test_oversized_body_is_413_and_never_parsed(api):
    client, tok, _, _ = api
    r = client.post(
        "/api/policies/simulate",
        content=b'{"reason": "' + b"x" * 200_000 + b'"}',
        headers={**tok["operator"], "content-type": "application/json"},
    )
    assert r.status_code == 413


def test_input_bounds_reject_hostile_values(api):
    client, tok, _, _ = api
    op = tok["operator"]
    bad_app = {"kind": "block_source", "app_id": "../../etc/passwd", "target": {}}
    assert client.post("/api/policies/simulate", json=bad_app, headers=op).status_code == 422
    big = {
        "since": "2026-01-01T00:00:00Z",
        "until": "2026-01-02T00:00:00Z",
        "attack_validation_ids": ["x"] * 51,
    }
    assert client.post("/api/profiles/rental/candidates", json=big, headers=op).status_code == 422
    assert client.get("/api/events?limit=99999999", headers=tok["viewer"]).status_code == 422


def test_health_is_minimal_without_a_token_and_detailed_with_one(api):
    client, tok, _, _ = api
    anon = client.get("/api/health").json()
    assert set(anon) == {"status", "version"}
    bad = client.get("/api/health", headers={"Authorization": "Bearer nonsense"})
    assert bad.status_code == 200 and set(bad.json()) == {"status", "version"}
    fw = client.get("/api/health", headers=tok["firewall"]).json()
    assert set(fw) == {"status", "version"}  # the firewall role is not a viewer
    full = client.get("/api/health", headers=tok["viewer"]).json()
    assert {"mode", "backends", "telemetry_degraded"} <= set(full)


def test_security_headers_and_no_cache_on_api(api):
    client, tok, _, _ = api
    r = client.get("/api/whoami", headers=tok["viewer"])
    assert r.headers["cache-control"] == "no-store"
    assert r.headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in r.headers["content-security-policy"]
    page = client.get("/")
    assert page.status_code == 200 and page.headers["x-frame-options"] == "DENY"


def test_token_guessing_is_locked_out(settings, tmp_path):
    client, tok, _, _ = _build(settings, tmp_path, api_auth_failures_per_min=5)
    codes = [
        client.get("/api/whoami", headers={"Authorization": f"Bearer g{i}"}).status_code
        for i in range(6)
    ]
    assert codes[:5] == [401] * 5 and codes[5] == 429
    # the lockout covers valid credentials too, until the window passes
    assert client.get("/api/whoami", headers=tok["viewer"]).status_code == 429


def test_expired_token_is_refused_and_revoked_token_stops_working(settings, tmp_path):
    client, _, _, s = _build(settings, tmp_path)
    old, entry = TokenStore.issue("old", "viewer", ttl_days=1)
    entry["expires"] = "2020-01-01"
    gone, gentry = TokenStore.issue("gone", "viewer")
    entries = [*yaml.safe_load(s.api_tokens_file.read_text()), entry, gentry]
    write_entries(s.api_tokens_file, entries)
    st = s.api_tokens_file.stat()
    os.utime(s.api_tokens_file, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    assert client.get("/api/whoami", headers={"Authorization": f"Bearer {old}"}).status_code == 401
    live = {"Authorization": f"Bearer {gone}"}
    assert client.get("/api/whoami", headers=live).status_code == 200
    write_entries(s.api_tokens_file, [e for e in entries if e["name"] != "gone"])
    os.utime(s.api_tokens_file, ns=(st.st_atime_ns, st.st_mtime_ns + 2_000_000_000))
    assert client.get("/api/whoami", headers=live).status_code == 401


def test_feedback_is_audited(api):
    client, tok, c, _ = api
    r = client.post(
        "/api/feedback", json={"label": "false_positive", "note": "ok"}, headers=tok["operator"]
    )
    assert r.status_code == 200, r.text
    assert any(
        a["action"] == "feedback.add" and a["actor"] == "operator" for a in c.audit.recent(50)
    )


# ----------------------------------------------------------------- readiness / metrics


def _cert(path, days):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "t")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=days))
        .sign(key, hashes.SHA256())
    )
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return path


def test_cert_days_left(tmp_path):
    from afw.api.ops import cert_days_left

    assert 99 < cert_days_left(_cert(tmp_path / "c.pem", 100)) < 100
    assert cert_days_left(None) is None
    assert cert_days_left(tmp_path / "missing.pem") is None
    (tmp_path / "junk.pem").write_text("not a cert")
    assert cert_days_left(tmp_path / "junk.pem") is None


def test_readyz_anonymous_gets_only_the_verdict(api):
    client, tok, _, _ = api
    r = client.get("/api/readyz")
    assert r.status_code == 200 and r.json() == {"ready": True}
    full = client.get("/api/readyz", headers=tok["viewer"]).json()
    assert full["ready"] is True
    assert {"database", "reconciled", "sensors_fresh", "models_loaded"} <= set(full["checks"])
    assert full["checks"]["backends_reachable"]["detail"] == "simulated"


def test_readyz_is_503_with_the_failing_check_named(api):
    client, tok, c, _ = api
    c.controller.model_error = "trusted model failed to load"
    r = client.get("/api/readyz")
    assert r.status_code == 503 and r.json() == {"ready": False}
    detail = client.get("/api/readyz", headers=tok["viewer"]).json()
    assert detail["checks"]["models_loaded"] == {
        "ok": False,
        "detail": "trusted model failed to load",
    }
    assert detail["checks"]["database"]["ok"] is True


def test_readyz_fails_when_the_certificate_is_about_to_expire(settings, tmp_path):
    cert = _cert(tmp_path / "srv.pem", 10)
    key = tmp_path / "srv.key"
    key.write_text("placeholder")
    client, tok, _, _ = _build(settings, tmp_path, tls_cert=cert, tls_key=key)
    r = client.get("/api/readyz", headers=tok["viewer"])
    assert r.status_code == 503
    assert r.json()["checks"]["certificate_valid"]["ok"] is False
    far = _cert(tmp_path / "srv2.pem", 365)
    client, tok, _, _ = _build(settings, tmp_path, tls_cert=far, tls_key=key)
    assert client.get("/api/readyz", headers=tok["viewer"]).json()["ready"] is True


def test_metrics_requires_a_viewer_and_is_valid_prometheus_text(api):
    client, tok, _, _ = api
    assert client.get("/api/metrics").status_code == 401
    assert client.get("/api/metrics", headers=tok["firewall"]).status_code == 403
    r = client.get("/api/metrics", headers=tok["viewer"])
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    sample = re.compile(r"^[a-zA-Z_:][a-zA-Z0-9_:]*(\{[^}]*\})? -?[0-9.e+-]+$")
    helps, types = {}, {}
    for line in r.text.splitlines():
        if line.startswith("# HELP "):
            helps[line.split()[2]] = helps.get(line.split()[2], 0) + 1
        elif line.startswith("# TYPE "):
            types[line.split()[2]] = types.get(line.split()[2], 0) + 1
        else:
            assert sample.match(line), line
    assert all(n == 1 for n in [*helps.values(), *types.values()])  # declared once each
    assert "afw_ready 1" in r.text and 'afw_info{version="' in r.text
    assert 'afw_ready_check{check="database"} 1' in r.text
    assert "afw_telemetry_degraded 0" in r.text and r.text.endswith("\n")


def test_metrics_show_degradation(api):
    client, tok, c, _ = api
    c.controller.model_error = "boom"
    text = client.get("/api/metrics", headers=tok["viewer"]).text
    assert "afw_ready 0" in text and 'afw_ready_check{check="models_loaded"} 0' in text
    assert "afw_telemetry_degraded 1" in text
