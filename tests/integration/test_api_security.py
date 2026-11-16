"""API security review (docs/SECURITY_CHECKLIST.md): authorization matrix, hardening, inputs.

ROLE_TABLE is the reviewed, intended minimum role of every API route. A new route that is not
in the table fails ``test_every_route_is_in_the_reviewed_table`` until someone decides its role.
"""

from __future__ import annotations

import os

import pytest
import yaml
from fastapi.testclient import TestClient

from afw.api.app import create_app
from afw.api.auth import Role, TokenStore, write_entries
from afw.container import build_container

PUBLIC = {("GET", "/api/health")}

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
