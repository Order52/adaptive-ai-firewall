from __future__ import annotations

import yaml
from fastapi.testclient import TestClient

from afw.api.app import create_app
from afw.api.auth import TokenStore
from afw.container import build_container


def client_with_tokens(settings):
    tokens, entries = {}, []
    for name, role, channel in [
        ("viewer", "viewer", "api"),
        ("op", "operator", "api"),
        ("admin", "admin", "api"),
        ("claude", "operator", "mcp"),
        ("fw", "firewall", "api"),
    ]:
        tok, entry = TokenStore.issue(name, role, channel)
        tokens[name] = {"Authorization": f"Bearer {tok}"}
        entries.append(entry)
    settings.api_tokens_file.parent.mkdir(parents=True, exist_ok=True)
    settings.api_tokens_file.write_text(yaml.safe_dump(entries))
    c = build_container(settings, simulated=True)
    c.policy_service.reconcile()
    return TestClient(create_app(c)), tokens, c


def test_auth_roles_and_validated_mutations(settings, tmp_path):
    settings = settings.model_copy(update={"api_tokens_file": tmp_path / "tokens.yaml"})
    client, tok, _ = client_with_tokens(settings)
    assert client.get("/api/health").status_code == 200
    assert client.get("/api/overview").status_code == 401
    assert client.get("/api/overview", headers=tok["viewer"]).status_code == 200

    body = {
        "kind": "source_block",
        "target": {"type": "source", "source_ip": "10.77.10.40"},
        "duration_s": 120,
        "reason": "test",
    }
    assert client.post("/api/policies", json=body, headers=tok["viewer"]).status_code == 403
    r = client.post("/api/policies", json=body, headers=tok["claude"])
    assert r.status_code == 200 and r.json()["state"] == "enforced"
    assert r.json()["intent"]["origin"] == "mcp"

    bad = {**body, "target": {"type": "source", "source_ip": "10.77.50.10"}}
    r = client.post("/api/policies", json=bad, headers=tok["op"])
    assert r.json()["state"] == "rejected"
    sim = client.post("/api/policies/simulate", json=bad, headers=tok["op"]).json()
    assert not sim["valid"] and any("protected" in e for e in sim["errors"])

    # free-form text is not a valid policy shape
    raw = {"kind": "source_block", "target": {"type": "raw", "rule": "pass all"}, "duration_s": 60}
    assert client.post("/api/policies", json=raw, headers=tok["admin"]).status_code == 422

    assert client.post("/api/mode", json={"mode": "auto"}, headers=tok["op"]).status_code == 403
    assert client.post("/api/mode", json={"mode": "auto"}, headers=tok["admin"]).status_code == 200

    pid = client.get("/api/policies", headers=tok["viewer"]).json()[-1]["policy_id"]
    ex = client.get(f"/api/policies/{pid}/explain", headers=tok["viewer"]).json()
    assert ex["enforcement"]["state"] in ("enforced", "rejected")
    assert client.get("/", headers={}).status_code == 200  # dashboard shell


def test_shadow_learning_endpoint_is_read_only_and_reports_state(settings):
    client, tok, _ = client_with_tokens(settings)
    assert client.get("/api/learning/shadow").status_code == 401
    body = client.get("/api/learning/shadow", headers=tok["viewer"]).json()
    status = body["status"]
    assert status["mode"].startswith("shadow")
    assert status["challenger"] is None  # no trusted profile yet -> learner unbound
    assert body["agreement"] is None and body["checkpoints"] == []
    assert client.post("/api/learning/shadow", headers=tok["admin"]).status_code == 405
    adapt = client.get("/api/adaptation", headers=tok["viewer"]).json()
    assert "shadow_learner" in adapt


def test_challenger_lifecycle_endpoints_are_admin_gated_and_refuse_without_a_challenger(settings):
    client, tok, _ = client_with_tokens(settings)
    body = client.get("/api/learning/challenger", headers=tok["viewer"]).json()
    assert body["probation"] is None and body["evaluations"] == []
    req = {"benign_dataset_ids": ["hold"], "attack_dataset_ids": []}
    for role in ("viewer", "op", "claude"):
        r = client.post("/api/learning/challenger/evaluate", json=req, headers=tok[role])
        assert r.status_code == 403
        r = client.post(
            "/api/learning/challenger/ev-x/promote", json={"note": "ok!"}, headers=tok[role]
        )
        assert r.status_code == 403
    r = client.post("/api/learning/challenger/evaluate", json=req, headers=tok["admin"])
    assert r.status_code == 409 and "no trusted profile" in r.json()["detail"]
    r = client.post(
        "/api/learning/challenger/ev-x/promote", json={"note": "ok!"}, headers=tok["admin"]
    )
    assert r.status_code == 409 and "unknown evaluation" in r.json()["detail"]
    r = client.post(
        "/api/learning/challenger/rollback", json={"note": "undo"}, headers=tok["admin"]
    )
    assert r.status_code == 409


def test_geoip_endpoints_lookup_preview_and_real_country_tables(settings, tmp_path):
    import gzip

    from conftest import T0

    from afw.geoip import install

    settings = settings.model_copy(update={"api_tokens_file": tmp_path / "tokens.yaml"})
    client, tok, _ = client_with_tokens(settings)
    assert client.get("/api/geo/status", headers=tok["viewer"]).json()["loaded"] is False
    assert client.get("/api/geo/lookup/1.0.1.1", headers=tok["viewer"]).status_code == 503

    src = tmp_path / "dl.csv.gz"
    with gzip.open(src, "wt") as f:
        f.write("1.0.0.0,1.0.0.255,AU\n1.0.1.0,1.0.3.255,CN\n")
    install(src, settings.data_dir / "geo", "2026-10", "u", T0, min_ranges=1)
    client, tok, _ = client_with_tokens(settings)
    v = tok["viewer"]
    assert client.get("/api/geo/status", headers=v).json()["release"] == "2026-10"
    assert client.get("/api/geo/lookup/1.0.1.1", headers=v).json()["country"] == "CN"
    assert client.get("/api/geo/lookup/10.77.10.10", headers=v).json()["country"] is None
    p = client.get("/api/geo/preview/cn", params={"direction": "inbound"}, headers=v).json()
    assert p["networks"] == 2 and p["lab_effect"].startswith("inbound: none")
    assert client.get("/api/geo/preview/XX", headers=v).status_code == 404
    assert client.get("/api/geo/status").status_code == 401
    real = {
        "kind": "geo_block",
        "target": {
            "type": "country",
            "country_code": "CN",
            "direction": "inbound",
            "simulated": False,
        },
        "duration_s": 600,
        "reason": "real country",
    }
    r = client.post("/api/policies", json=real, headers=tok["admin"])
    assert r.status_code == 200 and r.json()["state"] == "applied_unverified", r.text
    assert r.json()["verification"]["traffic_inbound"].startswith("n/a")

    # FW01's pull source: header with sha256 of the body, then the networks
    import hashlib

    fw = tok["fw"]
    r = client.get("/api/geo/enforcement/inbound", headers=fw)
    assert r.status_code == 200 and r.headers["content-type"].startswith("text/plain")
    head, body = r.text.split("\n", 1)
    assert body == "1.0.1.0/24\n1.0.2.0/23\n"
    assert head.endswith("sha256=" + hashlib.sha256(body.encode()).hexdigest())
    assert client.get("/api/geo/enforcement/outbound", headers=fw).text.startswith(
        "# afw-geo direction=outbound countries=- count=0"
    )
    # the firewall credential reads the country tables and nothing else
    assert client.get("/api/overview", headers=fw).status_code == 403
    assert client.get("/api/geo/status", headers=fw).status_code == 403
    assert client.get("/api/geo/enforcement/inbound").status_code == 401
