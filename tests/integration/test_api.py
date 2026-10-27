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
