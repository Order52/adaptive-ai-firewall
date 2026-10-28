"""MCP server (official SDK, ``mcp`` 2.x ``MCPServer``).

A thin, typed client of the controller REST API. It holds a token issued with
``channel=mcp`` so every mutation is recorded with origin ``mcp`` and passes
through exactly the same validator / enforcement path as AI decisions. There is
no tool that accepts free-form firewall or WAF text.

Run (stdio, for a local MCP client):
    AFW_API_URL=https://10.77.50.10:8080 AFW_API_CA=lab-ca.pem \\
    AFW_MCP_TOKEN_FILE=secrets/mcp.token afw-mcp
"""

from __future__ import annotations

import os
from ipaddress import IPv4Address
from pathlib import Path
from typing import Any, Literal

import httpx
from mcp.server import MCPServer

server = MCPServer(
    name="afw",
    title="AI-Adaptive-Firewall",
    instructions=(
        "Inspect and operate the AI-Adaptive-Firewall lab. Risk scores are evidence scores, "
        "not probabilities. Mutations are validated server-side; protected/management "
        "addresses are always refused. Country policies on lab addresses are SIMULATED unless "
        "a real GeoIP database is configured. Direction semantics: 'inbound' = connections "
        "initiated from the country toward protected services; 'outbound' = connections "
        "initiated from lab networks toward the country."
    ),
)


def _client() -> httpx.Client:
    token = (
        os.environ.get("AFW_MCP_TOKEN")
        or Path(os.environ.get("AFW_MCP_TOKEN_FILE", "secrets/mcp.token")).read_text().strip()
    )
    # When the controller API serves HTTPS, AFW_API_CA points at the lab CA so
    # the certificate is verified (never verify=False on the data path).
    ca = os.environ.get("AFW_API_CA")
    verify: str | bool = ca if ca else True
    return httpx.Client(
        base_url=os.environ.get("AFW_API_URL", "http://127.0.0.1:8080"),
        headers={"Authorization": f"Bearer {token}"},
        timeout=30,
        verify=verify,
    )


def _get(path: str, **params: Any) -> Any:
    with _client() as c:
        r = c.get(path, params={k: v for k, v in params.items() if v is not None})
        r.raise_for_status()
        return r.json()


def _obj(data: Any) -> dict[str, Any]:
    if not isinstance(data, dict):
        raise ValueError("expected a JSON object from the AFW API")
    return data


def _rows(data: Any) -> list[dict[str, Any]]:
    if not isinstance(data, list) or not all(isinstance(x, dict) for x in data):
        raise ValueError("expected a JSON array of objects from the AFW API")
    return data


def _post(path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    with _client() as c:
        r = c.post(path, json=body or {})
        if r.status_code >= 400:
            return {"error": r.status_code, "detail": r.json().get("detail", r.text)}
        data = r.json()
        return data if isinstance(data, dict) else {"result": data}


# ------------------------------------------------------------------ read tools
@server.tool()
def lab_health() -> dict[str, Any]:
    """Controller health: mode, strategy, telemetry state, enforcement backend read-back."""
    return _obj(_get("/api/health"))


@server.tool()
def overview() -> dict[str, Any]:
    """Live sources with risk, active policies, model/profile versions, resources."""
    return _obj(_get("/api/overview"))


@server.tool()
def recent_detections(limit: int = 20) -> list[dict[str, Any]]:
    """Recent anomalous detector outputs (with feature attributions)."""
    return _rows(_get("/api/detections", limit=min(limit, 200)))


@server.tool()
def risk_assessments(
    min_score: float = 25.0, source_ip: IPv4Address | None = None, limit: int = 20
) -> list[dict[str, Any]]:
    """Correlated risk assessments with their evidence items."""
    return _rows(
        _get(
            "/api/assessments",
            min_score=min_score,
            source=str(source_ip) if source_ip else None,
            limit=min(limit, 200),
        )
    )


@server.tool()
def model_status() -> list[dict[str, Any]]:
    """Versioned models with validation metrics and status."""
    return _rows(_get("/api/models"))


@server.tool()
def application_profiles() -> list[dict[str, Any]]:
    """Behavioral profile versions (trusted/candidate/retired) and provenance."""
    return [
        {
            k: p[k]
            for k in (
                "app_id",
                "version",
                "status",
                "provenance",
                "content_hash",
                "reviewed_by",
                "review_note",
            )
        }
        | {"endpoints": [f"{e['method']} {e['route']}" for e in p["endpoints"]]}
        for p in _get("/api/profiles")
    ]


@server.tool()
def adaptation_status() -> dict[str, Any]:
    """Shadow learning, drift reports and candidate evaluation gates."""
    return _obj(_get("/api/adaptation"))


@server.tool()
def shadow_learning() -> dict[str, Any]:
    """Online challenger (shadow only): learning state, why windows were excluded,
    checkpoints, and champion-vs-challenger agreement. Read-only; the challenger
    never affects enforcement."""
    return _obj(_get("/api/learning/shadow"))


@server.tool()
def challenger_lifecycle() -> dict[str, Any]:
    """Promotion-gate evaluations of the online challenger and the probation of any
    promoted one. Read-only: evaluation, promotion and rollback are admin REST
    actions reserved for a human reviewer."""
    return _obj(_get("/api/learning/challenger"))


@server.tool()
def active_policies() -> list[dict[str, Any]]:
    """Policies currently owning enforcement state."""
    return _rows(_get("/api/overview")["active_policies"])


@server.tool()
def policy_history(limit: int = 30) -> list[dict[str, Any]]:
    """Recent policy decisions including rejected/expired/rolled back."""
    return _rows(_get("/api/policies", limit=min(limit, 200)))


@server.tool()
def explain_policy(policy_id: str) -> dict[str, Any]:
    """Recorded explanation: evidence, model/profile, response, enforcement, legit traffic."""
    return _obj(_get(f"/api/policies/{policy_id}/explain"))


@server.tool()
def experiment_results(name: str | None = None) -> list[dict[str, Any]]:
    """M0/M1/M2 offline-replay comparison rows recorded by `afw experiment replay`.

    Each row is one arm (static / statistical / ML-assisted) with precision,
    recall, FPR, source containment and detection latency. The `scenario` field
    says whether the data is a synthetic demo or a captured lab run — only cite
    captured-lab rows as results.
    """
    return _rows(_get("/api/experiments", name=name))


@server.tool()
def verify_isolation() -> dict[str, Any]:
    """Run the zone-isolation checks from inside the guests (the G1 gate).

    Confirms clients cannot bypass the WAF to the app, cannot reach each other,
    have no Internet, and that management reaches everything. Slow (SSHes into
    guests). Returns per-check pass/fail plus a summary.
    """
    from afw.lab.verify import verify as _verify

    results = _verify()
    checks = [
        {
            "src": c.src,
            "dst": c.dst,
            "port": c.port or "icmp",
            "expect": "allow" if c.allowed else "deny",
            "observed": got,
            "passed": ok,
            "why": c.why,
        }
        for c, got, ok in results
    ]
    passed = sum(1 for c in checks if c["passed"])
    return {
        "passed": passed,
        "total": len(checks),
        "all_passed": passed == len(checks),
        "checks": checks,
    }


# ------------------------------------------------------------- mutation tools
def _source_intent(kind: str, ip: IPv4Address, duration_s: int, reason: str) -> dict[str, Any]:
    return {
        "kind": kind,
        "target": {"type": "source", "source_ip": str(ip)},
        "duration_s": duration_s,
        "reason": reason[:200],
    }


@server.tool()
def simulate_block(source_ip: IPv4Address, duration_s: int = 300) -> dict[str, Any]:
    """Dry-run: would blocking this source be valid and would it auto-apply?"""
    return _post(
        "/api/policies/simulate",
        _source_intent("source_block", source_ip, duration_s, "mcp simulate"),
    )


@server.tool()
def block_source(source_ip: IPv4Address, duration_s: int = 300, reason: str = "") -> dict[str, Any]:
    """Temporarily block one source from the protected web service (validated, expiring)."""
    return _post(
        "/api/policies", _source_intent("source_block", source_ip, duration_s, reason or "mcp")
    )


@server.tool()
def unblock(policy_id: str, reason: str = "operator unblock") -> dict[str, Any]:
    """Revoke a policy; rollback is confirmed by device read-back."""
    return _post(f"/api/policies/{policy_id}/revoke", {"reason": reason})


@server.tool()
def approve_policy(policy_id: str) -> dict[str, Any]:
    """Approve a pending AI proposal (assisted mode)."""
    return _post(f"/api/policies/{policy_id}/approve")


@server.tool()
def reject_policy(policy_id: str, reason: str) -> dict[str, Any]:
    """Reject a pending AI proposal."""
    return _post(f"/api/policies/{policy_id}/reject", {"reason": reason})


@server.tool()
def set_mode(mode: Literal["monitor", "assisted", "auto"]) -> dict[str, Any]:
    """Change the operating mode (requires an admin-role MCP token)."""
    return _post("/api/mode", {"mode": mode})


@server.tool()
def country_policy(
    country_code: str,
    direction: Literal["inbound", "outbound", "both"],
    duration_s: int = 3600,
    simulated: bool = True,
) -> dict[str, Any]:
    """OPTIONAL EXTENSION: country-scoped policy, e.g. 'block incoming traffic from China'
    -> country_code='CN', direction='inbound'. Only clearly-labelled simulated lab mappings
    can be enforced; real-country policies are refused (use geo_preview to see what one
    would cover)."""
    return _post(
        "/api/policies",
        {
            "kind": "geo_block",
            "target": {
                "type": "country",
                "country_code": country_code.upper(),
                "direction": direction,
                "simulated": simulated,
            },
            "duration_s": duration_s,
            "reason": f"mcp country policy {direction}",
        },
    )


@server.tool()
def geo_preview(
    country_code: str, direction: Literal["inbound", "outbound", "both"] = "inbound"
) -> dict[str, Any]:
    """Read-only: what a REAL country policy would cover (networks, addresses, observed
    lab sources in that country) from the installed DB-IP database, with its age."""
    return _obj(_get(f"/api/geo/preview/{country_code}", direction=direction))


@server.tool()
def geo_lookup(ip: IPv4Address) -> dict[str, Any]:
    """Read-only: country of an IPv4 address (None for private/lab space)."""
    return _obj(_get(f"/api/geo/lookup/{ip}"))


@server.tool()
def feedback(
    label: Literal["true_positive", "false_positive", "benign_change"],
    source_ip: IPv4Address | None = None,
    policy_id: str | None = None,
    note: str = "",
) -> dict[str, Any]:
    """Record analyst feedback used by drift monitoring and candidate learning."""
    return _post(
        "/api/feedback",
        {
            "label": label,
            "source_ip": str(source_ip) if source_ip else None,
            "policy_id": policy_id,
            "note": note,
        },
    )


# GNS3 lab-infrastructure tools (host-side; registered on the same server).
from afw.mcp import gns3_tools  # noqa: E402

gns3_tools.register(server)


def main() -> None:
    server.run("stdio")


if __name__ == "__main__":
    main()
