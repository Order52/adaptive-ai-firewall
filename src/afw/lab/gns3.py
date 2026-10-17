"""Thin client for the official GNS3 2.2 REST API (v2).

Only the calls the lab automation needs; every method is idempotent at the
level of "find by name, else create".
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any

import httpx

JSON = dict[str, Any]


def load_env(path: Path = Path("~/.config/afw/gns3.env")) -> dict[str, str]:
    """Read KEY=VALUE lines from the (untracked) GNS3 credentials file."""
    values: dict[str, str] = {}
    p = path.expanduser()
    if p.exists():
        for line in p.read_text().splitlines():
            if "=" in line and not line.lstrip().startswith("#"):
                k, v = line.split("=", 1)
                values[k.strip()] = v.strip().strip('"').strip("'")
    values.update({k: v for k, v in os.environ.items() if k.startswith("GNS3_")})
    return values


class Gns3Error(RuntimeError):
    pass


class Gns3Client:
    def __init__(self, url: str, user: str, password: str, timeout: float = 60.0) -> None:
        self._http = httpx.Client(
            base_url=url.rstrip("/") + "/v2", auth=(user, password), timeout=timeout
        )

    @classmethod
    def from_env(cls) -> Gns3Client:
        env = load_env()
        try:
            return cls(
                env.get("GNS3_URL", "http://127.0.0.1:3080"), env["GNS3_USER"], env["GNS3_PASSWORD"]
            )
        except KeyError as exc:
            raise Gns3Error(f"missing {exc.args[0]} in ~/.config/afw/gns3.env") from exc

    def _call(self, method: str, path: str, body: JSON | None = None) -> Any:
        r = self._http.request(method, path, json=body)
        if r.status_code >= 400:
            raise Gns3Error(f"{method} {path} -> {r.status_code}: {r.text[:500]}")
        return r.json() if r.content else None

    def version(self) -> JSON:
        return self._call("GET", "/version")  # type: ignore[no-any-return]

    # projects ------------------------------------------------------------
    def find_project(self, name: str) -> JSON | None:
        for p in self._call("GET", "/projects"):
            if p["name"] == name:
                return p  # type: ignore[no-any-return]
        return None

    def ensure_project(self, name: str) -> JSON:
        p = self.find_project(name)
        if p is None:
            p = self._call(
                "POST",
                "/projects",
                {"name": name, "auto_close": False, "auto_open": True, "auto_start": False},
            )
        elif p["status"] != "opened":
            p = self._call("POST", f"/projects/{p['project_id']}/open", {})
        return p

    # nodes ---------------------------------------------------------------
    def nodes(self, pid: str) -> list[JSON]:
        return self._call("GET", f"/projects/{pid}/nodes")  # type: ignore[no-any-return]

    def node_by_name(self, pid: str) -> dict[str, JSON]:
        return {n["name"]: n for n in self.nodes(pid)}

    def create_node(self, pid: str, body: JSON) -> JSON:
        return self._call("POST", f"/projects/{pid}/nodes", body)  # type: ignore[no-any-return]

    def update_node(self, pid: str, nid: str, body: JSON) -> JSON:
        return self._call("PUT", f"/projects/{pid}/nodes/{nid}", body)  # type: ignore[no-any-return]

    def delete_node(self, pid: str, nid: str) -> None:
        self._call("DELETE", f"/projects/{pid}/nodes/{nid}")

    def node_action(self, pid: str, nid: str, action: str) -> None:
        self._call("POST", f"/projects/{pid}/nodes/{nid}/{action}", {})

    # links ---------------------------------------------------------------
    def links(self, pid: str) -> list[JSON]:
        return self._call("GET", f"/projects/{pid}/links")  # type: ignore[no-any-return]

    def create_link(self, pid: str, ends: list[tuple[str, int, int]]) -> JSON:
        body = {
            "nodes": [{"node_id": n, "adapter_number": a, "port_number": p} for n, a, p in ends]
        }
        return self._call("POST", f"/projects/{pid}/links", body)  # type: ignore[no-any-return]

    def wait_status(self, pid: str, nid: str, status: str, timeout: float = 60) -> None:
        end = time.monotonic() + timeout
        while time.monotonic() < end:
            if self._call("GET", f"/projects/{pid}/nodes/{nid}")["status"] == status:
                return
            time.sleep(1)
        raise Gns3Error(f"node {nid} did not reach {status}")
