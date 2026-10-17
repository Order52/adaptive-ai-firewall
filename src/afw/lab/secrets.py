"""Generate lab secrets once on the host (``~/.config/afw``, outside Git).

Ansible only copies what this produces; re-running never rotates anything.
"""

from __future__ import annotations

import secrets
from pathlib import Path

import yaml

from afw.api.auth import TokenStore
from afw.lab.pki import ensure_ca, ensure_leaf

BASE = Path("~/.config/afw").expanduser()
API_PRINCIPALS = [  # name, role, channel
    ("admin", "admin", "api"),
    ("operator", "operator", "api"),
    ("dashboard", "viewer", "api"),
    ("mcp", "operator", "mcp"),
]
LEAVES = {
    "WAF01": ["10.77.30.10"],  # + DNS rental.lab.afw (see pki.ensure_leaf)
    "CTRL01": ["10.77.50.10"],
    "FW01": ["10.77.50.1"],
}


def _write_secret(path: Path, value: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    path.write_text(value + "\n")
    path.chmod(0o600)


def ensure_lab_secrets(base: Path = BASE) -> list[str]:
    created: list[str] = []
    for name in ("waf-helper", "probe"):
        p = base / "tokens" / f"{name}.token"
        if not p.exists():
            _write_secret(p, secrets.token_urlsafe(32))
            created.append(str(p))
    hashes_file = base / "api" / "api_tokens.yaml"
    entries = yaml.safe_load(hashes_file.read_text()) if hashes_file.exists() else []
    known = {e["name"] for e in entries or []}
    for name, role, channel in API_PRINCIPALS:
        if name in known and (base / "api" / f"{name}.token").exists():
            continue
        token, entry = TokenStore.issue(name, role, channel)
        _write_secret(base / "api" / f"{name}.token", token)
        entries = [e for e in entries or [] if e["name"] != name] + [entry]
        created.append(f"api token {name} ({role}/{channel})")
    hashes_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    hashes_file.write_text(yaml.safe_dump(entries))
    hashes_file.chmod(0o600)
    ensure_ca()
    for leaf, ips in LEAVES.items():
        ensure_leaf(leaf, ips)
    return created
