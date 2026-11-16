"""Bearer-token authentication with roles (firewall < viewer < operator < admin).

``firewall`` is FW01's pull credential (ADR-036): it may fetch the published
country tables and nothing else, because every other endpoint needs viewer or above.

Tokens are stored only as SHA-256 hashes in the tokens file (outside Git). Each entry may
carry an ``expires`` date (UTC); an expired token is refused. The file is re-read when it
changes on disk, so ``afw token revoke`` takes effect immediately without a restart.
"""

from __future__ import annotations

import hashlib
import hmac
import logging
import os
import secrets
import stat
from datetime import UTC, date, datetime, timedelta
from enum import IntEnum
from pathlib import Path
from typing import Annotated, Any

import yaml
from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel

log = logging.getLogger(__name__)

DEFAULT_TTL_DAYS = 90


class Role(IntEnum):
    FIREWALL = 0
    VIEWER = 1
    OPERATOR = 2
    ADMIN = 3


class Principal(BaseModel):
    name: str
    role: Role
    channel: str = "api"  # "api" or "mcp" — recorded as policy origin


class TokenStore:
    def __init__(self, path: Path) -> None:
        self.path = path
        self._entries: list[tuple[str, Principal, date | None]] = []
        self._mtime_ns: int | None = None
        self._load()

    def _load(self) -> None:
        entries: list[tuple[str, Principal, date | None]] = []
        mtime: int | None = None
        if self.path.exists():
            st = self.path.stat()
            mtime = st.st_mtime_ns
            if st.st_mode & stat.S_IRWXO:  # group access is legitimate (root:afwctl 0640)
                log.warning("token file %s is world-accessible; chmod o-rwx", self.path)
            for item in yaml.safe_load(self.path.read_text()) or []:
                exp = item.get("expires")
                entries.append(
                    (
                        item["sha256"],
                        Principal(
                            name=item["name"],
                            role=Role[item["role"].upper()],
                            channel=item.get("channel", "api"),
                        ),
                        date.fromisoformat(str(exp)) if exp else None,
                    )
                )
        self._entries, self._mtime_ns = entries, mtime

    def _refresh(self) -> None:
        try:
            current = self.path.stat().st_mtime_ns if self.path.exists() else None
        except OSError:
            return
        if current != self._mtime_ns:
            self._load()

    def lookup(self, token: str, now: datetime | None = None) -> Principal | None:
        self._refresh()
        today = (now or datetime.now(UTC)).date()
        digest = hashlib.sha256(token.encode()).hexdigest()
        found: Principal | None = None
        for stored, principal_, expires in self._entries:  # no early exit: constant work
            if hmac.compare_digest(stored, digest) and (expires is None or today <= expires):
                found = principal_
        return found

    @staticmethod
    def issue(
        name: str,
        role: str,
        channel: str = "api",
        ttl_days: int | None = None,
        now: datetime | None = None,
    ) -> tuple[str, dict[str, str]]:
        """Create a token. ``ttl_days=None`` means no expiry (kept for tests and old files)."""
        token = secrets.token_urlsafe(32)
        today = (now or datetime.now(UTC)).date()
        entry = {
            "name": name,
            "role": role,
            "channel": channel,
            "sha256": hashlib.sha256(token.encode()).hexdigest(),
            "created": today.isoformat(),
        }
        if ttl_days:
            entry["expires"] = (today + timedelta(days=ttl_days)).isoformat()
        return token, entry


def read_entries(path: Path) -> list[dict[str, Any]]:
    return (yaml.safe_load(path.read_text()) or []) if path.exists() else []


def write_entries(path: Path, entries: list[dict[str, Any]]) -> None:
    """Write the token file atomically with mode 0600 (never briefly world-readable)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.write(yaml.safe_dump(entries))
    tmp.replace(path)


def principal(request: Request) -> Principal:
    store: TokenStore = request.app.state.tokens
    header = request.headers.get("authorization", "")
    token = header.removeprefix("Bearer ").strip() if header.startswith("Bearer ") else ""
    found = store.lookup(token) if token else None
    if found is None:
        raise HTTPException(status.HTTP_401_UNAUTHORIZED, "invalid or missing bearer token")
    return found


def require(role: Role):  # type: ignore[no-untyped-def]
    def dep(p: Annotated[Principal, Depends(principal)]) -> Principal:
        if p.role < role:
            raise HTTPException(status.HTTP_403_FORBIDDEN, f"{role.name.lower()} role required")
        return p

    return dep
