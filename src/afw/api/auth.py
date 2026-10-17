"""Bearer-token authentication with roles (viewer < operator < admin).

Tokens are stored only as SHA-256 hashes in the tokens file (outside Git).
"""

from __future__ import annotations

import hashlib
import hmac
import secrets
from enum import IntEnum
from pathlib import Path
from typing import Annotated

import yaml
from fastapi import Depends, HTTPException, Request, status
from pydantic import BaseModel


class Role(IntEnum):
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
        self._entries: list[tuple[str, Principal]] = []
        if path.exists():
            data = yaml.safe_load(path.read_text()) or []
            for item in data:
                self._entries.append(
                    (
                        item["sha256"],
                        Principal(
                            name=item["name"],
                            role=Role[item["role"].upper()],
                            channel=item.get("channel", "api"),
                        ),
                    )
                )

    def lookup(self, token: str) -> Principal | None:
        digest = hashlib.sha256(token.encode()).hexdigest()
        for stored, principal in self._entries:
            if hmac.compare_digest(stored, digest):
                return principal
        return None

    @staticmethod
    def issue(name: str, role: str, channel: str = "api") -> tuple[str, dict[str, str]]:
        token = secrets.token_urlsafe(32)
        return token, {
            "name": name,
            "role": role,
            "channel": channel,
            "sha256": hashlib.sha256(token.encode()).hexdigest(),
        }


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
