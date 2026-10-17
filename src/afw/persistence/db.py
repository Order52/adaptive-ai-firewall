"""Engine creation and migrations."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from alembic import command
from alembic.config import Config
from sqlalchemy import Engine, create_engine, event

MIGRATIONS = Path(__file__).parent / "migrations"


def make_engine(url: str) -> Engine:
    if url.startswith("sqlite:///"):
        Path(url.removeprefix("sqlite:///")).parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(url, future=True, pool_pre_ping=True)
    if engine.dialect.name == "sqlite":

        @event.listens_for(engine, "connect")
        def _pragmas(dbapi_conn: Any, _: Any) -> None:
            cur = dbapi_conn.cursor()
            cur.execute("PRAGMA journal_mode=WAL")
            cur.execute("PRAGMA synchronous=NORMAL")
            cur.execute("PRAGMA busy_timeout=5000")
            cur.execute("PRAGMA foreign_keys=ON")
            cur.close()

    return engine


def alembic_config(url: str) -> Config:
    cfg = Config()
    cfg.set_main_option("script_location", str(MIGRATIONS))
    cfg.set_main_option("sqlalchemy.url", url)
    return cfg


def upgrade(url: str, revision: str = "head") -> None:
    make_engine(url).dispose()  # ensure the directory exists
    command.upgrade(alembic_config(url), revision)


def utc_naive(dt: datetime) -> datetime:
    """Store timestamps as naive UTC (portable across SQLite/PostgreSQL)."""
    return dt.astimezone(UTC).replace(tzinfo=None) if dt.tzinfo else dt
