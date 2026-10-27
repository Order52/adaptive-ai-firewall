"""Data store for the rental app — a real 3-tier split.

When ``DATABASE_URL`` is set, persistent business data (car catalogue, users,
bookings, reviews) lives in PostgreSQL on the DB tier (DB01, its own zone); the
app reaches it only across the firewall (APP -> DB:5432). When it is unset, an
in-memory store is used so unit tests and offline runs need no database.

Reference data (the catalogue and the synthetic users) is defined once here and
seeded into the database on first start, so password hashes have a single source
of truth (``_pw_hash``) whichever backend is active. Session tokens stay in the
app process (ephemeral auth state, not business data).
"""

from __future__ import annotations

import hashlib
import os
from typing import Any, Protocol

_SALT = b"afw-lab-static-salt"  # synthetic users only


def pw_hash(pw: str) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode(), _SALT, 20_000).hex()


def _catalogue() -> list[dict[str, Any]]:
    return [
        {"id": i, "model": m, "daily_rate": 30 + (i * 7) % 90, "city": c}
        for i, (m, c) in enumerate(
            [
                (f"Model-{chr(65 + k % 26)}{k}", ["Tripoli", "Benghazi", "Misrata"][k % 3])
                for k in range(40)
            ],
            start=1,
        )
    ]


def _users() -> dict[str, str]:
    return {f"user{n}": pw_hash(f"pw-{n}") for n in range(1, 51)}


class Store(Protocol):
    def cars(self, city: str | None) -> list[dict[str, Any]]: ...
    def car(self, car_id: int) -> dict[str, Any] | None: ...
    def car_count(self) -> int: ...
    def user_pw_hash(self, username: str) -> str | None: ...
    def add_booking(self, username: str, car_id: int, days: int, city: str) -> dict[str, Any]: ...
    def bookings(self, username: str) -> list[dict[str, Any]]: ...
    def booking(self, booking_id: int, username: str) -> dict[str, Any] | None: ...
    def add_review(self, username: str, car_id: int, stars: int, text: str) -> dict[str, Any]: ...
    def reviews(self, car_id: int) -> list[dict[str, Any]]: ...
    def backend(self) -> str: ...


class MemoryStore:
    """In-process store (default; used by tests and offline runs)."""

    def __init__(self) -> None:
        self._cars = _catalogue()
        self._users = _users()
        self._bookings: dict[int, dict[str, Any]] = {}
        self._reviews: dict[int, list[dict[str, Any]]] = {}

    def cars(self, city: str | None) -> list[dict[str, Any]]:
        return [c for c in self._cars if city is None or c["city"] == city]

    def car(self, car_id: int) -> dict[str, Any] | None:
        return self._cars[car_id - 1] if 1 <= car_id <= len(self._cars) else None

    def car_count(self) -> int:
        return len(self._cars)

    def user_pw_hash(self, username: str) -> str | None:
        return self._users.get(username)

    def add_booking(self, username: str, car_id: int, days: int, city: str) -> dict[str, Any]:
        bid = len(self._bookings) + 1
        row = {"id": bid, "user": username, "car_id": car_id, "days": days, "city": city}
        self._bookings[bid] = row
        return row

    def bookings(self, username: str) -> list[dict[str, Any]]:
        return [b for b in self._bookings.values() if b["user"] == username]

    def booking(self, booking_id: int, username: str) -> dict[str, Any] | None:
        b = self._bookings.get(booking_id)
        return b if b is not None and b["user"] == username else None

    def add_review(self, username: str, car_id: int, stars: int, text: str) -> dict[str, Any]:
        row = {"user": username, "car_id": car_id, "stars": stars, "text": text}
        self._reviews.setdefault(car_id, []).append(row)
        return row

    def reviews(self, car_id: int) -> list[dict[str, Any]]:
        return self._reviews.get(car_id, [])

    def backend(self) -> str:
        return "memory"


class PostgresStore:
    """PostgreSQL-backed store on the DB tier. Self-migrates and seeds once."""

    def __init__(self, dsn: str) -> None:
        from psycopg_pool import ConnectionPool

        self._pool = ConnectionPool(dsn, min_size=1, max_size=4, kwargs={"autocommit": True})
        self._pool.wait(timeout=30)
        self._migrate_and_seed()

    def _migrate_and_seed(self) -> None:
        ddl = """
        CREATE TABLE IF NOT EXISTS cars (
            id integer PRIMARY KEY, model text NOT NULL,
            daily_rate integer NOT NULL, city text NOT NULL);
        CREATE TABLE IF NOT EXISTS users (
            username text PRIMARY KEY, pw_hash text NOT NULL);
        CREATE TABLE IF NOT EXISTS bookings (
            id serial PRIMARY KEY, username text NOT NULL REFERENCES users(username),
            car_id integer NOT NULL REFERENCES cars(id), days integer NOT NULL,
            city text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
        CREATE TABLE IF NOT EXISTS reviews (
            id serial PRIMARY KEY, car_id integer NOT NULL REFERENCES cars(id),
            username text NOT NULL REFERENCES users(username), stars integer NOT NULL,
            text text NOT NULL, created_at timestamptz NOT NULL DEFAULT now());
        """
        with self._pool.connection() as conn:
            conn.execute(ddl)
            if conn.execute("SELECT count(*) FROM cars").fetchone()[0] == 0:
                with conn.cursor() as cur:
                    cur.executemany(
                        "INSERT INTO cars (id, model, daily_rate, city) VALUES (%s,%s,%s,%s)",
                        [(c["id"], c["model"], c["daily_rate"], c["city"]) for c in _catalogue()],
                    )
            if conn.execute("SELECT count(*) FROM users").fetchone()[0] == 0:
                with conn.cursor() as cur:
                    cur.executemany(
                        "INSERT INTO users (username, pw_hash) VALUES (%s,%s)",
                        list(_users().items()),
                    )

    def cars(self, city: str | None) -> list[dict[str, Any]]:
        sql = "SELECT id, model, daily_rate, city FROM cars"
        args: tuple[Any, ...] = ()
        if city is not None:
            sql += " WHERE city = %s"
            args = (city,)
        sql += " ORDER BY id"
        with self._pool.connection() as conn:
            rows = conn.execute(sql, args).fetchall()
        return [{"id": r[0], "model": r[1], "daily_rate": r[2], "city": r[3]} for r in rows]

    def car(self, car_id: int) -> dict[str, Any] | None:
        with self._pool.connection() as conn:
            r = conn.execute(
                "SELECT id, model, daily_rate, city FROM cars WHERE id = %s", (car_id,)
            ).fetchone()
        return {"id": r[0], "model": r[1], "daily_rate": r[2], "city": r[3]} if r else None

    def car_count(self) -> int:
        with self._pool.connection() as conn:
            return int(conn.execute("SELECT count(*) FROM cars").fetchone()[0])

    def user_pw_hash(self, username: str) -> str | None:
        with self._pool.connection() as conn:
            r = conn.execute(
                "SELECT pw_hash FROM users WHERE username = %s", (username,)
            ).fetchone()
        return r[0] if r else None

    def add_booking(self, username: str, car_id: int, days: int, city: str) -> dict[str, Any]:
        with self._pool.connection() as conn:
            r = conn.execute(
                "INSERT INTO bookings (username, car_id, days, city) VALUES (%s,%s,%s,%s) "
                "RETURNING id",
                (username, car_id, days, city),
            ).fetchone()
        return {"id": r[0], "user": username, "car_id": car_id, "days": days, "city": city}

    def bookings(self, username: str) -> list[dict[str, Any]]:
        with self._pool.connection() as conn:
            rows = conn.execute(
                "SELECT id, car_id, days, city FROM bookings WHERE username = %s ORDER BY id",
                (username,),
            ).fetchall()
        return [
            {"id": r[0], "user": username, "car_id": r[1], "days": r[2], "city": r[3]} for r in rows
        ]

    def booking(self, booking_id: int, username: str) -> dict[str, Any] | None:
        with self._pool.connection() as conn:
            r = conn.execute(
                "SELECT id, car_id, days, city FROM bookings WHERE id = %s AND username = %s",
                (booking_id, username),
            ).fetchone()
        if r is None:
            return None
        return {"id": r[0], "user": username, "car_id": r[1], "days": r[2], "city": r[3]}

    def add_review(self, username: str, car_id: int, stars: int, text: str) -> dict[str, Any]:
        with self._pool.connection() as conn:
            conn.execute(
                "INSERT INTO reviews (car_id, username, stars, text) VALUES (%s,%s,%s,%s)",
                (car_id, username, stars, text),
            )
        return {"user": username, "car_id": car_id, "stars": stars, "text": text}

    def reviews(self, car_id: int) -> list[dict[str, Any]]:
        with self._pool.connection() as conn:
            rows = conn.execute(
                "SELECT username, stars, text FROM reviews WHERE car_id = %s ORDER BY id",
                (car_id,),
            ).fetchall()
        return [{"user": r[0], "car_id": car_id, "stars": r[1], "text": r[2]} for r in rows]

    def backend(self) -> str:
        return "postgres"


def make_store() -> Store:
    """Return the Postgres store if ``DATABASE_URL`` is set, else the in-memory store."""
    dsn = os.environ.get("DATABASE_URL")
    return PostgresStore(dsn) if dsn else MemoryStore()
