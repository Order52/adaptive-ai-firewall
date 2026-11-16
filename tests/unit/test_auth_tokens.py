"""Token expiry, revocation (hot reload) and file permissions."""

from __future__ import annotations

import os
import stat
from datetime import UTC, datetime, timedelta

from afw.api.auth import Role, TokenStore, read_entries, write_entries

T0 = datetime(2026, 11, 16, 12, 0, tzinfo=UTC)


def _store(tmp_path, *entries):
    path = tmp_path / "tokens.yaml"
    write_entries(path, list(entries))
    return path, TokenStore(path)


def test_token_without_expiry_is_always_valid(tmp_path):
    tok, e = TokenStore.issue("a", "viewer")
    _, store = _store(tmp_path, e)
    assert "expires" not in e
    assert store.lookup(tok, now=T0 + timedelta(days=5000)).name == "a"


def test_expiry_is_enforced_inclusive_of_last_day(tmp_path):
    tok, e = TokenStore.issue("a", "operator", ttl_days=90, now=T0)
    assert e["expires"] == "2027-02-14" and e["created"] == "2026-11-16"
    _, store = _store(tmp_path, e)
    assert store.lookup(tok, now=T0 + timedelta(days=90)) is not None  # last valid day
    assert store.lookup(tok, now=T0 + timedelta(days=91)) is None


def test_unknown_token_and_role_parsing(tmp_path):
    tok, e = TokenStore.issue("a", "admin")
    _, store = _store(tmp_path, e)
    assert store.lookup(tok).role is Role.ADMIN
    assert store.lookup("not-a-token") is None
    assert store.lookup("") is None


def test_revocation_takes_effect_without_restart(tmp_path):
    t1, e1 = TokenStore.issue("a", "viewer")
    t2, e2 = TokenStore.issue("b", "viewer")
    path, store = _store(tmp_path, e1, e2)
    assert store.lookup(t1) and store.lookup(t2)
    write_entries(path, [e2])
    # make the change visible even on a coarse-mtime filesystem
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    assert store.lookup(t1) is None
    assert store.lookup(t2) is not None


def test_new_token_is_picked_up_live(tmp_path):
    path, store = _store(tmp_path)
    tok, e = TokenStore.issue("late", "viewer")
    assert store.lookup(tok) is None
    write_entries(path, [e])
    st = path.stat()
    os.utime(path, ns=(st.st_atime_ns, st.st_mtime_ns + 1_000_000_000))
    assert store.lookup(tok).name == "late"


def test_token_file_is_written_0600_and_roundtrips(tmp_path):
    _, e = TokenStore.issue("a", "viewer", ttl_days=1, now=T0)
    path, _ = _store(tmp_path, e)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert read_entries(path)[0]["name"] == "a"
    assert not list(tmp_path.glob("*.tmp"))


def test_missing_file_means_no_tokens(tmp_path):
    store = TokenStore(tmp_path / "absent.yaml")
    assert store.lookup("anything") is None
