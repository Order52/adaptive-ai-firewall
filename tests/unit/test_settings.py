"""Controller API TLS is gated on both cert and key existing on disk."""

from __future__ import annotations

from pathlib import Path

from afw.config import Settings


def _settings(tmp_path: Path, cert: Path | None, key: Path | None) -> Settings:
    return Settings(config=tmp_path / "lab.yaml", data_dir=tmp_path, tls_cert=cert, tls_key=key)


def test_tls_disabled_without_cert(tmp_path: Path) -> None:
    assert _settings(tmp_path, None, None).tls_enabled() is False


def test_tls_disabled_when_files_missing(tmp_path: Path) -> None:
    s = _settings(tmp_path, tmp_path / "missing.pem", tmp_path / "missing.key")
    assert s.tls_enabled() is False


def test_tls_enabled_when_both_present(tmp_path: Path) -> None:
    cert, key = tmp_path / "c.pem", tmp_path / "c.key"
    cert.write_text("x")
    key.write_text("y")
    assert _settings(tmp_path, cert, key).tls_enabled() is True


def test_tls_disabled_with_only_cert(tmp_path: Path) -> None:
    cert = tmp_path / "c.pem"
    cert.write_text("x")
    assert _settings(tmp_path, cert, tmp_path / "missing.key").tls_enabled() is False
