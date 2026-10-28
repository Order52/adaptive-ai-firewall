"""Lab PKI: leaves carry the required SANs, are stable, and are re-issued when one is missing."""

from __future__ import annotations

import subprocess

from afw.lab import pki


def _serial(crt):
    out = subprocess.run(
        [pki.OPENSSL, "x509", "-in", str(crt), "-noout", "-serial"],
        check=True,
        capture_output=True,
        text=True,
    )
    return out.stdout.strip()


def test_controller_leaf_covers_the_ssh_tunnel_names(tmp_path):
    crt, _ = pki.ensure_leaf("CTRL01", ["10.77.50.10", "127.0.0.1"], tmp_path)
    assert pki._cert_sans(crt) == {
        "IP:10.77.50.10",
        "IP:127.0.0.1",
        "DNS:ctrl01.lab.afw",
        "DNS:localhost",
    }


def test_existing_leaf_is_kept_when_its_sans_suffice(tmp_path):
    crt, _ = pki.ensure_leaf("FW01", ["10.77.50.1"], tmp_path)
    first = _serial(crt)
    pki.ensure_leaf("FW01", ["10.77.50.1"], tmp_path)
    assert _serial(crt) == first


def test_leaf_missing_a_required_san_is_reissued_under_the_same_ca(tmp_path):
    crt, _ = pki.ensure_leaf("CTRL01", ["10.77.50.10"], tmp_path)
    first = _serial(crt)
    pki.ensure_leaf("CTRL01", ["10.77.50.10", "127.0.0.1"], tmp_path)
    assert _serial(crt) != first
    assert "IP:127.0.0.1" in pki._cert_sans(crt)
    subprocess.run(
        [pki.OPENSSL, "verify", "-CAfile", str(tmp_path / "lab-ca.pem"), str(crt)],
        check=True,
        capture_output=True,
    )
