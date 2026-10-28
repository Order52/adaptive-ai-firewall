"""Live: the controller API is HTTPS only, verified against the lab CA (ADR-023)."""

from __future__ import annotations

import os
from pathlib import Path

import certifi
import httpx
import pytest

pytestmark = pytest.mark.skipif(not os.environ.get("AFW_LAB"), reason="needs the GNS3 lab")

CA = Path("~/.config/afw/pki/lab-ca.pem").expanduser()
TOKEN = Path("~/.config/afw/api/dashboard.token").expanduser()


def test_api_serves_https_verified_by_the_lab_ca():
    r = httpx.get(
        "https://10.77.50.10:8080/api/health",
        headers={"Authorization": f"Bearer {TOKEN.read_text().strip()}"},
        verify=str(CA),
        timeout=10,
    )
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_plain_http_is_not_served():
    with pytest.raises(httpx.HTTPError):
        r = httpx.get("http://10.77.50.10:8080/api/health", timeout=10)
        r.raise_for_status()


def test_a_client_with_only_public_cas_refuses_the_certificate():
    # certifi, not the system store: this host trusts the lab CA system-wide
    with pytest.raises(httpx.ConnectError) as e:
        httpx.get("https://10.77.50.10:8080/api/health", verify=certifi.where())
    assert "CERTIFICATE_VERIFY_FAILED" in str(e.value)
