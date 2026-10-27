"""Authenticated telemetry provenance and event dedup (ADR-029)."""

from __future__ import annotations

import asyncio
import datetime as dt
import ssl
from ipaddress import IPv4Address
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from test_telemetry import RID, access_line, app_line, audit_line

from afw.config import TelemetryConfig
from afw.container import build_container
from afw.domain.events import Provenance
from afw.telemetry.receiver import SyslogReceiver
from afw.telemetry.stats import TelemetryStats

OBS_T = dt.datetime(2026, 9, 21, 14, 13, 25, tzinfo=dt.UTC)  # just after access_line()
WAF = IPv4Address("10.77.30.10")
APP = IPv4Address("10.77.40.10")


def _flush(ctl):
    return ctl.correlator.flush(force=True)


@pytest.fixture
def ctl(settings):
    return build_container(settings, simulated=True).controller


def test_plaintext_observations_are_unverified(ctl):
    ctl.ingest_line(WAF, access_line())
    ctl.ingest_line(APP, app_line())
    (obs,) = _flush(ctl)
    assert obs.provenance is Provenance.UNVERIFIED


def test_authenticated_only_when_every_record_is(ctl):
    ctl.ingest_line(WAF, access_line(), "waf")
    ctl.ingest_line(APP, app_line(), "app")
    ctl.ingest_line(WAF, audit_line(), "waf")
    (obs,) = _flush(ctl)
    assert obs.provenance is Provenance.AUTHENTICATED


def test_unauthenticated_app_record_downgrades_the_observation(ctl):
    ctl.ingest_line(WAF, access_line(), "waf")
    ctl.ingest_line(APP, app_line())  # plaintext app record
    (obs,) = _flush(ctl)
    assert obs.provenance is Provenance.UNVERIFIED


def test_unjoined_request_is_never_authenticated(ctl):
    ctl.ingest_line(WAF, access_line(), "waf")
    (obs,) = _flush(ctl)
    assert not obs.app_joined
    assert obs.provenance is Provenance.UNVERIFIED


def test_sensor_cannot_speak_for_another_role(ctl):
    # A compromised APP sensor forging WAF access lines on its own channel.
    ctl.ingest_line(APP, access_line(), "app")
    assert ctl.correlator.pending == 0
    assert ctl.stats.snapshot()["counts"]["role_mismatch"] == 1


def test_replayed_request_id_is_windowed_once(settings):
    ctl = build_container(settings, simulated=True).controller
    ctl.correlator.join_wait_s = 0.0
    for _ in range(2):
        ctl.ingest_line(WAF, access_line(), "waf")
        ctl.ingest_line(APP, app_line(), "app")
        ctl.tick(OBS_T)
        # simulate the correlator's in-memory dedup cache having rolled over
        ctl.correlator._emitted.clear()
    assert sum(len(dq) for dq in ctl.windows._buf.values()) == 1
    assert ctl.stats.snapshot()["counts"]["duplicate_request_id"] == 1


# ---------------------------------------------------------------- mTLS channel
def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _cert(subject_cn, key, issuer_cn, issuer_key, ca=False, san_ip=None):
    now = dt.datetime.now(dt.UTC)
    b = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
        .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=1))
        .not_valid_after(now + dt.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
    )
    if san_ip:
        import ipaddress

        b = b.add_extension(
            x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address(san_ip))]),
            critical=False,
        )
    return b.sign(issuer_key, hashes.SHA256())


def _write(path: Path, cert, key=None):
    path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    if key is not None:
        path.with_suffix(".key").write_bytes(
            key.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )


@pytest.fixture
def pki(tmp_path):
    ca_key = _key()
    ca = _cert("afw-test-ca", ca_key, "afw-test-ca", ca_key, ca=True)
    _write(tmp_path / "ca.pem", ca)
    srv_key = _key()
    _write(
        tmp_path / "srv.pem",
        _cert("ctrl01", srv_key, "afw-test-ca", ca_key, san_ip="127.0.0.1"),
        srv_key,
    )
    for cn in ("waf01.lab.afw", "intruder.lab.afw"):
        k = _key()
        _write(tmp_path / f"{cn}.pem", _cert(cn, k, "afw-test-ca", ca_key), k)
    rogue_key = _key()  # self-signed: does not chain to the lab CA
    _write(
        tmp_path / "rogue.pem",
        _cert("waf01.lab.afw", rogue_key, "waf01.lab.afw", rogue_key),
        rogue_key,
    )
    return tmp_path


async def _send(port, pki, client: str | None, line: str) -> None:
    ctx = ssl.create_default_context(cafile=str(pki / "ca.pem"))
    ctx.check_hostname = False
    if client:
        ctx.load_cert_chain(pki / f"{client}.pem", pki / f"{client}.key")
    try:
        _, w = await asyncio.open_connection("127.0.0.1", port, ssl=ctx)
        w.write(line.encode() + b"\n")
        await w.drain()
        await asyncio.sleep(0.2)
        w.close()
    except (ssl.SSLError, ConnectionError):
        pass


def _run_receiver(pki, clients):
    cfg = TelemetryConfig(
        listen_host="127.0.0.1",
        listen_port=0,
        tls_port=0,
        tls_cert=pki / "srv.pem",
        tls_key=pki / "srv.key",
        tls_ca=pki / "ca.pem",
        tls_identities={"waf01.lab.afw": "waf"},
    )
    rx = SyslogReceiver(cfg, TelemetryStats())

    async def main():
        from afw.telemetry.receiver import tls_context

        srv = await asyncio.start_server(
            rx._handle_tls, "127.0.0.1", 0, ssl=tls_context(cfg), limit=70000
        )
        port = srv.sockets[0].getsockname()[1]
        async with srv:
            for client in clients:
                await _send(port, pki, client, access_line(RID))
            await asyncio.sleep(0.2)

    asyncio.run(main())
    got = []
    while not rx.lines.empty():
        got.append(rx.lines.get_nowait())
    return got, rx.stats.snapshot()["counts"]


def test_mtls_identity_is_attached_to_lines(pki):
    got, _ = _run_receiver(pki, ["waf01.lab.afw"])
    assert [(str(s), role) for s, _, role in got] == [("127.0.0.1", "waf")]


def test_unknown_identity_untrusted_ca_and_no_cert_are_rejected(pki):
    got, counts = _run_receiver(pki, ["intruder.lab.afw", "rogue", None])
    assert got == []
    assert counts.get("tls_identity_rejected", 0) == 1  # valid chain, unknown CN
