"""Bounded TCP syslog receiver (LF-framed, as sent by rsyslog omfwd/TCP).

Two listeners share one bounded queue:

* plaintext (``listen_port``): sender identified by its IP only (allowlist).
  Its lines are ``UNVERIFIED`` and never feed online learning (ADR-029).
* mutually authenticated TLS (``tls_port``, optional): the client certificate
  must chain to the lab CA and its common name must be a configured sensor
  identity; that identity's role ("waf", "app" or "ids") travels with every line.

Only configured sender addresses are accepted. Lines above ``max_line_bytes``
are dropped and counted. When the queue is full new lines are dropped (never
blocking senders indefinitely) and counted, which marks telemetry as degraded.
"""

from __future__ import annotations

import asyncio
import contextlib
import queue
import ssl
import threading
from ipaddress import IPv4Address, ip_address

import structlog

from afw.config import TelemetryConfig
from afw.telemetry.stats import TelemetryStats

log = structlog.get_logger(__name__)

# (sender IP, line, authenticated sensor role or None)
Line = tuple[IPv4Address, str, str | None]


def tls_context(cfg: TelemetryConfig) -> ssl.SSLContext:
    if not (cfg.tls_cert and cfg.tls_key and cfg.tls_ca):
        raise ValueError("tls_port requires tls_cert, tls_key and tls_ca")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_cert_chain(cfg.tls_cert, cfg.tls_key)
    ctx.load_verify_locations(cafile=str(cfg.tls_ca))
    return ctx


def peer_role(cert: dict[str, object] | None, identities: dict[str, str]) -> str | None:
    """Role of a verified client certificate, by exact common-name match."""
    if not cert:
        return None
    subject = cert.get("subject", ())
    assert isinstance(subject, tuple)
    for rdn in subject:
        for key, value in rdn:
            if key == "commonName" and value in identities:
                return identities[value]
    return None


class SyslogReceiver:
    def __init__(self, cfg: TelemetryConfig, stats: TelemetryStats) -> None:
        self.cfg = cfg
        self.stats = stats
        self.lines: queue.Queue[Line] = queue.Queue(maxsize=cfg.queue_size)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._servers: list[asyncio.base_events.Server] = []

    def _sender(
        self, writer: asyncio.StreamWriter, allowed: tuple[IPv4Address, ...]
    ) -> IPv4Address | None:
        peer = writer.get_extra_info("peername")
        try:
            addr = ip_address(peer[0])
        except (TypeError, ValueError):
            return None
        if not isinstance(addr, IPv4Address) or (allowed and addr not in allowed):
            self.stats.inc("sender_rejected")
            return None
        return addr

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = self._sender(writer, self.cfg.allowed_senders)
        if addr is None:
            writer.close()
            return
        await self._pump(reader, writer, addr, None)

    async def _handle_tls(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        addr = self._sender(writer, self.cfg.tls_allowed_senders)
        ssl_obj = writer.get_extra_info("ssl_object")
        role = peer_role(ssl_obj.getpeercert() if ssl_obj else None, self.cfg.tls_identities)
        if addr is None or role is None:
            if addr is not None:
                self.stats.inc("tls_identity_rejected")
            writer.close()
            return
        self.stats.inc(f"tls_session:{role}")
        await self._pump(reader, writer, addr, role)

    async def _pump(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        addr: IPv4Address,
        role: str | None,
    ) -> None:
        try:
            while True:
                try:
                    raw = await reader.readuntil(b"\n")
                except asyncio.LimitOverrunError as exc:
                    await reader.readexactly(exc.consumed)
                    self.stats.inc("oversize")
                    continue
                except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
                    break
                self.offer(addr, raw.decode("utf-8", errors="replace").rstrip("\r\n"), role)
        finally:
            writer.close()

    def offer(self, sender: IPv4Address, line: str, role: str | None = None) -> None:
        if len(line) > self.cfg.max_line_bytes:
            self.stats.inc("oversize")
            return
        try:
            self.lines.put_nowait((sender, line, role))
            self.stats.inc("received")
        except queue.Full:
            self.stats.inc("queue_drop")

    async def _serve(self) -> None:
        limit = self.cfg.max_line_bytes + 1
        if self.cfg.listen_port is not None:
            self._servers.append(
                await asyncio.start_server(
                    self._handle, self.cfg.listen_host, self.cfg.listen_port, limit=limit
                )
            )
            log.info("syslog_listening", host=self.cfg.listen_host, port=self.cfg.listen_port)
        if self.cfg.tls_port is not None:
            self._servers.append(
                await asyncio.start_server(
                    self._handle_tls,
                    self.cfg.listen_host,
                    self.cfg.tls_port,
                    limit=limit,
                    ssl=tls_context(self.cfg),
                )
            )
            log.info("syslog_tls_listening", port=self.cfg.tls_port)
        await asyncio.gather(*(s.serve_forever() for s in self._servers))

    def start(self) -> None:
        def run() -> None:
            self._loop = asyncio.new_event_loop()
            with contextlib.suppress(asyncio.CancelledError):
                self._loop.run_until_complete(self._serve())

        self._thread = threading.Thread(target=run, name="syslog-receiver", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._loop:
            for s in self._servers:
                self._loop.call_soon_threadsafe(s.close)
