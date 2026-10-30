"""Bounded syslog receiver: LF-framed TCP (rsyslog omfwd, syslog-ng) and RELP.

Up to three listeners share one bounded queue:

* plaintext (``listen_port``): sender identified by its IP only (allowlist).
  Its lines are ``UNVERIFIED`` and never feed online learning (ADR-029).
* mutually authenticated TLS (``tls_port``, optional): the client certificate
  must chain to the lab CA and its common name must be a configured sensor
  identity; that identity's role ("waf", "app" or "ids") travels with every line.
* RELP over the same mutual TLS (``relp_port``, optional; rsyslog omrelp): identical
  identity rules, but each line is acknowledged only after it is queued, so lines
  written into a dead session are resent by the sender instead of lost. A full queue
  holds the acknowledgement back (backpressure) for up to ``RELP_BACKPRESSURE_S``
  before the line is dropped and counted. Delivery is at-least-once (after a reconnect
  rsyslog resends its whole unacknowledged batch), so exact repeats of one of the
  role's last ``RELP_DEDUP_LINES`` queued lines are acknowledged, dropped and counted.
  Distinct sensor lines are never byte-identical: each carries a request id or a
  timestamp.

Only configured sender addresses are accepted. Lines above ``max_line_bytes``
are dropped and counted. When the queue is full new lines are dropped (never
blocking senders indefinitely) and counted, which marks telemetry as degraded.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import queue
import ssl
import threading
from collections import OrderedDict
from ipaddress import IPv4Address, ip_address

import structlog

from afw.config import TelemetryConfig
from afw.telemetry.stats import TelemetryStats

log = structlog.get_logger(__name__)

# (sender IP, line, authenticated sensor role or None)
Line = tuple[IPv4Address, str, str | None]

RELP_BACKPRESSURE_S = 30.0
RELP_DEDUP_LINES = 8192
RELP_OPEN_OK = b"200 OK\nrelp_version=0\nrelp_software=afw\ncommands=syslog"


class RelpError(ValueError):
    """Malformed RELP frame; the session is closed (the sender reconnects and resends)."""


async def _relp_field(reader: asyncio.StreamReader, stops: bytes, maxlen: int) -> tuple[bytes, int]:
    buf = bytearray()
    while True:
        c = (await reader.readexactly(1))[0]
        if c in stops:
            return bytes(buf), c
        buf.append(c)
        if len(buf) > maxlen:
            raise RelpError("header too long")


async def read_relp_frame(
    reader: asyncio.StreamReader, max_data: int
) -> tuple[int, str, bytes | None]:
    """One frame ``TXNR SP COMMAND SP DATALEN [SP DATA] LF``. Data above ``max_data``
    is read off in chunks and returned as None (the caller counts it as oversize)."""
    txnr, _ = await _relp_field(reader, b" ", 9)
    cmd, _ = await _relp_field(reader, b" ", 32)
    size, stop = await _relp_field(reader, b" \n", 9)
    if not (txnr.isdigit() and size.isdigit() and cmd.isalpha()):
        raise RelpError("bad header")
    n = int(size)
    data: bytes | None = b""
    if stop == ord(" "):
        if n <= max_data:
            data = await reader.readexactly(n)
        else:
            data, left = None, n
            while left:
                left -= len(await reader.readexactly(min(left, 65536)))
        if await reader.readexactly(1) != b"\n":
            raise RelpError("missing trailer")
    elif n:
        raise RelpError("data length without data")
    return int(txnr), cmd.decode(), data


def relp_rsp(txnr: int, body: bytes = b"200 OK") -> bytes:
    return b"%d rsp %d %s\n" % (txnr, len(body), body) if body else b"%d rsp 0\n" % txnr


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
        self._relp_recent: dict[str | None, OrderedDict[bytes, None]] = {}

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

    def _tls_peer(self, writer: asyncio.StreamWriter) -> tuple[IPv4Address, str] | None:
        addr = self._sender(writer, self.cfg.tls_allowed_senders)
        ssl_obj = writer.get_extra_info("ssl_object")
        role = peer_role(ssl_obj.getpeercert() if ssl_obj else None, self.cfg.tls_identities)
        if addr is None or role is None:
            if addr is not None:
                self.stats.inc("tls_identity_rejected")
            writer.close()
            return None
        return addr, role

    async def _handle_tls(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = self._tls_peer(writer)
        if peer is None:
            return
        self.stats.inc(f"tls_session:{peer[1]}")
        await self._pump(reader, writer, *peer)

    async def _handle_relp(
        self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter
    ) -> None:
        peer = self._tls_peer(writer)
        if peer is None:
            return
        self.stats.inc(f"relp_session:{peer[1]}")
        await self.relp_session(reader, writer, *peer)

    async def relp_session(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
        addr: IPv4Address,
        role: str | None,
    ) -> None:
        opened = False
        try:
            while True:
                try:
                    txnr, cmd, data = await read_relp_frame(reader, self.cfg.max_line_bytes)
                except RelpError:
                    self.stats.inc("relp_protocol_error")
                    break
                except (asyncio.IncompleteReadError, ConnectionError, ssl.SSLError):
                    break
                if cmd == "open":
                    opened = True
                    writer.write(relp_rsp(txnr, RELP_OPEN_OK))
                elif cmd == "close":
                    writer.write(relp_rsp(txnr, b""))
                    await writer.drain()
                    break
                elif cmd == "syslog" and opened:
                    if data is None:
                        self.stats.inc("oversize")  # acknowledged: a resend cannot fit
                    else:
                        line = data.decode("utf-8", errors="replace").rstrip("\r\n")
                        await self._offer_relp(addr, line, role)
                    writer.write(relp_rsp(txnr))
                else:
                    self.stats.inc("relp_protocol_error")
                    writer.write(relp_rsp(txnr, b"500 unexpected command"))
                await writer.drain()
        except (ConnectionError, ssl.SSLError):
            pass
        finally:
            writer.close()

    async def _offer_relp(self, addr: IPv4Address, line: str, role: str | None) -> None:
        """Queue before acknowledging; while the queue is full, hold the
        acknowledgement so the sender's window (and then its disk queue) absorbs it."""
        recent = self._relp_recent.setdefault(role, OrderedDict())
        digest = hashlib.blake2b(line.encode(), digest_size=16).digest()
        if digest in recent:
            self.stats.inc("relp_duplicate")
            return
        loop = asyncio.get_running_loop()
        deadline = loop.time() + RELP_BACKPRESSURE_S
        while not self.offer(addr, line, role, count_drop=False):
            if loop.time() >= deadline:
                self.stats.inc("queue_drop")
                return  # not remembered: a resend may still get through
            await asyncio.sleep(0.05)
        recent[digest] = None
        if len(recent) > RELP_DEDUP_LINES:
            recent.popitem(last=False)

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

    def offer(
        self, sender: IPv4Address, line: str, role: str | None = None, count_drop: bool = True
    ) -> bool:
        """False only when the queue is full (the line was not taken)."""
        if len(line) > self.cfg.max_line_bytes:
            self.stats.inc("oversize")
            return True
        try:
            self.lines.put_nowait((sender, line, role))
            self.stats.inc("received")
        except queue.Full:
            if count_drop:
                self.stats.inc("queue_drop")
            return False
        return True

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
        if self.cfg.relp_port is not None:
            self._servers.append(
                await asyncio.start_server(
                    self._handle_relp,
                    self.cfg.listen_host,
                    self.cfg.relp_port,
                    ssl=tls_context(self.cfg),
                )
            )
            log.info("relp_tls_listening", port=self.cfg.relp_port)
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
