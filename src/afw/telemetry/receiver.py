"""Bounded TCP syslog receiver (LF-framed, as sent by rsyslog omfwd/TCP).

Only configured sender addresses are accepted. Lines above ``max_line_bytes``
are dropped and counted. When the queue is full new lines are dropped (never
blocking senders indefinitely) and counted, which marks telemetry as degraded.
"""

from __future__ import annotations

import asyncio
import contextlib
import queue
import threading
from ipaddress import IPv4Address, ip_address

import structlog

from afw.config import TelemetryConfig
from afw.telemetry.stats import TelemetryStats

log = structlog.get_logger(__name__)


class SyslogReceiver:
    def __init__(self, cfg: TelemetryConfig, stats: TelemetryStats) -> None:
        self.cfg = cfg
        self.stats = stats
        self.lines: queue.Queue[tuple[IPv4Address, str]] = queue.Queue(maxsize=cfg.queue_size)
        self._loop: asyncio.AbstractEventLoop | None = None
        self._thread: threading.Thread | None = None
        self._server: asyncio.base_events.Server | None = None

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        peer = writer.get_extra_info("peername")
        try:
            addr = ip_address(peer[0])
        except (TypeError, ValueError):
            writer.close()
            return
        if not isinstance(addr, IPv4Address) or (
            self.cfg.allowed_senders and addr not in self.cfg.allowed_senders
        ):
            self.stats.inc("sender_rejected")
            writer.close()
            return
        try:
            while True:
                try:
                    raw = await reader.readuntil(b"\n")
                except asyncio.LimitOverrunError as exc:
                    await reader.readexactly(exc.consumed)
                    self.stats.inc("oversize")
                    continue
                except asyncio.IncompleteReadError:
                    break
                self.offer(addr, raw.decode("utf-8", errors="replace").rstrip("\r\n"))
        finally:
            writer.close()

    def offer(self, sender: IPv4Address, line: str) -> None:
        if len(line) > self.cfg.max_line_bytes:
            self.stats.inc("oversize")
            return
        try:
            self.lines.put_nowait((sender, line))
            self.stats.inc("received")
        except queue.Full:
            self.stats.inc("queue_drop")

    async def _serve(self) -> None:
        self._server = await asyncio.start_server(
            self._handle,
            self.cfg.listen_host,
            self.cfg.listen_port,
            limit=self.cfg.max_line_bytes + 1,
        )
        log.info("syslog_listening", host=self.cfg.listen_host, port=self.cfg.listen_port)
        async with self._server:
            await self._server.serve_forever()

    def start(self) -> None:
        def run() -> None:
            self._loop = asyncio.new_event_loop()
            with contextlib.suppress(asyncio.CancelledError):
                self._loop.run_until_complete(self._serve())

        self._thread = threading.Thread(target=run, name="syslog-receiver", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._loop and self._server:
            self._loop.call_soon_threadsafe(self._server.close)
