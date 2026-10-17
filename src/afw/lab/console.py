"""Minimal expect-style driver for GNS3/QEMU telnet serial consoles."""

from __future__ import annotations

import re
import socket
import time

IAC = 255


class ConsoleTimeout(TimeoutError):
    pass


class SerialConsole:
    def __init__(self, host: str, port: int, log: bool = False) -> None:
        self._sock = socket.create_connection((host, port), timeout=10)
        self._sock.settimeout(0.2)
        self._buf = ""
        self._log = log

    def close(self) -> None:
        self._sock.close()

    def _read(self) -> str:
        try:
            data = self._sock.recv(65536)
        except TimeoutError:
            return ""
        if not data:
            raise ConnectionError("console closed")
        out = bytearray()
        i = 0
        while i < len(data):  # strip telnet negotiation (IAC cmd opt)
            if data[i] == IAC and i + 1 < len(data):
                i += 3 if data[i + 1] in (251, 252, 253, 254) else 2
                continue
            out.append(data[i])
            i += 1
        text = out.decode("utf-8", "replace")
        if self._log:
            print(text, end="", flush=True)
        return text

    def expect(self, patterns: list[str], timeout: float = 60) -> tuple[int, str]:
        """Wait for any regex; returns (index, text consumed up to the match end)."""
        regs = [re.compile(p) for p in patterns]
        end = time.monotonic() + timeout
        while True:
            for i, r in enumerate(regs):
                m = r.search(self._buf)
                if m:
                    consumed, self._buf = self._buf[: m.end()], self._buf[m.end() :]
                    return i, consumed
            if time.monotonic() > end:
                raise ConsoleTimeout(f"waiting for {patterns}; tail={self._buf[-300:]!r}")
            self._buf += self._read()

    def send(self, text: str, delay: float = 0.0) -> None:
        self._sock.sendall(text.encode())
        if delay:
            time.sleep(delay)

    def sendline(self, text: str = "") -> None:
        self.send(text + "\r")

    def drain(self, quiet_s: float = 1.0) -> str:
        """Read until the console is quiet for ``quiet_s`` seconds."""
        last = time.monotonic()
        while time.monotonic() - last < quiet_s:
            chunk = self._read()
            if chunk:
                self._buf += chunk
                last = time.monotonic()
        out, self._buf = self._buf, ""
        return out
