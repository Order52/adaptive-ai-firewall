"""Network events: connection metadata beyond HTTP (N1).

One record per Suricata EVE ``flow``, ``dns``, ``tls``, ``ssh`` or ``anomaly`` event
from FW01's IDS interfaces. Payloads are never carried, only metadata. ``src``/``dst``
are the flow's client and server as Suricata oriented them (first packet).
Encrypted traffic contributes sizes, timing, ports, TLS SNI/version and SSH software
versions only; nothing inside the encryption is visible.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from ipaddress import IPv4Address

from pydantic import Field

from afw.domain.common import DomainModel

NETWORK_SCHEMA_VERSION = 1


class NetKind(StrEnum):
    FLOW = "flow"
    DNS = "dns"
    TLS = "tls"
    SSH = "ssh"
    ANOMALY = "anomaly"


class FlowState(StrEnum):
    NEW = "new"  # no reply seen (e.g. a SYN to a closed or filtered port)
    ESTABLISHED = "established"
    CLOSED = "closed"
    BYPASSED = "bypassed"
    UNKNOWN = "unknown"


class NetworkEvent(DomainModel):
    """``event_id`` is derived from the event's content, so a duplicated or replayed
    line maps to the same id and is stored once (as for IDS alerts)."""

    event_id: str
    kind: NetKind
    observed_at: datetime  # flow end for flows, event time otherwise
    sensor_id: str
    in_iface: str = ""
    src_ip: IPv4Address
    src_port: int | None = None
    dst_ip: IPv4Address
    dst_port: int | None = None
    proto: str
    app_proto: str = ""
    flow_id: int | None = None
    # flow
    started_at: datetime | None = None
    duration_s: float | None = Field(default=None, ge=0)
    pkts_to_server: int = Field(default=0, ge=0)
    pkts_to_client: int = Field(default=0, ge=0)
    bytes_to_server: int = Field(default=0, ge=0)
    bytes_to_client: int = Field(default=0, ge=0)
    state: FlowState | None = None
    end_reason: str = ""
    syn: bool = False
    rst: bool = False
    fin: bool = False
    alerted: bool = False
    # dns / tls / ssh / anomaly: short identifiers only
    dns_rrname: str = ""
    dns_rrtype: str = ""
    dns_rcode: str = ""
    tls_sni: str = ""
    tls_version: str = ""
    ssh_client: str = ""
    anomaly: str = ""
    schema_version: int = NETWORK_SCHEMA_VERSION
    received_at: datetime | None = None

    @property
    def answered(self) -> bool:
        """The server side sent at least one packet (a handshake was answered)."""
        return self.pkts_to_client > 0

    @property
    def failed(self) -> bool:
        """A connection attempt that never got a normal answer: no reply, or reset
        without data. UDP flows without a reply count too."""
        if self.kind is not NetKind.FLOW:
            return False
        return not self.answered or (self.rst and self.bytes_to_client == 0)
