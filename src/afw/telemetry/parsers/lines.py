"""Parse syslog-carried JSON lines from the WAF, the application and Suricata.

Every parser is total: it returns a record or raises ``ParseError`` with a
reason that the receiver counts. Bodies, tokens and passwords are never part of
the accepted formats.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from ipaddress import IPv4Address, ip_address
from typing import Any

from afw.domain.events import AuthOutcome
from afw.domain.network import BlockedConnection, FlowState, NetKind, NetworkEvent
from afw.telemetry.parsers.records import AppRecord, SuricataAlert, WafAccess, WafAudit

_REQUEST_ID = re.compile(r"^[A-Za-z0-9_\-]{8,64}$")
_TOTAL_SCORE = re.compile(r"Total Score: (\d+)")
# CRS v4 inbound scoring by ModSecurity severity (2=critical .. 5=notice).
_CRS_SEVERITY_POINTS = {2: 5, 3: 4, 4: 3, 5: 2}
# Scoring/reporting rules carry no detection of their own.
_CRS_NON_DETECTION = range(949000, 999999)
_SYSLOG_TAG = re.compile(
    r"\b(afw-waf-access|afw-waf-audit|afw-app|afw-heartbeat|suricata|filterlog)\b"
)


class ParseError(ValueError):
    def __init__(self, reason: str) -> None:
        super().__init__(reason)
        self.reason = reason


_FILTERLOG = re.compile(r"\bfilterlog\b")


def classify(line: str) -> tuple[str, dict[str, Any]]:
    """Return (kind, json payload) for a syslog line carrying JSON. pf's ``filterlog``
    carries CSV instead: its payload is ``{"csv": <last field of the line>}``."""
    brace = line.find("{")
    if brace < 0 and _FILTERLOG.search(line):
        return "filterlog", {"csv": line.rsplit(maxsplit=1)[-1]}
    if brace < 0:
        raise ParseError("no_json")
    header = line[:brace]
    try:
        payload = json.loads(line[brace:])
    except json.JSONDecodeError as exc:
        raise ParseError("bad_json") from exc
    if not isinstance(payload, dict):
        raise ParseError("bad_json")
    tag = _SYSLOG_TAG.search(header)
    if tag and tag.group(1) == "suricata" and payload.get("event_type") == "afw_heartbeat":
        # FW01's syslog forwards only listed programs, so its watchdog sends liveness
        # under the suricata tag; Suricata itself never emits this event type.
        return "afw-heartbeat", payload
    if tag:
        return tag.group(1), payload
    if payload.get("event_type") == "alert":
        return "suricata", payload
    if "transaction" in payload:
        return "afw-waf-audit", payload
    raise ParseError("unknown_source")


def _ts(value: Any) -> datetime:
    if isinstance(value, int | float) or (isinstance(value, str) and _is_number(value)):
        return datetime.fromtimestamp(float(value), tz=UTC)
    if isinstance(value, str):
        text = value.replace("Z", "+00:00")
        # ModSecurity: "Fri Oct 17 12:00:00 2026" is not used; we require ISO/epoch.
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError as exc:
            raise ParseError("bad_timestamp") from exc
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)
    raise ParseError("bad_timestamp")


def _is_number(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


def _ipv4(value: Any) -> IPv4Address:
    try:
        addr = ip_address(str(value))
    except ValueError as exc:
        raise ParseError("bad_ip") from exc
    if not isinstance(addr, IPv4Address):
        raise ParseError("ipv6_unsupported")
    return addr


def _rid(value: Any) -> str:
    text = str(value or "")
    if not _REQUEST_ID.match(text):
        raise ParseError("bad_request_id")
    return text


def _int(value: Any, default: int | None = None) -> int | None:
    if value in (None, "", "-"):
        return default
    try:
        return int(str(value).split(",")[-1].strip())
    except ValueError:
        return default


def _float(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def ua_hash(user_agent: str | None) -> str | None:
    if not user_agent:
        return None
    return hashlib.sha256(user_agent.encode()).hexdigest()[:16]


def parse_waf_access(p: dict[str, Any], sensor_ip: IPv4Address | None = None) -> WafAccess:
    path = str(p.get("uri", ""))
    if not path.startswith("/") or len(path) > 2048:
        raise ParseError("bad_path")
    status = _int(p.get("status"))
    if status is None:
        raise ParseError("bad_status")
    return WafAccess(
        request_id=_rid(p.get("rid")),
        observed_at=_ts(p.get("ts")),
        client_ip=_ipv4(p.get("src")),
        method=str(p.get("method", "")).upper()[:10],
        path=path,
        status=status,
        bytes_in=_int(p.get("req_len"), 0) or 0,
        bytes_out=_int(p.get("bytes"), 0) or 0,
        duration_ms=_float(p.get("rt")) * 1000.0,
        upstream_status=_int(p.get("upstream_status")),
        user_agent_hash=ua_hash(p.get("ua")),
        sensor_ip=sensor_ip,
        app_id=str(p["app"])[:32] if p.get("app") else None,
    )


def _audit_ts(value: Any) -> datetime:
    """ModSecurity v3 writes ctime-style UTC stamps ("Fri Oct 17 12:00:00 2026")."""
    if isinstance(value, str):
        try:
            return datetime.strptime(value, "%a %b %d %H:%M:%S %Y").replace(tzinfo=UTC)
        except ValueError:
            pass
    try:
        return _ts(value)
    except ParseError:
        return datetime.now(UTC)


def parse_waf_audit(p: dict[str, Any]) -> WafAudit:
    tx = p.get("transaction")
    if not isinstance(tx, dict):
        raise ParseError("bad_audit")
    rule_ids: list[int] = []
    score = 0
    summed = 0
    for message in tx.get("messages") or []:
        details = message.get("details") or {}
        rid = _int(details.get("ruleId"))
        if rid is not None:
            rule_ids.append(rid)
            if rid not in _CRS_NON_DETECTION:
                summed += _CRS_SEVERITY_POINTS.get(_int(details.get("severity"), 0) or 0, 0)
        for text in (message.get("message", ""), details.get("data", "")):
            found = _TOTAL_SCORE.search(str(text))
            if found:
                score = max(score, int(found.group(1)))
    score = max(score, summed)  # below threshold CRS reports no total
    response = tx.get("response") or {}
    http_code = _int(response.get("http_code"), 0) or 0
    blocked = http_code == 403 or 949110 in rule_ids
    return WafAudit(
        request_id=_rid(tx.get("unique_id")),
        observed_at=_audit_ts(tx.get("time_stamp")),
        client_ip=_ipv4(tx.get("client_ip")),
        rule_ids=tuple(sorted(set(rule_ids))),
        anomaly_score=score,
        blocked=blocked,
    )


def parse_app(p: dict[str, Any]) -> AppRecord:
    auth_raw = p.get("auth")
    auth = AuthOutcome(auth_raw) if auth_raw in ("success", "failure") else None
    status = _int(p.get("status"))
    if status is None:
        raise ParseError("bad_status")
    user_h = p.get("user_h")
    return AppRecord(
        request_id=_rid(p.get("rid")),
        app_id=str(p.get("app", ""))[:32] or "unknown",
        observed_at=_ts(p.get("ts")),
        route=str(p.get("route", ""))[:128],
        method=str(p.get("method", "")).upper()[:10],
        status=status,
        app_version=str(p.get("ver", "unknown"))[:32],
        auth_outcome=auth,
        username_hash=str(user_h)[:32] if user_h else None,
    )


def parse_suricata(p: dict[str, Any], sensor_id: str) -> SuricataAlert:
    if p.get("event_type") != "alert":
        raise ParseError("not_alert")
    alert = p.get("alert") or {}
    sid = _int(alert.get("signature_id"))
    if sid is None:
        raise ParseError("bad_signature")
    return SuricataAlert(
        observed_at=_ts(p.get("timestamp")),
        sensor_id=sensor_id,
        src_ip=_ipv4(p.get("src_ip")),
        dst_ip=_ipv4(p.get("dest_ip")),
        dst_port=_int(p.get("dest_port")),
        proto=str(p.get("proto", ""))[:8],
        signature_id=sid,
        signature=str(alert.get("signature", ""))[:256],
        severity=min(4, max(1, _int(alert.get("severity"), 3) or 3)),
        flow_id=_int(p.get("flow_id")),
    )


_NET_KINDS = {k.value: k for k in NetKind}


def is_network_event(p: dict[str, Any]) -> bool:
    return p.get("event_type") in _NET_KINDS


def _obj(p: dict[str, Any], key: str) -> dict[str, Any]:
    v = p.get(key)
    return v if isinstance(v, dict) else {}


def _short(value: Any, n: int) -> str:
    return str(value or "")[:n]


def _dns_fields(d: dict[str, Any]) -> tuple[str, str, str]:
    """Suricata 8 (DNS v3: ``queries`` list) and 7 (flat ``rrname``) layouts."""
    q = d.get("queries")
    first = q[0] if isinstance(q, list) and q and isinstance(q[0], dict) else d
    return (
        _short(first.get("rrname"), 128).lower(),
        _short(first.get("rrtype"), 8),
        _short(d.get("rcode"), 12),
    )


def parse_suricata_net(p: dict[str, Any], sensor_id: str) -> NetworkEvent:
    """A Suricata EVE flow/dns/tls/ssh/anomaly event as a ``NetworkEvent`` (N1)."""
    kind = _NET_KINDS.get(str(p.get("event_type")))
    if kind is None:
        raise ParseError("not_network_event")
    observed = _ts(p.get("timestamp"))
    fields: dict[str, Any] = {}
    if kind is NetKind.FLOW:
        f = p.get("flow")
        if not isinstance(f, dict):
            raise ParseError("bad_flow")
        tcp = _obj(p, "tcp")
        start = _ts(f["start"]) if f.get("start") else None
        end = _ts(f["end"]) if f.get("end") else observed
        try:
            state = FlowState(str(f.get("state", "unknown")))
        except ValueError:
            state = FlowState.UNKNOWN
        fields = {
            "observed_at": end,
            "started_at": start,
            "duration_s": max(0.0, (end - start).total_seconds()) if start else None,
            "pkts_to_server": max(0, _int(f.get("pkts_toserver"), 0) or 0),
            "pkts_to_client": max(0, _int(f.get("pkts_toclient"), 0) or 0),
            "bytes_to_server": max(0, _int(f.get("bytes_toserver"), 0) or 0),
            "bytes_to_client": max(0, _int(f.get("bytes_toclient"), 0) or 0),
            "state": state,
            "end_reason": _short(f.get("reason"), 16),
            "syn": bool(tcp.get("syn")),
            "rst": bool(tcp.get("rst")),
            "fin": bool(tcp.get("fin")),
            "alerted": bool(f.get("alerted")),
        }
    elif kind is NetKind.DNS:
        d = p.get("dns")
        if not isinstance(d, dict):
            raise ParseError("bad_dns")
        rrname, rrtype, rcode = _dns_fields(d)
        answer = str(d.get("type", "")).lower() in ("answer", "response") or (
            _int(p.get("src_port")) == 53 and _int(p.get("dest_port")) != 53
        )
        fields = {
            "dns_rrname": rrname,
            "dns_rrtype": rrtype,
            "dns_rcode": rcode if answer else "",
            "dns_answer": answer,
        }
    elif kind is NetKind.TLS:
        t = _obj(p, "tls")
        fields = {
            "tls_sni": _short(t.get("sni"), 128).lower(),
            "tls_version": _short(t.get("version"), 16),
        }
    elif kind is NetKind.SSH:
        sh = _obj(p, "ssh")
        client = _obj(sh, "client")
        fields = {"ssh_client": _short(client.get("software_version"), 64)}
    else:
        a = _obj(p, "anomaly")
        fields = {"anomaly": _short(f"{a.get('type', '')}:{a.get('event', '')}", 64)}
    src, dst = _ipv4(p.get("src_ip")), _ipv4(p.get("dest_ip"))
    sport, dport = _int(p.get("src_port")), _int(p.get("dest_port"))
    if fields.get("dns_answer"):
        # Suricata logs a DNS response from the resolver's side; the behaviour (and the
        # NXDOMAIN) belongs to the client that asked
        src, dst, sport, dport = dst, src, dport, sport
    flow_id = _int(p.get("flow_id"))
    key = "|".join(
        str(x)
        for x in (
            sensor_id,
            kind.value,
            flow_id,
            p.get("timestamp"),
            src,
            p.get("src_port"),
            dst,
            p.get("dest_port"),
            p.get("tx_id", ""),
        )
    )
    return NetworkEvent(
        event_id="net-" + hashlib.sha256(key.encode()).hexdigest()[:32],
        kind=kind,
        observed_at=fields.pop("observed_at", observed),
        sensor_id=sensor_id,
        in_iface=_short(p.get("in_iface"), 16),
        src_ip=src,
        src_port=sport,
        dst_ip=dst,
        dst_port=dport,
        proto=_short(p.get("proto"), 8).upper(),
        app_proto=_short(p.get("app_proto"), 16),
        flow_id=flow_id,
        **fields,
    )


def parse_filterlog(
    p: dict[str, Any], sensor_id: str, received: datetime
) -> BlockedConnection | None:
    """An IPv4 connection pf blocked on the way in, from OPNsense's ``filterlog`` CSV;
    None for anything else (passes, outbound, IPv6). Fields used: 3 rule label,
    4 interface, 6 action, 7 direction, 8 IP version, 16 protocol, 18 source,
    19 destination, 20/21 ports (TCP and UDP only)."""
    f = str(p.get("csv", "")).split(",")
    if len(f) < 20:
        raise ParseError("bad_filterlog")
    if f[6] != "block" or f[7] != "in" or f[8] != "4":
        return None
    proto = f[16].upper()
    ports = proto in ("TCP", "UDP") and len(f) > 21
    return BlockedConnection(
        observed_at=received,
        sensor_id=sensor_id,
        iface=_short(f[4], 16),
        src_ip=_ipv4(f[18]),
        dst_ip=_ipv4(f[19]),
        proto=_short(proto, 8),
        src_port=_int(f[20]) if ports else None,
        dst_port=_int(f[21]) if ports else None,
        rule=_short(f[3], 64),
    )
