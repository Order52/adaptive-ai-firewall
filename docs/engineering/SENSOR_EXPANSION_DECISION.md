# Sensor expansion on FW01: decision (NV1 §6.3)

Recorded 2026-10-29 ~10:15Z. The decision is **not to enable inspection of
DMZ/APP/DB now**. This is a decision on the evidence below, not a deferral for lack of
time; §4 says what would change it. No FW01 configuration was changed. Evidence:
`artifacts/evidence/sensor-expansion-2026-10-29/`, `nv1-2026-10-29/fw01-load-*`.

## 1. What it would add

The aim is visibility of server-side behaviour: WAF01→APP01, APP01→DB01, and lateral
movement from a compromised server (NV1 §2).

On FW01, pcap capture sees an interface's inbound packets *before* pf and its outbound
packets *after* pf passes them. Per interface:

| Inspect | Sees | Misses |
|---|---|---|
| vtnet4 (DMZ) | Everything WAF01 *tries*, including blocked attempts towards APP/DB/MGMT (inbound, before pf) | — but also every client→WAF01 connection a second time (outbound), see §2.2 |
| vtnet5 (APP) | WAF01→APP01 (outbound) and everything APP01 tries (inbound) | WAF01's blocked attempts (dropped on vtnet4) |
| vtnet6 (DB) | APP01→DB01 (outbound) and what DB01 tries | as above |

## 2. Why not now

### 2.1 No detection value with the current design

DMZ, APP and DB are protected networks (`config/lab.yaml`). The runtime stores a
protected source's network events and never assesses them (`services/runtime.py`,
`tick`). That rule is right: a protected server must never be acted on, and the client
detector's calibration describes users, not servers.

Expanding the sensor would therefore add stored events and no verdict. A useful version
needs a **separate server detector** in shadow. It would need its own baseline, and
server traffic is regular enough for an allow-list of expected flows. It would also
need its own predeclared validation, and lateral-movement runs that only the team can
supply.

### 2.2 It would disturb what already works

FW01's Suricata 8.0.6 runs with `livedev.use-for-tracking: false`, so flows are keyed
without the interface. A client→WAF01:443 connection enters on vtnet3 (or vtnet2) and
leaves on vtnet4. With vtnet4 inspected, it would be one flow receiving every packet
twice. There are two ways to configure this, and both have a cost:

- **Keep `false`.** Duplicate packets in one TCP stream look like retransmissions and
  overlaps to the stream engine. This puts at risk the reassembly that the existing IDS
  rules depend on, on the application's main path. That path is the one with measured
  evidence (A3, P6/P7, NV1/NV2 captures).
- **Set `true`.** The client connection becomes two flow events with different flow
  ids. Its failed connections to WAF01 count twice in `failed_60`/`failed_300`. That
  would change the inputs of the NV2-validated client calibration without a new
  validation.

Either way, the client features would need a filter to the client-zone interfaces
before expansion. NV2's result would have to be re-established.

### 2.3 Cost is acceptable, but it is not the reason

The cost was measured during the A3/NV1 capture (58 users):
- FW01 has 2 vCPUs, is 95–97 % idle, and Suricata uses 330 MB RSS.
- Inspecting DMZ+APP would raise inspected packets about 3.4×.
- WAF01→APP01 uses keepalive (16 connections), so the added *flow events* are few; the
  added cost is mostly packets.

The headroom is real. Cost is not what decides against expansion.

## 3. A cheaper signal for the main gap

The gap that matters most is lateral movement from a compromised server towards zones
pf forbids. pf already blocks those connections at FW01, by default deny between server
zones. Its log (`filterlog`) records them:
- the volume is small;
- there is no stream engine involved;
- nothing is duplicated.

The controller recognises the `filterlog` syslog tag but does not parse it. Parsing pf
blocks of *server-originated* connections into network events, as evidence on
protected sources only and in shadow, would give the lateral-movement signal without
touching Suricata.

**Implemented 2026-10-29 (commit `f16798a`, shadow).**

What changed:
- pf already logged these blocks: OPNsense's "block … log" rules for each server zone.
- FW01's existing mTLS feed now forwards `suricata,filterlog`.
- The controller keeps inbound IPv4 blocks whose source is protected, together with the
  reason the source is protected. They are shown under `protected_blocked` in
  `/api/network`. Client blocks are counted only.
- Nothing enters the client network features, datasets or decisions.

Baseline. In FW01's logs of 2026-10-28/29, every server-originated block came from the
isolation suite's deliberate checks. There were 10 tuples, each seen once per run.

End to end (`pf-blocks-live-verify.txt`):
- `afw lab verify` passed 41/41.
- All 10 server-originated deny checks appeared, with the right zone, and no policy
  was created.

Still open:
- Recall against a real compromise needs a team lateral-movement scenario.
- Nothing is stored beyond the bounded in-memory list and the controller's journal
  (`protected_source_blocked` warnings).
- Verification runs are not marked, so their blocks look like any other.

## 4. What would change the decision

Enable server-segment inspection only when all of these hold:
1. A server detector exists and is predeclared, as §2.1 describes.
2. Client features are restricted to client-zone interfaces, and the effect on the
   NV2 calibration is re-measured.
3. Stream integrity on the main path is checked after the change: Suricata stream
   anomaly counters, and IDS alert parity on a replayed benign capture.
4. Team lateral-movement runs exist to measure the gain.

Until then, the coverage limits in NV1 §2 and ADR-042 stand.
