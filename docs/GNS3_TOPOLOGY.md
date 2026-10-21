# GNS3 topology

_Live, verified against the running GNS3 project `AI-Adaptive-Firewall`
(API v2, 127.0.0.1:3080) on 2026-10-17. Reproduce the canvas with
`afw lab layout`._

## Logical architecture

```
                    MANAGEMENT ZONE  (10.77.50.0/24, host-only)
             ┌───────────────────────────────────────────────┐
             │   CTRL01  —  AI-ADAPTIVE-FIREWALL              │
             │   AI / ML / profiling / correlation / MCP      │
             │   dashboard (HTTP via SSH tunnel) · control    │
             │        │                                       │
             │   SW-MGMT ── HOST-MGMT (host TAP)  MAINT-NAT   │
             └────────┼──────────────────────────────────────┘
                      │  management API (bearer token; TLS opt-in)
                      ▼
                   ┌──────┐
     ATTACK  ──────┤ FW01 ├────── USERS
   10.77.10.0/24   │OPNsense│   10.77.20.0/24
    ATK01──SW-ATTACK  pf+Suricata  SW-USERS──USR01
                   └──┬───┘
                      │  firewall policy
                      ▼
                   DMZ ZONE  (10.77.30.0/24)
                   SW-DMZ ── WAF01  (OWASP CRS / ModSecurity, nginx)
                      │  through firewall policy only
                      ▼
                   APPLICATION ZONE  (10.77.40.0/24)
                   SW-APP ── APP01  (rental web app)
```

The management plane (CTRL01 ↔ FW01 API) is isolated on the host-only MGMT zone.
The data path is **clients → FW01 → WAF01 (DMZ) → APP01**; there is no direct
client→APP path (gate G1 verifies this, see below). OPNsense is **one enforcement
backend**; the AI controller (CTRL01) is the project's primary contribution.

## Node inventory (13 nodes, 12 links)

| Node | GNS3 type | Role | Address | Zone |
|---|---|---|---|---|
| **CTRL01** | qemu (guest) | AI-Adaptive-Firewall controller: AI/ML, profiling, correlation, policy, MCP, dashboard | 10.77.50.10 | MGMT |
| **FW01** | qemu (guest) | OPNsense 26.7 — pf firewall + Suricata IDS; 6 NICs (MGMT/MAINT/ATTACK/USERS/DMZ/APP) | .1 in each zone | router/core |
| **WAF01** | qemu (guest) | OWASP CRS ModSecurity (nginx, host networking) + policy helper | 10.77.30.10 | DMZ |
| **APP01** | qemu (guest) | Protected rental web app | 10.77.40.10 | APP |
| **USR01** | qemu (guest) | Legitimate user client + probe agent | 10.77.20.10 | USERS |
| **ATK01** | qemu (guest) | Attack-scenario client + probe agent | 10.77.10.10 | ATTACK |
| SW-MGMT / SW-ATTACK / SW-USERS / SW-DMZ / SW-APP | ethernet_switch | Per-zone L2 segments | — | infra |
| HOST-MGMT | cloud | Host TAP `afw-mgmt0` (10.77.50.254) into the MGMT segment | — | infra |
| MAINT-NAT | nat | Maintenance/IDS-rule-update uplink on FW01's MAINT NIC | — | infra |

**Six functional machines** (CTRL01, FW01, WAF01, APP01, USR01, ATK01). The five
switches, the cloud and the NAT are infrastructure, not guests. No node is
redundant: each switch is one security zone's L2 segment, HOST-MGMT is the only
host entry point, and MAINT-NAT is FW01's only outbound path (IDS rule updates),
kept off the data zones.

### Links (every guest reaches the network only through its zone switch → FW01)

```
FW01:0 ── SW-MGMT      SW-MGMT ── CTRL01, HOST-MGMT
FW01:1 ── MAINT-NAT    SW-ATTACK ── ATK01
FW01:2 ── SW-ATTACK    SW-USERS ── USR01
FW01:3 ── SW-USERS     SW-DMZ ── WAF01
FW01:4 ── SW-DMZ       SW-APP ── APP01
FW01:5 ── SW-APP
```

No link bypasses FW01: clients (ATTACK/USERS) and the DMZ/APP segments each meet
only at FW01, so every cross-zone packet is subject to pf. The WAF is the only
path from a client zone into the APP zone.

## Canvas layout (professional, reproducible)

`afw lab layout` (idempotent) arranges the canvas top-to-bottom to mirror the
traffic path and draws colour-coded zone boxes + labels:

- **Management** (blue, top): CTRL01 prominent, SW-MGMT, HOST-MGMT, MAINT-NAT.
- **FW01** (centre): OPNsense, labelled, firewall symbol.
- **Attack** (red, left) / **Users** (green, right): client zones feeding FW01.
- **DMZ** (amber): SW-DMZ + WAF01, directly below FW01.
- **Application** (teal, bottom): SW-APP + APP01, reachable only via the WAF.

Symbols are role-appropriate (server for CTRL01/WAF01/APP01, firewall for FW01,
ethernet-switch for switches, cloud for HOST-MGMT/MAINT-NAT). Node positions,
symbols and drawings are persisted by the GNS3 controller and survive a project
close/reopen (verified in earlier sessions).

## Isolation gate (G1)

`afw lab verify` runs 26 reachability checks from *inside* the guests (also
exposed as the MCP tool `verify_isolation`). It confirms: clients cannot bypass
the WAF to the app, clients cannot reach each other, clients have no Internet,
telemetry/SSH ports are closed to clients, and management reaches all zones.
Historical result: **26/26**.

## Reproduce from code

```
afw lab build → afw lab start → afw lab provision-fw → afw lab provision-ids
→ afw lab deploy → afw lab layout → afw lab verify
```

The authoritative topology is `lab/gns3/topology.yaml` (nodes + links); the
canvas presentation is `src/afw/lab/layout.py`.
