# NV1: network novelty on ordinary network use (protocol)

Status: **protocol, written 2026-10-29 ~03:35Z, before any NV1 data exists.** Results
are added in §7. §1–§6 do not change after the data is collected. Changes made during
development (§4) are recorded with their reason, before the test set is evaluated.

## 1. Problem

The N2 calibration (2026-10-28) used 1,296 windows from web-only users. All were zero
vectors, so every non-web packet counted as "unfamiliar". On 2026-10-29 the live
controller marked USR01's own DNS and NTP traffic unfamiliar 400+ times. A detector with
nothing to compare against cannot separate the normal from the unusual. In addition:

- **DNS answers had the wrong owner** (fixed in `f1b352a`, verified live).
  - Suricata logs an answer from the resolver's side, so it was stored under 1.1.1.1 or
    8.8.8.8.
  - As a result, the resolvers were scored as sources.
  - The client's NXDOMAIN count was always 0, so the NXDOMAIN ceiling could never fire.
  - Dataset capture, which filters by labelled source, dropped every answer.

## 2. What FW01 can and cannot see (2026-10-29)

Suricata runs in pcap mode on two interfaces: vtnet2 (ATTACK, 10.77.10.0/24) and vtnet3
(USERS, 10.77.20.0/24). A packet is seen only if it crosses one of them.

| Traffic | Seen? | Why |
|---|---|---|
| ATTACK or USERS client → WAF01:443 (the app) | yes | crosses vtnet2/vtnet3; the HTTP pipeline also sees it request by request |
| Client → FW01 itself (NTP 123, ICMP, blocked ports) | yes | arrives on the client interface |
| Client → Internet (DNS to public resolvers, HTTPS) | yes | leaves through FW01 from vtnet3/vtnet2 |
| Client → blocked lab zones (DMZ other ports, APP, DB, MGMT) | yes, as failed flows | the SYN arrives on the client interface before pf drops it |
| Client ↔ client inside one segment (e.g. USR01 ↔ another USERS host) | **no** | switched on SW-USERS, never reaches FW01 |
| WAF01 → APP01:8000, APP01 → DB01:5432 | **no** | DMZ/APP/DB interfaces are not inspected |
| Server → server lateral movement (e.g. a compromised WAF01 probing DB01) | **no** | as above |
| Telemetry WAF01/APP01 → CTRL01 | **no** | DMZ/APP → MGMT, not inspected |
| Management → client zones (SSH from the host 10.77.50.254 or CTRL01 into USR01/ATK01) | yes | routed by FW01 out of vtnet2/vtnet3; stored, but from protected sources, so never assessed |
| Management → servers (host or CTRL01 to WAF01/APP01/DB01) | **no** | leaves FW01 on MGMT/DMZ/APP/DB interfaces, none inspected |
| Contents of TLS/SSH sessions | **no** | only SNI, version, sizes, timing and SSH software strings |

**SSH administration.** Clients cannot start SSH anywhere in the lab: "telemetry/SSH
ports are closed to clients" (`afw lab verify`). Legitimate administration starts on
MGMT. Into the client zones it is visible:
- every one of the 41 SSH events stored up to 2026-10-29 03:10Z is management SSH from
  10.77.50.254 or 10.77.50.10 into USR01 or ATK01;
- these are stored but never assessed, because the sources are protected.

**Not done: benign client-initiated SSH.** Generating it would mean opening SSH from
USERS, which weakens the segmentation the project relies on. An SSH flow *initiated
from* a client zone is therefore abnormal by policy, and the fixed ceiling plus "no
benign client SSH" is the correct baseline for client sources.

Sensor expansion is assessed separately (§6.3), after this data is collected; FW01 is
not changed during a capture.

## 3. Data

Generator: `traffic/benign_personas.py` with `AFW_NET=1`, at the commit that adds this
file.
- **What it adds.** Per-user ordinary network use: DNS through public resolvers (2–3 %
  local-name leaks that answer NXDOMAIN), HTTPS/HTTP visits to looked-up sites, NTP and
  ping to the gateway, and an occasional `http://` attempt to the app that fails.
- **User habits.** Each user draws a light, normal or heavy habit (weights 2:3:1).
- **Separation from web traffic.** Web journeys are unchanged and run alongside.

All data is collected in the same 60 min session as the A3 selection data:

| Dataset | Users (10.77.20.x) | Seed | Role |
|---|---|---|---|
| `nv1-train` | .100–.123 (24) | 921 | calibration |
| `nv1-val` | .124–.135 (12) | 922 | development (may be used repeatedly) |
| `a3-sel` + `a3-sel-shift` network events | .140–.161 (22) | 913/914 | **test: unseen users, evaluated once** |

The test users are the A3 selection users. The two uses are independent: network
evaluation never feeds the A3 decision, and A3 never tunes the network detector.

## 4. Detector and development rules

**Detector.** As shipped in N2 (`ml/network_detector.py`):
- a per-quantity benign upper quantile at 1 − α/k (α = 0.01, k = 26, Bonferroni);
- fixed protocol ceilings (ADR-042);
- calibration on every emission of every benign user, zero vectors included
  (`calibration_windows`), now with the DNS fix.

**Development on `nv1-val` only.** A change to the detector is allowed only if:
- it answers a cause demonstrated on `nv1-val`; and
- it is committed with that reason before the test.

Allowed kinds of change: the quantile method, α, which quantities are calibrated, and
how zero vectors are weighted. Ceilings are never raised.

**Freeze.** The calibration and code are committed; then the test runs once.

## 5. Measurements

On `nv1-val` (development) and on the test users (once):

- **Window FPR, unfamiliar.** The share of emissions with any quantity above its
  calibrated level, with a 95 % bootstrap CI over users. Emissions overlap, so users,
  not windows, are resampled.
- **Window FPR, strong.** The share of emissions at a fixed ceiling, and the number of
  users with any strong verdict.
- **Per user.** The share of each user's emissions that are unfamiliar, broken down by
  habit.
- **Drivers.** For each quantity, how often it caused an unfamiliar verdict.
- **Calibration content.** The share of non-zero calibration windows, and the quantiles
  per quantity.

## 6. Criteria and what they allow

### 6.1 On the test users, evaluated once

1. Unfamiliar window FPR ≤ **0.02**, with upper CI ≤ **0.05**.
2. **No** legitimate user receives a strong verdict.

Passing allows the claim: "the network detector has learned normal network use for this
lab population, at a measured false-unfamiliar rate". It does **not** allow any claim
about detecting network attacks, which needs the team's `net-portscan` and SSH-guessing
runs (`TEAM_ATTACK_QUICKSTART.md`).

### 6.2 Mode

The detector stays in **shadow** whatever the result. Moving it towards decisions needs:
- §6.1 passed;
- attack recall measured on team runs;
- a human decision.

### 6.3 Sensor expansion (assessed after the capture)

Inspecting DMZ and APP (vtnet4/vtnet5) would show WAF01→APP01 and APP01→DB01, and
server-side lateral movement. Cost and benefit are measured on FW01 (1 vCPU) before
anything is enabled:
- CPU load and Suricata memory;
- event rate added to CTRL01.

Server sources are management-protected and never enforced against, so they would be
assessed in shadow only. The decision and its measurement are recorded in ADR-042.

*Correction, 2026-10-29 03:55Z (factual, before any NV1 data was read; no criterion
changes):* FW01 has **2 vCPUs** and 1.5 GB RAM, not 1 vCPU. A baseline was measured
during the capture: `artifacts/evidence/nv1-2026-10-29/fw01-load-during-a3-capture.txt`.

## 7. Results

(Empty until the test has run.)
