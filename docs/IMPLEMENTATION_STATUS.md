# Implementation status

_Last updated: 2026-10-17 (session 3). Read this first when resuming._

## Session 3 — REAL-DATA AI MILESTONE (2026-10-17)

**First model trained on real lab traffic, with verified live inference.** Built a
benign user-journey generator (`traffic/benign_personas.py`), drove real traffic from
6 client source IPs (USR01) through the WAF to APP01, captured real datasets on CTRL01
(`real-benign-train2` 2464 obs/361 windows, `real-benign-val` 1049/154,
`real-benign-train` 1306/191 held-out), and trained **trusted profile v2** (6 sources,
361 windows). Measured on REAL data: **validation FPR ~1.3%** (1% budget); **live
inference → 0 false positives** on fresh held-out benign traffic (all detector scores
below threshold; the synthetic profile had falsely flagged the same traffic); M0/M1/M2
replay on held-out real benign → **FPR 0 / legit 100%**, M1 ~63 µs vs M2 ~11.9 ms
scoring. recall=null (no attack data — honest). Evidence:
`artifacts/evidence/real-benign-baseline-2026-10-17.md`. **Attack recall / scenarios
A,B,E remain BLOCKED on team attack traces** (machinery complete).

## Session 3 additions (MCP control plane, dashboard, GNS3 layout, TLS)

- **MCP control plane (`afw` server) — built, verified, registered.** One server,
  two backends: AI/policy/OPNsense/WAF via the controller REST API (`channel=mcp`
  token, HTTPS, lab-CA verified → same validator/enforcement/audit path) and
  host-side GNS3 lab tools. **26 tools** verified with a real stdio MCP client
  (real GNS3 topology, real AI data, safety guards: `restart_node CTRL01` refused,
  management-address block rejected). Registered in Claude Code via project
  `.mcp.json` (no secrets — token file paths); `claude mcp list` → **Connected**.
  See `docs/MCP_GUIDE.md`. New: `src/afw/mcp/gns3_tools.py`, `experiment_results`
  + `verify_isolation` tools.
- **Dashboard — fixed and populated on the live lab.** Rendered in headless
  Chromium; fixed ML-tile overflow + telemetry empty state; **explanation
  durability fixed** (detector outputs snapshotted onto the assessment, ADR-024).
  Root-caused "doesn't work well": TLS made it HTTPS-only with a host-pinned
  self-signed cert, which breaks SSH-tunnelled `localhost:PORT` access. Reverted
  the live controller to **HTTP** (operator access is via SSH tunnel, already
  encrypted; TLS is now opt-in, ADR-023). Populated the live controller with a
  clearly labelled `synthetic-ui-demo (NOT a lab result)` profile + M0/M1/M2
  experiments via the supported train→promote→replay workflow, so every panel
  shows real backend data. Access: `ssh -N -L 18080:10.77.50.10:8080 …` →
  `http://localhost:18080/`.
- **GNS3 canvas — professionally reorganised** (`afw lab layout`, idempotent):
  top-to-bottom traffic-flow layout, 5 colour-coded zones, role-appropriate
  symbols, title/subnet labels. See `docs/GNS3_TOPOLOGY.md`.
- **Controller API TLS — implemented, opt-in** (ADR-023): `afw serve` serves
  HTTPS when `AFW_TLS_CERT`/`AFW_TLS_KEY` are set (lab leaf cert + MCP/client CA
  verification wired and tested). The lab **defaults to HTTP** because operator
  access is via SSH tunnel; forcing HTTPS broke tunnelled `localhost` access.
- Tests: **54 passed, 9 lab-skipped**, mypy strict clean (81 files), ruff clean.

## Verified host facts (Phase 0)

| Item | Finding |
|---|---|
| Platform | Bare metal, Ubuntu 24.04.5, kernel 6.8.0-147, i7-13650HX (VT-x/EPT), 15 GiB RAM |
| Disk | `/` 200 GiB. Other partitions (p5 ext4, p6 btrfs) unmounted — **not touched** |
| Network | `enp8s0` 192.168.0.108/24, `tailscale0`; default route unchanged by the lab |
| Host setup (done) | GNS3 2.2.61 (held), ubridge (caps), dynamips (built-in switch nodes), QEMU 8.2.2/KVM, libvirt NAT (`virbr0` 192.168.122.1), host-only TAP `afw-mgmt0` 10.77.50.254 + route 10.77.0.0/16 via FW01. GNS3 API on 127.0.0.1:3080 with auth |

## Lab (GNS3 project `AI-Adaptive-Firewall`) — built and running

| Node | Role | Address | State |
|---|---|---|---|
| FW01 | OPNsense 26.7 nano; vtnet0 MGMT, vtnet1 MAINT (NAT), vtnet2 ATTACK, vtnet3 USERS, vtnet4 DMZ, vtnet5 APP | .1 in each zone | provisioned via serial console |
| CTRL01 | controller (`afw serve`), telemetry receiver | 10.77.50.10 | running |
| WAF01 | OWASP CRS 4.25.2 nginx (host networking) + policy helper :9443 | 10.77.30.10 | running |
| APP01 | rental app v1.0.0 | 10.77.40.10:8000 | running |
| USR01 / ATK01 | client zones + probe agents :9180 (probe sources .250) | 10.77.20.10 / 10.77.10.10 | running |
| HOST-MGMT / MAINT-NAT | host TAP on SW-MGMT / maintenance uplink | — | — |

Rebuild from nothing: `lab/images/bake-golden.sh` → `afw lab build` → `afw lab start` →
`afw lab provision-fw` → `afw lab provision-ids` → `afw lab deploy` → `afw lab verify` →
`AFW_LAB=1 uv run pytest tests/lab`.

## Done and tested (with evidence)

- **Golden image** (`lab/images/bake-golden.sh`): Ubuntu 24.04 + controller venv (pinned lock) + CRS image by digest; guests need no Internet. Verified: `AFW_BAKE_OK`, image digest present on WAF01.
- **Topology as code** (`lab/gns3/topology.yaml`, `src/afw/lab/`): idempotent build (second run creates nothing); per-node NoCloud seeds; all guests reachable on first boot.
- **FW01 provisioning** (`afw lab provision-fw`): config transformed from the image's own factory config (no image keys in Git); lab-CA certificate with IP SAN; least-privilege API user `afw-controller` (`page-diagnostics-tables`, `page-diagnostics-showstates`). Verified: factory password rejected; alias/state API 200, filter API **403**, bad secret **401**; TLS verified against lab CA.
- **G1 zone isolation**: `afw lab verify` **26/26** (no WAF bypass to APP, no lateral client↔client, no egress from DMZ/APP/clients, telemetry/SSH closed to clients, MGMT reaches all).
- **OPNsense adapter on the real firewall**: add/read-back/idempotent re-apply/remove. State-row format verified on 26.7 (`id` = `<id>/<creatorid>`, bare `src_addr`; searchPhrase is substring → exact filtering in code).
- **Heartbeat watchdog (ADR-009)**: heartbeat resets pf "Cleared"; with no heartbeat FW01 flushed `AFW_BLOCK_WEB` after **106 s** and logged `afw-watchdog … heartbeat age 104s > 90s`.
- **Deployment** (`afw lab deploy`, Ansible roles common/app/waf/controller/probe): second run `changed=0` on every host. Host firewalls default-deny (nftables).
- **Attribution & correlation on the real path**: WAF and app record the true client IP; forged `X-Forwarded-For`/`X-Request-ID` ignored; WAF `rid` == app `rid` == ModSecurity `unique_id`; controller joins all three (`app_joined: true`).
- **Lab acceptance** (`AFW_LAB=1 uv run pytest tests/lab`): **9/9** (enforcement, safety, IDS path, MCP). SOURCE_BLOCK enforced and verified in **4.90 s** (API → OPNsense → device read-back → probe shows drop; legitimate probe unaffected); revoke restores access; WAF_DENY gives 403 to target only; protected addresses (probe source, CTRL01, WAF01, FW gateway) refused.
- **Suricata IDS** (`afw lab provision-ids`, API with provisioner key): pcap/IDS on ATTACK+USERS, HOME_NET = DMZ/APP/MGMT, 7 ET Open categories; EVE → syslog-ng → CTRL01. Verified: one SYN to 10.77.30.10:3306 → ET SCAN 2010937 on vtnet2 → parsed and stored as IDS alert for 10.77.10.10. Finding: after a controller restart FW01's syslog-ng reconnects on its ~60 s timer (**measured 58 s**, alert buffered, not lost).
- **MCP with a real client** (`tests/lab/test_mcp_lab.py`, stdio `ClientSession`): tools listed; protected address refused; MCP block enforced with origin `mcp`; unblock rolls back.
- **Country policy (optional extension), SIMULATED only**: `geo_simulation` in `config/lab.yaml` maps fictitious countries to lab client addresses. Inbound CN policy enforced on OPNsense (read-back of all members, probe-verified block of 10.77.10.10, legitimate probe OK); outbound/both, unmapped countries and non-simulated (no GeoIP DB) are rejected with reasons.
- **Reopenable project + restart recovery**: project closed (all nodes powered off) and reopened (13 nodes/12 links); FW01 runtime alias empty after boot; controller restored the active block from its DB **5 s after start** (pf entry "Cleared" 14:23:14 vs service start 14:23:09); G1 26/26 and lab suite 9/9 afterwards.
- Unit/integration tests: **46 passing** (+9 lab tests skipped without `AFW_LAB=1`); **mypy strict clean** (78 files); ruff lint+format clean for the whole repo.

## Fixed from live-lab findings (this session)

1. First-boot NIC rename (`set-name`) raced networkd → guests unreachable until reboot. Seeds now match by driver only.
2. CRS 920350 (numeric Host) was counted as WAF evidence for every benign request (risk 20 for a normal user). Anomaly score now derived from CRS severities; only blocked or score ≥ 5 requests are evidence. Clients use `rental.lab.afw`.
3. WAF helper read-back proxied `/health`, producing fake client traffic from WAF01 every 5 s. Now a dedicated unlogged `/__afw/selftest`; sensor-IP traffic dropped in the controller; backend checked directly.
4. WAF read-back now fails (→ UNKNOWN) when nginx is not serving the helper's recorded revision.

## Not done / next

1. IDS-only sources (e.g. a scanner sending no HTTP) produce no assessment: assessments are per HTTP window. By design IDS alone is one category and cannot authorize a block; a scanner view is future work.
2. **Lab traffic generation** (benign personas + scenario drivers) is not implemented by me; the dataset/manifest format is defined in `src/afw/ml/datasets.py`. Without real lab runs there is **no evaluation data and no reported metrics**. The probe agent (`traffic/probe_agent.py`) is a verification tool only (fixed single GET).
3. **Offline replay experiment runner (M0/M1/M2) — now implemented** in
   `src/afw/ml/experiments.py` (`afw experiment replay --datasets <ids>`). It
   replays one labeled dataset through the *exact* live pipeline
   (`InferenceEngine`/`CorrelationEngine`/`DecisionEngine`) under all three
   strategies on the identical observation stream and the same trained FP budget,
   crediting M0 with the WAF's own inline blocks so the static baseline is fair.
   Reports window-level precision/recall/FPR/F1, source-level containment,
   legitimate-request success, detection latency and per-arm scoring latency; a
   run with no attack windows reports `recall = null`, never a fabricated 0.
   Correctness-tested on the synthetic fixture (`tests/integration/test_experiments.py`,
   2 tests) — those numbers are NOT results. **Still blocked on item 2 for any
   real metric: no labeled lab traffic has been supplied, so no M0/M1/M2 numbers
   may be cited yet.** Scenario A–E runs likewise blocked on item 2. GNS3
   portable snapshot not taken (project is reopenable and fully rebuildable from code).
4. **Dashboard — rendered in a real (headless) browser, two bugs fixed, and the
   fixes deployed to the live CTRL01 (session 3).** Chrome-extension control was
   unavailable, so the dashboard was rendered with **headless Chromium
   (Playwright)** against a locally-seeded controller (synthetic data, clearly not
   a result): every panel validated with real backend data and **zero console /
   page errors** — overview tiles/timeline/telemetry/resources, models (3
   detectors + metrics), profiles, `/api/sources/{ip}` baseline-vs-current (13
   features + series), policy lifecycle, the interactive **decision `explain`
   (all 8 sections incl. populated occlusion attributions)**, adaptation, audit,
   and the new M0/M1/M2 **experiments** table. Two real bugs found and fixed:
   the ML-model tile overflowed on the long model version (CSS wrap + shorter
   value), and the telemetry panel had no empty state. The updated assets ship in
   the wheel and were **deployed to CTRL01**; re-verified live over HTTPS (idle
   lab → clean empty states, no errors). Still needs live traffic for the
   live-sources/timeline panels (team data, item 2).
   **Explanation durability — FIXED.** The full detector outputs (incl. occlusion
   attributions) are now snapshotted onto the `RiskAssessment` at decision time
   (`correlation/engine.py`), so `explain` stays self-contained after
   `Controller._retention` purges the detections table (7-day `WATCH_RETENTION`).
   `explain_policy` reads the snapshot and falls back to the table for older
   assessments. Covered by `tests/integration/test_explain.py` (explanation
   survives a full detection purge). No schema migration (assessment stored as
   JSON body).
5. **Controller API TLS — DONE.** `afw serve` serves HTTPS when `AFW_TLS_CERT`/
   `AFW_TLS_KEY` are set (backward-compatible: plain HTTP otherwise). The lab
   leaf cert `CTRL01.pem` (SAN `IP:10.77.50.10`, `DNS:ctrl01.lab.afw`, lab-CA
   signed) is deployed to `/etc/afw/secrets/` by the controller role and enabled
   in the service unit. **Live CTRL01 now serves HTTPS on 8080** (plain HTTP
   refused; HTTPS verified against the lab CA → 200; no `verify=False` anywhere).
   The MCP client verifies via `AFW_API_CA`; lab tests updated to
   `https://10.77.50.10:8080` + lab CA. Dashboard URL is now
   **`https://10.77.50.10:8080/`** (browsers warn until the lab CA
   `~/.config/afw/pki/lab-ca.pem` is trusted).
6. Probe verification covers only addresses an agent owns (10.77.{10,20}.10 and .250); blocks on other addresses stay `applied_unverified` (honest, not a failure).
7. Golden image lacks `ping` (added to the bake list; current image unchanged). Verification uses a raw-socket ICMP probe.

## Secrets (never in Git)

`~/.config/afw/`: `gns3.env`, `lab_ed25519`, `ssh_config`, `opnsense/` (root password, controller + provisioner API keys), `pki/` (lab CA + leaf certs), `tokens/` (WAF helper, probe), `api/` (API tokens + hashes).
