# FW01 Suricata OOM — resource-safe fix and verification (P1)

**2026-10-29 ~17:40Z.** Resolves the OOM recorded in `fw01-ids-oom-2026-10-29/`.

## Diagnosis (where the shortage was)
- OOM was **inside the FW01 guest**, not host pressure: FW01 dmesg "was killed: failed to
  reclaim memory"; FW01 had **1536 MB RAM and no swap**; the **host** has 15 GB RAM with
  ~7.7 GB available and 4 GB swap (not the bottleneck).
- Suricata idle RSS ~460 MB; its memcaps (flow 128 + stream 64 + stream-reassembly 256 +
  host 32 + defrag 32 MB …) bound it to ~700–900 MB worst case. On 1536 MB with ~290 MB
  FreeBSD wired and no swap, the free margin was <90 MB — too thin, so a load spike
  (the 66-user A4 capture) OOM-killed it.

## Fix (resource-safe; detection preserved)
1. **FW01 RAM 1536 → 2560 MB** (GNS3 node property; primary fix, physical RAM for the
   latency-sensitive IDS). Host budget after change: started VMs 11 776 MB of 15 GB →
   ~3.2 GB for host OS/GNS3 + reclaimable cache. Reversible (set ram back, restart).
2. **1 GB persistent guest swap** on FW01 (`/swap0`, md99, `/etc/fstab`:
   `md99 none swap sw,file=/swap0,late 0 0`) — a supplementary safety net, per the
   "swap as supplement, not replacement" guidance.
3. **Suricata memcaps unchanged** — not lowered, so detection coverage is not sacrificed.
4. Started `cron` on FW01 (`cron_enable=YES` was set but cron was not running after the
   RAM-change boot), restoring the per-minute heartbeat watchdog (ADR-037).

## Verification (controlled legitimate workload)
- **Sustained stress:** 54 persona users with `AFW_NET=1` for 10 min (`fw_mon2.py`).
  - Suricata **stayed up** the whole time (pid constant, no restart).
  - RSS **plateaued at ~481 MB** (bounded by memcaps; did not grow unboundedly).
  - **Free memory ~461 MB** throughout; **swap 0 B used** (RAM alone sufficient).
  - Contrast: the same ~460–480 MB Suricata RSS OOM'd on 1536 MB with <90 MB free.
- **IDS path continuity:** SYN ATK01→10.77.30.10:3306 → alert at CTRL01 in ~8 s; IDS
  heartbeat fresh (1–14 s) once cron was running.
- **Full-lab recovery:** `afw lab verify` **41/41**; `AFW_LAB=1 pytest tests/lab`
  **14/14** (incl. `test_ids_alert_reaches_controller`); controller ok/monitor, not
  degraded; all three sensors fresh.

## Persistence / recovery
- RAM: saved in the GNS3 project node property.
- Swap: `/etc/fstab` (survives reboot).
- cron: `cron_enable=YES` (starts on boot). *Note:* cron did not auto-start on the
  RAM-change boot (started manually); watch the IDS heartbeat after any FW01 reboot and
  run `service cron start` if the heartbeat is stale.
- Mitigation still open: tune Suricata memcaps only if an even larger population is
  needed; current 2560 MB + 1 GB swap covers the lab's 66-user captures with margin.
