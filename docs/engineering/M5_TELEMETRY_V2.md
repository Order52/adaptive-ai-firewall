# M5: Telemetry v2 (ADR-031)

Status: implemented, unit-tested, deployed and verified live (2026-10-27).
Builds on ADR-029 (mTLS sensors, role-checked ingest, HTTP request-id dedup).

## 1. Scope (Phase 0 audit §3.3, roadmap M5)

| Requirement | Implementation | Evidence |
|---|---|---|
| Schema version and receipt time | `schema_version` (2) and `received_at` on `HttpObservation` and `IdsAlert`; records written before v2 load as version 1 | `test_http_observation_carries_envelope_v2`, `test_v1_records_still_load`; live `artifacts/evidence/m5-2026-10-27/live-envelope.txt` |
| Duplicate lines ignored | HTTP: request-id UNIQUE (ADR-029). **IDS: new.** `event_id` was random (`new_id`), so a replayed Suricata line was stored twice and **counted twice as IDS evidence**. Now content-derived (sha256 of sensor, flow, time, signature, endpoints); idempotent insert; only new alerts reach correlation and taint | `test_ids_ids_are_content_derived`, `test_replayed_ids_line_is_stored_and_counted_once` (mutation-checked) |
| IDS-only sources assessed, never blocked on IDS alone | Every hop, sources with IDS alerts in the lookback but no HTTP window get a `view="ids_only"` assessment (at most once a minute per source; protected sources skipped). The decision engine caps IDS-only assessments at WATCH, whatever the score | `test_ids_only_source_is_assessed_but_never_more_than_watched` (thresholds lowered so the cap is what decides; mutation-checked); live: ATK01 scan → `ids_only` assessment score 29 |

## 2. Telemetry-loss defect found during M5 verification (fixed)

**Symptom.** After the 19:19Z controller restart, CTRL01 received **no HTTP telemetry for
about 55 minutes**, with no alarm. IDS (plaintext, FW01) kept flowing.

**Cause, established step by step:**

1. WAF01/APP01 rsyslog kept writing into the TCP session of the *old* controller
   process (socket in CLOSE-WAIT with unsent data). rsyslog's gtls driver does not act
   on the receiver's FIN.
2. A packet capture on CTRL01 showed **zero** packets arriving on 5514: FW01's stateful
   firewall silently drops the stale flow, so no RST ever reaches the sender. Linux
   retransmits for `tcp_retries2=15` (more than 15 min) before failing the send.
3. After a restart, `degraded()` keyed on `age("waf") > 120 s`, but the age was *unknown*
   (nothing seen since start), so the controller never flagged the stall. A stuck sender
   and an idle one looked identical.

**Fixes:**

* **Sensors** (`sensor_tls` role): `net.ipv4.tcp_retries2 = 8` (a dead session fails in
  about 100 s, then rsyslog suspends the action and reconnects); omfwd `RebindInterval`
  and a 10 s resume interval.
* **Heartbeat**: a systemd timer on each sensor writes one line every 30 s, forwarded over
  the same mTLS channel. The heartbeat counts only on an authenticated channel. The
  regular writes also surface a dead session within a minute, which stops the
  long-idle case from silently ageing out of FW01's state table.
* **Controller**: once the live receiver runs, each mTLS sensor role (from
  `tls_identities`) is stale after 150 s without a heartbeat, *including never since
  start*. A stale sensor marks evidence degraded (`/api/overview` →
  `telemetry.sensors`, `telemetry_degraded`). Tests:
  `test_heartbeat_counts_only_on_an_authenticated_channel`,
  `test_silent_sensor_after_restart_marks_evidence_degraded`.
* **CTRL01 host firewall**: telemetry flows in `ct state invalid` from known senders get a
  TCP reset instead of a silent drop. This helps only when packets reach CTRL01; the
  sensor-side bound is the fix that matters for the FW01 path.

Measured recovery without touching the sensors (`reconnect.txt`, before the heartbeat
was deployed):

| Case | Telemetry flowing again after |
|---|---|
| Controller restart under traffic | about 12 s |
| Restart, sensors idle 60 s, then traffic | about 12 s |
| Restart, sensors idle 17 min (beyond FW01's closing-state timeouts), then traffic | about 120 s. The first write found the dead TLS session (`GnuTLS error -53`, `TCPSendBuf error`); rsyslog suspended the action and reconnected within 1 s. The lines written during that time were lost (see residual risk) |

**Second defect, found on live deployment of the heartbeat.** The first heartbeat unit
built its JSON line with `printf` inside `ExecStart=/bin/sh -c '...'`. systemd's own
quote handling stripped the inner double quotes, so the line arrived as `{hb:...}`.
The controller counted it as `parse_error:bad_json` and never saw a heartbeat. Unit
tests could not catch this because they feed correct lines. Fix: the line is written by
`/usr/local/sbin/afw-heartbeat`, which removes the nested quoting. After the fix, live
`/api/overview` showed heartbeat ages of 9–10 s for both sensors.

Live liveness checks with the heartbeat deployed (`heartbeat-liveness.txt`):

| Check | Result |
|---|---|
| Controller restart, no client traffic, no sensor action | both heartbeats seen again after **59 s**. The heartbeat's own writes surface the dead session, so recovery no longer waits for client traffic |
| app01 heartbeat timer stopped | app marked **stale and evidence degraded after 148 s** (limit 150 s); WAF unaffected |
| app01 timer restarted | stale and degraded cleared within **2 s** |

**Residual risk.** rsyslog over TCP has no application-level acknowledgement: lines
written into a dead session before the failure is detected are lost (bounded by the
socket buffer and about 100 s). RELP would close this gap but needs a RELP server on the
controller; not done. Heartbeat staleness makes such gaps visible instead of silent.

## 3. Not in scope / still open

* ~~FW01's IDS feed stays plaintext on 5515.~~ Closed 2026-10-28 (P5, ADR-035): FW01
  now exports Suricata alerts over mutual TLS to 5514 with its own client certificate
  (role `ids`), and the plaintext listener is disabled. FW01 still sends no heartbeat.
* No session- or account-level view. The IDS-only view adds the missing non-HTTP
  source view only.
* `/var/log/afw/*.log` on the sensors has no rotation (pre-existing; the heartbeat log has
  its own).
