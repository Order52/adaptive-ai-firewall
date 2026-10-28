# Architecture

AI-Adaptive-Firewall is a control plane (CTRL01) that sits on top of mature
enforcement and sensing engines in an isolated GNS3 lab. The engines are OPNsense pf
with Suricata on FW01, and an OWASP CRS WAF on WAF01. The control plane learns how the
protected application is normally used, detects and correlates deviations, decides on
proportional responses, validates them against safety rules, enforces them through the
real firewall/WAF, verifies the effect, and adapts to legitimate change through a gated
online learner.

Design decisions are recorded as ADRs in `ARCHITECTURE_DECISIONS.md` (ADR-001…033).
Node, port and entry-point details are in `COMPONENT_INVENTORY.md`.

## 1. Lab topology

```
            ATTACK 10.77.10.0/24          USERS 10.77.20.0/24
            ATK01 .10 (+probe .250)       USR01 .10 (+probe .250)
                     \                       /
                      \    (443 only)       /
                       +------ FW01 -------+         OPNsense 26.7: pf, aliases,
                       |   (.1 in every    |         Suricata (pcap) on ATTACK+USERS,
                       |    zone)          |         heartbeat watchdog
       DMZ 10.77.30.0/24                APP 10.77.40.0/24        DB 10.77.60.0/24
       WAF01 .10 :443 ------------->    APP01 .10 :8000 ------>  DB01 .10 :5432
       OWASP CRS 4 + helper :9443       rental app               PostgreSQL 16
                                   MGMT 10.77.50.0/24
                     CTRL01 .10 (controller, API/dashboard :8080, syslog mTLS 5514)
                     DESK01 .20 (operator desktop)    HOST-MGMT TAP .254 (host)
```

Only these inter-zone paths exist (verified by `afw lab verify`, 37 checks):

* ATTACK/USERS → WAF01:443;
* WAF01 → APP01:8000;
* APP01 → DB01:5432;
* MGMT → all hosts for management;
* sensors → CTRL01 telemetry ports.

Clients cannot reach APP01 or DB01 directly, and client zones cannot reach each other.
Since 2026-10-22 every zone also has outbound Internet egress through NAT on FW01.

## 2. Control-plane software (CTRL01)

Modular monolith with hexagonal boundaries: `domain` (pure models), `ports`
(protocols), adapters (`persistence`, `enforcement`, `telemetry`), services. SQLAlchemy
is confined to `persistence`; everything crossing a boundary is a typed Pydantic model;
mypy runs in strict mode.

```
 syslog 5514 (mTLS, WAF01/APP01)  ─┐
 syslog 5514 (mTLS, FW01 IDS)     ─┼─► telemetry: parse ▸ role check ▸ dedup ▸ correlate (rid join)
                                   │        │
                                   │        ▼ HttpObservation / IdsAlert (envelope v2)
                                   │   features: 30 s windows, 5 s hop, 13 behavioural features
                                   │        │
                                   │        ▼
                                   │   ml: robust stats (M1) · Isolation Forest (M2) · HST champion
                                   │        │            └──► shadow challenger (online, gated) ──► M3 gate
                                   │        ▼
                                   │   correlation: evidence items, independent categories, risk score
                                   │        │
                                   │        ▼
                                   │   policy: decision ▸ validator (safety) ▸ lifecycle state machine
                                   │        │
                                   │        ▼
                                   │   enforcement: OPNsense alias · WAF helper · memory (tests)
                                   │        │  reconcile (level-triggered) + read-back + probe verify
                                   ▼        ▼
                     persistence (SQLite, Alembic)  ◄──►  API (FastAPI) ─► dashboard, MCP server
```

The control loop:

1. **Ingest.** Each line is classified by tag. A line on an mTLS channel is accepted
   only from the role its certificate names. HTTP records are deduplicated by request
   id, IDS records by a content hash.
2. **Correlate and window.** WAF, app and audit records are joined by request id into
   one `HttpObservation`. Every 5 s hop, the windows that have closed become feature
   vectors per source and application.
3. **Detect.** The detectors score each window against the trusted profile. Thresholds
   were set on benign validation data at a 1 % FPR budget.
4. **Assess.** Detector outputs, WAF, IDS and auth evidence become evidence items in
   categories. Any traffic-affecting action needs at least two independent categories
   (ADR-013, ADR-027). Sources seen only by the IDS get an `ids_only` assessment,
   capped at WATCH.
5. **Decide and validate.** The response is proportional: WATCH, RATE_LIMIT, WAF_DENY
   or SOURCE_BLOCK. Every proposal, whether from the AI, an operator or MCP, passes the
   same validator:
   * protected and management addresses are refused;
   * client zones only;
   * bounded duration;
   * mode-dependent automation (monitor / assisted / auto), with rate limits;
   * automation is suspended while evidence is degraded.
6. **Enforce and verify.** The reconciler drives desired state into each backend and
   reads it back. A policy is `enforced` only after read-back plus probe verification.
   Policies expire, and can be revoked or rolled back.
7. **Learn.** The online path is in §4. The trusted profile and models change only by
   human promotion.

## 3. Trust boundaries and communication flows

| Flow | Transport and authentication | Trust decision |
|---|---|---|
| Clients → WAF01 | HTTPS 443 through FW01 pf | Untrusted. Client identity is the WAF's TCP peer only; forged XFF/X-Request-ID are overwritten (ADR-007) |
| WAF01 → APP01 | HTTP 8000, APP host firewall allows WAF01 only | App trusts identity headers from WAF01's IP only |
| WAF01/APP01 → CTRL01 | rsyslog over **mutual TLS** on 5514, lab CA; client CN mapped to sensor role (ADR-029) | A sensor may only speak for its own role. Only authenticated telemetry is eligible for learning |
| FW01 Suricata → CTRL01 | syslog-ng over **mutual TLS** on 5514 with its own client certificate (CN `fw01-telemetry.lab.afw` → role `ids`, ADR-035). The plaintext 5515 listener is disabled | Authenticated; still supporting evidence only and never blocks alone. No heartbeat (OPNsense cannot send one), so FW01 feed liveness is not observable |
| Sensors → CTRL01 heartbeat | 30 s line over the same mTLS channel | Liveness counts only on an authenticated channel; 150 s silence marks evidence degraded (ADR-031) |
| CTRL01 → FW01 | OPNsense REST over TLS (lab CA), least-privilege API user: alias membership and state queries only (ADR-017/018) | A stolen controller key cannot rewrite rules |
| CTRL01 → WAF01 helper | HTTPS 9443, token, CTRL01 only | Deny-list and rate-limit membership only |
| Operator / Claude → CTRL01 | HTTP :8080 from MGMT only (operator access via SSH tunnel), bearer tokens with roles viewer/operator/admin and channel api/mcp | MCP mutations use the same validator and audit as AI decisions; no shell tool |
| FW01 watchdog | Local cron on FW01 | Flushes dynamic blocks within about 120 s if controller heartbeats stop (ADR-009) |

## 4. Adaptive learning lifecycle

Full design: `ADAPTATION_DESIGN.md`.

```
 live windows ─► champion HST scores (production) ──────────────► decisions
        │
        └─► eligibility gate (stage 1: authenticated, untainted, tenured, not sensitive,
              not policed; stage 2: anomalous windows need behaviourally similar
              corroboration) ─► shadow challenger learns (River HST, prequential)
                                    │ atomic checkpoints, lineage ledger
                                    ▼
          admin: evaluate ─► promotion gate (holdout, FPR, attack recall on REAL runs,
                                    │          sensitive invariance) ─► frozen CANDIDATE
          admin: promote ─► champion swap + probation ─► auto-rollback to parent on
                                                           excess anomalies or FP reports
```

## 5. Failure behaviour

| Failure | Behaviour |
|---|---|
| Controller down | FW01 watchdog flushes dynamic blocks within about 120 s; on restart the reconciler restores owned policies from the DB (measured 5 s) |
| Sensor silent or telemetry session dead | Sensor marked stale after 150 s and evidence degraded, so automatic actions pause. TCP retries are bounded so rsyslog reconnects in about 100 s. Lines written into a dead session are lost (residual risk, ADR-031) |
| Backend unreachable or ambiguous | Policy goes to `unknown` and is resolved on the next reconcile; never reported as enforced without read-back |
| Bad challenger | Never affects decisions while in shadow; a promoted one is rolled back automatically during probation |
| GeoIP database missing, stale or tampered | Reported in status; real-country enforcement is not implemented anyway (ADR-033) |
