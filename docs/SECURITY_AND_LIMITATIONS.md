# Security and limitations

Threats, adversaries and mitigations: `THREAT_MODEL.md`. Trust boundaries and
communication flows: `ARCHITECTURE.md` §3. This page lists the safety invariants and
the known gaps.

## Safety invariants (enforced in code, tested)

- An anomaly **alone** never authorises a traffic-affecting change — a block needs ≥2
  independent evidence categories (ADR-013). Risk is a capped additive **evidence
  score**, never presented as a probability.
- Protected/management addresses are always refused (probe source, CTRL01, WAF01, FW
  gateway). Verified: such a block ends `rejected`.
- Enforcement is **level-triggered and ownership-aware** (idempotent duplicates,
  overlaps, restarts, reboots). Policies are bounded-duration and expire.
- Learning is anti-poisoning. The trusted profile and champion are frozen. Batch
  candidates and the online challenger learn only from authenticated, untainted,
  population-level benign traffic, under the following controls:
  * source-share and rate caps;
  * sensitive-feature limits;
  * similarity-based corroboration for anomalous windows.

  Promotion needs a passing gate (incl. real-attack recall) and a human admin; probation
  rolls back automatically (ADR-012, ADR-028, ADR-030).
- Evidence from a stale sensor (no heartbeat for 150 s) is marked degraded and
  automatic enforcement pauses (ADR-031). IDS-only evidence never exceeds WATCH.
- Dead-controller fail-safe: FW01 flushes dynamic blocks within ~120 s without
  heartbeats (ADR-009).

## Limitations (honest)

- **No attack-side results.** Attack recall, scenarios A/B/E and the incremental value
  of the AI under attack are **BLOCKED** on team-run attack scenarios. This project
  does not generate attack traffic. The M6 harness and the evaluation machinery are
  complete and tested; benign-side training, inference and FPR are real and measured.
- **High false-positive rate under a workload shift.** The v2 detectors, trained on one
  5.4-minute run of six addresses at one request cadence, flagged 13 % (robust stats) to
  72 % (Isolation Forest) of windows when the same personas ran at a slower cadence ten
  days later (`RESULTS.md` §3; P1 measures unseen users). Do not run enforce mode on
  this profile.
- **Online learning not yet observed live.** The live challenger learned 0 windows,
  because champion proposals tainted every new source (fail-closed). Adaptation is
  shown on recorded real drift only, and the gate refuses the adapted challenger.
- **Residual poisoning risk.** Four or more colluding, tenured, behaviourally similar
  sources can corroborate each other (M4). SV-1: occlusion attribution does not prove
  causal independence of evidence.
- **Telemetry loss window.** Closed for WAF01/APP01 by RELP over mutual TLS (ADR-038):
  in a dead-session test 150 of 150 lines arrived (plain TCP lost 105 of 150). An
  acknowledgement means "queued in memory", so a controller crash can still lose lines
  acknowledged but not yet processed (normally under a second). FW01's IDS feed stays
  on syslog-ng TLS (no RELP in OPNsense) and keeps the loss window of about 100 s. FW01's IDS feed is authenticated (mTLS since 2026-10-28, ADR-035) and,
  since ADR-037, heartbeats every 30 s while Suricata runs; a stopped Suricata or feed
  makes the `ids` sensor stale. The heartbeat cannot show that Suricata still inspects
  traffic correctly, only that it runs and its log path reaches CTRL01.
- **IDS visibility.** Client→WAF traffic is HTTPS, so Suricata mainly catches scans and
  non-HTTPS signatures; IDS is supporting evidence only and never blocks alone.
- **Low-and-slow / distributed** misuse falls below the per-window minimum by design
  (expected miss); an application-level aggregate detector is future work.
- **Self-signed lab PKI.** Fine inside the lab only. The controller API is HTTPS with a
  lab-CA certificate (since 2026-10-28); clients must be given the lab CA. The CTRL01
  certificate also names `localhost`/`127.0.0.1` for the SSH tunnel, so any client
  that trusts the lab CA accepts it on a local port.
- **Single-host scale.** ~7 GB of a 16 GB host; the modular-monolith design scales to
  more apps/sensors/backends by configuration, but large-scale throughput is untested.
- **ML caveats.** Isolation-Forest/robust-stats scores are anomaly scores, not
  calibrated probabilities. Single-row IF scoring is ~11.9 ms on CTRL01 (within the 5 s
  enforcement budget) but much costlier than the statistical arm (~63 µs).
- **Not air-gapped.** Guests can reach the Internet for real tests; revert by removing
  the per-zone egress rules in `opnsense_config.lab_rules` and re-provisioning.
- **Country policies.** Real-country enforcement runs on FW01 (ADR-036):
  * inbound is verified only by table read-back, because no real-country traffic
    reaches the lab;
  * outbound covers the client zones only and is proven by an egress probe;
  * countries above 40,000 networks (e.g. US) are refused;
  * existing connections are not killed;
  * geography is as accurate as DB-IP.
- **GNS3 canvas** is a desktop GUI — organised and verified via the API, but not
  captured as a pixel screenshot here.

## Secrets handling

All credentials live under `~/.config/afw/` and are never committed; the sanitized
source archive (`git archive`) contains only tracked files and was scanned to confirm
no keys/tokens/DBs/VM-disks are included.
