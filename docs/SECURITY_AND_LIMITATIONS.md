# Security model & limitations

## Threat model & trust boundaries

**Protected asset:** the rental application (APP01) and the availability of
legitimate users. **Adversary:** a client in the ATTACK/USERS zones attempting
application abuse (auth abuse, injection, scanning, novel misuse). **Isolation:** the
whole lab is a self-contained GNS3 project on a host-only management TAP. Since
2026-10-22 each zone has outbound Internet egress (NAT via FW01, "real-test mode");
all inter-zone traffic is still blocked except the explicit service paths, and the
database tier (DB01, PostgreSQL) is reachable only from APP01:5432.

Trust boundaries:

- **Client zones → FW01**: every cross-zone packet is subject to OPNsense pf. Clients
  cannot reach APP01 directly — only via WAF01 (gate G1: 35/35 verified, incl. DB isolation).
- **WAF → app identity**: client identity is taken only from the WAF's TCP peer; the
  WAF overwrites `X-Forwarded-For`/`X-Real-IP`/`X-Request-ID`, and the app trusts those
  headers only from the WAF IP. Forged-header bans are therefore impossible (ADR-007).
- **Controller ↔ firewall**: a least-privilege OPNsense API user can only change alias
  membership and read/delete states; a stolen controller key cannot rewrite rules
  (ADR-017). All controller→device TLS is verified against the lab CA (ADR-018).
- **Claude/operator vs AI runtime**: development/admin privileges (lab operations) are
  separate from the AI runtime's restricted enforcement broker. MCP mutations pass the
  same typed policy validator as autonomous decisions; there is **no raw-shell tool**.
- **Management plane**: host-only MGMT zone, reached locally or over SSH (which
  encrypts transport). Bearer-token API; TLS is implemented and opt-in.

## Safety invariants (enforced in code, tested)

- An anomaly **alone** never authorises a traffic-affecting change — a block needs ≥2
  independent evidence categories (ADR-013). Risk is a capped additive **evidence
  score**, never presented as a probability.
- Protected/management addresses are always refused (probe source, CTRL01, WAF01, FW
  gateway). Verified: such a block ends `rejected`.
- Enforcement is **level-triggered and ownership-aware** (idempotent duplicates,
  overlaps, restarts, reboots). Policies are bounded-duration and expire.
- Learning is anti-poisoning: the trusted profile is frozen; candidates are built from
  reputation-gated, population-level benign traffic with a source-share cap, sensitive
  feature limits and an attack-recall regression gate; promotion is human-reviewed.
  Repeated malicious traffic cannot redefine "normal".
- Dead-controller fail-safe: FW01 flushes dynamic blocks within ~120 s without
  heartbeats (ADR-009).

## Limitations (honest)

- **No attack-side results.** Attack/adversarial recall, scenarios A/B/E and the
  incremental-AI-value numbers are **BLOCKED** on team-supplied attack traces;
  generating an attack driver was stopped by the safety classifier. The machinery is
  complete and tested; benign-side training/inference/FPR are real and measured.
- **IDS visibility.** Client→WAF traffic is HTTPS, so Suricata mainly catches scans and
  non-HTTPS signatures; IDS is supporting evidence only and never blocks alone.
- **Low-and-slow / distributed** misuse falls below the per-window minimum by design
  (expected miss); an application-level aggregate detector is future work.
- **Self-signed lab PKI.** Fine inside the lab; the controller serves HTTP by default
  because operator access is via an SSH tunnel (already encrypted). TLS is opt-in.
- **Single-host scale.** ~7 GB of a 16 GB host; the modular-monolith design scales to
  more apps/sensors/backends by configuration, but large-scale throughput is untested.
- **ML caveats.** Isolation-Forest/robust-stats scores are anomaly scores, not
  calibrated probabilities. Single-row IF scoring is ~11.9 ms on CTRL01 (within the 5 s
  enforcement budget) but much costlier than the statistical arm (~63 µs).
- **Not air-gapped.** Guests can reach the Internet for real tests; revert by removing
  the per-zone egress rules in `opnsense_config.lab_rules` and re-provisioning.
- **Country policies are simulated** (no GeoIP database loaded).
- **GNS3 canvas** is a desktop GUI — organised and verified via the API, but not
  captured as a pixel screenshot here.

## Secrets handling

All credentials live under `~/.config/afw/` and are never committed; the sanitized
source archive (`git archive`) contains only tracked files and was scanned to confirm
no keys/tokens/DBs/VM-disks are included.
