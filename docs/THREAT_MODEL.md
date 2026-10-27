# Threat model

Scope: the GNS3 lab and the AFW control plane. Trust boundaries and flows are in
`ARCHITECTURE.md` §3. Gaps and operational risks are in `SECURITY_AND_LIMITATIONS.md`.

## 1. Assets

1. Availability and integrity of the protected application (APP01) and its data (DB01).
2. Legitimate users' access: false positives are a harm, not a free side effect.
3. The enforcement plane: FW01 rules and aliases, the WAF deny/rate lists.
4. The trusted models and profile, and the training data and ledger behind them.
5. The control plane: API, tokens, MCP, audit log, controller host and its secrets.

## 2. Adversaries

| Adversary | Position | Capability assumed |
|---|---|---|
| External client attacker | ATTACK or USERS zone | Arbitrary HTTP(S) to WAF01:443, scanning, many requests, slow attacks; may know the system design |
| Poisoner | One or more client sources over time | Sends benign-looking traffic to shift what the learner considers normal |
| Compromised sensor or spoofer | DMZ/APP host or any lab host | Sends forged syslog lines to the controller |
| Malicious or mistaken operator / AI agent | MGMT, API or MCP | Holds a token; may issue harmful policy requests (prompt injection into an AI operator included) |
| Out of scope | Hypervisor/host compromise, FW01 OS compromise, physical access, supply chain of OPNsense/CRS/River | — |

## 3. Threats and mitigations

### 3.1 Network and application

| Threat | Mitigation | Residual |
|---|---|---|
| Bypass the WAF to reach APP/DB | FW01 pf: clients reach only WAF01:443; APP accepts WAF01 only; DB accepts APP01 only (37/37 isolation checks) | Lab clients have Internet egress (real-test mode) |
| Spoof client identity to frame a victim | Identity is the WAF's TCP peer; forged XFF / X-Request-ID overwritten (ADR-007) | — |
| Low-and-slow or distributed abuse | Per-window features plus WAF/auth evidence | Falls below per-window minimums by design: expected miss |
| Encrypted traffic hides payloads from IDS | IDS is supporting evidence only | IDS mostly sees scans and non-HTTPS traffic |

### 3.2 Enforcement

| Threat | Mitigation | Residual |
|---|---|---|
| Induce self-denial-of-service (get the controller to block itself, the WAF or the gateway) | Validator always refuses protected/management addresses; only client zones; bounded duration; never on IDS alone; at least two independent evidence categories (ADR-013/027) | — |
| Mass blocking through automation | Monitor/assisted/auto modes; auto rate limits; auto paused while evidence is degraded; max active policies | — |
| Stale blocks after controller death | FW01 watchdog flushes within about 120 s (ADR-009) | About 120 s window |
| Claimed-but-not-real enforcement | `enforced` only after device read-back and probe verification; ambiguous results stay `unknown` | — |
| Stolen controller firewall key | Least-privilege API user: alias membership and states only (ADR-017) | Attacker could still change block membership |

### 3.3 Models and learning

| Threat | Mitigation | Residual |
|---|---|---|
| Poisoning the online learner | Authenticated provenance only, taint, tenure, rate and share caps, quarantine with late evidence, sensitive-feature caps, similarity-based corroboration (ADR-028; M4 fix) | 4+ colluding similar tenured sources (documented) |
| Promoting a degraded model | Gate with real-attack recall and sensitive invariance; human promotion; probation with automatic rollback (ADR-030) | Gate cannot pass without real attack runs |
| Evasion by mimicking the profile | Multiple evidence categories; WAF/CRS inline independent of ML | Mimicry of benign behaviour is not detectable by anomaly detection alone |
| Tampered model artifact | sha256 recorded and verified on load and promotion | Host compromise is out of scope |
| Over-claiming detection | Risk is an evidence score, not a probability; no attack metric is reported without real labelled runs; synthetic data is refused for evaluation | — |

### 3.4 Datasets and evidence

| Threat | Mitigation | Residual |
|---|---|---|
| Train/test leakage | Splits by whole run (`assert_disjoint`); thresholds from validation only; holdout disjointness checked by the gate | Single-run CIs describe source variation, not run variation |
| Mislabelled attack runs | M6 journal: named operator, exact run windows, attacker addresses validated against the ATTACK zone, manifests generated from the journal | Depends on the team following the procedure |
| Synthetic data cited as results | Synthetic generators labelled; `aggregate` and the gate refuse synthetic data | — |
| Wrong geography | DB-IP database hash-verified, freshness reported, private space never mapped; real-country enforcement refused (ADR-033) | Database accuracy is DB-IP's |

### 3.5 Telemetry

| Threat | Mitigation | Residual |
|---|---|---|
| Forged sensor lines | mTLS with client CN mapped to role; a sensor may only send its own kind (ADR-029) | FW01 IDS feed is plaintext (source-IP allowlist only) |
| Replayed lines inflating evidence | Request-id UNIQUE; content-hash IDS ids (ADR-031) | — |
| Silencing a sensor | Heartbeat staleness at 150 s marks evidence degraded and pauses automation | Lines written into a dead session (about 100 s) are lost |

### 3.6 MCP and control plane

| Threat | Mitigation | Residual |
|---|---|---|
| AI agent / prompt injection issues harmful actions | MCP tokens are channel `mcp`, operator role at most; every mutation goes through the same validator and audit; no shell tool; no promotion tool; `restart_node CTRL01` refused | An operator-role agent can still request (validated) blocks |
| Token theft | Tokens stored hashed server-side; role-scoped; API reachable from MGMT only | Plain HTTP on MGMT (operator access via SSH tunnel; TLS opt-in, ADR-023) |
| Repudiation | Audit log for every policy, promotion, rollback, mode change and feedback item | Audit log lives on the controller host |
| Secret leakage via Git | Secrets only in `~/.config/afw/`; evidence scanned before commit | — |
