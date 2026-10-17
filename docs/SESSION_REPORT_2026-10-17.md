# Session report — 2026-10-17

AI-Adaptive-Firewall final-year project. This report covers the work done on
2026-10-17 (session 1 built the controller code; session 2, the main part of
this report, built and tested the GNS3 lab). Every "done" item below was tested
on the running lab unless it says otherwise.

---

## 1. What happened this session (timeline)

1. **Host preparation, completed.** GNS3 2.2.61, QEMU/KVM, ubridge, libvirt NAT and
   the host-only management TAP `afw-mgmt0` (10.77.50.254) were set up.
   `dynamips` was added because GNS3 2.2's built-in Ethernet switch depends on it.
2. **Golden Ubuntu image baked.** One Ubuntu 24.04 image now contains the controller
   runtime (pinned dependencies), Docker with the pinned OWASP CRS WAF image
   (by digest), rsyslog and nftables. Lab machines never need Internet access.
3. **OPNsense image prepared and studied.** I booted a throwaway copy to read the real
   26.7 factory config and API code. This settled two open assumptions: the
   firewall-state row format and the API permission names.
4. **GNS3 topology built from code.** `lab/gns3/topology.yaml` defines 13 nodes
   and 12 links, created through the GNS3 REST API. Re-running it creates nothing new.
5. **FW01 provisioned over its serial console.** The factory config was dumped and
   transformed on the host: zones, firewall rules, block/heartbeat aliases, a
   least-privilege API user, a lab-CA certificate and a new root password. A
   heartbeat watchdog was installed.
6. **Zone isolation verified (gate G1).** 26/26 reachability checks pass from inside
   the machines.
7. **Services deployed with Ansible.** The app, WAF, WAF policy helper, controller
   and probe agents were deployed, each with a default-deny host firewall. A second
   run changes nothing.
8. **End-to-end testing.** A live-lab acceptance test suite was written and run:
   enforcement, safety, IDS path and MCP.
9. **Bugs found by the live lab, then fixed** (see §4).
10. **Suricata IDS enabled** on FW01, with alerts forwarded to the controller.
11. **MCP exercised by a real MCP client.** The optional country-policy feature
    was implemented as a clearly labelled simulation.
12. **Full power-cycle test.** The GNS3 project was closed and reopened. The
    controller restored the active block on the firewall, and all tests passed
    again.
13. **Code quality.** mypy strict is clean, ruff lint and format are clean, and
    the docs were updated.

---

## 2. What is finished (with evidence)

| Area | Result |
|---|---|
| **Lab topology** | 5 zones (ATTACK, USERS, DMZ, APP, MGMT); FW01, CTRL01, WAF01, APP01, USR01, ATK01. Saved GNS3 project, reopenable (tested). |
| **Rebuild from code** | `bake-golden.sh` → `afw lab build` → `afw lab start` → `afw lab provision-fw` → `afw lab provision-ids` → `afw lab deploy` → `afw lab verify` |
| **Zone isolation (G1)** | `afw lab verify`: **26/26**. Clients can't bypass the WAF to reach the app, can't reach each other, and have no Internet; telemetry and SSH ports are closed to clients. |
| **Firewall API security** | Controller key can use only alias and state endpoints (filter API → 403, wrong secret → 401); TLS verified against the lab CA; factory password no longer works. |
| **Blocking (OPNsense)** | Source block enforced and *verified* in **4.9 s**: device read-back shows the entry, a probe confirms traffic is dropped, and a legitimate client stays unaffected. Revoke restores access. |
| **WAF deny** | Returns 403 only to the targeted client. |
| **Safety** | Probe source, CTRL01, WAF01 and the gateway are always refused. |
| **Dead-controller watchdog** | Without heartbeats, FW01 flushed its block table on its own after **106 s** and logged why. |
| **Client identity** | WAF and app record the true client IP; forged `X-Forwarded-For` / `X-Request-ID` are ignored; one request ID links WAF access log, app log and ModSecurity audit log. |
| **Telemetry pipeline** | WAF, app and IDS logs arrive at CTRL01 over syslog and are correlated per request. |
| **Suricata IDS** | One test connection triggered ET SCAN rule 2010937 on FW01; the alert reached the controller and was attributed to 10.77.10.10. |
| **MCP** | A real stdio MCP client listed tools, was refused on a protected address, blocked and unblocked a source (recorded with origin `mcp`). |
| **Country policy (optional)** | Simulated mapping only (§5). Inbound "CN" policy enforced on the real firewall and probe-verified; outbound, unmapped and "real GeoIP" requests are rejected with reasons. |
| **Restart recovery** | After a full project power-off and reopen, the controller restored an active block **5 s** after starting (proved by the firewall entry's timestamp). |
| **Tests** | 46 unit/integration tests pass; 9 live-lab tests pass (`AFW_LAB=1 uv run pytest tests/lab`). |
| **Code quality** | mypy strict clean (78 files); ruff lint and format clean for the whole repo. |
| **Docs** | `IMPLEMENTATION_STATUS.md` and `ARCHITECTURE_DECISIONS.md` (ADR-001 … ADR-022) updated. |

---

## 3. What is NOT finished

| Item | Status / reason |
|---|---|
| **AI evaluation (M0 static / M1 statistical / M2 ML)** | **Not done. No metrics exist.** It needs real labelled lab traffic. |
| **Scenarios A–E** | Not run. They need benign and attack traffic generators, which I was not permitted to write (blocked by the safety system). The team must supply them in the format in `src/afw/ml/datasets.py`. |
| **Model training on real data** | Not done; only a clearly labelled *synthetic* test fixture exists, used for functional tests only. |
| **Offline replay experiment runner** | Not written. |
| **Controlled adaptation on live data** (Scenario C: shadow learning, drift, promotion) | Code exists and is unit-tested; not yet run on lab traffic. |
| **Dashboard** | Served by the controller, but not yet opened in a browser to check it. |
| **TLS for the controller API** | Plain HTTP on the host-only management network (token-protected). |
| **GNS3 portable snapshot** | Not taken; the project reopens fine and is fully rebuildable from code. |
| **Git commit** | Nothing committed yet (not requested). |

---

## 4. Bugs found by the live lab, and fixed

1. **Guests unreachable on first boot:** renaming the network card raced the network service. Fixed in the per-node seed config.
2. **Normal users scored risk 20:** CRS rule 920350 ("Host header is an IP") was counted as attack evidence. Now only blocked requests or anomaly score ≥ 5 count, the score is computed from rule severities, and clients use the hostname `rental.lab.afw`.
3. **Fake client traffic every 5 s:** the WAF helper's self-test went through the app. It now uses a dedicated, unlogged `/__afw/selftest`, and the controller ignores the WAF's own address.
4. **False "enforced":** the WAF read-back now fails if nginx is not serving the policy revision the helper recorded.
5. **Firewall state-deletion fields were guessed wrong:** corrected to the real 26.7 format (`id` = `<id>/<creatorid>`).
6. **Country policy accepted then failed:** it is now enforced via a simulated mapping, or rejected up front.

---

## 5. Limitations (important for the report/viva)

- **No accuracy, detection-rate or false-positive numbers.** None may be quoted until real lab runs exist. The synthetic test's AUC = 1.0 is meaningless and must not be cited.
- **Country blocking is simulated.** `config/lab.yaml` maps fictitious countries to lab IPs. It is *not* real geography, and only "inbound" is supported (the protected services never start connections to clients).
- **IDS sees little of the web traffic.** Client traffic to the WAF is HTTPS, so Suricata mainly catches scans and non-HTTPS signatures. IDS is supporting evidence only.
- **IDS-only sources get no risk assessment.** Assessments are built per HTTP window, so a pure scanner with no web requests isn't scored. By design IDS alone could never justify a block (blocks need ≥ 2 evidence categories).
- **IDS alerts can be delayed ~60 s after a controller restart** (measured 58 s; buffered, not lost), because of the firewall log forwarder's reconnect timer.
- **Traffic verification covers only addresses a probe agent owns** (10.77.10.10, 10.77.20.10, and the .250 probe addresses). Blocks on other addresses stay `applied_unverified`. That is correct behaviour, not an error.
- **Dead-controller fail-safe is ~1.5–2 min.** The watchdog clears dynamic blocks within about 120 s, so stale blocks can persist that long.
- **Low-and-slow / distributed attacks** fall below the per-window minimum by design and are expected to be missed.
- **ML latency:** single-row Isolation Forest scoring was ≈10 ms on the host; not yet measured on CTRL01.
- **Lab-only security choices:** a self-made lab CA; the WAF VM lets unprivileged processes bind port 443 (needed for the non-root nginx with host networking); the controller API is HTTP on the management network; FW01 has an Internet uplink (outbound only) for IDS rule updates.
- **Resources:** the lab uses ~7 GB of the host's 16 GB RAM; scaling to more clients is limited.
- **Golden image** lacks `ping` (fixed in the bake script, current image unchanged); the tests use a raw-socket ping instead.

---

## 6. What is left (suggested order)

1. **Team: deliver traffic tooling.** Benign personas plus Scenario A–E drivers, producing `DatasetManifest` + `SourceLabel` datasets (`src/afw/ml/datasets.py`).
2. Capture benign training/validation runs → `afw train bootstrap` → review and promote the first profile.
3. Write the offline replay runner and compare M0 / M1 / M2 on held-out runs (same false-positive budget, run-level splits).
4. Run Scenarios A–E live, including Scenario C (app v2 rollout → shadow learning → drift → reviewed promotion).
5. Measure detection-to-enforcement latency and controller resources on CTRL01.
6. Open and check the dashboard in a browser (`http://10.77.50.10:8080/`, token in `~/.config/afw/api/dashboard.token`).
7. Add TLS to the controller API; optionally take a GNS3 snapshot.
8. Commit the work to Git.

---

## 7. Where things are

| What | Where |
|---|---|
| Status (read first) | `docs/IMPLEMENTATION_STATUS.md` |
| Design decisions | `docs/ARCHITECTURE_DECISIONS.md` |
| AI method notes | `docs/AI_RESEARCH.md` |
| Topology | `lab/gns3/topology.yaml` |
| Lab automation code | `src/afw/lab/` |
| Ansible | `lab/ansible/` |
| Firewall watchdog | `lab/opnsense/` |
| Live-lab tests | `tests/lab/` |
| Secrets (never in Git) | `~/.config/afw/` |
