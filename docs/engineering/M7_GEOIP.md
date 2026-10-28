# M7: Real GeoIP (ADR-033, ADR-036)

Status: real country lookup, provenance, integrity, freshness and preview implemented,
tested and installed on CTRL01 (2026-10-27). **Directional real-country enforcement on
FW01 added 2026-10-28 (P5, ADR-036, §5).** Simulated lab geography (`geo_simulation`)
is unchanged and stays labelled SIMULATED.

## 1. Data source and provenance

| Item | Value |
|---|---|
| Database | DB-IP "IP to Country Lite", CSV, release 2026-10 |
| Licence | CC BY 4.0; attribution "IP Geolocation by DB-IP (https://db-ip.com)", shown in every status response |
| Download | `https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz` (free, no account) |
| SHA-256 | `097426b8ddae89157d444a59ac1847e873f7943c32d52becc4371c8b0273af80` |
| Content | 710,834 rows; 362,122 IPv4 ranges kept (IPv6 ignored); 245 country codes |
| Installed | CTRL01 `/var/lib/afw/geo/` (`country.csv.gz` + `country.meta.json`); not in Git |
| Cost | Loaded in about 1.2 s, about 46 MB resident (host measurement) |

`afw geoip install <file> --release YYYY-MM --source URL` does the following:

* parses the file before accepting it;
* refuses overlapping or unsorted ranges, and files with fewer than 100,000 IPv4 ranges;
* records the SHA-256, source URL and release month.

At load, the controller re-hashes the file, and a mismatch makes the database unusable
(reported, not fatal). The database is considered stale 45 days after its release month
begins (DB-IP releases monthly). The age and stale flag are reported in
`/api/overview` → `geoip` and in `/api/geo/status`.

## 2. Semantics

* `lookup(ip)` returns the ISO country code, or `None`. RFC 1918, reserved, loopback and
  link-local addresses always return `None`, whatever the data says. DB-IP's `ZZ`
  (unassigned) is not a country.
* **Inbound:** every lab client is RFC 1918, so real geography never matches the
  sources the controller sees. This is a property of the lab, not a defect.
* **Outbound:** since 2026-10-22 each zone has Internet egress (NAT via FW01), so lab
  hosts do open connections to real countries. The controller does not observe those
  flows: its telemetry is WAF/app HTTP and IDS alerts. The preview says this explicitly.
* Direction (as in the MCP server instructions):
  * `inbound` means connections initiated from the country toward the protected services.
  * `outbound` means connections initiated from lab networks toward the country.
* `preview(cc, direction)` (`GET /api/geo/preview/{cc}`, MCP `geo_preview`) reports:
  * the country's IPv4 networks (CIDR-summarised) and address count;
  * a sample of those networks;
  * which sources seen in the last 24 h (HTTP clients and IDS sources) fall in the country;
  * the lab effect for that direction (inbound: observed sources covered; outbound: lab
    egress affected but not observed);
  * the database status.

  It never enforces anything.

## 3. Why real-country enforcement was refused at first (superseded by §5)

Enforcement in this system goes through `DesiredState.blocked_sources`. That is a set of
host addresses, reconciled into the single host alias `AFW_BLOCK_WEB`, with read-back by
alias membership (ADR-009). A real country is thousands of networks (CN: 8,331 CIDRs in
this release). Enforcing it correctly would need all of the following:

* network-granular desired state and read-back;
* a separate bulk-loaded alias per direction;
* new pre-installed FW01 rules referencing it, including an outbound rule on the LAN side.

Silently accepting such a policy would leave it stuck in an applying state, or worse,
look enforced while it was not. The validator therefore rejects it with
`real-country enforcement is not implemented; use the GeoIP preview (ADR-033)`. Earlier
it said "no GeoIP database loaded", which would have become misleading once a database
was installed.

Verification would also be weak. No inbound real-country traffic reaches the protected
services, so an inbound policy could only be checked by alias read-back. An outbound
policy could additionally be checked with a probe from a lab host to an address in the
country, which is possible because of the per-zone egress. It remains future work.

## 5. Real-country enforcement (ADR-036, 2026-10-28)

The two obstacles in §3 were the controller's one-address-per-call key and the lack of
inbound traffic to verify. The design avoids widening the key and does not overclaim:

| Part | What it does |
|---|---|
| Validator | Real `geo_block` only from an operator or MCP (never the AI); database loaded, hash-verified and not stale; country known, has global networks, at most 40,000 networks per direction; networks may not overlap lab or protected space |
| Publication | The policy service computes, per direction, the sorted global networks of all active countries and serves them at `GET /api/geo/enforcement/{direction}` with a header `# afw-geo direction=… countries=… count=… sha256=…`. Only the `firewall` role (FW01's token) and above can read it; that role can read nothing else |
| FW01 | The watchdog (cron, every 30 s) pulls both lists **only while the controller heartbeat is fresh**, drops a list whose sha256 differs from its header, and loads a changed list with one `pfctl -T replace`. With a stale heartbeat it flushes `AFW_GEO_IN`, `AFW_GEO_OUT` and `AFW_BLOCK_WEB` |
| Rules | Installed once by `afw lab provision-geo` with the root provisioner key: `block in quick` from `AFW_GEO_IN` on every interface; `reject in quick` from ATTACK and USERS to `AFW_GEO_OUT`. Servers and MGMT are not covered, so a country policy cannot cut deployment or management egress |
| Read-back | The OPNsense adapter lists the live tables with the existing least-privilege key, in pages of 1,000 rows (OPNsense 26.7 returns a malformed chunked body at about 5,000 rows, found live). A country counts as present only when every one of its networks is in the table; countries being removed are still read back, so removal is confirmed by the firewall, not assumed |
| Verification | **Inbound:** read-back only. No real-country connection reaches the lab, so the policy stays `applied_unverified` with `traffic_inbound: n/a`. **Outbound:** `enforced` only after read-back and an egress probe: the USR01 agent opens one TCP connection to a target from its own fixed allowlist (`geo_enforcement.egress_targets`, country from GeoIP) inside the country, which must fail, and one to a control target outside every blocked country, which must succeed (otherwise "outage, not proof") |

Limits:
* Large countries are refused (US: 155,176 networks > 40,000).
* Existing connections are not killed; they last until they close.
* GeoIP accuracy is DB-IP's; anycast addresses are attributed to one country.
* Only one egress target per country can prove outbound blocking; countries without
  one stay `applied_unverified`.

Live (2026-10-28, `artifacts/evidence/p1-2026-10-28/`):
* `p5-geo-lab-test.txt`: AU outbound (12,265 networks) `enforced` after read-back and
  probe. Checked independently over SSH: USR01 could not reach 1.1.1.1:443 but reached
  8.8.8.8:443, and APP01 still reached 1.1.1.1. Access returned after revocation. KP
  inbound (14 networks) was read back and stayed `applied_unverified`. The file also
  records the read-back defect (malformed chunked responses, policy flapping to
  `unknown`), the fix, and 29 stable read-back cycles afterwards.
* `p5-geo-watchdog.txt`: the controller was stopped while AU was enforced. FW01 fetches
  failed; the watchdog flushed 12,265 entries at heartbeat age 103 s, and USR01 reached
  1.1.1.1 again 84 s after the stop. After restart the still-valid policy was re-pulled
  and blocking resumed within 26 s.
* `p5-geo-mutation-check.txt`: 9/9 mutations caught.

## 4. Tests and evidence

* `tests/unit/test_geoip.py`, 6 tests:
  * lookup, including RFC 1918 with bad upstream data, ZZ, gaps and IPv6 rows;
  * tampered file refused by hash;
  * missing database reported;
  * partial, unsorted and badly-dated files refused at install;
  * freshness from the release month;
  * preview counts and observed-source matching.
* `tests/integration/test_api.py::test_geoip_endpoints_lookup_and_preview_without_enforcing`:
  * 503 before install;
  * lookup, preview and 404 after install;
  * 401 without a token;
  * real-country policy accepted and left `applied_unverified` for inbound (ADR-036);
  * FW01 pull list hash-addressed; the `firewall` role cannot read anything else.
* `tests/unit/test_policy.py`: real-country policy rejected when enforcement is not enabled.
* `tests/unit/test_geo_enforcement.py` and `tests/lab/test_geo_enforcement_lab.py` (§5).
* 7 of 7 mutations caught: `artifacts/evidence/m7-2026-10-27/mutation-check.txt`.
* Live install and API checks: `artifacts/evidence/m7-2026-10-27/`.
