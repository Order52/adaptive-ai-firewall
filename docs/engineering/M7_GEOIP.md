# M7: Real GeoIP (ADR-033)

Status: real country lookup, provenance, integrity, freshness and preview implemented,
tested and installed on CTRL01 (2026-10-27). **Real-country enforcement is not
implemented**, and the validator refuses such policies explicitly. Simulated lab
geography (`geo_simulation`) is unchanged and stays labelled SIMULATED.

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

## 3. Why real-country enforcement is refused

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
  * real-country policy refused.
* `tests/unit/test_policy.py`: real-country policy rejected.
* 7 of 7 mutations caught: `artifacts/evidence/m7-2026-10-27/mutation-check.txt`.
* Live install and API checks: `artifacts/evidence/m7-2026-10-27/`.
