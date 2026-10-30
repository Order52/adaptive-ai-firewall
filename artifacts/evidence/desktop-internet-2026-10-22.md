# Operator desktop + Internet egress (2026-10-22)

Two operator-requested additions, applied live and verified: a **graphical
workstation** in GNS3 for interactive testing, and **Internet egress** for the lab
guests so real-world tests are possible — while keeping inter-zone segmentation.

## 1. DESK01 — management desktop (MGMT zone)

- New node **DESK01** (`10.77.50.20`, MGMT zone, VNC console) from a baked XFCE
  image (`lab/images/bake-desktop.sh` → `afw-ubuntu-desktop.qcow2`): XFCE + Firefox,
  the `afw` venv, the Claude CLI, and desktop launchers for the dashboard and an MCP
  tool tester.
- **Verified live:**
  - XFCE desktop renders over VNC (lightdm active, Xorg running); launchers present.
  - Reaches the **AI dashboard** (`http://10.77.50.10:8080/` → 200) and the API
    (`/api/overview` → profile v2).
  - **afw MCP works from the desktop**: `mcp-tools` connects the stdio MCP server and
    lists **26 tools**; `lab_health` and `overview` return live controller data.
  - Claude CLI installed (`/usr/local/bin/claude`, 2.1.x) for `claude mcp list` /
    chat (needs the operator's login + Internet, now available).

## 2. Internet egress — "real-test" mode (no longer air-gapped)

- Firewall now allows each zone to reach the **Internet** (NAT out the MAINT uplink),
  with **inter-zone traffic still blocked** (`opnsense_config.lab_rules`: the specific
  allows match first, then a block of the `10.77.0.0/16` supernet, then a pass to
  anywhere else). Public DNS (`1.1.1.1`, `8.8.8.8`) added to the guest seeds.
- **Verified live:**
  - `usr01`, `atk01`, `desk01` reach `https://example.com` → **200** (real DNS + TLS).
  - All seven guests resolve names (`dns_ok`).
  - **Isolation gate: 35/35** — Internet checks now PASS as *allowed*, and every
    inter-zone property still holds (no WAF bypass, DB isolation, telemetry integrity,
    management isolation). Segmentation preserved; only the "no egress" property was
    intentionally removed per the operator request.

## Security note

Giving the guests Internet is a deliberate change for real testing. The important
segmentation guarantees are unchanged and still enforced + verified (35/35). To return
to a fully air-gapped posture, remove the two egress rules per zone in
`opnsense_config.lab_rules` and re-provision; the isolation checks for "to Internet"
flip back to *deny*.

## MCP from the operator's own session

The `afw` MCP server is reachable from the operator's Claude Code session as well as
from DESK01 — `mcp__afw__lab_health`, `overview`, `adaptation_status`, etc. were
exercised live throughout this work.
