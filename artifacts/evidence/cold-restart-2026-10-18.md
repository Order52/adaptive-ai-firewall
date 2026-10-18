# Cold-restart recovery evidence (2026-10-18)

Full GNS3 lab power cycle (`afw lab stop` → `afw lab start`), verifying the project
reopens correctly and the AI control plane recovers its state — the P9 cold-restart
and P1 close/reopen gates.

## Procedure & timings

| Step | Time (UTC) | Result |
|---|---|---|
| Pre-restart baseline | 04:19:41 | 13/13 nodes; profile **v2**, 3 models, monitor |
| `afw lab stop` | 04:20 | 6 QEMU guests powered off; controller unreachable (000) |
| `afw lab start` (cold boot) | 04:20:19 | 6 guests started |
| Controller back up | ~04:23 | `/api/overview` → 200 |

## Recovery verification (fresh)

- **Nodes**: 13/13 started.
- **Controller**: recovered automatically (systemd); **trusted profile v2 + 3 active
  models restored** from the DB — identical to the pre-restart baseline (no retrain,
  no manual step).
- **Zone isolation**: `afw lab verify` → **26/26** after reopen — no WAF/app bypass
  introduced by the power cycle, management still reaches all zones.
- **Canvas**: professional layout and all **14 zone annotations persisted**
  (CTRL01 at (-30,-540), FW01 at (-20,-180)) — the saved GNS3 project retained the
  organised canvas across the restart.
- **MCP**: `claude mcp list` → `afw ✔ Connected` after the restart.

## Conclusion

The lab survives a full cold restart: the GNS3 project reopens with its saved
topology/canvas, the controller restores the real trained profile and enforcement
state without intervention, isolation is intact, and MCP reconnects. One documented
command path (`afw lab start` + `afw lab verify`) brings the lab back for the demo.
