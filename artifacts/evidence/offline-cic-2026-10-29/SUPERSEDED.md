# Superseded static-Suricata results (kept, not deleted)

`cic-static-vs-ml-tuesday.json` and `cic-static-vs-ml-friday.json` (and any document quoting
"static Suricata detects 0.0", "the AI catches 128 windows Suricata misses and Suricata catches
0") were produced with a **flawed baseline**: `suricata-rules.yaml` set
`HOME_NET = [192.168.10.0/24, 205.174.165.0/24, 172.16.0.0/16]`, which put the ATTACKER's own
addresses (172.16.0.1, 205.174.165.x) inside the home network. About 11,900 of the 53,254 ET Open
rules only match traffic from an *external* source (`$EXTERNAL_NET = !$HOME_NET`), so they could
never fire on the attacker. That made static Suricata look far weaker than it is.

Corrected baseline: `suricata-rules-fair.yaml` (`HOME_NET = [192.168.10.0/24]`, the victim LAN
only), results in `cic-static-vs-ml-tuesday-FAIR.json`, `../offline-cic-friday-2026-10-29/
cic-static-vs-ml-friday-FAIR.json`, `../offline-cic-thursday-2026-10-30/`. See
`docs/engineering/ERRATUM_STATIC_BASELINE.md`. The ML-only numbers are unaffected.
