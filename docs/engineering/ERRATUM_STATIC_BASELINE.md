# Erratum: the "static Suricata detects 0.0" baseline was unfair

Written 2026-10-30. **Earlier documents said static Suricata (ET Open rules) detected none of
the brute-force attacks and that "the AI catches 128 attack windows Suricata misses, Suricata
catches 0 the ML misses". That comparison used a misconfigured baseline and overstated the AI's
advantage. Corrected below.**

## What was wrong
The Suricata config I built for the offline runs set
`HOME_NET = [192.168.10.0/24, 205.174.165.0/24, 172.16.0.0/16]`. That put the **attacker's own
addresses** (172.16.0.1 after NAT, and 205.174.165.x) *inside* the home network. About 11,900
of the 53,254 ET Open rules only match traffic from an external source
(`$EXTERNAL_NET = !$HOME_NET`), so they could never fire on the attacker. The ML numbers were
unaffected; only the static side was.

## Corrected baseline
`HOME_NET = [192.168.10.0/24]` (the victim LAN only; `suricata-rules-fair.yaml`). Static
Suricata now fires on the attacker on every day, for example: Tuesday 2,372 "ET SCAN Potential
FTP Brute-Force attempt response" + SSH scan alerts; Friday scan rules; Thursday 891 "Script tag
in URI … Cross Site Scripting" plus SQL-injection signatures.

## Corrected comparison (window level; static = attack-category alert for the source in the
## last 60 s; ML = RandomForest, behaviour-only; compromised hosts excluded on Thursday)

| Capture / slice | Static recall | Static FPR | ML recall | ML FPR | Only static | Only ML |
|---|---|---|---|---|---|---|
| Tuesday brute force (test split) | **0.434** | 0.032 | **0.895** | 0.000 | 2 | 68 |
| Friday families (test split) | **0.133** | 0.027 | **0.267** | 0.0005 | 8 | 16 |
| Thursday morning web attacks, whole capture, ML never saw Thursday | **0.282** | 0.055 | **0.877** | 0.000 | 5 | 102 |
| Thursday afternoon, same setup | 0.043 | 0.037 | 0.205 | 0.000 | 4 | 30 |

Thursday morning: static OR ML detects **0.908** (both 41, neither 15).

## What this means
- **The AI advantage is real but about half what was claimed**: on brute-force-style activity
  ML detects roughly twice what static Suricata does (0.90 vs 0.43; 0.88 vs 0.28) at near-zero
  false positives, where static raises 3–5 % false-positive windows and alerts on hundreds of
  benign sources.
- **They are complementary, not substitutes**: static catches windows ML misses (2, 8, 5), and
  the union is better than either (Thursday morning 0.91).
- On the hard families (Friday, Thursday afternoon) **both are weak**.
- Caveats: the ET Open ruleset is the 2026 release applied to 2017 traffic (some 2017-era
  signatures may be gone); "static" here is alert-based and window-aligned, not a tuned
  production ruleset; ML is trained on CIC itself (cross-capture for Thursday only).
- The independent run-level sample is still small (Tuesday 3 bursts, Friday 4, Thursday 7).

## Corrections applied
`ARCHITECTURE_VS_GOALS.md` (Goal C, §2 table, §6), `STATUS_LIMITATIONS_FIXES.md`. The old result
files are kept and listed in `artifacts/evidence/offline-cic-2026-10-29/SUPERSEDED.md`.
