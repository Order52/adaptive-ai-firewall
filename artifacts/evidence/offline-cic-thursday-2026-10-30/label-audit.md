# Thursday label audit (CIC-IDS2017, 2017-07-06)

Source facts: UNB documentation (https://www.unb.ca/cic/datasets/ids-2017.html) — Thursday
morning web attacks (brute force, XSS, SQL injection) from Kali 205.174.165.73 to the web
server 192.168.10.50; afternoon infiltration: Meta exploit on Win Vista 192.168.10.8, "Cool disk"
on a Mac 192.168.10.25, then the Vista host runs an Nmap portscan against all other clients.

Measured in our Suricata output (thu-rules-out/eve.json):
- `172.16.0.1` (the attacker's post-NAT address; 205.174.165.73/.80 are never a flow source):
  3,142 flows, **only** to 192.168.10.50 (:80 ×2,115, :443, :21) and 192.168.10.51 (a few
  service ports); active 12–13 UTC (web attacks), 16–19 UTC (afternoon). Attack-only traffic,
  so an IP label is correct for it.
- `192.168.10.8`: **89,036 flows over 1,152 distinct destination ports** — the compromised
  Vista host's internal scan. An IP-based "benign" label would be WRONG for it.

Decision: attack label = 172.16.0.1 only. Windows from 192.168.10.8 and 192.168.10.25 are
EXCLUDED (neither benign nor attack): counting them benign would penalise correct detections,
counting them attack would be a guess without per-flow ground truth (and the CICFlowMeter
labels have documented errors; Engelen et al. 2021). Consequence: the infiltration/scan phase
is NOT evaluated; this run evaluates the web-attack family from 172.16.0.1.
