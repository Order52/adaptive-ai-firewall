# Offline evaluation on recorded real attack traffic (CIC-IDS2017) — provenance

**Separate gate from live GNS3.** This evaluates our pipeline on an EXTERNAL, recorded
packet capture processed OFFLINE. It is NOT an attack executed in our GNS3 lab and NEVER
counts toward the live GNS3 attack-detection gate.

- **Dataset:** CIC-IDS2017 (Canadian Institute for Cybersecurity, UNB), Tuesday-WorkingHours
  (FTP-Patator + SSH-Patator brute force + benign). Downloaded from a public mirror; cite
  Sharafaldin et al., ICISSP 2018. Stored under `~/afw-external-datasets/` (not in Git).
- **Known labelling defects:** CICFlowMeter-derived flow labels have documented errors
  (Engelen et al., IEEE SPW/WTMC 2021; >20% reconstructed/relabelled). We DO NOT use those
  labels. Ground truth here is **by attacker IP** (Kali 205.174.165.73 / NAT 172.16.0.1),
  the authoritative who-attacked signal, which is defect-resistant.
- **Offline analysis:** `suricata -r <pcap> -c suricata-offline.yaml` (no packets on any
  network); eve.json flow/dns/tls/ssh.
- **Adapter + models:** `cic_offline_eval.py` reuses our production `parse_suricata_net`
  → `NetworkEvent` → `NetworkWindows(services=frozenset())` → our 28 network features;
  then RandomForest (batch), River ARF (incremental, predict-before-learn), the unsupervised
  NetworkNovelty (calibrated on CIC benign, domain-adapted), and a held-out-family
  (FTP↔SSH) generalisation test.
- **Domain adaptation caveat:** models/calibration are CIC-specific; CIC benign ≠ our lab
  benign, so these results do NOT transfer to the GNS3 lab without re-training. Reported
  as external evidence only.
