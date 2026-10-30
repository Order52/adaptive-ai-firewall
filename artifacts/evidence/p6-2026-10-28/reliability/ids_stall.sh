#!/bin/bash
# IDS engine-stall experiment (directive item 6). Suricata on FW01 runs in pcap (IDS,
# detection-only) mode, so pausing it does not affect traffic. The engine is frozen
# with SIGSTOP for STALL seconds (longer than the 150 s staleness limit), then resumed.
# Question: does the controller notice that the IDS stopped inspecting?
# usage: ids_stall.sh <out.txt> [stall_s]
set -u
OUT=$1; STALL=${2:-240}
cd "$(dirname "$0")/../../../.."
FW="uv run python artifacts/evidence/p6-2026-10-28/reliability/fw01_cmd.py"
CA=$HOME/.config/afw/pki/lab-ca.pem
api() { curl -s --cacert $CA -H "Authorization: Bearer $(cat ~/.config/afw/api/dashboard.token)" \
  https://10.77.50.10:8080/api/overview | python3 -c "import json,sys;d=json.load(sys.stdin);print('ids',d['telemetry']['sensors'].get('ids'),'degraded',d['telemetry_degraded'])"; }
fwstate() { $FW 'ps -axo pid,stat,comm | grep -w suricata | grep -v grep; stat -f "stats.log mtime %Sm" -t %T /var/log/suricata/stats.log; date -u +%T' 2>/dev/null | tr '\n' ' '; echo; }
{
echo "# IDS stall: SIGSTOP suricata for ${STALL}s at $(date -u +%FT%TZ)"
echo "before: $(api)"; echo "fw: $(fwstate)"
$FW 'pkill -STOP -x suricata; echo stopped' 2>/dev/null
T=$(date +%s)
while [ $(( $(date +%s) - T )) -lt $STALL ]; do
  sleep 30; echo "+$(( $(date +%s) - T ))s $(api) | fw: $(fwstate)"
done
$FW 'pkill -CONT -x suricata; echo resumed' 2>/dev/null
echo "resumed at $(date -u +%FT%TZ)"
sleep 40; echo "after: $(api) | fw: $(fwstate)"
} 2>&1 | tee "$OUT"
