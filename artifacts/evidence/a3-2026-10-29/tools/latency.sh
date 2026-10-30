#!/bin/bash
# Telemetry latency, end to end: benign marked request at USR01 -> WAF01 -> rsyslog -> CTRL01 observation store.
# Measures (time first visible in CTRL01's DB, polled every 0.25 s) - (send time at USR01). Clocks: chrony on all VMs.
S="ssh -F $HOME/.config/afw/ssh_config"
$S usr01 'sudo ip addr add 10.77.20.99/24 dev ens3 2>/dev/null; true'
for i in 1 2 3 4 5 6 7 8; do
  N=afwlat-$(date +%s%N)
  SENT=$($S usr01 "date +%s.%N; curl -sk -o /dev/null --interface 10.77.20.99 https://10.77.30.10/$N" | head -1)
  $S ctrl01 "sudo /opt/afw/venv/bin/python3 -c \"
import sqlite3,time,sys
c=sqlite3.connect('file:/var/lib/afw/afw.sqlite3?mode=ro',uri=True)
t0=time.time()
while time.time()-t0<60:
    if c.execute(\\\"select 1 from observations where body like '%$N%' limit 1\\\").fetchone():
        print('$N', round(time.time()-$SENT,2)); sys.exit()
    time.sleep(0.25)
print('$N', 'not seen in 60 s')\""
  sleep 7
done
