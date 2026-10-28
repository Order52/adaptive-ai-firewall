#!/bin/bash
# RELP crash-loss experiment (directive item 6). Lab only; benign traffic from one
# discarded smoke-test address. The controller is killed with SIGKILL mid-stream;
# every request id the WAF logged for that source is then looked up in the
# controller's observations. usage: relp_crash.sh <ip,ip,...> <seed> <out.txt>
# (power-archetype users, so requests are in flight when the controller dies)
set -u
IP=$1; SEED=$2; OUT=$3
S="ssh -F $HOME/.config/afw/ssh_config"
DUR=240
{
[ "$($S usr01 'pgrep -fc benign_personas_v2')" = "0" ] || { echo "generators running: refusing"; exit 1; }
echo "# RELP crash-loss run: source $IP seed $SEED duration ${DUR}s; SIGKILL at +90 s"
$S usr01 "for a in ${IP//,/ }; do sudo ip addr add \$a/24 dev ens3 2>/dev/null; done; AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_ARCHETYPES=power AFW_SOURCES=$IP AFW_DURATION=$DUR AFW_SEED=$SEED setsid nohup python3 /tmp/benign_personas_v2.py >/tmp/relp-$SEED.log 2>&1 </dev/null &"
T0=$(date -u +%s); echo "start $(date -u -d @$T0 +%FT%TZ)"
sleep 90
echo "kill  $(date -u +%FT%T.%NZ) $($S ctrl01 'systemctl show afw-controller -p MainPID --value')"
$S ctrl01 'sudo systemctl kill -s KILL afw-controller'
for i in $(seq 1 30); do sleep 2; st=$($S ctrl01 'systemctl is-active afw-controller'); [ "$st" = active ] && break; done
echo "back  $(date -u +%FT%TZ) state=$st pid=$($S ctrl01 'systemctl show afw-controller -p MainPID --value')"
# run between experiment phases only: no other generator may be running
while [ "$($S usr01 'pgrep -fc benign_personas_v2')" != "0" ]; do sleep 10; done
sleep $(( T0 + DUR + 20 - $(date -u +%s) > 0 ? T0 + DUR + 20 - $(date -u +%s) : 0 ))
sleep 60   # let resends and the queue drain
$S waf01 "sudo grep -aE '\"src\":\"(${IP//,/|})\"' /var/log/afw/waf-access.log" | python3 -c "
import json,sys
t0=$T0
r=[json.loads(l) for l in sys.stdin if l.strip()]
r=[x for x in r if float(x['ts'])>=t0-5]
k=$(( T0 + 90 ))
print('waf_requests_before_kill',sum(float(x['ts'])<k for x in r),'within_10s_after_kill',sum(k<=float(x['ts'])<k+10 for x in r))
open('/tmp/relp-waf-$SEED.txt','w').write('\n'.join(x['rid'] for x in r))
print('waf_requests',len(r))"
$S ctrl01 "sudo -u afwctl /opt/afw/venv/bin/python -c \"
import sqlite3;c=sqlite3.connect('file:/var/lib/afw/afw.sqlite3?mode=ro',uri=True)
ips=tuple('$IP'.split(','))
q='select request_id from observations where observed_at >= ? and client_ip in (%s)' % ','.join('?'*len(ips))
print('\n'.join(r[0] for r in c.execute(q,('$(date -u -d @$((T0-5)) '+%F %T')',)+ips)))\"" > /tmp/relp-ctl-$SEED.txt
python3 - <<PY
w=set(open('/tmp/relp-waf-$SEED.txt').read().split()); c=set(open('/tmp/relp-ctl-$SEED.txt').read().split())
print('controller_observations', len(c & w))
print('lost', len(w - c), sorted(w - c)[:20])
print('unexpected', len(c - w))
PY
} 2>&1 | tee "$OUT"
