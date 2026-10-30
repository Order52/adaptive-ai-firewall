# NV2 data (protocol docs/engineering/NV2_NETWORK_NOVELTY_REVALIDATION.md §2), 60 min, all concurrent.
# generator: traffic/benign_personas.py at the protocol commit, copied to /tmp/benign_personas_nv2.py
TR=$(seq -s, -f 10.77.20.%g 100 123); HV=$(seq -s, -f 10.77.20.%g 162 169)
VA=$(seq -s, -f 10.77.20.%g 124 135); TE=$(seq -s, -f 10.77.20.%g 140 155); SH=$(seq -s, -f 10.77.20.%g 156 161)
for i in $(seq 100 169); do sudo ip addr add 10.77.20.$i/24 dev ens3 2>/dev/null; done
date -u +NV2_START=%Y-%m-%dT%H:%M:%S > /tmp/nv2-times.txt
G=/tmp/benign_personas_nv2.py
AFW_NET=1 AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$TR AFW_DURATION=3600 AFW_SEED=941 setsid nohup python3 $G >/tmp/nv2-train.log 2>&1 </dev/null &
AFW_NET=1 AFW_NET_HABITS=heavy AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$HV AFW_DURATION=3600 AFW_SEED=945 setsid nohup python3 $G >/tmp/nv2-heavy.log 2>&1 </dev/null &
AFW_NET=1 AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$VA AFW_DURATION=3600 AFW_SEED=942 setsid nohup python3 $G >/tmp/nv2-val.log 2>&1 </dev/null &
AFW_NET=1 AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$TE AFW_DURATION=3600 AFW_SEED=943 setsid nohup python3 $G >/tmp/nv2-test.log 2>&1 </dev/null &
AFW_NET=1 AFW_MODE=shared AFW_SOURCES=$SH AFW_DURATION=3600 AFW_SEED=944 setsid nohup python3 $G >/tmp/nv2-test-shift.log 2>&1 </dev/null &
sleep 3; cat /tmp/nv2-times.txt; pgrep -fc benign_personas_nv2
