# A3 selection + NV1 network data (protocols A3_AUTH_CONTROLS.md, NV1_NETWORK_NOVELTY_VALIDATION.md), 60 min
# generator: traffic/benign_personas.py sha256 3dbf49a4...fcf3 copied to /tmp/benign_personas_nv1.py
SEL=$(seq -s, -f 10.77.20.%g 140 155); SH=$(seq -s, -f 10.77.20.%g 156 161)
TR=$(seq -s, -f 10.77.20.%g 100 123); VA=$(seq -s, -f 10.77.20.%g 124 135)
for i in $(seq 100 161); do sudo ip addr add 10.77.20.$i/24 dev ens3 2>/dev/null; done
date -u +A3_START=%Y-%m-%dT%H:%M:%S > /tmp/a3-times.txt
G=/tmp/benign_personas_nv1.py
AFW_NET=1 AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$SEL AFW_DURATION=3600 AFW_SEED=913 setsid nohup python3 $G >/tmp/a3-sel.log 2>&1 </dev/null &
AFW_NET=1 AFW_MODE=shared AFW_SOURCES=$SH AFW_DURATION=3600 AFW_SEED=914 setsid nohup python3 $G >/tmp/a3-sel-shift.log 2>&1 </dev/null &
AFW_NET=1 AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$TR AFW_DURATION=3600 AFW_SEED=921 setsid nohup python3 $G >/tmp/nv1-train.log 2>&1 </dev/null &
AFW_NET=1 AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$VA AFW_DURATION=3600 AFW_SEED=922 setsid nohup python3 $G >/tmp/nv1-val.log 2>&1 </dev/null &
sleep 3; cat /tmp/a3-times.txt; pgrep -fc benign_personas_nv1
