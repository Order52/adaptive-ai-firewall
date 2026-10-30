# Phase E for A3 (A3 §5 "Freeze and final evaluation"): P6 phaseE-launch.sh (a197a87) unchanged except the generator:
# traffic/benign_personas.py sha256 3dbf49a4...fcf3 (A3 generator; web journeys equal to A2 for the same seeds, web-equivalence.txt), copied to /tmp/benign_personas_e.py.
# Run only after the freeze commit 39b0c3b.
# p6-final .170-.185 seed 701 v2 personas; p6-final-shift .186-.191 shared seed 702;
# p6-final-v1 .192-.197 v1 personas seed 703; 45 min. Addresses added on USR01 first.
for i in $(seq 170 197); do sudo ip addr add 10.77.20.$i/24 dev ens3 2>/dev/null; done
FIN=$(seq -s, -f 10.77.20.%g 170 185); SH=$(seq -s, -f 10.77.20.%g 186 191); V1=$(seq -s, -f 10.77.20.%g 192 197)
date -u +E_START=%Y-%m-%dT%H:%M:%S > /tmp/p6E-times.txt
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$FIN AFW_DURATION=2700 AFW_SEED=701 setsid nohup python3 /tmp/benign_personas_e.py >/tmp/p6-final.log 2>&1 </dev/null &
AFW_MODE=shared AFW_SOURCES=$SH AFW_DURATION=2700 AFW_SEED=702 setsid nohup python3 /tmp/benign_personas_e.py >/tmp/p6-final-shift.log 2>&1 </dev/null &
AFW_MODE=personas AFW_PERSONA_SET=v1 AFW_SOURCES=$V1 AFW_DURATION=2700 AFW_SEED=703 setsid nohup python3 /tmp/benign_personas_e.py >/tmp/p6-final-v1.log 2>&1 </dev/null &
sleep 3; cat /tmp/p6E-times.txt; pgrep -fc benign_personas_e
