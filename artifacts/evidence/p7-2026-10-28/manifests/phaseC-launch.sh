# P7 Phase C' (P6 amendment A2): p7-train .100-.123 seed 811 + .136-.139 seed 815
# (AFW_ARCHETYPES=forgetful,slow,power); p7-val .124-.135 seed 812; 90 min.
# Generator: traffic/benign_personas.py at the A2 commit, copied to /tmp/benign_personas_a2.py
TR=$(seq -s, -f 10.77.20.%g 100 123); ST=$(seq -s, -f 10.77.20.%g 136 139); VA=$(seq -s, -f 10.77.20.%g 124 135)
date -u +C_START=%Y-%m-%dT%H:%M:%S > /tmp/p7C-times.txt
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$TR AFW_DURATION=5400 AFW_SEED=811 setsid nohup python3 /tmp/benign_personas_a2.py >/tmp/p7-train.log 2>&1 </dev/null &
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_ARCHETYPES=forgetful,slow,power AFW_SOURCES=$ST AFW_DURATION=5400 AFW_SEED=815 setsid nohup python3 /tmp/benign_personas_a2.py >/tmp/p7-train-strat.log 2>&1 </dev/null &
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$VA AFW_DURATION=5400 AFW_SEED=812 setsid nohup python3 /tmp/benign_personas_a2.py >/tmp/p7-val.log 2>&1 </dev/null &
sleep 3; cat /tmp/p7C-times.txt; pgrep -fc benign_personas_a2
