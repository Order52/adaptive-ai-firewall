# P7 Phase D' (A2): p7-sel .140-.155 seed 813 v2 personas; p7-sel-shift .156-.161 shared seed 814; 45 min
SEL=$(seq -s, -f 10.77.20.%g 140 155); SH=$(seq -s, -f 10.77.20.%g 156 161)
date -u +D_START=%Y-%m-%dT%H:%M:%S > /tmp/p7D-times.txt
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$SEL AFW_DURATION=2700 AFW_SEED=813 setsid nohup python3 /tmp/benign_personas_a2.py >/tmp/p7-sel.log 2>&1 </dev/null &
AFW_MODE=shared AFW_SOURCES=$SH AFW_DURATION=2700 AFW_SEED=814 setsid nohup python3 /tmp/benign_personas_a2.py >/tmp/p7-sel-shift.log 2>&1 </dev/null &
sleep 3; cat /tmp/p7D-times.txt; pgrep -fc benign_personas_a2
