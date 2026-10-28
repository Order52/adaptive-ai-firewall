# Phase D (P6 protocol): p6-sel .140-.155 seed 603 v2 personas; p6-sel-shift .156-.161 shared seed 604; 45 min
SEL=$(seq -s, -f 10.77.20.%g 140 155); SH=$(seq -s, -f 10.77.20.%g 156 161)
date -u +D_START=%Y-%m-%dT%H:%M:%S > /tmp/p6D-times.txt
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$SEL AFW_DURATION=2700 AFW_SEED=603 setsid nohup python3 /tmp/benign_personas_v2.py >/tmp/p6-sel.log 2>&1 </dev/null &
AFW_MODE=shared AFW_SOURCES=$SH AFW_DURATION=2700 AFW_SEED=604 setsid nohup python3 /tmp/benign_personas_v2.py >/tmp/p6-sel-shift.log 2>&1 </dev/null &
sleep 3; cat /tmp/p6D-times.txt; pgrep -fc benign_personas_v2
