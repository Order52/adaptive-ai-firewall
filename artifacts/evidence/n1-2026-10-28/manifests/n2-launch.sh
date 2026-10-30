# N2 network calibration run: 30 min benign v2 personas (A2 generator); train .100-.123 seed 821, val .124-.135 seed 822
TR=$(seq -s, -f 10.77.20.%g 100 123); VA=$(seq -s, -f 10.77.20.%g 124 135)
date -u +N2_START=%Y-%m-%dT%H:%M:%S > /tmp/n2-times.txt
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$TR AFW_DURATION=1800 AFW_SEED=821 setsid nohup python3 /tmp/benign_personas_a2.py >/tmp/n2-train.log 2>&1 </dev/null &
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$VA AFW_DURATION=1800 AFW_SEED=822 setsid nohup python3 /tmp/benign_personas_a2.py >/tmp/n2-val.log 2>&1 </dev/null &
sleep 3; cat /tmp/n2-times.txt; pgrep -fc benign_personas_a2
