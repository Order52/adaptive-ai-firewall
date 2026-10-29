#!/bin/bash
# A4 benign capture (A4_AUTH_HOUSEHOLD_REVALIDATION.md §2), run on USR01.
# Committed BEFORE the capture. Generator traffic/benign_personas.py at the committing
# commit (sha256 recorded here), copied to /tmp/benign_personas_a4.py. Web only (AFW_NET=0).
# Selection and final addresses/seeds are disjoint; final is evaluated only after the
# selection freeze.
#   a4-sel .100-.119 seed 811 personas v2 (natural)
#   a4-sel-hh .120-.127 seed 812 personas v2 AFW_ARCHETYPES=household
#   a4-sel-shift .128-.133 seed 813 shared
#   a4-final .134-.153 seed 814 personas v2 (natural)
#   a4-final-hh .154-.161 seed 815 personas v2 AFW_ARCHETYPES=household
#   a4-final-shift .162-.167 seed 816 shared
# 45 min. Addresses added on USR01 first.
set -eu
G=/tmp/benign_personas_a4.py
for i in $(seq 100 167); do sudo ip addr add 10.77.20.$i/24 dev ens3 2>/dev/null || true; done
rng() { seq -s, -f 10.77.20.%g $1 $2; }
date -u +A4_START=%Y-%m-%dT%H:%M:%S | tee /tmp/a4-times.txt
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$(rng 100 119) AFW_SEED=811 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-sel.log 2>&1 </dev/null &
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_ARCHETYPES=household AFW_SOURCES=$(rng 120 127) AFW_SEED=812 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-sel-hh.log 2>&1 </dev/null &
AFW_MODE=shared AFW_SOURCES=$(rng 128 133) AFW_SEED=813 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-sel-shift.log 2>&1 </dev/null &
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$(rng 134 153) AFW_SEED=814 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-final.log 2>&1 </dev/null &
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_ARCHETYPES=household AFW_SOURCES=$(rng 154 161) AFW_SEED=815 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-final-hh.log 2>&1 </dev/null &
AFW_MODE=shared AFW_SOURCES=$(rng 162 167) AFW_SEED=816 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-final-shift.log 2>&1 </dev/null &
sleep 3; cat /tmp/a4-times.txt; pgrep -fc benign_personas_a4
