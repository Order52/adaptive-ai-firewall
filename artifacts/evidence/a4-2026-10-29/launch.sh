#!/bin/bash
# A4 benign capture (A4_AUTH_HOUSEHOLD_REVALIDATION.md §2), run on USR01.
# Committed BEFORE the (re)capture. Generator traffic/benign_personas.py (sha256 in
# generator-sha.txt), copied to /tmp/benign_personas_a4.py. Web only (AFW_NET=0).
# Addresses .140-.193 and seeds 1001-1006 are DISJOINT from the candidates' training
# sets p7-train/p7-val (.100-.139, seeds 811/812), so selection/final users are unseen.
# Selection (.140-.166) and final (.167-.193) are disjoint; final is evaluated only
# after the selection freeze.
#   a4-sel .140-.155 seed 1001 personas v2 (natural)
#   a4-sel-hh .156-.161 seed 1002 personas v2 AFW_ARCHETYPES=household
#   a4-sel-shift .162-.166 seed 1003 shared
#   a4-final .167-.182 seed 1004 personas v2 (natural)
#   a4-final-hh .183-.188 seed 1005 personas v2 AFW_ARCHETYPES=household
#   a4-final-shift .189-.193 seed 1006 shared
# 45 min. Addresses added on USR01 first.
set -eu
G=/tmp/benign_personas_a4.py
for i in $(seq 140 193); do sudo ip addr add 10.77.20.$i/24 dev ens3 2>/dev/null || true; done
rng() { seq -s, -f 10.77.20.%g $1 $2; }
date -u +A4_START=%Y-%m-%dT%H:%M:%S | tee /tmp/a4-times.txt
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$(rng 140 155) AFW_SEED=1001 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-sel.log 2>&1 </dev/null &
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_ARCHETYPES=household AFW_SOURCES=$(rng 156 161) AFW_SEED=1002 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-sel-hh.log 2>&1 </dev/null &
AFW_MODE=shared AFW_SOURCES=$(rng 162 166) AFW_SEED=1003 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-sel-shift.log 2>&1 </dev/null &
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_SOURCES=$(rng 167 182) AFW_SEED=1004 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-final.log 2>&1 </dev/null &
AFW_MODE=personas AFW_PERSONA_SET=v2 AFW_ARCHETYPES=household AFW_SOURCES=$(rng 183 188) AFW_SEED=1005 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-final-hh.log 2>&1 </dev/null &
AFW_MODE=shared AFW_SOURCES=$(rng 189 193) AFW_SEED=1006 AFW_DURATION=2700 setsid nohup python3 $G >/tmp/a4-final-shift.log 2>&1 </dev/null &
sleep 3; cat /tmp/a4-times.txt; pgrep -fc benign_personas_a4
