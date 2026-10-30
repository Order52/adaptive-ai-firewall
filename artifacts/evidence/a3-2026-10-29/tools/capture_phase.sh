#!/bin/bash
# usage: capture_phase.sh <phase> <start> <end>   (run from the evidence dir)
set -eu
PH=$1; ST=$2; EN=$3
SP=${SP:-$(cd "$(dirname "$0")" && pwd)}  # where mkman.py lives
S="ssh -F $HOME/.config/afw/ssh_config"
python3 $SP/mkman.py manifests "$ST" "$EN" $PH
case $PH in sel) DS="p6-sel:test p6-sel-shift:test";; final) DS="p6-final:test p6-final-shift:test p6-final-v1:test";; p7c) DS="p7-train:train p7-val:validation";; p7d) DS="p7-sel:test p7-sel-shift:test";; n2) DS="n2-benign-train:train n2-benign-val:validation";; a3) DS="a3-sel:test a3-sel-shift:test nv1-train:train nv1-val:validation";; esac
AFWC='sudo -u afwctl env -C /var/lib/afw AFW_CONFIG=/etc/afw/lab.yaml AFW_DATA_DIR=/var/lib/afw AFW_API_TOKENS_FILE=/etc/afw/secrets/api_tokens.yaml /opt/afw/venv/bin/afw'
for d in $DS; do n=${d%%:*}; scp -q -F ~/.config/afw/ssh_config manifests/$n.json ctrl01:/tmp/; done
case $PH in sel) OUT=phaseD-capture.txt;; final) OUT=phaseE-capture.txt;; p7c) OUT=phaseC-capture.txt;; p7d) OUT=phaseD-capture.txt;; n2) OUT=n2-capture.txt;; a3) OUT=a3-capture.txt;; esac
CMD=""; for d in $DS; do n=${d%%:*}; p=${d##*:}; CMD="$CMD $AFWC dataset capture $n --manifest /tmp/$n.json --purpose $p 2>&1 | tail -1;"; done
for d in $DS; do n=${d%%:*}; CMD="$CMD $AFWC dataset validate $n 2>&1 | grep -E '^(PASS|WARN|FAIL|p6)';"; done
$S ctrl01 "$CMD" | tee $OUT
# completeness: WAF01 log lines per dataset in the same period
$S waf01 "sudo python3 - '$ST' '$EN' '$PH'" <<'PY' | tee -a $OUT
import json, sys, datetime as dt
st, en, ph = sys.argv[1:4]
t0 = dt.datetime.fromisoformat(st).timestamp(); t1 = dt.datetime.fromisoformat(en).timestamp()
rng = {"sel": {"p6-sel": (140, 155), "p6-sel-shift": (156, 161)},
       "final": {"p6-final": (170, 185), "p6-final-shift": (186, 191), "p6-final-v1": (192, 197)},
       "p7c": {"p7-train": (100, 123), "p7-val": (124, 135), "p7-train-strat": (136, 139)},
       "p7d": {"p7-sel": (140, 155), "p7-sel-shift": (156, 161)},
       "n2": {"n2-benign-train": (100, 123), "n2-benign-val": (124, 135)},
       "a3": {"a3-sel": (140, 155), "a3-sel-shift": (156, 161), "nv1-train": (100, 123), "nv1-val": (124, 135)}}[ph]
n = dict.fromkeys(rng, 0)
import glob, gzip
def lines():  # the live log and its rotations (copytruncate, dateext, gz)
    for f in sorted(glob.glob("/var/log/afw/waf-access.log*")):
        op = gzip.open if f.endswith(".gz") else open
        with op(f, "rt", errors="replace") as fh:
            yield from fh
for l in lines():
    if '"src":"10.77.20.1' not in l: continue
    try: x = json.loads(l)
    except ValueError: continue
    if not t0 <= float(x["ts"]) <= t1: continue
    o = int(x["src"].split(".")[-1])
    for k, (a, b) in rng.items():
        if a <= o <= b: n[k] += 1
print("# Completeness: WAF01 access-log lines for the same sources and period:", n)
PY
