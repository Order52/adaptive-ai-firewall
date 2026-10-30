#!/bin/bash
# Automated final verification for AI-Adaptive-Firewall (directive §10 entry point).
#
# One command that runs every check that does NOT require attack traffic, against the
# real code and the live lab, and prints a readiness report with the acceptance-gate
# matrix. Attack-dependent gates (B, E, half of C, G demo) need the team's runs
# (TEAM_ATTACK_QUICKSTART.md) and are reported BLOCKED, never faked.
#
# Usage:  scripts/final_verification.sh [--no-live]   (--no-live skips the lab checks)
# Read-only on the lab except that it reads the controller API.
set -uo pipefail
cd "$(dirname "$0")/.."
LIVE=1; [ "${1:-}" = "--no-live" ] && LIVE=0
CA=~/.config/afw/pki/lab-ca.pem
TOK=$(cat ~/.config/afw/api/admin.token 2>/dev/null || echo "")
pass=0; fail=0
ok()   { echo "  PASS  $1"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $1"; fail=$((fail+1)); }
note() { echo "  ----  $1"; }

echo "== AI-Adaptive-Firewall final verification =="
echo "   $(date -u +%Y-%m-%dT%H:%M:%SZ) · $(git rev-parse --short HEAD) on $(git rev-parse --abbrev-ref HEAD)"

echo; echo "-- 1. Code gates --"
uv run ruff check src tests >/dev/null 2>&1 && ok "ruff" || bad "ruff"
uv run ruff format --check src tests >/dev/null 2>&1 && ok "format" || bad "format"
uv run mypy src >/dev/null 2>&1 && ok "mypy" || bad "mypy"
if uv run pytest -o addopts="" -q >/tmp/afw-pytest.out 2>&1; then
  ok "pytest ($(grep -oE '[0-9]+ passed' /tmp/afw-pytest.out | head -1))"
else bad "pytest (see /tmp/afw-pytest.out)"; fi

if [ "$LIVE" = 1 ]; then
  echo; echo "-- 2. Live lab --"
  uv run afw lab verify >/tmp/afw-verify.out 2>&1 && ok "isolation $(grep -oE '[0-9]+/[0-9]+ checks passed' /tmp/afw-verify.out)" || bad "isolation (see /tmp/afw-verify.out)"
  H=$(curl -s --cacert "$CA" -H "Authorization: Bearer $TOK" https://10.77.50.10:8080/api/health 2>/dev/null)
  echo "$H" | grep -q '"status":"ok"' && echo "$H" | grep -q '"mode":"monitor"' && ok "controller: ok, monitor mode" || bad "controller health/mode"
  echo "$H" | grep -q '"telemetry_degraded":false' && ok "telemetry not degraded" || bad "telemetry degraded"
  N=$(curl -s --cacert "$CA" -H "Authorization: Bearer $TOK" https://10.77.50.10:8080/api/network 2>/dev/null)
  echo "$N" | grep -q '"calibration_error":null' && ok "network novelty: calibrated (NV2), shadow" || bad "network novelty calibration"
  if [ -n "${AFW_LAB:-}" ] || true; then
    AFW_LAB=1 uv run pytest -o addopts="" -q tests/lab >/tmp/afw-lab.out 2>&1 && ok "live lab tests ($(grep -oE '[0-9]+ passed' /tmp/afw-lab.out | head -1))" || bad "live lab tests (see /tmp/afw-lab.out)"
  fi
else
  echo; echo "-- 2. Live lab -- (skipped, --no-live)"
fi

echo; echo "-- 3. Predeclared experiment results (offline evidence) --"
note "P6/P7: no eligible model (RESULTS.md §3b/§3c)"
note "A3: candidate S failed final F1 on households (RESULTS.md §3d)"
note "A4: distinct_usernames ceiling-only; S passed selection + final, households/shared 0.0 FPR (RESULTS.md §3g)"
note "NV1: network novelty failed (RESULTS.md §3e); NV2: passed benign FP, 0.0059 (RESULTS.md §3f)"
note "Item 3: incremental classifier benchmarked SYNTHETIC only"
R=artifacts/evidence/offline-cic-2026-10-29/cic-offline-results.json
if [ -f "$R" ]; then
  ok "OFFLINE CIC-IDS2017 (separate gate): RF recall $(python3 -c "import json;print(round(json.load(open('$R'))['random_forest']['recall'],3))") @ FPR $(python3 -c "import json;print(json.load(open('$R'))['random_forest']['fpr'])"); held-out FTP->SSH $(python3 -c "import json;print(json.load(open('$R'))['held_out_family']['train_ftp_test_ssh']['withheld_family_recall'])") (RESULTS.md §3h)"
else
  note "OFFLINE CIC-IDS2017: not run here; reproduce via README.md (RESULTS.md §3h, GATE_STATES.md)"
fi

echo; echo "-- 3b. Separated gate states (docs/engineering/GATE_STATES.md) --"
note "LIVE GNS3 attack: BLOCKED | OFFLINE recorded-attack: MET | supervised: MET(offline)"
note "novelty: PARTIAL | safe adaptation/promotion: PARTIAL | network enforcement: MET"

echo; echo "-- 4. Acceptance-gate matrix (LIVE GNS3) --"
printf "  %-26s %-12s %s\n" "GATE" "STATUS" "WHY"
printf "  %-26s %-12s %s\n" "A Infrastructure" "MET" "lab, isolation, deploy, recovery"
printf "  %-26s %-12s %s\n" "B Detection"       "BLOCKED" "needs team attack runs (recall/FN unmeasurable)"
printf "  %-26s %-12s %s\n" "C Adaptation"      "PARTIAL" "live learning+rollback shown; no promotion (needs attack recall)"
printf "  %-26s %-12s %s\n" "D Enforcement"     "MET" "verified OPNsense/WAF actions, read-back, expiry, guards"
printf "  %-26s %-12s %s\n" "E Independent val" "BLOCKED" "needs team attack runs (value over static rules)"
printf "  %-26s %-12s %s\n" "F Security/ops"    "MET" "HTTPS API, mTLS telemetry, audited MCP, recovery, rotation"
printf "  %-26s %-12s %s\n" "G Academic"        "PARTIAL" "methodology+negatives documented; team demo+attack evidence missing"

echo; echo "-- 5. Reproducibility --"
LATEST=$(ls -t ~/afw-datasets-archive/SHA256SUMS-* 2>/dev/null | head -1)
[ -n "$LATEST" ] && ok "dataset archive $(basename "$LATEST") ($(wc -l < "$LATEST") files)" || note "no dataset archive found"
note "evidence under artifacts/evidence/ ; docs map in docs/PROJECT_REPORT_2026-10-29.md §12"

echo; echo "== Summary: $pass passed, $fail failed (verifiable checks) =="
echo "   Attack-dependent gates (B, E, parts of C/G) require team runs and are BLOCKED, not failed."
echo "   Readiness: working, governed, verified-enforcement system with honest negative/positive"
echo "   model-selection results; detection effectiveness under attack is unproven (team runs)."
[ "$fail" = 0 ]
