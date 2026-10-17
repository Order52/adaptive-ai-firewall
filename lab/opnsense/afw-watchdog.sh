#!/bin/sh
# AFW heartbeat watchdog (runs on FW01 from cron, twice per minute).
# The controller refreshes the AFW_HEARTBEAT pf table entry on every successful
# reconcile (delete+add resets its "Cleared" timestamp). If that entry is older
# than MAX_AGE seconds, or missing while blocks exist, the controller is presumed
# dead and the dynamic block table is flushed so stale blocks cannot persist.
# Static policy (zone rules) is unaffected. The controller re-applies desired
# state on its next reconcile.
MAX_AGE=${AFW_WATCHDOG_MAX_AGE:-90}
BLOCK=AFW_BLOCK_WEB
HB=AFW_HEARTBEAT

check() {
  blocked=$(/sbin/pfctl -t "$BLOCK" -T show 2>/dev/null | /usr/bin/wc -l | /usr/bin/tr -d ' ')
  [ "${blocked:-0}" -eq 0 ] && return 0
  cleared=$(/sbin/pfctl -t "$HB" -T show -v 2>/dev/null \
            | /usr/bin/awk '/Cleared:/ { sub(/.*Cleared:[ \t]*/, ""); print; exit }')
  if [ -z "$cleared" ]; then
    reason="heartbeat missing"
  else
    then_s=$(/bin/date -j -f "%a %b %e %T %Y" "$cleared" +%s 2>/dev/null) || then_s=0
    age=$(( $(/bin/date +%s) - then_s ))
    [ "$age" -le "$MAX_AGE" ] && return 0
    reason="heartbeat age ${age}s > ${MAX_AGE}s"
  fi
  /sbin/pfctl -t "$BLOCK" -T flush >/dev/null 2>&1
  /usr/bin/logger -t afw-watchdog "flushed $BLOCK ($blocked entries): $reason"
}

check
/bin/sleep 30
check
