#!/bin/sh
# AFW heartbeat watchdog and country-table sync (runs on FW01 from cron, twice per minute).
# The controller refreshes the AFW_HEARTBEAT pf table entry on every successful
# reconcile (delete+add resets its "Cleared" timestamp).
# * Heartbeat fresh: the controller is alive, so pull the published real-country
#   network lists (ADR-036) and atomically replace AFW_GEO_IN / AFW_GEO_OUT when their
#   sha256 changed. A list whose sha256 does not match its header is never loaded.
# * Heartbeat older than MAX_AGE seconds, or missing, while any AFW table has entries:
#   the controller is presumed dead and every dynamic table is flushed, so neither
#   source blocks nor country blocks can outlive it. Static zone rules are unaffected;
#   the controller re-applies desired state on its next reconcile.
MAX_AGE=${AFW_WATCHDOG_MAX_AGE:-90}
TABLES="AFW_BLOCK_WEB AFW_GEO_IN AFW_GEO_OUT"
HB=AFW_HEARTBEAT
GEO_URL=https://10.77.50.10:8080/api/geo/enforcement
GEO_TOKEN=/usr/local/etc/afw/geo.token
GEO_CA=/usr/local/etc/afw/lab-ca.pem
STATE=/var/db/afw-geo

entries() {
  /sbin/pfctl -t "$1" -T show 2>/dev/null | /usr/bin/wc -l | /usr/bin/tr -d ' '
}

heartbeat_age() {
  cleared=$(/sbin/pfctl -t "$HB" -T show -v 2>/dev/null \
            | /usr/bin/awk '/Cleared:/ { sub(/.*Cleared:[ \t]*/, ""); print; exit }')
  [ -z "$cleared" ] && { echo -1; return; }
  then_s=$(/bin/date -j -f "%a %b %e %T %Y" "$cleared" +%s 2>/dev/null) || then_s=0
  echo $(( $(/bin/date +%s) - then_s ))
}

geo_sync() {  # $1 = inbound|outbound, $2 = pf table
  f="$STATE/$1"
  /usr/local/bin/curl -fsS -m 20 --cacert "$GEO_CA" \
    -H "Authorization: Bearer $(/bin/cat "$GEO_TOKEN")" "$GEO_URL/$1" -o "$f.new" \
    || { /usr/bin/logger -t afw-geo "fetch $1 failed"; return; }
  want=$(/usr/bin/head -1 "$f.new" | /usr/bin/sed -n 's/^# afw-geo .* sha256=\([0-9a-f]*\)$/\1/p')
  /usr/bin/tail -n +2 "$f.new" > "$f.body"
  got=$(/sbin/sha256 -q "$f.body")
  if [ -z "$want" ] || [ "$want" != "$got" ]; then
    /usr/bin/logger -t afw-geo "$1 list rejected: sha256 mismatch"
    return
  fi
  n=$(/usr/bin/wc -l < "$f.body" | /usr/bin/tr -d ' ')
  if [ "$(/bin/cat "$f.applied" 2>/dev/null)" = "$want" ] && [ "$(entries "$2")" -eq "$n" ]; then
    return
  fi
  /sbin/pfctl -t "$2" -T replace -f "$f.body" >/dev/null 2>&1 \
    && echo "$want" > "$f.applied" \
    && /usr/bin/logger -t afw-geo "$2 replaced: $n networks sha256=$want"
}

check() {
  age=$(heartbeat_age)
  if [ "$age" -ge 0 ] && [ "$age" -le "$MAX_AGE" ]; then
    if [ -r "$GEO_TOKEN" ]; then
      /bin/mkdir -p "$STATE"
      geo_sync inbound AFW_GEO_IN
      geo_sync outbound AFW_GEO_OUT
    fi
    return 0
  fi
  total=0
  for t in $TABLES; do total=$(( total + $(entries "$t") )); done
  [ "$total" -eq 0 ] && return 0
  if [ "$age" -lt 0 ]; then reason="heartbeat missing"; else reason="heartbeat age ${age}s > ${MAX_AGE}s"; fi
  for t in $TABLES; do /sbin/pfctl -t "$t" -T flush >/dev/null 2>&1; done
  /bin/rm -f "$STATE"/*.applied
  /usr/bin/logger -t afw-watchdog "flushed $TABLES ($total entries): $reason"
}

check
/bin/sleep 30
check
