#!/usr/bin/env bash
# alert-stdout.sh — 경보를 표준출력으로. cron/launchd 로그에 그대로 남는다.
set -u
printf '=== canon alert [%s] from %s at %s ===\n' \
  "${CANON_ALERT_LEVEL:-ALERT}" "${CANON_ALERT_FROM:-canon@sentinel}" "$(date '+%Y-%m-%dT%H:%M:%S%z')"
cat
