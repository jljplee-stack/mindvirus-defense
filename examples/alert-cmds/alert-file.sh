#!/usr/bin/env bash
# alert-file.sh — 경보를 파일에 append 한다(가장 단순한 채널·기본 폴백과 동일 동작).
# 계약: 본문 = stdin · 등급 = $CANON_ALERT_LEVEL · 발신자 = $CANON_ALERT_FROM
set -u
LOG="${CANON_ALERT_LOG:-$HOME/.canon/alerts.log}"
mkdir -p "$(dirname "$LOG")" 2>/dev/null
{
  printf '[%s] %s [%s]\n' "${CANON_ALERT_FROM:-canon@sentinel}" \
         "$(date '+%Y-%m-%dT%H:%M:%S%z')" "${CANON_ALERT_LEVEL:-ALERT}"
  cat
  printf '\n'
} >> "$LOG"
