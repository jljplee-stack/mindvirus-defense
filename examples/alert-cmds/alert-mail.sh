#!/usr/bin/env bash
# alert-mail.sh — 경보를 메일로(mail(1) 또는 sendmail 사용).
# 필요: CANON_MAIL_TO
set -u
: "${CANON_MAIL_TO:?CANON_MAIL_TO 미설정 — 경보를 보낼 곳이 없다}"
LEVEL="${CANON_ALERT_LEVEL:-ALERT}"
SUBJ="[canon $LEVEL] 정본 무결성 경보 (${CANON_ALERT_FROM:-canon@sentinel})"
if command -v mail >/dev/null 2>&1; then
  mail -s "$SUBJ" "$CANON_MAIL_TO"
elif command -v sendmail >/dev/null 2>&1; then
  { printf 'To: %s\nSubject: %s\n\n' "$CANON_MAIL_TO" "$SUBJ"; cat; } | sendmail -t
else
  echo "alert-mail: mail(1)·sendmail 둘 다 부재 — 전송 불가(경보가 유실된다)" >&2
  exit 3
fi
