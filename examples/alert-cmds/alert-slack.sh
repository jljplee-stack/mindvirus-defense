#!/usr/bin/env bash
# alert-slack.sh — 경보를 Slack incoming webhook 으로.
# 필요: CANON_SLACK_WEBHOOK
# 계약: 본문 = stdin · 등급 = $CANON_ALERT_LEVEL · 발신자 = $CANON_ALERT_FROM
#
# ⚠ 경보 본문에는 **파일 경로와 해시**가 들어간다. 그 자체가 조직 내부 정보다.
#   공개 채널이 아니라 운영자만 보는 비공개 채널로 보내라.
set -u
: "${CANON_SLACK_WEBHOOK:?CANON_SLACK_WEBHOOK 미설정 — 경보를 보낼 곳이 없다}"
BODY="$(cat)"
LEVEL="${CANON_ALERT_LEVEL:-ALERT}"
case "$LEVEL" in
  ALERT)  EMOJI=":rotating_light:" ;;
  BROKEN) EMOJI=":skull:" ;;
  *)      EMOJI=":memo:" ;;
esac
PY="$(command -v python3 || command -v python)" || { echo "python 부재 — 전송 불가" >&2; exit 3; }
PAYLOAD="$(BODY="$BODY" LEVEL="$LEVEL" EMOJI="$EMOJI" FROM="${CANON_ALERT_FROM:-canon@sentinel}" "$PY" - <<'PYEOF'
import json, os
text = "%s *canon %s* (%s)\n```%s```" % (
    os.environ["EMOJI"], os.environ["LEVEL"], os.environ["FROM"], os.environ["BODY"][:3500])
print(json.dumps({"text": text}))
PYEOF
)"
curl -sS -X POST -H 'Content-type: application/json' --data "$PAYLOAD" "$CANON_SLACK_WEBHOOK" >/dev/null
