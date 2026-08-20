#!/usr/bin/env bash
# canon-sentinel.sh — 정본 무결성 경보기. canon-verify.sh 판정을 경보 채널로 1회 발신 + 해소 추적.
# mindvirus-defense kit — 층 ② (무결성 워치) · MIT
#
# ★이미 돌고 있는 다른 감시기에 손대지 않는 **독립 경로**로 설계했다.
#   별도 관심사는 별도 스크립트·별도 주기 — 가동 중 자산을 고치면 그 감시까지 함께 죽는다.
#
# ── 경보 채널은 플러거블하다 ─────────────────────────────────────────
#   CANON_ALERT_CMD 를 주면 그 명령을 실행하고 **경보 본문을 stdin 으로** 넘긴다.
#   그 명령은 다음 환경변수를 받는다:
#       CANON_ALERT_LEVEL = ALERT | NOTICE | BROKEN   (BROKEN = 대조 자체가 실패)
#       CANON_ALERT_FROM  = 발신자 표기($CANON_FROM)
#   비워 두면 내장 폴백으로 $CANON_ALERT_LOG 파일에 append 한다(설정 0으로도 돈다).
#   예) CANON_ALERT_CMD="$KIT/examples/alert-cmds/alert-slack.sh"    (웹훅)
#       CANON_ALERT_CMD="$KIT/examples/alert-cmds/alert-mail.sh"     (메일)
#       CANON_ALERT_CMD="my-fleet notify --to orchestrator"          (사내 도구 아무거나)
#
# 재발화 억제: 지문 = kind|path|실측해시. 같은 지문은 평생 1회만 push한다.
#              해시가 또 바뀌면 새 지문 → 새 경보(변조가 진행 중이라는 신호이므로 알려야 한다).
#
# ★해소 판정(명시):
#   해소 = 그 경로에 finding이 **하나도 없는** 상태. 도달 경로는 둘뿐이다.
#     ⑴ 오케스트레이터가 canon-resign.sh 로 재서명 → 베이스라인이 현재를 인정
#     ⑵ 파일을 원래 내용으로 되돌림 → 해시가 베이스라인과 재일치
#   그 외(무시·시간 경과·재시작)로는 절대 해소되지 않는다. 해소 시 [해소] 1줄을 push하고
#   상태를 지운다. 같은 경로에 다른 finding이 남아 있으면 해소로 치지 않는다.
#
# 사용: canon-sentinel.sh            # 평시(launchd/cron)
#       canon-sentinel.sh --dry-run  # push 없이 무엇이 나갈지만 출력
#       canon-sentinel.sh --self-test
# 종료코드: 0 무변화 | 1 NOTICE push | 2 ALERT push | 3 판정 불가(설정 오류)
set -u

CANON_BIN="${CANON_BIN:-$(cd "$(dirname "$0")" 2>/dev/null && pwd)}"
CANON_HOME="${CANON_HOME:-$HOME/.canon}"
VERIFY="${CANON_VERIFY:-$CANON_BIN/canon-verify.sh}"
STATE="${CANON_ALERT_STATE:-$CANON_HOME/alert-state.tsv}"
ALERT_CMD="${CANON_ALERT_CMD:-}"
ALERT_LOG="${CANON_ALERT_LOG:-$CANON_HOME/alerts.log}"
FROM="${CANON_FROM:-canon@sentinel}"

# 경보 배달 — 본문은 stdin, 등급은 $1. 채널 교체는 CANON_ALERT_CMD 한 변수로만 한다.
deliver_alert() {
  _lvl="${1:-ALERT}"
  if [ -n "$ALERT_CMD" ]; then
    CANON_ALERT_LEVEL="$_lvl" CANON_ALERT_FROM="$FROM" sh -c "$ALERT_CMD"
  else
    mkdir -p "$(dirname "$ALERT_LOG")" 2>/dev/null
    {
      printf '[%s] %s [%s]\n' "$FROM" "$(date '+%Y-%m-%dT%H:%M:%S%z')" "$_lvl"
      cat
      printf '\n'
    } >> "$ALERT_LOG"
  fi
}
DRY=0
case " $* " in *" --dry-run "*) DRY=1 ;; esac

PY="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || printf '')"
[ -n "$PY" ] || { echo "canon-sentinel: python3 부재 — 판정 불가" >&2; exit 3; }

# ── self-test 는 아래 배터리로 분기 ────────────────────────────────
case " $* " in *" --self-test "*) exec "$0" --run-self-test-impl ;; esac
if [ "${1:-}" = "--run-self-test-impl" ]; then
  T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
  mkdir -p "$T/canon" "$T/docs"
  printf 'v1\n' > "$T/docs/CLAUDE.md"
  printf 'strict\t%s\n' "$T/docs/CLAUDE.md" > "$T/canon/inventory.conf"
  export CANON_HOME="$T/canon" CANON_INVENTORY="$T/canon/inventory.conf" \
         CANON_BASELINE="$T/canon/baseline.tsv" CANON_LEDGER="$T/canon/resign-ledger.jsonl" \
         CANON_ALERT_STATE="$T/canon/alert-state.tsv" CANON_ALERT_LOG="$T/alerts.log" \
         CANON_ALERT_CMD="" CANON_FROM="canon-test@sentinel" CANON_RESIGN_TEST=1
  ALERT_LOG="$T/alerts.log"; : > "$ALERT_LOG"
  fails=0
  "$CANON_BIN/canon-resign.sh" --rebuild --reason "self-test 최초" >/dev/null 2>&1 \
    || { echo "  FAIL 베이스라인 생성 실패"; fails=$((fails+1)); }
  # ① 정상 → 무push
  "$0" >/dev/null 2>&1; rc=$?
  [ "$rc" = "0" ] || { echo "  FAIL ①정상인데 rc=$rc"; fails=$((fails+1)); }
  [ "$(grep -c . "$ALERT_LOG")" = "0" ] || { echo "  FAIL ①정상인데 push 발생"; fails=$((fails+1)); }
  # ② 변조 → ALERT push 1회
  printf 'v1\nINJECTED\n' > "$T/docs/CLAUDE.md"
  "$0" >/dev/null 2>&1; rc=$?
  [ "$rc" = "2" ] || { echo "  FAIL ②변조인데 rc=$rc"; fails=$((fails+1)); }
  n1=$(grep -c '【경고】' "$ALERT_LOG")
  [ "$n1" = "1" ] || { echo "  FAIL ②경고 1건이어야(실제 $n1)"; fails=$((fails+1)); }
  # ③ 같은 상태 재실행 → 억제(추가 push 0)
  "$0" >/dev/null 2>&1
  n2=$(grep -c '【경고】' "$ALERT_LOG")
  [ "$n2" = "1" ] || { echo "  FAIL ③재발화 억제 실패(경고 ${n2}건)"; fails=$((fails+1)); }
  # ④ 재서명 → 해소 push 1회 + 상태 소거
  "$CANON_BIN/canon-resign.sh" "$T/docs/CLAUDE.md" --reason "self-test 정당한 변경" >/dev/null 2>&1
  "$0" >/dev/null 2>&1
  n3=$(grep -c '【해소】' "$ALERT_LOG")
  [ "$n3" = "1" ] || { echo "  FAIL ④해소 push 1건이어야(실제 $n3)"; fails=$((fails+1)); }
  [ ! -s "$CANON_ALERT_STATE" ] || { echo "  FAIL ④해소 후 상태가 남음"; fails=$((fails+1)); }
  # ⑤ 해소 뒤 재실행 → 아무 것도 안 나감
  "$0" >/dev/null 2>&1; rc=$?
  [ "$rc" = "0" ] || { echo "  FAIL ⑤해소 후 rc=$rc"; fails=$((fails+1)); }
  n4=$(grep -c '【경고】' "$ALERT_LOG"); n5=$(grep -c '【해소】' "$ALERT_LOG")
  [ "$n4" = "1" ] && [ "$n5" = "1" ] || { echo "  FAIL ⑤최종 마커 수 예상밖(경고 ${n4} 해소 ${n5})"; fails=$((fails+1)); }
  if [ "$fails" = "0" ]; then
    echo "self-test OK — 5 배터리(정상무push·변조ALERT·재발화억제·재서명해소·해소후정지)"; exit 0
  fi
  echo "self-test: $fails 실패" >&2; exit 1
fi

mkdir -p "$CANON_HOME" 2>/dev/null
REPORT="$("$VERIFY" --json 2>/dev/null)"; VRC=$?
if [ "$VRC" = "3" ] || [ -z "$REPORT" ]; then
  # 판정 불가도 사건이다 — 조용히 죽지 않는다.
  MSGF="$(mktemp)"
  printf '【경고】 canon-sentinel 판정 불가 — 무결성 대조가 돌지 않았다(verify rc=%s).\n' "$VRC" > "$MSGF"
  printf '  인벤토리/베이스라인 오류이거나 canon-verify.sh 가 훼손됐다. 감시 공백 상태다.\n' >> "$MSGF"
  printf '  확인: %s --json\n' "$VERIFY" >> "$MSGF"
  if [ "$DRY" = "1" ]; then cat "$MSGF"; else deliver_alert BROKEN < "$MSGF"; fi
  rm -f "$MSGF"; exit 3
fi

export CANON_REPORT="$REPORT" STATE DRY VERIFY
OUT="$("$PY" - <<'PYEOF'
import hashlib, json, os, sys, time

report = json.loads(os.environ["CANON_REPORT"])
state_path = os.environ["STATE"]

def fp(f):
    raw = "%s|%s|%s" % (f["kind"], f["path"], f["actual"])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:16]

prev = {}
if os.path.isfile(state_path):
    with open(state_path, encoding="utf-8") as fh:
        for line in fh:
            p = line.rstrip("\n").split("\t")
            if len(p) >= 5:
                prev[p[0]] = {"path": p[1], "level": p[2], "kind": p[3], "first_seen": p[4]}

findings = report.get("findings", [])
cur = {fp(f): f for f in findings}
paths_with_findings = {f["path"] for f in findings}

new = [(k, v) for k, v in cur.items() if k not in prev]
resolved = [(k, v) for k, v in prev.items() if k not in cur and v["path"] not in paths_with_findings]

now = time.strftime("%Y-%m-%dT%H:%M:%S%z")
lines = []
alerts  = [f for _, f in new if f["level"] == "ALERT"]
notices = [f for _, f in new if f["level"] != "ALERT"]

# ★지침 7-1: 경고·결정은 맨 위 머리표로. 각주 금지.
if alerts:
    lines.append("【경고】 정본 파일 무단 변경 %d건 — 자동 로드 정본이 서명과 다르다(마인드바이러스 감염 경로)."
                 % len(alerts))
    lines.append("  판정: 베이스라인 불일치 + 재서명 원장 부재 = 정당한 변경이 아니다.")
    for f in alerts:
        lines.append("  ─ [%s] %s" % (f["kind"], f["path"]))
        lines.append("      기대(서명) sha256 : %s" % f["expect"])
        lines.append("      실측       sha256 : %s" % f["actual"])
        lines.append("      마지막 정당 서명   : %s" % f.get("last_signed", "-"))
        lines.append("      %s" % f["note"])
if notices:
    if alerts:
        lines.append("")
    lines.append("【알림】 정본 추가·append %d건(정상 증가일 수 있으나 기록으로 남긴다)." % len(notices))
    for f in notices:
        lines.append("  ─ [%s] %s" % (f["kind"], f["path"]))
        lines.append("      %s" % f["note"])
if resolved:
    if lines:
        lines.append("")
    lines.append("【해소】 정본 경보 %d건 해소(재서명 또는 원상복구로 서명 일치)." % len(resolved))
    for _, v in resolved:
        lines.append("  ─ [%s] %s (최초 발화 %s)" % (v["kind"], v["path"], v["first_seen"]))
if lines:
    lines.append("")
    lines.append("  해소 방법 = ⑴ 오케스트레이터 재서명: canon-resign.sh <파일> --reason \"<근거>\"")
    lines.append("             ⑵ 원상복구: 파일을 서명 당시 내용으로 되돌린다")
    lines.append("  전체 대조: %s" % os.environ.get("VERIFY", "canon-verify.sh"))

# 상태 갱신(현재 finding 지문만 남긴다 — 해소분은 제거)
if os.environ.get("DRY") != "1":
    tmp = state_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        for k, f in sorted(cur.items()):
            first = prev.get(k, {}).get("first_seen", now)
            fh.write("%s\t%s\t%s\t%s\t%s\n" % (k, f["path"], f["level"], f["kind"], first))
    os.replace(tmp, state_path)

rc = 0
if alerts: rc = 2
elif notices or resolved: rc = 1
sys.stdout.write("\x00RC=%d\x00\n" % rc)
sys.stdout.write("\n".join(lines))
PYEOF
)" || { echo "canon-sentinel: 조립 실패" >&2; exit 3; }

RC="$(printf '%s' "$OUT" | head -1 | sed -n 's/.*RC=\([0-9]\).*/\1/p')"
BODY="$(printf '%s' "$OUT" | tail -n +2)"
[ -n "$RC" ] || RC=3

if [ -z "$BODY" ]; then
  exit "$RC"
fi

if [ "$DRY" = "1" ]; then
  printf '%s\n' "$BODY"
  echo "[dry-run] 위 내용이 경보 채널로 나갔을 것. rc=$RC (상태 미갱신)"
  exit "$RC"
fi

MSGF="$(mktemp)"; printf '%s\n' "$BODY" > "$MSGF"
case "$RC" in 2) LVL=ALERT ;; 1) LVL=NOTICE ;; *) LVL=NOTICE ;; esac
deliver_alert "$LVL" < "$MSGF"
rm -f "$MSGF"
exit "$RC"
