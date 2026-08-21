#!/usr/bin/env bash
# canon-edit.sh — 정본 편집 + 재서명을 **한 트랜잭션**으로 묶는 명령 1개.
# mindvirus-defense kit — 층 ② (무결성 워치) · MIT
#
# 왜: 편집과 서명이 따로 놀면 "고치고 서명을 깜빡한다" → 경보가 울린다 → 사람이 경보에 둔감해진다.
#     경보 피로는 감시 체계를 죽이는 가장 흔한 사인이다. 그래서 정당 편집의 정본 입구를 하나로 만든다.
#
# 사용:  canon-edit.sh <정본파일> --reason "<변경 근거>"
#        EDITOR=nano canon-edit.sh ~/agents/CLAUDE.md --reason "ADR-12 반영(소유자 승인 2026-01-15)"
#
# 절차: ⑴ 인벤토리 소속·현재 무결성 확인(더러우면 거부 — 먼저 해소하라)
#       ⑵ $EDITOR 로 편집
#       ⑶ 실제로 바뀌었으면 canon-resign.sh 로 즉시 재서명(같은 사유)
#       ⑷ 대조로 clean 확인
# 종료코드: 0 성공(또는 무변경) | 3 설정오류 | 4 인자오류 | 5 권한거부 | 6 선행 경보 미해소
set -u
CANON_BIN="${CANON_BIN:-$(cd "$(dirname "$0")" 2>/dev/null && pwd)}"
VERIFY="${CANON_VERIFY:-$CANON_BIN/canon-verify.sh}"
RESIGN="${CANON_RESIGN:-$CANON_BIN/canon-resign.sh}"

FILE=""; REASON=""
while [ $# -gt 0 ]; do
  case "$1" in
    --reason) shift; REASON="${1:-}" ;;
    --reason=*) REASON="${1#--reason=}" ;;
    --self-test) SELFTEST=1 ;;
    -*) echo "canon-edit: 알 수 없는 옵션 $1" >&2; exit 4 ;;
    *) FILE="$1" ;;
  esac
  shift || true
done

if [ "${SELFTEST:-0}" = "1" ]; then
  # 배터리: 인자 검증 경로만(편집기 상호작용은 대상 밖 — EDITOR=true 로 무편집 시뮬)
  f=0
  TMP_TEST_DIR="$(mktemp -d)"
  trap 'rm -rf "$TMP_TEST_DIR"' EXIT
  "$0" --reason "x" >/dev/null 2>&1; [ $? = 4 ] || { echo "  FAIL ①파일 누락이 거부 안 됨"; f=$((f+1)); }
  "$0" "$TMP_TEST_DIR/nope.md" >/dev/null 2>&1;  [ $? = 4 ] || { echo "  FAIL ②사유 누락이 거부 안 됨"; f=$((f+1)); }
  "$0" "$TMP_TEST_DIR/definitely-not-here.md" --reason "x" >/dev/null 2>&1
  [ $? = 4 ] || { echo "  FAIL ③없는 파일이 거부 안 됨"; f=$((f+1)); }
  [ "$f" = "0" ] && { echo "self-test OK — 3 배터리(파일필수·사유필수·실존필수)"; exit 0; }
  echo "self-test: $f 실패" >&2; exit 1
fi

[ -n "$FILE" ]   || { echo "canon-edit: 대상 파일 필요"   >&2; exit 4; }
[ -n "$REASON" ] || { echo "canon-edit: --reason 필수 — 근거 없는 변경 확정은 확정이 아니다" >&2; exit 4; }
[ -f "$FILE" ]   || { echo "canon-edit: 파일 없음: $FILE" >&2; exit 4; }

# ⑴ 선행 무결성 — 이미 경보 상태면 편집을 얹지 않는다(무단 변경을 정당 편집으로 세탁 방지).
PRE_TMP="$(mktemp)"
trap 'rm -f "$PRE_TMP"' EXIT
"$VERIFY" >"$PRE_TMP" 2>&1; PRE=$?
if [ "$PRE" = "2" ]; then
  if grep -qF "$FILE" "$PRE_TMP"; then
    echo "canon-edit 거부: '$FILE' 은 이미 무단 변경 경보 상태다." >&2
    echo "  ⛔ 그 위에 편집을 얹으면 무단 변경이 정당한 변경으로 세탁된다." >&2
    echo "  먼저 해소하라 — 원상복구 후 편집하거나, 변경 내용을 확인하고 별도 사유로 재서명하라." >&2
    grep -A3 -F "$FILE" "$PRE_TMP" >&2
    exit 6
  fi
fi
if [ "$PRE" = "3" ]; then
  echo "canon-edit: 대조 자체가 실패(설정 오류) — 편집을 진행하지 않는다." >&2
  cat "$PRE_TMP" >&2; exit 3
fi

# 해시는 python 으로 낸다 — shasum(1) 은 POSIX 표준이 아니고 배포판마다 없다(sha256sum 만 있거나
# 둘 다 없다). 이 킷은 이미 python3 를 요구하므로 의존성을 그쪽으로 통일한다. 값은 동일하다.
CANON_PY="${CANON_PY:-$(command -v python3 2>/dev/null || command -v python 2>/dev/null)}"
[ -n "$CANON_PY" ] || { echo "canon-edit: python3 부재 — 해시 대조 불가" >&2; exit 3; }
_sha256() {
  "$CANON_PY" - "$1" <<'PYEOF'
import hashlib, sys
h = hashlib.sha256()
with open(sys.argv[1], "rb") as f:
    for chunk in iter(lambda: f.read(1 << 20), b""):
        h.update(chunk)
print(h.hexdigest())
PYEOF
}
BEFORE="$(_sha256 "$FILE")"
"${EDITOR:-vi}" "$FILE"
AFTER="$(_sha256 "$FILE")"

if [ "$BEFORE" = "$AFTER" ]; then
  echo "canon-edit: 변경 없음 — 재서명 불요."
  exit 0
fi

echo "canon-edit: 변경 감지 $(printf '%.16s' "$BEFORE") -> $(printf '%.16s' "$AFTER") · 즉시 재서명"
"$RESIGN" "$FILE" --reason "$REASON" || exit $?
"$VERIFY" >/dev/null 2>&1
case $? in
  0|1) echo "canon-edit: 완료 — 대조 clean." ; exit 0 ;;
  *)   echo "canon-edit: ⚠재서명 후에도 경보가 남아 있다. canon-verify.sh 로 확인하라." >&2; exit 2 ;;
esac
