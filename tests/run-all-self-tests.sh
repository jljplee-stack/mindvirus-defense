#!/usr/bin/env bash
# run-all-self-tests.sh — 킷 내장 배터리 전건 실행.
# mindvirus-defense kit · MIT
#
# 이 스크립트는 **킷 상태 그대로**(사이트 설정 없이) 돌아야 한다. 하나라도 빨간 채로
# 설치를 진행하지 마라 — 감시자가 고장난 상태로 감시를 켜는 것이기 때문이다.
set -u
KIT_ROOT="${KIT_ROOT:-$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)}"
fails=0; total=0
for s in verify resign edit sentinel guard; do
  total=$((total+1))
  printf '%-10s ' "$s"
  out="$(bash "$KIT_ROOT/scripts/canon-$s.sh" --self-test </dev/null 2>&1)"; rc=$?
  if [ "$rc" = "0" ]; then
    printf '%s\n' "$(printf '%s' "$out" | tail -1)"
  else
    printf 'FAIL (rc=%s)\n%s\n' "$rc" "$out"; fails=$((fails+1))
  fi
done
# 인자 검증 경로(설치기)
total=$((total+1)); printf '%-10s ' "installer"
if bash "$KIT_ROOT/hooks/install-canon-guard.sh" >/dev/null 2>&1; then
  printf 'FAIL — 인자 없이 성공하면 안 된다\n'; fails=$((fails+1))
else
  printf 'OK — 인자 없으면 usage 후 거부(exit 4)\n'
fi
# 경보 채널 예시 계약(stdin 본문이 실제로 실려 나가는가)
total=$((total+1)); printf '%-10s ' "alert-cmd"
T="$(mktemp -d)"
printf '【경고】 배터리 본문\n' | CANON_ALERT_LOG="$T/a.log" CANON_ALERT_LEVEL=ALERT \
  bash "$KIT_ROOT/examples/alert-cmds/alert-file.sh"
if grep -q '【경고】 배터리 본문' "$T/a.log" 2>/dev/null; then
  printf 'OK — stdin 본문이 채널로 그대로 전달됨\n'
else
  printf 'FAIL — 채널이 본문을 잃었다\n'; fails=$((fails+1))
fi
rm -rf "$T"

# 공개 위생 게이트 + 그 게이트가 눈이 멀지 않았는지 자기 검산
total=$((total+1)); printf '%-10s ' "hygiene"
if bash "$KIT_ROOT/tests/publish-hygiene.sh" >/dev/null 2>&1 \
   && bash "$KIT_ROOT/tests/publish-hygiene.sh" --mutation >/dev/null 2>&1; then
  printf 'OK — 금지 표현 0건 + 게이트 자기 검산 통과\n'
else
  printf 'FAIL — 아래를 직접 확인하라: tests/publish-hygiene.sh\n'; fails=$((fails+1))
fi

echo "─────────────────────────────────────────"
if [ "$fails" = "0" ]; then echo "전건 통과 ($total 묶음)"; exit 0; fi
echo "실패 $fails / $total 묶음" >&2; exit 1
