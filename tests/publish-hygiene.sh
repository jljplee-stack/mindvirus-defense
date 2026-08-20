#!/usr/bin/env bash
# publish-hygiene.sh — 공개 위생 게이트. 저장소에 남으면 안 되는 표현·식별자를 전수로 센다.
# mindvirus-defense kit · MIT
#
# 왜 스크립트인가: "다 지웠다"는 주장은 검증 대상이 아니다. **세는 도구가 0을 내야** 증거가 된다.
# 새 문서를 쓸 때마다 돌려라. 항목이 늘면 아래 목록에 한 줄 더 넣는다.
#
# ⚠**범위는 추적 대상 텍스트 파일이다. git 커밋 메타데이터(작성자 이름·이메일)는 여기서 세지 않는다.**
#   그것은 저장소 소유자가 의도적으로 남기는 귀속이지 잔재가 아니다(공개 저장소의 표준 관행 =
#   실이메일 대신 호스팅 서비스의 noreply 주소). 세지 않는 것을 밝혀 두는 이유는,
#   **보이지 않는 억제는 미탐과 구별되지 않기 때문이다.**
#
# 사용: publish-hygiene.sh              # 검사
#       publish-hygiene.sh --mutation   # ★이 게이트가 실제로 잡는지 자기 검산
# 종료코드: 0 클린 | 1 잔재 발견 | 2 자기 검산 실패
set -u
KIT_ROOT="${KIT_ROOT:-$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)}"
cd "$KIT_ROOT" || exit 1

# ── 금지 목록 ────────────────────────────────────────────────────────
# ① 개인 식별자·내부 절대경로  ② 내부 조직·도구 고유명  ③ 공식 문서에 부적합한 내부 은어
DENY='oogisoogi|/Users/[a-z]|/home/[a-z]|/var/folders'
DENY="$DENY"'|박사님|자비스|페인|갈무리|폐역|박제|고스트|인박스|워커|주인님'
DENY="$DENY"'|강제발화|surface:[0-9]|master#'
# 이메일은 별도 축 — 예약 예시 도메인(RFC 2606: example.com/org/net, *.invalid)은 정당하므로 뺀다.
MAIL='[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z][A-Za-z]+'
RESERVED='@(example\.(com|org|net)|[A-Za-z0-9.-]*\.invalid)'

# 검사 대상 = 담는 목록 방식(제외 목록이 아니라) — 새 폴더가 생겨도 자동 포함된다.
list_files() {
  find . -type f -not -path './.git/*' -not -path './.briefs/*' \
    \( -name '*.md' -o -name '*.sh' -o -name '*.conf' -o -name '*.example' -o -name '*.json' \
       -o -name '*.plist' -o -name '*.service' -o -name '*.timer' -o -name 'LICENSE' -o -name '.gitignore' \) \
    | sort
}
scan() {  # -> stdout = 잔재 줄들
  local files; files="$(list_files)"
  { printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 grep -nE "$DENY" 2>/dev/null
    printf '%s\n' "$files" | tr '\n' '\0' | xargs -0 grep -nE "$MAIL" 2>/dev/null | grep -vE "$RESERVED"
  } | grep -v '^\./tests/publish-hygiene\.sh:' | sort -u
}

if [ "${1:-}" = "--mutation" ]; then
  # ★게이트가 실제로 잡는지 검산한다 — 0건은 "깨끗하다"일 수도 있고 "안 보고 있다"일 수도 있다.
  P="./docs/.hygiene-mutation-probe.md"
  # 두 잔재를 **다른 줄**에 심는다 — 같은 줄에 심으면 sort -u 가 한 줄로 접어 계수가 1이 된다
  # (이 함정에 한 번 걸렸다: 게이트는 멀쩡한데 검산기가 1건만 세어 거짓 실패를 냈다).
  printf 'oogisoogi 라는 사용자명\nreal.person@corp.example 이라는 이메일\n' > "$P"
  n="$(scan | grep -c "hygiene-mutation-probe" || true)"
  rm -f "$P"
  if [ "$n" -ge 2 ]; then
    echo "자기 검산 OK — 심어 둔 잔재 2종(사용자명·이메일)을 모두 잡았다"; exit 0
  fi
  echo "자기 검산 실패 — 심어 둔 잔재를 ${n}건만 잡았다(게이트가 눈이 멀었다)" >&2; exit 2
fi

echo "검사 대상 $(list_files | grep -c .) 개 파일"
echo "금지 패턴 ①②③: $DENY"
echo "금지 패턴 ④ 이메일: $MAIL   (예외: RFC 2606 예약 도메인 $RESERVED)"
echo "─────────────────────────────────────────"
HITS="$(scan || true)"
N="$(printf '%s' "$HITS" | grep -c . || true)"

# ★억제한 것을 전수로 밝힌다 — 보이지 않는 억제는 미탐과 구별되지 않는다.
SUP_SELF=1
SUP_MAIL="$(list_files | tr '\n' '\0' | xargs -0 grep -nE "$MAIL" 2>/dev/null | grep -cE "$RESERVED" || true)"
echo "억제(정당) 내역: 이 스크립트 자신 ${SUP_SELF}개 파일 · 예약 예시 도메인 ${SUP_MAIL}건"
[ "$SUP_MAIL" = "0" ] || list_files | tr '\n' '\0' | xargs -0 grep -nE "$MAIL" 2>/dev/null | grep -E "$RESERVED" | sed 's/^/    /'

if [ "$N" = "0" ]; then echo "공개 위생 0건 — 클린"; exit 0; fi
echo "★잔재 $N 건:"; printf '%s\n' "$HITS"; exit 1
