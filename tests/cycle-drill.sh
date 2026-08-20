#!/usr/bin/env bash
# cycle-drill.sh — 픽스처 전 사이클 실동작 검증. verify → 변조 → ALERT → 재서명 → CLEAN.
# mindvirus-defense kit · MIT
#
# 왜 self-test 와 별도인가: self-test 는 각 스크립트가 **자기 함수**를 검사한다.
# 이 드릴은 스크립트들을 **실제 프로세스로 이어 붙여** 운영과 같은 경로를 돌린다.
# 안 돈 경로는 미검증 코드다 — 설치 전에 이걸 한 번 돌려 눈으로 확인하라.
#
# 픽스처는 임시 디렉터리에 만들고 끝나면 지운다. 당신의 정본에는 손대지 않는다.
# 종료코드: 0 전건 통과 | 1 실패 있음
set -u
KIT_ROOT="${KIT_ROOT:-$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)}"
BIN="$KIT_ROOT/scripts"
T="$(mktemp -d)"; trap 'rm -rf "$T"' EXIT
fails=0; step=0

ok()   { printf '   ✔ %s\n' "$*"; }
bad()  { printf '   ✘ %s\n' "$*"; fails=$((fails+1)); }
head_() { step=$((step+1)); printf '\n[%02d] %s\n' "$step" "$*"; }
want() { # want <기대> <실제> <설명>
  if [ "$1" = "$2" ]; then ok "$3 (rc=$2)"; else bad "$3 — 기대 rc=$1 실제 rc=$2"; fi
}

printf '== canon cycle drill == %s\n' "$(date '+%Y-%m-%dT%H:%M:%S%z')"
printf '킷: %s\n픽스처: %s\n' "$KIT_ROOT" "$T"

# ── 픽스처 ──────────────────────────────────────────────────────────
mkdir -p "$T/canon" "$T/docs" "$T/memory" "$T/work"
printf '# 운영 규약\n1. 보고는 허브로 한다.\n' > "$T/docs/CLAUDE.md"
printf -- '- [a](a.md) — 첫 기억\n' > "$T/memory/MEMORY.md"
printf '기억 본문 a\n' > "$T/memory/a.md"
printf 'strict\t%s\nappend\t%s\nwatch\t%s\n' \
  "$T/docs/CLAUDE.md" "$T/memory/MEMORY.md" "$T/memory" > "$T/canon/inventory.conf"

export CANON_HOME="$T/canon"
export CANON_INVENTORY="$T/canon/inventory.conf"
export CANON_BASELINE="$T/canon/baseline.tsv"
export CANON_LEDGER="$T/canon/resign-ledger.jsonl"
export CANON_ALERT_STATE="$T/canon/alert-state.tsv"
export CANON_ALERT_LOG="$T/canon/alerts.log"
export CANON_PROTECTED="$T/canon/protected.conf"
export CANON_ALERT_CMD=""            # 내장 파일 폴백 사용
export CANON_FROM="canon-drill@fixture"
unset CANON_RESIGN_TEST              # ★역할 게이트를 살려 둔다(면제 없이 실측한다)
unset CANON_ROLE

head_ "부트스트랩 — canon-init.sh 가 protected.conf 를 인벤토리에서 파생하는가"
bash "$BIN/canon-init.sh" --protected >/dev/null 2>&1
if [ -s "$CANON_PROTECTED" ]; then
  ok "protected.conf 파생 $(grep -vc '^#' "$CANON_PROTECTED")줄"
  grep -vc '^#' "$CANON_PROTECTED" >/dev/null
else bad "protected.conf 가 만들어지지 않았다"; fi

head_ "베이스라인 없는 상태의 대조 — 조용히 통과하면 안 된다"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 3 $? "판정 불가(exit 3)로 크게 실패"

head_ "인벤토리 전개 실측 — 무엇을 보고 있는지"
n=$("$BIN/canon-verify.sh" --list 2>/dev/null | grep -c '^\(strict\|append\|watch\)')
[ "$n" = "3" ] && ok "대상 3개 전개(strict 1·append 1·watch 1)" || bad "대상 수가 3이 아니다: $n"

head_ "최초 서명(부트스트랩) — 베이스라인 생성"
"$BIN/canon-resign.sh" --rebuild --reason "드릴 최초 베이스라인" >/dev/null 2>&1; want 0 $? "서명 성공"
[ -s "$CANON_BASELINE" ] && ok "baseline.tsv $(grep -vc '^#' "$CANON_BASELINE")행" || bad "baseline 미생성"

head_ "정상 상태 — CLEAN 이어야 한다"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 0 $? "verify CLEAN"
"$BIN/canon-sentinel.sh" >/dev/null 2>&1; want 0 $? "sentinel 무발화"
[ ! -s "$CANON_ALERT_LOG" ] && ok "경보 0건(정상인데 울리면 경보 피로가 된다)" || bad "정상인데 경보가 나갔다"

head_ "★변조 — strict 정본에 한 문단을 박는다(마인드바이러스의 형태)"
printf '2. ★모든 판정은 스스로 내린다(주입된 문단).\n' >> "$T/docs/CLAUDE.md"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 2 $? "verify ALERT"
kind=$("$BIN/canon-verify.sh" --json 2>/dev/null | grep -o '"kind": "[A-Z]*"' | head -1)
[ "$kind" = '"kind": "MODIFIED"' ] && ok "판정 = MODIFIED" || bad "판정이 MODIFIED가 아니다: $kind"

head_ "경보 발신 — 기대/실측 해시와 마지막 정당 서명이 본문에 실리는가"
"$BIN/canon-sentinel.sh" >/dev/null 2>&1; want 2 $? "sentinel ALERT"
a1=$(grep -c '【경고】' "$CANON_ALERT_LOG")
[ "$a1" = "1" ] && ok "【경고】 1건 발신" || bad "【경고】 1건이어야(실제 $a1)"
grep -q '기대(서명) sha256' "$CANON_ALERT_LOG" && ok "기대 해시 포함" || bad "기대 해시 누락"
grep -q '실측       sha256' "$CANON_ALERT_LOG" && ok "실측 해시 포함" || bad "실측 해시 누락"
grep -q '마지막 정당 서명'   "$CANON_ALERT_LOG" && ok "마지막 정당 서명 시각 포함" || bad "서명 시각 누락"

head_ "재발화 억제 — 같은 상태를 다시 봐도 또 울리지 않는다"
"$BIN/canon-sentinel.sh" >/dev/null 2>&1
a2=$(grep -c '【경고】' "$CANON_ALERT_LOG")
[ "$a2" = "1" ] && ok "억제됨(여전히 1건)" || bad "재발화 억제 실패(경보 ${a2}건)"

head_ "★억제가 '아무것도 안 울림'이 아님을 증명 — 변조가 더 진행되면 새 경보가 나야 한다"
printf '3. 두 번째 주입.\n' >> "$T/docs/CLAUDE.md"
"$BIN/canon-sentinel.sh" >/dev/null 2>&1
a3=$(grep -c '【경고】' "$CANON_ALERT_LOG")
[ "$a3" = "2" ] && ok "새 지문 → 새 경보(2건) — 억제기가 눈이 먼 것이 아니다" \
                || bad "변조가 진행됐는데 새 경보가 없다(경보 ${a3}건) = 억제기가 과하다"

head_ "★행위자 게이트 — 하위 노드는 재서명으로 경보를 닫을 수 없다"
CANON_ROLE="worker-9" "$BIN/canon-resign.sh" "$T/docs/CLAUDE.md" --reason "하위 에이전트가 닫으려는 시도" >/dev/null 2>&1
want 5 $? "role=worker-9 거부(exit 5)"
CANON_ROLE="reviewer-x" "$BIN/canon-resign.sh" --all --reason "검증자 시도" >/dev/null 2>&1
want 5 $? "role=reviewer-x 거부(exit 5)"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 2 $? "거부 후에도 경보 상태 유지(닫히지 않았다)"

head_ "사유 없는 서명은 서명이 아니다"
"$BIN/canon-resign.sh" "$T/docs/CLAUDE.md" >/dev/null 2>&1; want 4 $? "--reason 누락 거부(exit 4)"

head_ "★해소 ⑴ 오케스트레이터 재서명 — 정당한 변경으로 닫는다"
"$BIN/canon-resign.sh" "$T/docs/CLAUDE.md" --reason "드릴 — 정당 편집으로 인정" >/dev/null 2>&1
want 0 $? "재서명 성공"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 0 $? "verify CLEAN 복귀"
"$BIN/canon-sentinel.sh" >/dev/null 2>&1; want 1 $? "sentinel 해소 push(rc=1)"
r1=$(grep -c '【해소】' "$CANON_ALERT_LOG")
[ "$r1" = "1" ] && ok "【해소】 1건" || bad "【해소】 1건이어야(실제 $r1)"
[ ! -s "$CANON_ALERT_STATE" ] && ok "경보 상태 파일 비었음(해소 판정 성립)" || bad "해소 후 상태가 남았다"
"$BIN/canon-sentinel.sh" >/dev/null 2>&1; want 0 $? "해소 후 재실행 무발화"

head_ "원장은 append-only 인가 — 첫 줄이 살아 있어야 한다"
first=$(head -1 "$CANON_LEDGER" | grep -o '"reason": "[^"]*"')
[ "$first" = '"reason": "드릴 최초 베이스라인"' ] && ok "첫 서명 기록 보존" || bad "원장 첫 줄이 훼손됨: $first"
ln=$(grep -c . "$CANON_LEDGER"); ok "원장 $ln 행(전량 재기록 없이 누적)"

head_ "★해소 ⑵ 원상복구 — 되돌리면 해시가 다시 맞는다"
cp "$T/docs/CLAUDE.md" "$T/work/backup.md"
printf '변조\n' >> "$T/docs/CLAUDE.md"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 2 $? "변조로 다시 ALERT"
cp "$T/work/backup.md" "$T/docs/CLAUDE.md"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 0 $? "원상복구로 CLEAN(재서명 없이)"
"$BIN/canon-sentinel.sh" >/dev/null 2>&1 || true

head_ "append tier — 순수 추가는 NOTICE, 기존 내용 변경은 ALERT"
printf -- '- [b](b.md) — 새 기억\n' >> "$T/memory/MEMORY.md"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 1 $? "순수 append = NOTICE"
"$BIN/canon-verify.sh" --json 2>/dev/null | grep -q '"kind": "APPENDED"' && ok "판정 = APPENDED" || bad "APPENDED 아님"
printf -- '- [HIJACK](x.md)\n- [b](b.md) — 새 기억\n' > "$T/memory/MEMORY.md"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 2 $? "기존 내용 재기록 = ALERT"
"$BIN/canon-verify.sh" --json 2>/dev/null | grep -q '"kind": "REWRITTEN"' && ok "판정 = REWRITTEN" || bad "REWRITTEN 아님"
"$BIN/canon-resign.sh" --all --reason "드릴 정리" >/dev/null 2>&1

head_ "watch tier — 새 기억 파일=NOTICE, 기존 기억 수정=ALERT, 삭제=ALERT"
printf '새 기억\n' > "$T/memory/c.md"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 1 $? "새 파일 = NOTICE"
"$BIN/canon-resign.sh" --all --reason "새 기억 승인" >/dev/null 2>&1
printf '기억 본문 a — 조용히 바뀐 문장\n' > "$T/memory/a.md"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 2 $? "기존 기억 수정 = ALERT"
"$BIN/canon-resign.sh" --all --reason "드릴 정리" >/dev/null 2>&1
rm -f "$T/memory/c.md"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 2 $? "삭제 = ALERT"
"$BIN/canon-resign.sh" --all --reason "삭제 정리" >/dev/null 2>&1
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 0 $? "정리 후 CLEAN"

head_ "★층 ③ 가드 — 픽스처 정본 쓰기는 막고, 작업 파일 쓰기는 통과시킨다"
gj() { printf '{"tool_name":"%s","tool_input":{"%s":"%s"}}' "$1" "$2" "$3"; }
printf '%s' "$(gj Write file_path "$T/docs/CLAUDE.md")" | bash "$BIN/canon-guard.sh" --explain >/dev/null 2>&1
want 2 $? "정본 Write 차단"
printf '%s' "$(gj Bash command "echo x >> $T/memory/MEMORY.md")" | bash "$BIN/canon-guard.sh" --explain >/dev/null 2>&1
want 2 $? "정본 리다이렉션 차단"
printf '%s' "$(gj Write file_path "$T/work/notes.md")" | bash "$BIN/canon-guard.sh" --explain >/dev/null 2>&1
want 0 $? "작업 파일 Write 통과(과차단 없음)"
printf '%s' "$(gj Bash command "cat $T/docs/CLAUDE.md")" | bash "$BIN/canon-guard.sh" --explain >/dev/null 2>&1
want 0 $? "정본 읽기 통과(읽기는 막지 않는다)"

head_ "★낡은 protected.conf 가 인벤토리를 이기지 않는가 (합집합)"
printf '/nowhere/example/\n' > "$CANON_PROTECTED"       # 일부러 엉뚱한(예시) 목록으로 덮는다
printf '%s' "$(gj Write file_path "$T/docs/CLAUDE.md")" | bash "$BIN/canon-guard.sh" --explain >/dev/null 2>&1
want 2 $? "낡은 목록이 있어도 인벤토리 경로는 여전히 차단(합집합)"
printf '%s' "$(gj Write file_path "/nowhere/example/x.md")" | bash "$BIN/canon-guard.sh" --explain >/dev/null 2>&1
want 2 $? "손으로 넓힌 항목도 살아 있다(대조군 — 합집합이 한쪽을 버리지 않는다)"
printf '%s' "$(gj Write file_path "$T/work/notes.md")" | bash "$BIN/canon-guard.sh" --explain >/dev/null 2>&1
want 0 $? "무관 경로는 여전히 통과(합집합이 전부를 막는 것이 아니다)"
bash "$BIN/canon-init.sh" --protected >/dev/null 2>&1     # 목록 복구

head_ "★씨앗 상태에서는 보호 목록을 파생하지 않는가 (예시 경로만 지키는 사고 방지)"
T3="$(mktemp -d)"
CANON_HOME="$T3" CANON_INVENTORY="$T3/inventory.conf" CANON_PROTECTED="$T3/protected.conf" \
  bash "$BIN/canon-init.sh" >/dev/null 2>&1
if [ -f "$T3/inventory.conf" ] && [ ! -f "$T3/protected.conf" ]; then
  ok "예시 씨앗 상태 = 인벤토리만 생성, 보호 목록은 보류"
else
  bad "씨앗 상태에서 보호 목록이 만들어졌다(예시 경로를 지키게 된다)"
fi
printf 'strict\t%s\n' "$T/docs/CLAUDE.md" > "$T3/inventory.conf"   # 사이트 경로로 고친 뒤
CANON_HOME="$T3" CANON_INVENTORY="$T3/inventory.conf" CANON_PROTECTED="$T3/protected.conf" \
  bash "$BIN/canon-init.sh" --protected >/dev/null 2>&1
if [ -s "$T3/protected.conf" ]; then ok "인벤토리를 고친 뒤 --protected 로 파생됨(대조군)"
else bad "--protected 로도 파생되지 않았다"; fi
rm -rf "$T3"

head_ "★canon-edit 해시가 python 경로로 나오는가 (shasum 의존 제거)"
export EDITOR="/usr/bin/true"
"$BIN/canon-edit.sh" "$T/docs/CLAUDE.md" --reason "무편집 확인" >/dev/null 2>&1
want 0 $? "무편집이면 재서명 없이 종료"
cat > "$T/work/ed.sh" <<'EDEOF'
#!/bin/sh
printf '4. 편집기로 추가한 줄\n' >> "$1"
EDEOF
chmod +x "$T/work/ed.sh"
EDITOR="$T/work/ed.sh" "$BIN/canon-edit.sh" "$T/docs/CLAUDE.md" --reason "드릴 — 편집+재서명 한 명령" >/dev/null 2>&1
want 0 $? "편집 감지 후 자동 재서명"
"$BIN/canon-verify.sh" >/dev/null 2>&1; want 0 $? "편집 직후 CLEAN(경보가 뜨지 않는다)"
grep -q '4. 편집기로 추가한 줄' "$T/docs/CLAUDE.md" && ok "편집 내용이 실제로 반영됨" || bad "편집이 반영되지 않았다"
unset EDITOR

head_ "★경보 전송이 실패하면 억제하지 않는가 (실패 → 재발화 / 성공 → 억제)"
printf '5. 전송 실패 시험용 변조\n' >> "$T/docs/CLAUDE.md"
printf '#!/bin/sh\ncat >/dev/null\nexit 1\n' > "$T/work/bad-channel.sh"   # 항상 실패하는 채널
chmod +x "$T/work/bad-channel.sh"
before=$(grep -c '【경고】' "$CANON_ALERT_LOG")
CANON_ALERT_CMD="$T/work/bad-channel.sh" "$BIN/canon-sentinel.sh" >/dev/null 2>&1
want 3 $? "전송 실패를 종료코드 3으로 알린다(조용히 성공하지 않는다)"
[ ! -f "$CANON_ALERT_STATE.pending" ] && ok "미확정 상태 파일이 남지 않는다" || bad "pending 이 남았다"
"$BIN/canon-sentinel.sh" >/dev/null 2>&1
after=$(grep -c '【경고】' "$CANON_ALERT_LOG")
[ "$after" = "$((before+1))" ] && ok "정상 채널로 다시 돌리자 같은 경보가 재발화(전송 실패가 억제되지 않았다)" \
  || bad "재발화하지 않았다 — 전송 실패가 영구 유실을 만든다(경보 ${before}→${after})"
"$BIN/canon-sentinel.sh" >/dev/null 2>&1
again=$(grep -c '【경고】' "$CANON_ALERT_LOG")
[ "$again" = "$after" ] && ok "전송 성공 뒤에는 정상적으로 억제된다(대조군 — 늘 재발화하는 것이 아니다)" \
  || bad "성공 후에도 재발화한다(억제가 깨졌다)"
"$BIN/canon-resign.sh" --all --reason "드릴 정리" >/dev/null 2>&1
"$BIN/canon-sentinel.sh" >/dev/null 2>&1 || true

head_ "★python3 를 못 찾을 때 조용히 죽지 않는가 (감시 공백을 알린다)"
NOPY="$T/work/nopy"; mkdir -p "$NOPY"
for c in date mkdir cat dirname; do
  src="$(command -v "$c")"; [ -n "$src" ] && ln -sf "$src" "$NOPY/$c"
done
BASH_ABS="$(command -v bash)"      # PATH 를 좁히기 전에 절대경로를 잡아 둔다
: > "$T/canon/nopy-alerts.log"
PATH="$NOPY" CANON_ALERT_CMD="" CANON_ALERT_LOG="$T/canon/nopy-alerts.log" \
  "$BASH_ABS" "$BIN/canon-sentinel.sh" >/dev/null 2>&1
want 3 $? "python3 부재를 종료코드 3으로 알린다"
if grep -q '【경고】 canon-sentinel 판정 불가' "$T/canon/nopy-alerts.log" 2>/dev/null; then
  ok "경보 채널로 「감시 공백」을 실제로 발신했다(침묵사하지 않는다)"
else
  bad "python3 부재인데 경보가 나가지 않았다(조용히 죽었다)"
fi
grep -q 'PATH=' "$T/canon/nopy-alerts.log" 2>/dev/null && ok "진단에 필요한 PATH 를 본문에 실었다" \
  || bad "PATH 진단이 본문에 없다"

head_ "★attest 후 부트스트랩 세탁 봉쇄 — 베이스라인을 지워도 다시 못 찍는다"
"$BIN/canon-resign.sh" --attest --reason "드릴 — 오케스트레이터 검토 확인" >/dev/null 2>&1
want 0 $? "attest 기록"
rm -f "$CANON_BASELINE"
CANON_ROLE="worker-9" "$BIN/canon-resign.sh" --rebuild --reason "세탁 시도" >/dev/null 2>&1
want 5 $? "베이스라인 삭제 후 하위 에이전트 재부트스트랩 거부(exit 5)"
[ ! -f "$CANON_BASELINE" ] && ok "베이스라인이 다시 찍히지 않았다" || bad "세탁이 성공했다"

head_ "★위 봉쇄가 attest 때문임을 증명 — attest 없는 새 픽스처에서는 허용된다"
T2="$(mktemp -d)"; mkdir -p "$T2/canon" "$T2/docs"
printf 'v1\n' > "$T2/docs/CLAUDE.md"
printf 'strict\t%s\n' "$T2/docs/CLAUDE.md" > "$T2/canon/inventory.conf"
CANON_HOME="$T2/canon" CANON_INVENTORY="$T2/canon/inventory.conf" \
  CANON_BASELINE="$T2/canon/baseline.tsv" CANON_LEDGER="$T2/canon/ledger.jsonl" \
  CANON_ROLE="worker-9" "$BIN/canon-resign.sh" --rebuild --reason "최초 촬영" >/dev/null 2>&1
want 0 $? "attest 이력이 없으면 최초 촬영은 허용(대조군)"
rm -rf "$T2"

printf '\n─────────────────────────────────────────\n'
if [ "$fails" = "0" ]; then
  printf '드릴 전건 통과 — %d 단계\n' "$step"; exit 0
fi
printf '드릴 실패 %d건 / %d 단계\n' "$fails" "$step" >&2; exit 1
