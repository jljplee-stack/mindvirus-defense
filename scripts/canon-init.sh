#!/usr/bin/env bash
# canon-init.sh — 킷 부트스트랩. CANON_HOME 을 만들고 설정 씨앗을 깐다.
# mindvirus-defense kit · MIT
#
# 이 스크립트는 층 ②③의 **동작을 바꾸지 않는다.** 새 조직이 빈손에서 시작할 수 있게
# 설정 파일을 놓아 주는 역할만 한다(원본 5종은 설정이 이미 있다고 가정하고 짜여 있다).
#
# 사용:  canon-init.sh                 # ~/.canon 에 씨앗 설치(있으면 덮지 않는다)
#        CANON_HOME=/opt/canon canon-init.sh
#        canon-init.sh --dry-run
#        canon-init.sh --protected     # 인벤토리에서 protected.conf 를 다시 파생
#
# 종료코드: 0 성공 | 3 오류
set -u
KIT_ROOT="${KIT_ROOT:-$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)}"
CANON_HOME="${CANON_HOME:-$HOME/.canon}"
INVENTORY="${CANON_INVENTORY:-$CANON_HOME/inventory.conf}"
PROTECTED="${CANON_PROTECTED:-$CANON_HOME/protected.conf}"

_py_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s' "$1"
  fi
}
DRY=0; ONLY_PROT=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    --protected) ONLY_PROT=1 ;;
    -h|--help) sed -n '2,16p' "$0"; exit 0 ;;
    *) echo "canon-init: 알 수 없는 인자 $a" >&2; exit 3 ;;
  esac
done

say() { printf '%s\n' "$*"; }
run() { if [ "$DRY" = "1" ]; then say "  [dry-run] $*"; else eval "$@"; fi; }

say "canon-init — CANON_HOME=$CANON_HOME"
[ -d "$KIT_ROOT/examples" ] || { echo "킷 구조를 못 찾겠다: $KIT_ROOT/examples 부재" >&2; exit 3; }

if [ "$ONLY_PROT" = "0" ]; then
  run "mkdir -p '$CANON_HOME'"
  if [ -f "$INVENTORY" ]; then
    say "  · inventory.conf 이미 존재 — 덮지 않는다($INVENTORY)"
  else
    run "cp '$KIT_ROOT/examples/inventory.example.conf' '$INVENTORY'"
    say "  · inventory.conf 씨앗 설치 — ★반드시 사이트 경로로 고쳐라(예시는 그대로 쓰면 0건이다)"
  fi
fi

# protected.conf 파생 — 층 ③은 ②보다 넓어야 하므로 글롭·디렉터리를 디렉터리로 넓힌다.
#
# ★씨앗 상태(예시 인벤토리를 아직 안 고침)에서는 파생하지 않는다.
#   예시 경로로 만든 보호 목록은 **아무것도 아닌 경로를 지키면서 정상으로 보인다.**
SEED_UNCHANGED=0
if [ -f "$INVENTORY" ] && [ -f "$KIT_ROOT/examples/inventory.example.conf" ]; then
  if cmp -s "$INVENTORY" "$KIT_ROOT/examples/inventory.example.conf"; then SEED_UNCHANGED=1; fi
fi
if [ "$SEED_UNCHANGED" = "1" ] && [ "$ONLY_PROT" = "0" ]; then
  say "  · protected.conf 파생 보류 — 인벤토리가 아직 예시 그대로다"
  say "    ★인벤토리를 사이트 경로로 고친 뒤 반드시: canon-init.sh --protected"
  say "    (그때까지 층 ③ 가드는 인벤토리에서 직접 파생한 목록으로 동작한다)"
elif [ -f "$PROTECTED" ] && [ "$ONLY_PROT" = "0" ]; then
  say "  · protected.conf 이미 존재 — 덮지 않는다($PROTECTED)"
elif [ -f "$INVENTORY" ]; then
  PY="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || printf '')"
  if [ -z "$PY" ]; then
    say "  · python 부재 — protected.conf 파생 생략(가드가 실행 시 인벤토리에서 파생한다)"
  else
    TMPOUT="$(mktemp)"
    INVENTORY="$(_py_path "$INVENTORY")" CANON_HOME="$(_py_path "$CANON_HOME")" KIT_ROOT="$(_py_path "$KIT_ROOT")" "$PY" - > "$TMPOUT" <<'PYEOF'
import os, re

def _canon(p):
    p = os.path.expanduser(str(p or "")).replace("\\", "/")
    if os.name == "nt":
        if p == "/tmp" or p.startswith("/tmp/"):
            temp_root = os.environ.get("TEMP") or os.environ.get("TMP")
            if temp_root:
                p = temp_root.replace("\\", "/").rstrip("/") + p[4:]
        m = re.match(r"^/([A-Za-z])(/|$)", p)
        if m:
            p = m.group(1).upper() + ":/" + p[3:]
    if not os.path.isabs(p):
        p = os.path.abspath(p)
    return os.path.normpath(p).replace("\\", "/")

inv = _canon(os.environ["INVENTORY"])
out = []
for line in open(inv, encoding="utf-8"):
    s = line.rstrip("\n")
    if not s.strip() or s.lstrip().startswith("#"):
        continue
    parts = [x for x in s.split("\t") if x != ""]
    if len(parts) < 2:
        continue
    tier, sel = parts[0].strip(), _canon(parts[1].strip())
    if tier in ("watch", "watch-soft"):
        out.append(_canon(sel) + "/")
    elif any(c in sel for c in "*?["):
        out.append(_canon(os.path.dirname(sel)) + "/")
    else:
        out.append(_canon(sel))
out.append(_canon(os.environ["CANON_HOME"]) + "/")
out.append(_canon(os.environ["KIT_ROOT"]) + "/scripts/")
print("# canon protected v1 — 층 ③ 가드의 보호 경로 목록(줄당 1개, 끝의 / = 디렉터리 접두).")
print("# canon-init.sh 가 inventory.conf 에서 파생했다. **손으로 더 넓혀도 된다** —")
print("# ③은 예방이라 넓을수록 좋고, 과차단 여부는 canon-guard.sh --self-test 의 A군이 지킨다.")
for p in sorted(set(out)):
    print(p)
PYEOF
    if [ "$DRY" = "1" ]; then
      say "  [dry-run] protected.conf 파생 결과 $(grep -vc '^#' "$TMPOUT") 줄:"
      sed -e 's/^/      /' "$TMPOUT"
    else
      cat "$TMPOUT" > "$PROTECTED"
      say "  · protected.conf 파생 완료 — $(grep -vc '^#' "$PROTECTED") 줄 ($PROTECTED)"
    fi
    rm -f "$TMPOUT"
  fi
else
  say "  · inventory.conf 가 없어 protected.conf 를 파생하지 못했다"
fi

say ""
say "다음 순서(docs/INSTALL.md 가 정본):"
say "  1) \$EDITOR $INVENTORY            # 감시 대상을 사이트 경로로 확정"
say "  2) $KIT_ROOT/scripts/canon-verify.sh --list   # 전개 결과 실측(0건이면 인벤토리가 안 맞는 것)"
say "  3) $KIT_ROOT/scripts/canon-resign.sh --rebuild --reason '최초 베이스라인 서명'"
say "  4) ★내용 검토 후 canon-resign.sh --attest --reason '...'   # 이게 실질 게이트다"
say "  5) 상주 배선(examples/scheduler/) · 훅 설치(hooks/install-canon-guard.sh --dry-run)"
exit 0
