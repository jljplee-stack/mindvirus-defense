#!/usr/bin/env bash
# install-canon-guard.sh — 층 ③ 훅을 에이전트 공용 settings.json 에 **멱등** 설치/제거.
# mindvirus-defense kit · MIT
# ⛔ 하위 에이전트의 임의 실행 금지 — master(오케스트레이터) 승인 후 집행.
#
# 대상 설정 파일: CANON_GUARD_SETTINGS (기본 = ${CLAUDE_CONFIG_DIR:-~/.claude}/settings.json)
#   ※ 에이전트들이 별도 CLAUDE_CONFIG_DIR 를 쓴다면 그 경로를 반드시 명시하라 —
#      설정 파일이 갈려 있으면 「설치했는데 아무 에이전트에도 안 걸리는」 사고가 난다.
#
# 사용: install-canon-guard.sh --dry-run   # 무엇이 바뀌는지만
#       install-canon-guard.sh --apply     # 실제 설치(백업 자동)
#       install-canon-guard.sh --remove    # 제거(예외가 필요할 때의 유일한 정식 경로)
#
# 보장: ⑴기존 훅 배열 보존(추가만) ⑵중복 설치 방지(같은 command 이미 있으면 무동작)
#       ⑶쓰기 전 타임스탬프 백업 ⑷JSON 파싱 실패 시 아무것도 안 씀
set -u
KIT_ROOT="${KIT_ROOT:-$(cd "$(dirname "$0")/.." 2>/dev/null && pwd)}"
SETTINGS="${CANON_GUARD_SETTINGS:-${CLAUDE_CONFIG_DIR:-$HOME/.claude}/settings.json}"
HOOK_CMD="${CANON_GUARD_HOOK_CMD:-sh $KIT_ROOT/scripts/canon-guard.sh}"
MODE=""
for a in "$@"; do case "$a" in --dry-run) MODE=dry;; --apply) MODE=apply;; --remove) MODE=remove;; esac; done
[ -n "$MODE" ] || { echo "usage: $0 --dry-run | --apply | --remove" >&2; exit 4; }
PY="$(command -v python3 || command -v python)" || { echo "python 부재" >&2; exit 3; }

export SETTINGS HOOK_CMD MODE
"$PY" - <<'PYEOF'
import json, os, shutil, sys, time
S = os.environ["SETTINGS"]; CMD = os.environ["HOOK_CMD"]; MODE = os.environ["MODE"]
MATCHER = "Write|Edit|MultiEdit|NotebookEdit|Bash"
if not os.path.isfile(S):
    print("설정 파일 없음: %s" % S, file=sys.stderr); sys.exit(3)
try:
    data = json.load(open(S, encoding="utf-8"))
except Exception as e:
    print("JSON 파싱 실패 — 아무것도 쓰지 않는다: %s" % e, file=sys.stderr); sys.exit(3)

hooks = data.setdefault("hooks", {})
pre = hooks.setdefault("PreToolUse", [])
present = [i for i, e in enumerate(pre)
           if any((h or {}).get("command") == CMD for h in (e or {}).get("hooks", []))]

if MODE == "remove":
    if not present:
        print("canon-guard 미설치 — 제거할 것 없음"); sys.exit(0)
    for i in reversed(present):
        pre.pop(i)
    action = "제거"
else:
    if present:
        print("canon-guard 이미 설치됨(항목 %s) — 무동작(멱등)" % present); sys.exit(0)
    pre.append({"matcher": MATCHER, "hooks": [{"type": "command", "command": CMD}]})
    action = "설치"

out = json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n"
if MODE == "dry":
    print("[dry-run] %s 예정 — PreToolUse 항목 %d개 → %d개" % (action, len(pre) - 1, len(pre)))
    print("  matcher: %s" % MATCHER); print("  command: %s" % CMD)
    print("  (실제 쓰기 없음. --apply 로 집행)"); sys.exit(0)

bk = "%s.bak-canonguard-%s" % (S, time.strftime("%Y%m%d-%H%M%S"))
shutil.copy2(S, bk)
tmp = S + ".tmp"
open(tmp, "w", encoding="utf-8").write(out)
os.replace(tmp, S)
print("canon-guard %s 완료." % action)
print("  대상: %s" % S)
print("  백업: %s" % bk)
print("  ★검증 필수: 새 에이전트 1기에서 정본 쓰기를 시도해 차단을 실측하라(안 돈 경로는 미검증 코드다).")
PYEOF
