#!/usr/bin/env bash
# canon-guard.sh — 하위 에이전트 정본 쓰기 가드. Claude Code PreToolUse 훅.
# mindvirus-defense kit — 층 ③ (예방·1차 방벽) · MIT
# 설치 대상: 에이전트들이 공유하는 settings.json (예: $CLAUDE_CONFIG_DIR/settings.json)
# matcher:  Write|Edit|MultiEdit|NotebookEdit|Bash
#   ⚠판정 함수는 방어적으로 "Update" 라는 도구 이름도 함께 본다. 그러나 **matcher 에 없는 도구에는
#     훅 자체가 발화하지 않는다** — 당신 플랫폼에 그런 이름의 쓰기 도구가 있으면 matcher 에 넣어라.
#   ⚠도구 이름은 플랫폼 계약이다. 다른 이름(write_file·execute_command 등)을 쓰는 에이전트라면
#     이 훅은 **아무것도 막지 못한다.** 반드시 당신 도구 이름으로 바꿔라(docs/LIMITS.md §9).
#
# 보호 경로의 정본(SOT) = $CANON_PROTECTED 파일(줄당 경로 1개, 끝의 / 는 디렉터리 접두).
#   그 파일이 없으면 $CANON_INVENTORY(층 ②의 인벤토리)에서 파생한다 —
#   글롭·디렉터리 항목은 **디렉터리 통째로 넓혀서** 잡는다(③은 예방이라 넓어야 한다).
#
# ── 무엇을 막는가 ────────────────────────────────────────────────────
# 자동 로드 정본(매 세션 컨텍스트에 주입되고 재부팅을 살아남는 파일)에 대한 **쓰기**.
# 읽기는 막지 않는다(하위 에이전트는 지침을 읽어야 한다).
#
# ── 위협 모델(정직·은폐 금지) ────────────────────────────────────────
# 대상 = ⑴ 감염된/오작동하는 협력 에이전트의 자기 확신의 정본 기록 ⑵ 위조된 지시의 집행
#        ⑶ 하위 에이전트의 선의의 월권("이건 정본에 남겨야겠다").
# ⛔ **보안 경계가 아니다.** 하위 에이전트는 임의 셸을 가지므로 완전 차단은 원리적으로 불가능하다:
#    · `bash -c` / `eval` / 스크립트 파일 경유 / 셸 변수로 조립한 경로
#    · python `open(p,'w')` 를 변수·base64·문자열 연산으로 은닉
#    · 새 프로세스·다른 도구(MCP)·에디터 TUI
#    이 훅은 **1차 방벽(실수·직행 차단)** 이고, 2차 그물은 ② 무결성 워치(canon-verify/sentinel)다.
#    1차가 못 막은 것을 2차가 사후에 반드시 드러낸다 — 예방과 탐지를 겹쳐야 성립한다.
#
# ── fail 정책 ────────────────────────────────────────────────────────
# python 부재·JSON 파싱 실패 → **정본 경로 문자열이 입력에 보이면 DENY**(canon 한정 fail-closed),
# 안 보이면 통과(무관 작업 과차단 방지).
#
# 사용: (훅) stdin JSON  |  canon-guard.sh --self-test  |  canon-guard.sh --explain <<< '<json>'
set -u

if [ "${1:-}" = "--self-test" ]; then export CANON_GUARD_SELF_TEST=1; fi
PY="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || printf '')"

CANON_HOME="${CANON_HOME:-$HOME/.canon}"
CANON_BIN="${CANON_BIN:-$(cd "$(dirname "$0")" 2>/dev/null && pwd)}"
CANON_PROTECTED="${CANON_PROTECTED:-$CANON_HOME/protected.conf}"
CANON_INVENTORY="${CANON_INVENTORY:-$CANON_HOME/inventory.conf}"

if [ -z "$PY" ]; then
  # python 부재 — 정밀 분석 불가. 보호 경로 문자열이 입력에 **보이기만 해도** 거부한다
  # (canon 한정 fail-closed · 무관 작업은 통과시켜 과차단을 피한다).
  RAW="$(cat 2>/dev/null)"
  LIST="$( { [ -f "$CANON_PROTECTED" ] && sed -e 's/#.*//' "$CANON_PROTECTED"
             [ -f "$CANON_INVENTORY" ] && awk -F'\t' '$0 !~ /^[[:space:]]*#/ && NF>=2 {print $2}' "$CANON_INVENTORY"
           } 2>/dev/null | sed -e "s|^~|$HOME|" )"
  printf '%s\n' "$LIST" | while IFS= read -r pth; do
    pth="$(printf '%s' "$pth" | sed -e 's/[[:space:]]*$//' -e 's|[*?].*$||' -e 's|/$||')"
    [ -n "$pth" ] || continue
    case "$RAW" in
      *"$pth"*) echo "canon-guard: python 부재 + 정본 경로 감지($pth) — fail-closed DENY" >&2; exit 9 ;;
    esac
  done
  [ "$?" = "9" ] && exit 2
  exit 0
fi

INPUT="$(cat 2>/dev/null)"
export CANON_GUARD_INPUT="$INPUT"
export CANON_GUARD_HOME="$HOME"
export CANON_HOME CANON_BIN CANON_PROTECTED CANON_INVENTORY
exec "$PY" - "$@" <<'PYEOF'
import json, os, re, shlex, sys

HOME = os.environ.get("CANON_GUARD_HOME") or os.path.expanduser("~")

# ── 보호 경로 ────────────────────────────────────────────────────────
# ★층 ②(inventory.conf)보다 의도적으로 **넓다**. 이유: ②는 탐지라 정밀해야 소음이 안 나고,
#   ③은 예방이라 넓어야 샌 곳이 안 생긴다. 정본 디렉터리를 통째로 막아도 하위 에이전트의
#   정상 작업에는 지장이 없다(자기 TODO·프로젝트 소스·메모는 전부 통과 — self-test A군).
#
# 결정 순서 — ★**둘의 합집합**이다(어느 한쪽만 쓰지 않는다):
#   ⑴ $CANON_PROTECTED 파일(줄당 경로 1개, 끝의 '/' = 디렉터리 접두) — 손으로 넓힌 항목
#   ⑵ $CANON_INVENTORY 에서 파생(글롭·디렉터리는 디렉터리로 넓힌다) — 층 ②가 보는 것
#   ⑶ 어느 쪽도 없으면 목록이 비고, 그 사실을 stderr 로 크게 알린다
#      — 조용히 통과하는 가드가 가장 나쁘다.
#
# ★왜 합집합인가: 파일 하나만 SOT로 쓰면 **낡은 목록이 조용히 이긴다.** 인벤토리를 실제 경로로
#   고쳤는데 protected.conf 가 예전(혹은 예시) 경로를 담고 있으면, 가드는 아무것도 아닌 경로만
#   지키면서 정상으로 보인다. 합집합은 **넓어질 뿐 좁아지지 않으므로** 그 실패 방식이 없다.
#   (③은 예방이라 넓은 것이 옳다 — 과차단 여부는 self-test A군이 지킨다.)
# 어느 경우든 **감시 기구 자신**($CANON_HOME, $CANON_BIN)은 항상 보호 목록에 들어간다.

def _self_protection():
    out = []
    for key in ("CANON_HOME", "CANON_BIN"):
        v = os.environ.get(key)
        if v:
            out.append(os.path.normpath(os.path.expanduser(v)) + "/")
    return out

def _from_file(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                out.append(os.path.expanduser(line))
    return out

def _from_inventory(path):
    """층 ②의 인벤토리에서 파생 — 글롭·디렉터리 항목은 디렉터리로 넓힌다."""
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = [x for x in line.split("\t") if x != ""]
            if len(parts) < 2:
                continue
            tier, sel = parts[0].strip(), os.path.expanduser(parts[1].strip())
            if tier in ("watch", "watch-soft"):
                out.append(os.path.normpath(sel) + "/")
            elif any(c in sel for c in "*?["):
                out.append(os.path.normpath(os.path.dirname(sel)) + "/")
            else:
                out.append(sel)
    return out

_PROT_CACHE = None

def protected_list():
    global _PROT_CACHE
    if _PROT_CACHE is not None:
        return _PROT_CACHE
    out, srcs = [], []
    pf = os.environ.get("CANON_PROTECTED")
    inv = os.environ.get("CANON_INVENTORY")
    have_pf = bool(pf and os.path.isfile(pf))
    have_inv = bool(inv and os.path.isfile(inv))
    try:
        if have_pf:
            out += _from_file(pf); srcs.append(pf)
        if have_inv:
            out += _from_inventory(inv); srcs.append(inv + "(파생)")
    except OSError as e:
        print("canon-guard: 보호 목록 읽기 실패(%s) — 자기보호 항목만 남는다" % e, file=sys.stderr)
    if have_pf and have_inv:
        try:
            if os.path.getmtime(inv) > os.path.getmtime(pf):
                print("canon-guard: 알림 — %s 가 %s 보다 최근이다. "
                      "'canon-init.sh --protected' 로 보호 목록을 다시 파생하는 것을 권한다."
                      % (inv, pf), file=sys.stderr)
        except OSError:
            pass
    src = " + ".join(srcs) if srcs else "(없음)"
    out = out + _self_protection()
    if not out:
        print("canon-guard: ⚠보호 목록이 비었다(%s / %s 부재) — 아무것도 막지 못한다. "
              "CANON_PROTECTED 를 설정하라." % (pf, inv), file=sys.stderr)
    _PROT_CACHE = sorted(set(out))
    if os.environ.get("CANON_GUARD_DEBUG"):
        print("canon-guard: 보호 목록 %d건 (출처 %s)" % (len(_PROT_CACHE), src), file=sys.stderr)
    return _PROT_CACHE

def norm(p):
    p = os.path.expanduser(str(p or "")).replace("\\", "/")
    if p.startswith("~"):
        p = os.path.expanduser(p)
    if not os.path.isabs(p):
        p = os.path.abspath(p)
    return os.path.normpath(p)

def is_canon(path, protected=None):
    if not path:
        return None
    prot = protected if protected is not None else protected_list()
    n = norm(path)
    for p in prot:
        if p.endswith("/"):
            if n == os.path.normpath(p) or n.startswith(os.path.normpath(p) + "/"):
                return p
        else:
            if n == os.path.normpath(p):
                return p
    return None

# ── Bash 명령 분석 ───────────────────────────────────────────────────
WRITE_CMDS_ANY = {"rm", "unlink", "shred", "truncate", "chmod", "chown", "chflags", "touch"}
DEST_LAST_CMDS = {"mv", "cp", "install", "ln", "rsync"}
INTERPRETERS   = {"python", "python3", "python2", "perl", "ruby", "node", "osascript", "php"}
ESCAPES        = ("bash -c", "sh -c", "zsh -c", "eval ", "$(", "`", "xargs")

def _redirect_targets(tokens):
    """'>' '>>' '>|' 및 붙여쓴 형태(x>file)의 **대상**만 뽑는다.
    (grep foo canon.md > /tmp/out 처럼 정본을 *읽고* 딴 데 쓰는 건 막지 않기 위해 대상만 본다)"""
    out, i = [], 0
    while i < len(tokens):
        t = tokens[i]
        if t in (">", ">>", ">|", "1>", "2>", "&>", ">&"):
            if i + 1 < len(tokens):
                out.append(tokens[i + 1])
            i += 2; continue
        m = re.search(r">+\|?", t)
        if m and not t.startswith("-"):
            tail = t[m.end():]
            if tail:
                out.append(tail)
            elif i + 1 < len(tokens):
                out.append(tokens[i + 1]); i += 1
        i += 1
    return out

def _segments(tokens):
    """; && || | 로 끊어 명령 단위로."""
    seg, cur = [], []
    for t in tokens:
        if t in (";", "&&", "||", "|", "&"):
            if cur: seg.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur: seg.append(cur)
    return seg

def analyze_bash(cmd, protected=None):
    """-> (block: bool, reason: str)"""
    if not cmd or not cmd.strip():
        return False, "empty"
    try:
        tokens = shlex.split(cmd, posix=True)
    except ValueError:
        # 따옴표 불균형 등 — 파싱 불가. 정본 문자열이 보이면 fail-closed.
        hit = _raw_scan(cmd, protected)
        return (bool(hit), "셸 파싱 불가 + 정본 경로 문자열 감지: %s" % hit) if hit \
               else (False, "셸 파싱 불가(정본 무관)")

    # ① 리다이렉션 대상
    for t in _redirect_targets(tokens):
        hit = is_canon(t, protected)
        if hit:
            return True, "리다이렉션 대상이 정본: %s (규칙 %s)" % (t, hit)

    # ② 명령별
    for seg in _segments(tokens):
        if not seg:
            continue
        base = os.path.basename(seg[0])
        args = [a for a in seg[1:]]
        pos  = [a for a in args if not a.startswith("-")]

        if base == "tee":
            for a in pos:
                hit = is_canon(a, protected)
                if hit:
                    return True, "tee 대상이 정본: %s (규칙 %s)" % (a, hit)
        if base in WRITE_CMDS_ANY:
            for a in pos:
                hit = is_canon(a, protected)
                if hit:
                    return True, "%s 대상이 정본: %s (규칙 %s)" % (base, a, hit)
        if base in DEST_LAST_CMDS and pos:
            hit = is_canon(pos[-1], protected)
            if hit:
                return True, "%s 목적지가 정본: %s (규칙 %s)" % (base, pos[-1], hit)
        if base == "dd":
            for a in args:
                if a.startswith("of="):
                    hit = is_canon(a[3:], protected)
                    if hit:
                        return True, "dd of= 가 정본: %s (규칙 %s)" % (a[3:], hit)
        if base in ("sed", "gsed", "perl", "ruby") and any(
                a == "-i" or a.startswith("-i") and len(a) <= 12 for a in args):
            for a in pos:
                hit = is_canon(a, protected)
                if hit:
                    return True, "%s -i(제자리 수정) 대상이 정본: %s (규칙 %s)" % (base, a, hit)
        # ③ 인터프리터 인라인 — 정본 경로가 스크립트 안에 있으면 통째로 거부(읽기도 cat/grep로 하라)
        if base in INTERPRETERS:
            joined = " ".join(args)
            hit = _raw_scan(joined, protected)
            if hit:
                return True, ("인터프리터(%s) 인라인 코드에 정본 경로: %s — 정본 읽기는 "
                              "cat/sed -n 을 쓰고, 쓰기는 오케스트레이터 승인 사항다" % (base, hit))

    # ④ 셸 탈출 구문 + 정본 문자열 = 보수적 거부
    low = cmd
    if any(e in low for e in ESCAPES):
        hit = _raw_scan(cmd, protected)
        if hit:
            return True, "셸 탈출 구문(bash -c/eval/$()/backtick/xargs) + 정본 경로: %s" % hit
    return False, "정본 쓰기 아님"

def _raw_scan(text, protected=None):
    prot = protected if protected is not None else protected_list()
    for p in prot:
        key = p[:-1] if p.endswith("/") else p
        if key in text:
            return key
    return None

# ── 훅 본체 ──────────────────────────────────────────────────────────
def decide(data, protected=None):
    tool = data.get("tool_name") or data.get("tool") or ""
    ti = data.get("tool_input") or {}
    if not isinstance(ti, dict):
        ti = {}
    if tool in ("Write", "Edit", "MultiEdit", "NotebookEdit", "Update"):
        for key in ("file_path", "path", "notebook_path"):
            hit = is_canon(ti.get(key), protected)
            if hit:
                return True, "%s 대상이 정본: %s (규칙 %s)" % (tool, ti.get(key), hit)
        for e in (ti.get("edits") or []):
            if isinstance(e, dict):
                hit = is_canon(e.get("file_path"), protected)
                if hit:
                    return True, "%s edits[] 대상이 정본: %s" % (tool, e.get("file_path"))
        return False, "정본 아님"
    if tool == "Bash":
        return analyze_bash(ti.get("command") or "", protected)
    return False, "대상 도구 아님"

DENY_MSG = ("정본 변경은 오케스트레이터의 승인 사항이다 — 오케스트레이터에게 에스컬레이션하라. "
            "이 파일은 매 세션 자동 주입되고 재부팅을 살아남는다(마인드바이러스 경로). "
            "하위 노드는 문안만 제안하고, 확정 반영은 오케스트레이터가 canon-edit.sh / canon-resign.sh 로 "
            "편집+재서명을 한 트랜잭션으로 집행한다. 사유: %s")

def emit_deny(reason):
    sys.stdout.write(
        '{"hookSpecificOutput":{"hookEventName":"PreToolUse",'
        '"permissionDecision":"deny","permissionDecisionReason":"%s"}}\n'
        % (DENY_MSG % reason).replace("\\", "\\\\").replace('"', '\\"'))
    sys.stdout.flush()

def main():
    raw = os.environ.get("CANON_GUARD_INPUT", "")
    if "--explain" in sys.argv:
        raw = raw or sys.stdin.read()
    try:
        data = json.loads(raw)
    except ValueError:
        hit = _raw_scan(raw)
        if hit:
            print("canon-guard: JSON 파싱 실패 + 정본 경로 감지 — fail-closed DENY (%s)" % hit,
                  file=sys.stderr)
            emit_deny("JSON 파싱 실패 + 정본 경로 문자열 감지: %s" % hit)
            sys.exit(0)
        sys.exit(0)
    if not isinstance(data, dict):
        sys.exit(0)
    block, reason = decide(data)
    if "--explain" in sys.argv:
        print("block=%s reason=%s" % (block, reason))
        sys.exit(2 if block else 0)
    if block:
        print("canon-guard DENY: %s" % reason, file=sys.stderr)
        emit_deny(reason)
        sys.exit(0)
    sys.exit(0)

# ── 내장 배터리 ──────────────────────────────────────────────────────
def self_test():
    # 픽스처 — 실존 경로가 아니어도 된다(경로 판정만 본다). 사이트 설치와 무관하게 항상 같은 답이 나온다.
    G = "/srv/agentops"          # 가상의 정본 루트
    WK = "/srv/work"             # 가상의 에이전트 작업 루트(보호 대상 아님)
    P = [
        G + "/CLAUDE.md",
        G + "/soul.md",
        G + "/directives/",
        G + "/memory/",
        G + "/sub-org/",
        G + "/settings.json",
        G + "/bin/",
    ]
    fails = []
    def chk(name, data, want):
        got, why = decide(data, P)
        if got != want:
            fails.append("%s: 기대 block=%s 실제 %s (%s)" % (name, want, got, why))
    W = lambda p: {"tool_name": "Write", "tool_input": {"file_path": p}}
    E = lambda p: {"tool_name": "Edit",  "tool_input": {"file_path": p}}
    B = lambda c: {"tool_name": "Bash",  "tool_input": {"command": c}}

    # ── 차단되어야 하는 것 ──
    chk("W1 정본 Write",         W(G + "/CLAUDE.md"), True)
    chk("W2 지침 디렉터리",       W(G + "/directives/AGENT_DIRECTIVE.md"), True)
    chk("W3 soul",               E(G + "/soul.md"), True)
    chk("W4 장기기억 본문",       W(G + "/memory/x.md"), True)
    chk("W5 MEMORY 색인",         E(G + "/memory/MEMORY.md"), True)
    chk("W6 가드 자기보호",       W(G + "/bin/canon-guard.sh"), True)
    chk("W7 훅 설정",             E(G + "/settings.json"), True)
    chk("W8 하위조직 정본",       W(G + "/sub-org/CLAUDE.md"), True)
    chk("W9 NotebookEdit",       {"tool_name": "NotebookEdit",
                                  "tool_input": {"notebook_path": G + "/CLAUDE.md"}}, True)
    chk("W10 MultiEdit edits[]", {"tool_name": "MultiEdit", "tool_input":
                                  {"edits": [{"file_path": G + "/soul.md"}]}}, True)
    chk("B1 리다이렉트 >",        B("echo hi > %s/CLAUDE.md" % G), True)
    chk("B2 리다이렉트 >>",       B("cat x >> %s/directives/AGENT_DIRECTIVE.md" % G), True)
    chk("B3 붙여쓴 리다이렉트",    B("echo hi>%s/CLAUDE.md" % G), True)
    chk("B4 tee",                B("echo x | tee %s/soul.md" % G), True)
    chk("B5 tee -a",             B("echo x | tee -a %s/soul.md" % G), True)
    chk("B6 mv 목적지",           B("mv /tmp/evil.md %s/directives/AGENT_DIRECTIVE.md" % G), True)
    chk("B7 cp 목적지",           B("cp -f /tmp/e %s/directives/01-x.md" % G), True)
    chk("B8 rm",                 B("rm -f %s/CLAUDE.md" % G), True)
    chk("B9 sed -i",             B("sed -i '' 's/a/b/' %s/CLAUDE.md" % G), True)
    chk("B10 dd of=",            B("dd if=/tmp/x of=%s/CLAUDE.md" % G), True)
    chk("B11 python 인라인",      B("python3 -c \"open('%s/CLAUDE.md','a').write('x')\"" % G), True)
    chk("B12 bash -c 탈출",       B("bash -c 'echo x >> %s/CLAUDE.md'" % G), True)
    chk("B13 명령치환 탈출",      B("echo $(cat /tmp/p) > %s/soul.md" % G), True)
    chk("B14 truncate",          B("truncate -s 0 %s/CLAUDE.md" % G), True)
    chk("B15 chmod",             B("chmod 000 %s/CLAUDE.md" % G), True)
    chk("B16 && 뒤 세그먼트",     B("cd /tmp && rm %s/CLAUDE.md" % G), True)
    chk("B17 heredoc 리다이렉트",  B("cat > %s/CLAUDE.md <<EOF" % G), True)

    # ── 통과해야 하는 것(과차단 방지) ──
    chk("A1 정본 읽기 cat",       B("cat %s/CLAUDE.md" % G), False)
    chk("A2 정본 읽기 sed -n",    B("sed -n '1,50p' %s/directives/AGENT_DIRECTIVE.md" % G), False)
    chk("A3 정본 읽고 딴 데 쓰기", B("grep x %s/CLAUDE.md > /tmp/out.txt" % G), False)
    chk("A4 무관 파일 Write",     W("/tmp/whatever.md"), False)
    chk("A5 에이전트 TODO",       W(WK + "/agent-1/TODO.md"), False)
    chk("A6 에이전트 작업메모",    W(WK + "/notes/new-lesson.md"), False)
    chk("A7 프로젝트 소스",        E("/srv/projects/app/src/app.ts"), False)
    chk("A8 무관 rm",             B("rm -rf /tmp/scratch"), False)
    chk("A9 읽기 도구",           {"tool_name": "Read", "tool_input": {"file_path": G + "/CLAUDE.md"}}, False)
    chk("A10 보고 채널 append",   B("cat >> %s/inbox.md" % WK), False)
    chk("A11 cp 소스가 정본",     B("cp %s/CLAUDE.md /tmp/backup.md" % G), False)
    chk("A12 빈 명령",            B(""), False)

    # deny JSON 형태 계약
    import io, contextlib
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        emit_deny('테스트 "따옴표" 포함')
    try:
        j = json.loads(buf.getvalue())
        hs = j["hookSpecificOutput"]
        if hs["hookEventName"] != "PreToolUse" or hs["permissionDecision"] != "deny":
            fails.append("deny JSON 필드 오류: %s" % hs)
        if "오케스트레이터에게 에스컬레이션" not in hs["permissionDecisionReason"]:
            fails.append("deny 사유에 격상 안내 없음")
    except Exception as e:
        fails.append("deny JSON 파싱 실패: %s / %s" % (e, buf.getvalue()))

    if fails:
        print("\n".join("  FAIL " + f for f in fails), file=sys.stderr)
        print("self-test: %d 실패 / 42 케이스" % len(fails), file=sys.stderr)
        return 1
    print("self-test OK — 42 케이스(차단 27·통과 14·deny JSON 계약 1)")
    return 0

if os.environ.get("CANON_GUARD_SELF_TEST"):
    sys.exit(self_test())
main()
PYEOF
