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

_py_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s' "$1"
  fi
}

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
export CANON_GUARD_HOME="$(_py_path "$HOME")"
export CANON_HOME="$(_py_path "$CANON_HOME")"
export CANON_BIN="$(_py_path "$CANON_BIN")"
export CANON_PROTECTED="$(_py_path "$CANON_PROTECTED")"
export CANON_INVENTORY="$(_py_path "$CANON_INVENTORY")"
exec "$PY" - "$@" <<'PYEOF'
import json, os, re, shlex, sys

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
    p = os.path.normpath(p).replace("\\", "/")
    if os.name == "nt":
        p = p.lower()
    return p

HOME = _canon(os.environ.get("CANON_GUARD_HOME") or os.path.expanduser("~"))

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
            out.append(_canon(v) + "/")
    return out

def _from_file(path):
    out = []
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if line:
                is_dir = line.replace("\\", "/").endswith("/")
                out.append(_canon(line.rstrip("/\\")) + ("/" if is_dir else ""))
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
            tier, sel = parts[0].strip(), _canon(parts[1].strip())
            if tier in ("watch", "watch-soft"):
                out.append(_canon(sel) + "/")
            elif any(c in sel for c in "*?["):
                out.append(_canon(os.path.dirname(sel)) + "/")
            else:
                out.append(_canon(sel))
    return out

_PROT_CACHE = None

def protected_list():
    global _PROT_CACHE
    if _PROT_CACHE is not None:
        return _PROT_CACHE
    out, srcs = [], []
    pf = _canon(os.environ.get("CANON_PROTECTED")) if os.environ.get("CANON_PROTECTED") else None
    inv = _canon(os.environ.get("CANON_INVENTORY")) if os.environ.get("CANON_INVENTORY") else None
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

_BASH_CONTEXT = None


def _shell_path(p, cwd, directory=False):
    p = str(p or "")
    p = re.sub(r"^\$(?:HOME\b|\{HOME\})", HOME, p)
    if p == "~" or p.startswith("~/"):
        p = HOME + p[1:]
    if directory and (any(c in p for c in ("$", "`")) or p.startswith("~")):
        return None
    absolute = p.startswith(("/", "\\")) or bool(re.match(r"^[A-Za-z]:[/\\]", p))
    if not absolute:
        if cwd is None:
            return None
        p = cwd.rstrip("/\\") + "/" + p
    return _canon(p)


def norm(p):
    if _BASH_CONTEXT is not None:
        return _shell_path(p, _BASH_CONTEXT[0])
    return _canon(p)

def is_canon(path, protected=None):
    if not path:
        return None
    prot = protected if protected is not None else protected_list()
    n = norm(path)
    if n is None:
        return "unresolved shell path/cwd; target could be canon" if prot else None
    for p in prot:
        if p.endswith("/"):
            base = _canon(p[:-1])
            if n == base or n.startswith(base + "/"):
                return p
        else:
            if n == _canon(p):
                return p
    return None

# ── Bash 명령 분석 ───────────────────────────────────────────────────
WRITE_CMDS_ANY = {"rm", "unlink", "shred", "truncate", "chmod", "chown", "chflags", "touch"}
DEST_LAST_CMDS = {"mv", "cp", "install", "ln", "rsync"}
def _interpreter(command):
    base = command.replace("\\", "/").rsplit("/", 1)[-1].lower()
    base = base.removesuffix(".exe")
    return bool(re.fullmatch(r"(?:py(?:thon)?|perl|ruby|node|osascript|php)(?:\d+(?:\.\d+)*)?", base))
ESCAPES        = ("bash -c", "sh -c", "zsh -c", "eval ", "$(", "`", "xargs")

# ★세그먼트 앞에 붙어 실제 명령을 가리는 것들. 이것을 벗기지 않으면
#   `LANG=C tee <정본>` · `env tee <정본>` · `command tee <정본>` 이 전부 통과한다
#   (분석기가 첫 토큰만 명령으로 보기 때문). 2026 공개 전 적대 검토에서 실측된 우회다.
_ASSIGN_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
WRAPPERS = {"env", "command", "builtin", "exec", "nohup", "nice", "ionice",
            "stdbuf", "time", "setsid", "doas", "sudo"}
# 값을 하나 더 먹는 옵션(래퍼별) — 그 값을 명령 이름으로 오인하지 않기 위해 함께 건너뛴다
WRAPPER_OPTS_WITH_ARG = {"-u", "--unset", "-n", "-c", "-C", "--chdir", "-o", "-e", "-i0", "-S", "--user"}

def strip_prefixes(seg, legacy=False):
    """환경변수 할당·래퍼를 벗겨 **실제 명령 토큰부터 시작하는** 세그먼트를 돌려준다.
    벗길 수 없으면 원본을 그대로 돌려준다(과차단보다 원형 유지가 안전한 지점은 없다 —
    이 층은 예방이므로, 애매하면 아래 ⑤ 잔여 스캔이 다시 본다)."""
    i, n = 0, len(seg)
    options = WRAPPER_OPTS_WITH_ARG - {"-C"} if legacy else WRAPPER_OPTS_WITH_ARG
    while i < n:
        t = seg[i]
        if _ASSIGN_RE.match(t):          # LANG=C · FOO=bar
            i += 1; continue
        if os.path.basename(t) in WRAPPERS:   # env · command · nice · sudo …
            i += 1
            while i < n:
                a = seg[i]
                if _ASSIGN_RE.match(a):       # env FOO=bar cmd
                    i += 1; continue
                if a.startswith("-"):
                    i += 2 if a in options else 1
                    continue
                break
            continue
        break
    return seg[i:] if i < n else seg

_FD_NUM = re.compile(r"\d+")
_FD_AMP = re.compile(r"&\d+")


def _redirect_targets(tokens):
    """'>' '>>' '>|' 및 붙여쓴 형태(x>file)의 **대상**만 뽑는다.
    (grep foo canon.md > /tmp/out 처럼 정본을 *읽고* 딴 데 쓰는 건 막지 않기 위해 대상만 본다)"""
    out, i = [], 0
    while i < len(tokens):
        t = tokens[i]
        if getattr(t, "literal_operator", False):
            i += 1
            continue
        if t in (">", ">>", ">|", "1>", "2>", "&>", ">&"):
            nxt = tokens[i + 1] if i + 1 < len(tokens) else None
            # ★fd 복제: `2> &1` 처럼 띄어 쓴 형태와 `>& 2`. 대상이 파일이 아니라 디스크립터다.
            if nxt is not None and (_FD_AMP.fullmatch(str(nxt))
                                    or (t == ">&" and _FD_NUM.fullmatch(str(nxt)))):
                i += 2; continue
            if nxt is not None:
                out.append(nxt)
            i += 2; continue
        m = re.search(r">+(?:\||&)?", t)
        if m and not t.startswith("-"):
            op = t[m.start():m.end()]
            tail = t[m.end():]
            # ★fd 복제(2>&1 · 1>&2 · >&2)의 꼬리는 **파일이 아니라 파일 디스크립터**다.
            #   파일명으로 잡으면 '1' 이 정본 디렉터리 기준으로 정규화돼 정상 명령을 오차단한다
            #   (2026-08-23 실측 3건). '&' 가 붙은 연산자 + **순수 숫자 꼬리**일 때만 건너뛴다 —
            #   `> 1`(파일명이 1)·`2>&1 > 정본`(뒤의 진짜 쓰기)은 그대로 대상으로 남는다.
            if "&" in op:
                if _FD_NUM.fullmatch(tail):
                    i += 1
                    continue
                # ★`2>&` + `1` 로 쪼개진 형태 — tail 이 비어 있으면 아래 '빈 tail' 분기가
                #   다음 토큰(디스크립터 번호)을 **파일 대상으로** 집어간다. 여기서 끊는다.
                if not tail and i + 1 < len(tokens) and _FD_NUM.fullmatch(str(tokens[i + 1])):
                    i += 2
                    continue
            if tail:
                out.append(tail)
            elif i + 1 < len(tokens):
                out.append(tokens[i + 1]); i += 1
        i += 1
    return out

def _clean_token(token):
    """PowerShell/Windows 토큰의 인용부호와 끝 구두점을 경로 비교 전에 제거한다."""
    return str(token or "").strip().strip("'\"").rstrip(",)]}")

_OPERATOR_CHARS = set("<>&|;")
_ESCAPED_OPERATOR_MARK = "\ue000"
_ESCAPED_OPERATOR_CODES = {"<": "L", ">": "G", "&": "A", "|": "P", ";": "S"}
_ESCAPED_OPERATOR_RESTORE = {
    _ESCAPED_OPERATOR_MARK + code: char
    for char, code in _ESCAPED_OPERATOR_CODES.items()
}

class _LiteralToken(str):
    def __new__(cls, value, literal_operator=False):
        obj = str.__new__(cls, value)
        obj.literal_operator = literal_operator
        return obj

def _operator_mark(ch):
    return _ESCAPED_OPERATOR_MARK + _ESCAPED_OPERATOR_CODES[ch]

def _restore_operator_marks(value):
    text = str(value or "")
    for mark, char in _ESCAPED_OPERATOR_RESTORE.items():
        text = text.replace(mark, char)
    return text

def _normalize_operator_runs(command):
    """Tokenization 전에 따옴표/escape를 존중하며 연산자 런을 공백으로 감싼다."""
    text = str(command or "")
    out, quote, i = [], None, 0
    while i < len(text):
        ch = text[i]
        if quote:
            if ch == "\\" and quote == '"' and i + 1 < len(text):
                if text[i + 1] in _OPERATOR_CHARS:
                    out.append(_operator_mark(text[i + 1]))
                else:
                    out.extend((ch, text[i + 1]))
                i += 2; continue
            out.append(_operator_mark(ch) if ch in _OPERATOR_CHARS else ch)
            if ch == quote:
                quote = None
            i += 1
            continue
        if ch in ("'", '"'):
            quote = ch; out.append(ch); i += 1; continue
        if ch == "\\" and i + 1 < len(text):
            if text[i + 1] in _OPERATOR_CHARS:
                out.append(_operator_mark(text[i + 1]))
            else:
                out.extend((ch, text[i + 1]))
            i += 2
            continue
        if ch not in _OPERATOR_CHARS:
            out.append(ch); i += 1; continue

        start = i
        while i < len(text) and text[i] in _OPERATOR_CHARS:
            i += 1
        fd_start = start
        digit = start - 1
        if digit >= 0 and text[digit].isdigit():
            fd_start = digit
            while fd_start > 0 and text[fd_start - 1].isdigit():
                fd_start -= 1
            if fd_start > 0 and not text[fd_start - 1].isspace():
                fd_start = start
        if fd_start < start:
            del out[-(start - fd_start):]
        if out and not out[-1].isspace():
            out.append(" ")
        out.extend(text[fd_start:i])
        if i < len(text) and not text[i].isspace():
            out.append(" ")
    return "".join(out)

def _command_tokens(cmd, preserve_backslashes=False):
    """POSIX shlex를 기본으로 하되, Windows 경로가 있으면 백슬래시를 보존한다."""
    try:
        normalized = _normalize_operator_runs(cmd)
        lexer = shlex.shlex(normalized, posix=not preserve_backslashes, punctuation_chars="")
        lexer.whitespace_split = True
        tokens = list(lexer)
    except ValueError:
        return []
    cooked = []
    for token in tokens:
        cleaned = _clean_token(token)
        literal = any(mark in cleaned for mark in _ESCAPED_OPERATOR_RESTORE)
        cooked.append(_LiteralToken(_restore_operator_marks(cleaned), literal))
    return cooked

def _path_hits(text, protected=None):
    """문자열 안의 토큰/인용 문자열을 _canon() 경유로 정본과 대조한다."""
    prot = protected if protected is not None else protected_list()
    raw = str(text or "")
    candidates = _command_tokens(raw, preserve_backslashes=True)
    candidates += re.findall(r"['\"]([^'\"]+)['\"]", raw)
    for candidate in candidates:
        candidate = _clean_token(candidate)
        hit = is_canon(candidate, prot)
        if hit:
            return hit, candidate
        if "=" in candidate and candidate.split("=", 1)[0].startswith("-"):
            value = candidate.split("=", 1)[1]
            hit = is_canon(value, prot)
            if hit:
                return hit, value
    return None, None

def _segments(tokens):
    """; && || | 로 끊어 명령 단위로."""
    seg, cur = [], []
    for t in tokens:
        if not getattr(t, "literal_operator", False) and t in (";", "&&", "||", "|", "&"):
            if cur: seg.append(cur)
            cur = []
        else:
            cur.append(t)
    if cur: seg.append(cur)
    return seg

def _analyze_bash_segment(cmd, protected=None, legacy=False):
    """-> (block: bool, reason: str)"""
    if not cmd or not cmd.strip():
        return False, "empty"
    try:
        # shlex(posix=True)는 C:\\...의 백슬래시를 이스케이프 문자로 먹는다.
        # Windows 경로가 보이는 경우에만 비-POSIX 토큰화를 사용해 기존 POSIX 결과를 보존한다.
        windows_path = bool(":\\" in cmd or "\\\\" in cmd)
        tokens = _command_tokens(cmd, preserve_backslashes=windows_path)
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
    for raw_seg in _segments(tokens):
        if not raw_seg:
            continue
        seg = strip_prefixes(raw_seg, legacy=legacy)        # ★LANG=C · env · command … 를 벗기고 본다
        if not seg:
            continue
        base = os.path.basename(seg[0])
        args = [a for a in seg[1:]]
        pos  = [a for a in args if not a.startswith("-")]

        for destination in _option_destinations(seg):
            resolved = norm(destination)
            if _canon_directory(resolved, protected if protected is not None else protected_list()):
                return True, "%s option write destination is canon: %s" % (base, destination)

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
        # ★제자리 수정 옵션은 짧은 표기와 긴 표기를 **함께** 본다.
        #   `sed --in-place` 만 검사에서 빠져 있던 것이 적대 검토에서 실측됐다.
        if base in ("sed", "gsed", "perl", "ruby") and any(
                a == "-i" or (a.startswith("-i") and len(a) <= 12)
                or a == "--in-place" or a.startswith("--in-place=") for a in args):
            for a in pos:
                hit = is_canon(a, protected)
                if hit:
                    return True, "%s -i(제자리 수정) 대상이 정본: %s (규칙 %s)" % (base, a, hit)
        # ③ 인터프리터 인라인 — 정본 경로가 스크립트 안에 있으면 통째로 거부(읽기도 cat/grep로 하라)
        if _interpreter(base):
            joined = " ".join(args)
            hit = _raw_scan(joined, protected)
            if hit:
                return True, ("인터프리터(%s) 인라인 코드에 정본 경로: %s — 정본 읽기는 "
                              "cat/sed -n 을 쓰고, 쓰기는 오케스트레이터 승인 사항다" % (base, hit))

    # ④ 셸 탈출 구문 + 정본 쓰기 대상 = 보수적 거부
    low = cmd
    if any(e in low for e in ESCAPES):
        hit = _escape_write_hit(cmd, protected)
        if hit:
            return True, "셸 탈출 구문(bash -c/eval/$()/backtick/xargs) + 정본 경로: %s" % hit
    return False, "정본 쓰기 아님"


def _git_message_argument(words):
    return bool(len(words) >= 3 and os.path.basename(words[0]) == "git" and words[1] == "commit"
                and (words[-1] in ("-m", "--message") or words[-1].startswith("--message=")))


def _git_stdin_message(words):
    if len(words) < 3 or os.path.basename(words[0]) != "git" or words[1] != "commit":
        return False
    return any(a in ("-F-", "--file=-") or
               (a in ("-F", "--file") and i+1 < len(words) and words[i+1] == "-")
               for i,a in enumerate(words))


def _heredoc_documents(command):
    # One lexical ownership pass. A body is never re-tokenized as another
    # header. Quoting/comments/substitutions belong to the surrounding shell;
    # the collected body belongs only to the command before its << operator.
    lines = command.splitlines(keepends=True)
    docs, pending, quote, substitutions = [], [], None, []
    for number,line in enumerate(lines):
        if pending:
            doc = pending[0]
            probe = line.lstrip("\t") if doc["tabs"] else line
            if probe.rstrip("\r\n") == doc["delimiter"]:
                doc["closed"], doc["end"] = True, number
                pending.pop(0)
            else:
                doc["body_lines"].append(number)
                doc["body"] += line
            continue
        i, start = 0, 0
        while i < len(line):
            ch = line[i]
            if ch == "\\" and quote != "'":
                i += 2; continue
            if quote != "'" and line[i:i+2] == "$(":
                parent = line[start:i].rstrip()
                if quote and parent.endswith(quote):
                    parent = parent[:-1]
                words = strip_prefixes(_command_tokens(parent))
                substitutions.append((quote, start, _git_message_argument(words)))
                quote, start = None, i+2
                i += 2; continue
            if not quote and ch == ")" and substitutions:
                quote, start, _ = substitutions.pop()
                i += 1; continue
            if quote:
                if ch == quote:
                    quote = None
            elif ch in "'\"":
                quote = ch
            elif ch == "#" and (i == 0 or line[i-1].isspace() or line[i-1] in ";|&()"):
                break
            elif ch in ";|&()":
                start = i+1
            elif line[i:i+2] == "<<" and line[i:i+3] != "<<<":
                match = re.match(r"<<(-?)\s*(?:(['\"])([^'\"\r\n]+)\2|([A-Za-z_][A-Za-z0-9_]*))", line[i:])
                if match:
                    header = line[start:i]
                    words = strip_prefixes(_command_tokens(header))
                    owner = os.path.basename(words[0]) if words else ""
                    inherited_argument = bool(substitutions and all(item[2] for item in substitutions))
                    # Only these two git-message consumers qualify. Terminal
                    # cat output and every file-redirect cat keep live analysis.
                    git_data = ((owner == "cat" and inherited_argument) or
                                (_git_stdin_message(words) and all(item[2] for item in substitutions)))
                    git_data = git_data and not _redirect_targets(_command_tokens(header))
                    doc = dict(owner=owner, header=header, quoted=bool(match.group(2)),
                               delimiter=match.group(3) if match.group(2) else match.group(4),
                               tabs=bool(match.group(1)), git_data=git_data, line=number,
                               tail=line[i+match.end():], body="", body_lines=[], closed=False, end=number)
                    docs.append(doc); pending.append(doc)
                    i += match.end(); continue
            i += 1
    return docs


def _without_literal_heredocs(command, documents=None):
    docs = _heredoc_documents(command) if documents is None else documents
    lines = command.splitlines(keepends=True)
    # Consumer checks inspect syntax outside all body data, not text such as
    # '<(' or '|' quoted inside a commit message.
    syntax = list(lines)
    for doc in docs:
        for i in doc["body_lines"]:
            syntax[i] = "\n" if lines[i].endswith("\n") else ""
    process_substitution = bool(re.search(r"[<>]\(", "".join(syntax)))
    out = list(lines)
    for doc in docs:
        following = "".join(syntax[doc["end"]+1:]).lstrip()
        connected_pipe = "|" in doc["tail"] or bool(re.match(r"^[)}\s]*\|", following))
        if (doc["quoted"] and doc["closed"] and doc["git_data"] and not process_substitution
                and not connected_pipe and not lines[doc["line"]].rstrip("\r\n").endswith("\\")):
            for i in doc["body_lines"]:
                out[i] = "\n" if lines[i].endswith("\n") else ""
    return "".join(out)


def _shell_parts(cmd):
    # Split only syntax outside quotes/escapes; preserve each segment verbatim
    # for the established write-target analyzer. Parentheses have scope.
    parts, buf, quote, i, start = [], [], None, 0, 0
    while i < len(cmd):
        c = cmd[i]
        if c == "\\" and quote != "'" and i + 1 < len(cmd):
            buf.extend(cmd[i:i+2]); i += 2; continue
        if quote:
            buf.append(c)
            if c == quote:
                quote = None
            i += 1; continue
        if c in "'\"":
            quote = c; buf.append(c); i += 1; continue
        if c in "<>" or (c == "&" and cmd[i:i+2] == "&>"):
            start = i
            while i < len(cmd) and cmd[i] in "<>&|":
                i += 1
            buf.extend(cmd[start:i]); continue
        if c in ";|&()\n":
            # Descriptor duplication is not command control flow.
            if c == "&" and buf and buf[-1] in "><":
                buf.append(c); i += 1; continue
            op = c
            if c in "&|" and cmd[i:i+2] == c*2:
                op = c*2; i += 1
            parts.append(("".join(buf), op, cmd.count("\n", 0, start))); buf = []
            start = i+1
        else:
            buf.append(c)
        i += 1
    parts.append(("".join(buf), "", cmd.count("\n", 0, start)))
    return parts


def _directory_args(tokens):
    args, i = [], 1
    while i < len(tokens):
        t = tokens[i]
        if not getattr(t, "literal_operator", False) and re.match(r"^(?:\d*[<>]|&>)", t):
            # _command_tokens separates active operators from their operands,
            # including fd duplication (2>&1). Quoted/escaped operators survive.
            i += 2 if re.fullmatch(r"(?:\d*[<>]+[|&]?|&>)", t) else 1
            continue
        if t not in ("--", "-P", "-L", "-e", "-@"):
            args.append(t)
        i += 1
    return args


def _canon_directory(d, protected):
    if d is None:
        return True
    value = _canon(d)
    return any((value == _canon(p.rstrip('/')) or value.startswith(_canon(p.rstrip('/')) + '/'))
               if p.endswith('/') else os.path.dirname(_canon(p)).replace('\\', '/') == value
               for p in protected)


def _env_wrapped(tokens, dirs):
    i = 0
    while i < len(tokens) and _ASSIGN_RE.match(tokens[i]):
        i += 1
    if i == len(tokens) or os.path.basename(tokens[i]) != "env":
        return None
    i += 1
    result = set(dirs)
    while i < len(tokens):
        arg = tokens[i]
        if arg in ("-C", "--chdir"):
            value = tokens[i+1] if i+1 < len(tokens) else "$UNRESOLVED"
            result = {_shell_path(value, d, directory=True) for d in result}
            i += 2
        elif arg.startswith("--chdir="):
            result = {_shell_path(arg.split('=',1)[1], d, directory=True) for d in result}
            i += 1
        elif arg == "--":
            i += 1; break
        elif _ASSIGN_RE.match(arg):
            i += 1
        elif arg.startswith("-"):
            i += 2 if arg in WRAPPER_OPTS_WITH_ARG else 1
        else:
            break
    return tokens[i:], result


def _join_shell_tokens(tokens):
    return " ".join(str(t) if not getattr(t, 'literal_operator', False) and
                    re.fullmatch(r"(?:\d*[<>]+[|&]?|&>)", t) else shlex.quote(str(t)) for t in tokens)


def _copy_operands(seg):
    """One option parser for both copy write locations and staged-file updates."""
    base, args = os.path.basename(seg[0]), seg[1:]
    grouped_flags = {"cp": "abdfHiklLnPpRrsTuvx", "mv": "bfinTuv", "install": "bcdDpprsTvC"}[base]
    value_flags = "Smog" if base == "install" else "S"
    targets, positional, i = [], [], 0
    while i < len(args):
        arg = args[i]
        if arg == "--":
            positional.extend(args[i+1:]); break
        if arg in ("-t", "--target-directory"):
            if i+1 < len(args):targets.append(args[i+1])
            i += 2; continue
        if arg.startswith("--target-directory="):
            targets.append(arg.split("=",1)[1])
        elif arg in ("--suffix", "--mode", "--owner", "--group", "--strip-program"):
            i += 2; continue
        elif arg.startswith("--"):
            pass
        elif arg.startswith("-") and len(arg) > 1:
            short = arg[1:]
            for index, flag in enumerate(short):
                if flag == "t":
                    value = short[index+1:] or (args[i+1] if i+1 < len(args) else None)
                    if value is not None:targets.append(value)
                    if not short[index+1:]:i += 1
                    break
                if flag in value_flags:
                    if not short[index+1:]:i += 1
                    break
                if flag not in grouped_flags:
                    break
        else:
            positional.append(arg)
        i += 1
    return targets, positional


def _option_destinations(seg):
    """Directory options which select a write location, preserving read commands."""
    base = os.path.basename(seg[0]) if seg else ""
    args = seg[1:]
    if base in ("cp", "mv", "install"):
        return _copy_operands(seg)[0]
    if base not in ("git", "tar"):
        return []
    dirs, remainder, i = [], [], 0
    while i < len(args):
        arg = args[i]
        if arg in ("-C", "--directory") and i+1 < len(args):
            dirs.append(args[i+1]); i += 2; continue
        if arg.startswith("-C") and len(arg) > 2:
            dirs.append(arg[2:])
        elif arg.startswith("--directory="):
            dirs.append(arg.split("=",1)[1])
        elif base == "git" and arg in ("-c", "--config-env", "--git-dir", "--work-tree", "--namespace", "--super-prefix"):
            i += 2; continue
        elif base == "git" and arg.startswith("-"):
            pass  # Global Boolean flags and --key=value options precede the verb.
        else:
            if base == "git":
                remainder = args[i:]
                break
            remainder.append(arg)
        i += 1
    if base == "git":
        writes = {"checkout", "reset", "restore", "switch", "clean", "merge", "rebase",
                  "cherry-pick", "revert", "pull", "fetch", "clone", "init", "apply", "am",
                  "commit", "add", "rm", "mv", "update-index"}
        if not remainder or remainder[0] not in writes:
            return []
        options = remainder[1:remainder.index("--")] if "--" in remainder else remainder[1:]
        if "--dry-run" in options or (remainder[0] in ("add", "clean", "mv", "rm") and "-n" in options):
            return []
        if (remainder[0] == "apply" and "--apply" not in options
                and any(a in ("--stat", "--numstat", "--summary", "--check") for a in options)):
            return []
        # Repeated git -C values are relative to the preceding -C directory.
        target = ""
        for value in dirs:
            target = value if not target else _shell_path(value, norm(target), directory=True)
        return [target] if dirs else []
    extracting = any(a == "--extract" or (a.startswith("-") and not a.startswith("--") and "x" in a[1:])
                     for a in remainder) or bool(remainder and not remainder[0].startswith("-") and "x" in remainder[0])
    stdout = any(a == "--to-stdout" or (a.startswith("-") and not a.startswith("--") and "O" in a[1:])
                 for a in remainder) or bool(remainder and not remainder[0].startswith("-") and "O" in remainder[0])
    target = ""
    for value in dirs:
        target = value if not target else _shell_path(value, norm(target), directory=True)
    return [target] if extracting and dirs and not stdout else []


def _script_operand(seg):
    """Select a script only after consuming Python options with operands."""
    args, i = seg[1:], 0
    base = seg[0].replace("\\", "/").rsplit("/", 1)[-1].lower().removesuffix(".exe")
    python = bool(re.fullmatch(r"py(?:thon)?(?:\d+(?:\.\d+)*)?", base))
    while i < len(args):
        arg = args[i]
        if arg == "--":
            return args[i+1] if i+1 < len(args) else None
        if (arg == "-" or arg in ("-c", "-e", "--eval") or (arg == "-E" and not python)
                or (python and arg.startswith(("-c", "-m")))):
            return None
        if python and arg in ("-W", "-X", "--check-hash-based-pycs"):
            i += 2; continue
        if not arg.startswith("-"):
            return arg
        i += 1
    return None


def _invalidate_staged(seg, tokens, dirs, staged):
    """Later filesystem changes make the earlier cat body obsolete evidence."""
    if not seg:
        return
    base, args = os.path.basename(seg[0]), seg[1:]
    # Appends retain the known earlier body even if the extra content is unknown.
    overwrite_tokens = [_LiteralToken(str(t), True) if not getattr(t, 'literal_operator', False)
                        and re.match(r"^(?:\d*|&)>>", str(t)) else t for t in tokens]
    paths = list(_redirect_targets(overwrite_tokens))
    positional = [a for a in args if not a.startswith("-")]
    if base in ("rm", "unlink", "truncate") or (base == "tee" and not any(a in ("-a", "--append") for a in args)):
        paths.extend(positional)
    elif base in ("cp", "mv", "install"):
        targets, operands = _copy_operands(seg)
        sources = operands if targets else operands[:-1]
        destinations = targets or operands[-1:]
        for destination in destinations:
            if not targets:paths.append(destination)
            for source in sources:
                paths.append(destination.rstrip('/\\') + '/' + source.replace('\\','/').rstrip('/').rsplit('/',1)[-1])
        if base == "mv":paths.extend(sources)
    for path in paths:
        for d in dirs:
            staged.pop(_shell_path(path, d), None)


def analyze_bash(cmd, protected=None, start_dirs=None, depth=0, staged_scripts=None):
    global _BASH_CONTEXT
    original = _BASH_CONTEXT
    prot = protected if protected is not None else protected_list()
    dirs, previous, stack, directory_stack = (set(start_dirs) if start_dirs is not None else {_canon(os.getcwd())}), set(), [], []
    staged = staged_scripts if staged_scripts is not None else {}
    consumed_documents = set()
    try:
        raw_command = str(cmd or "")
        documents = _heredoc_documents(raw_command)
        document_data_lines = {line for doc in documents for line in doc["body_lines"]}
        document_data_lines.update(doc["end"] for doc in documents if doc["closed"])
        command = _without_literal_heredocs(raw_command, documents)
        # Additive by construction. With no cwd override this is the installed
        # whole-command analyzer, including cross-segment escape/path checks.
        # The only permitted preprocessing blanks proven-inert cat body data.
        _BASH_CONTEXT = None
        blocked, reason = _analyze_bash_segment(command, prot, legacy=True)
        if blocked:
            return True, "whole-command: " + reason
        for document in documents:
            if _interpreter(document["owner"]):
                hit = _raw_scan(document["body"], prot)
                if hit:
                    return True, "interpreter heredoc body contains canon path: %s" % hit
        if depth >= 8:
            return (True, "nested shell depth with write marker") if _has_write_marker(command) else (False, "nested read")
        for segment, op, line_number in _shell_parts(command):
            tokens = _command_tokens(segment)
            tracking = line_number not in document_data_lines
            wrapped = _env_wrapped(tokens, dirs)
            if wrapped is not None:
                inner, env_dirs = wrapped
                blocked, reason = analyze_bash(_join_shell_tokens(inner), prot, env_dirs, depth+1,
                                               staged if tracking else {})
                if blocked:
                    return True, "env directory: " + reason
                segment, tokens = "", []  # still restore a closing subshell below
            seg = strip_prefixes(tokens) if tokens else []
            if seg and os.path.basename(seg[0]) in ("cd", "pushd", "popd"):
                # Redirections on cd itself run before the directory change.
                for d in dirs:
                    _BASH_CONTEXT = (d,)
                    for target in _redirect_targets(tokens):
                        hit = is_canon(target, protected)
                        if hit:
                            return True, "directory-command redirect targets canon: %s" % hit
                base = os.path.basename(seg[0])
                args = _directory_args(seg)
                if base == "popd":
                    targets = directory_stack.pop() if directory_stack else {None}
                elif not args:
                    targets = {HOME} if base == "cd" else (directory_stack.pop() if directory_stack else {None})
                elif len(args) != 1:
                    targets = {None}
                elif args[0] == "-":
                    targets = previous or {None}
                else:
                    targets = {_shell_path(args[0], d, directory=True) for d in dirs}
                old = dirs
                if base == "pushd":
                    directory_stack.append(set(old))
                # && reaches the next command only on successful cd. With ;
                # or || retain both branches (failed cd cannot clear protection).
                dirs = targets if op == "&&" else dirs | targets
                previous = old
            elif segment.strip():
                base = os.path.basename(seg[0]) if seg else ""
                if tracking:
                    _invalidate_staged(seg, tokens, dirs, staged)
                if tracking and base == "cat" and "<<" in segment:
                    targets = _redirect_targets(_command_tokens(segment))
                    for doc_index, document in enumerate(documents):
                        if (doc_index in consumed_documents or document["line"] != line_number
                                or document["owner"] != "cat" or not document["closed"]):
                            continue
                        owned_targets = _redirect_targets(_command_tokens(document["header"] + document["tail"]))
                        for target in targets:
                            if target in owned_targets:
                                for d in dirs:
                                    key = _shell_path(target, d)
                                    append_targets = []
                                    for index, token in enumerate(tokens):
                                        if not getattr(token, 'literal_operator', False) and re.match(r"^(?:\d*|&)>>", str(token)):
                                            append_targets.extend(_redirect_targets(tokens[index:index+2]))
                                    staged[key] = (staged.get(key, "") if target in append_targets else "") + document["body"]
                                consumed_documents.add(doc_index)
                if tracking and (base in ("bash", "sh", "zsh", "source", ".") or _interpreter(base)):
                    args = seg[1:]
                    script = _script_operand(seg)
                    if script:
                        for d in dirs:
                            body = staged.get(_shell_path(script, d))
                            if body is None:
                                continue
                            if _interpreter(base):
                                hit = _raw_scan(body, prot)
                                if hit or _canon_directory(d, prot):
                                    return True, "staged interpreter script touches canon: %s" % (hit or d)
                            else:
                                hit = _raw_scan(body, prot)
                                if hit and _has_write_marker(body):
                                    return True, "executed staged shell body has canon write: %s" % hit
                                blocked, reason = analyze_bash(body, prot, {d}, depth+1)
                                if blocked:
                                    return True, "executed staged shell script: " + reason
                if base in ("bash", "sh", "zsh"):
                    for idx, arg in enumerate(seg[1:],1):
                        if arg.startswith('-') and 'c' in arg[1:] and idx+1 < len(seg):
                            blocked, reason = analyze_bash(str(seg[idx+1]), prot, dirs, depth+1,
                                                           staged if tracking else {})
                            if blocked:
                                return True, "nested shell: " + reason
                            break
                for d in dirs:
                    _BASH_CONTEXT = (d,)
                    body = command if "<<" in segment else segment
                    interpreter_code = _interpreter(base) and (
                        "<<" in segment or any(a in ("-c", "-e", "-E", "--eval") for a in seg[1:]))
                    if interpreter_code and _canon_directory(d, prot):
                        return True, "interpreter code in canon or unresolved directory (reads use cat/sed)"
                    if base in {"eval", "xargs"} and _canon_directory(d, prot) and _has_write_marker(body):
                        return True, "eval/xargs write in canon or unresolved directory"
                    blocked, reason = _analyze_bash_segment(segment, protected)
                    if blocked:
                        return True, reason
            if op == "(":
                stack.append((set(dirs), set(previous), [set(d) for d in directory_stack]))
            elif op == ")" and stack:
                dirs, previous, directory_stack = stack.pop()
        return False, "no canon write in effective shell directories"
    finally:
        _BASH_CONTEXT = original


# ── PowerShell 명령의 예방층 분석 ─────────────────────────────────────
# PowerShell은 별칭과 매개변수 표기가 넓으므로 전면 파싱하지 않는다.
PWSH_READ_CMDS = {
    "get-content", "gc", "cat", "type", "select-string", "sls", "test-path",
    "get-item", "gi", "get-childitem", "gci", "ls", "dir",
}
PWSH_WRITE_CMDS = {
    "set-content", "sc", "add-content", "ac", "clear-content", "clc",
    "out-file", "tee-object", "tee", "new-item", "ni", "remove-item", "ri",
    "del", "erase", "rd", "rmdir", "rm", "rename-item", "ren", "rni",
    "move-item", "mi", "move", "mov", "mv", "copy-item", "cpi", "ci", "copy", "cp",
    "set-itemproperty", "sp", "icacls",
}
PWSH_PATH_OPTIONS = {"-path", "-literalpath", "-filepath", "-destination", "-target"}

def _pwsh_base(segment):
    if not segment:
        return ""
    base = _clean_token(segment[0]).lower()
    if base == "&" and len(segment) > 1:
        base = _clean_token(segment[1]).lower()
    base = os.path.basename(base)
    return base[:-4] if base.endswith(".exe") else base

def _pwsh_option_values(args, options):
    out = []
    i = 0
    while i < len(args):
        arg = _clean_token(args[i])
        low = arg.lower()
        for option in options:
            if low == option and i + 1 < len(args):
                out.append(_clean_token(args[i + 1])); i += 1; break
            if low.startswith(option + "="):
                out.append(_clean_token(arg[len(option) + 1:])); break
        i += 1
    return out

def _pwsh_positional(args):
    return [a for a in args if a and not a.startswith("-") and a not in (";", "|", "&&", "||", "&")]

def analyze_powershell(cmd, protected=None, allow_escape=True):
    """PowerShell 예방층: 정본 쓰기 대상만 차단하고 읽기→비정본 쓰기는 통과한다."""
    if not cmd or not cmd.strip():
        return False, "empty"
    prot = protected if protected is not None else protected_list()
    windows_path = bool(re.search(r"(?:[A-Za-z]:[\\/]|/)", cmd))
    tokens = _command_tokens(cmd, preserve_backslashes=windows_path)
    if not tokens:
        tokens = [_clean_token(x) for x in re.split(r"\s+", cmd.strip())]

    for target in _redirect_targets(tokens):
        hit = is_canon(_clean_token(target), prot)
        if hit:
            return True, "PowerShell 리다이렉션 대상이 정본: %s (규칙 %s)" % (target, hit)

    for raw_seg in _segments(tokens):
        if not raw_seg:
            continue
        base = _pwsh_base(raw_seg)
        args = raw_seg[1:] if not (raw_seg and raw_seg[0] == "&") else raw_seg[2:]
        low_seg = " ".join(raw_seg).lower()

        # [IO.File]::WriteAllText/WriteAllLines/AppendAllText/Delete 계열.
        if re.search(r"(?:\[\s*(?:system\.)?io\.file\s*\]|(?:system\.)?io\.file)\s*::\s*"
                     r"(?:writealltext|writealllines|appendalltext|delete)\b", low_seg, re.I):
            quoted = re.findall(r"['\"]([^'\"]+)['\"]", " ".join(raw_seg))
            for value in quoted:
                hit = is_canon(value, prot)
                if hit:
                    return True, "PowerShell IO.File 쓰기 대상이 정본: %s (규칙 %s)" % (value, hit)

        if base not in PWSH_WRITE_CMDS:
            continue

        if base in ("copy-item", "cpi", "ci", "copy", "cp", "move-item", "mi", "move", "mov", "mv"):
            named_dest = _pwsh_option_values(args, {"-destination", "-d"})
            positional = _pwsh_positional(args)
            destinations = named_dest or (positional[1:2] if len(positional) > 1 else [])
            for value in destinations:
                hit = is_canon(value, prot)
                if hit:
                    return True, "PowerShell %s 목적지가 정본: %s (규칙 %s)" % (base, value, hit)
            continue

        targets = _pwsh_option_values(args, PWSH_PATH_OPTIONS)
        if not targets:
            targets = _pwsh_positional(args)
        for value in targets:
            hit = is_canon(value, prot)
            if hit:
                return True, "PowerShell %s 쓰기 대상이 정본: %s (규칙 %s)" % (base, value, hit)

    if allow_escape and _has_powershell_escape(cmd):
        hit = _escape_write_hit(
            cmd, prot,
            nested_analyzer=lambda inner, p: analyze_powershell(inner, p, allow_escape=False),
        )
        if hit:
            return True, "PowerShell 탈출 구문 + 정본 쓰기: %s" % hit
    return False, "정본 쓰기 아님"

def _raw_path_candidates(text):
    """원문 속 POSIX/Windows 절대경로 후보를 뽑는다(경로 비교는 _canon에 위임)."""
    raw = str(text or "")
    # 따옴표 안의 명령 전체도 훑되, 아래의 절대경로 정규식으로 실제 경로만 다시 추린다.
    chunks = [raw] + re.findall(r"['\"]([^'\"]+)['\"]", raw)
    pattern = re.compile(r"(?:[A-Za-z]:[\\/]|/[A-Za-z](?:[\\/])|/)[^\s'\"`;&|<>(),]+")
    for chunk in chunks:
        for match in pattern.finditer(chunk):
            candidate = match.group(0).rstrip(".])}")
            if candidate:
                yield candidate

def _raw_scan(text, protected=None):
    """표기(C:/, c:/, /c/)가 달라도 _canon() 결과로 정본을 찾는다."""
    prot = protected if protected is not None else protected_list()
    for candidate in _raw_path_candidates(text):
        hit = is_canon(candidate, prot)
        if hit:
            return hit[:-1] if hit.endswith("/") else hit
    return None

def _has_powershell_escape(text):
    low = str(text or "").lower()
    if re.search(r"(?<![\w-])(?:iex|invoke-expression|invoke-command|invokecommand|invokescript|start-process|start-job|start-threadjob|powershell|pwsh|icm|get-command|gcm|saps)(?![\w-])", low):
        return True
    if re.search(r"(?<![\w-])-(?:encodedcommand|command)(?![\w-])", low):
        return True
    if re.search(r"(?m)^\s*&\s*(?:\{|['\"])", text) or re.search(r"(?m)^\s*\.\s*\{", text):
        return True
    if re.search(r"&\s*\{", text):
        return True
    if re.search(r"&\s*\(", text):
        return True
    return False

def _raw_redirect_scan(text, protected=None):
    prot = protected if protected is not None else protected_list()
    for match in re.finditer(r">+(?:\||&)?\s*['\"]?([^'\"\s;&|<>(),]+)", str(text or "")):
        candidate = match.group(1).rstrip(".])}")
        hit = is_canon(candidate, prot)
        if hit:
            return hit[:-1] if hit.endswith("/") else hit
    return None

def _has_write_marker(text):
    low = str(text or "").lower()
    words = (
        "set-content", "sc", "add-content", "ac", "clear-content", "clc",
        "out-file", "tee-object", "tee", "new-item", "ni", "remove-item", "ri",
        "del", "erase", "rd", "rmdir", "rm", "rename-item", "ren", "rni",
        "move-item", "mi", "move", "mov", "mv", "copy-item", "cpi", "ci",
        "copy", "cp", "set-itemproperty", "sp", "icacls", "truncate", "chmod",
        "chown", "chflags", "unlink", "shred", "touch",
    )
    if any(re.search(r"(?<![\w-])%s(?![\w-])" % re.escape(word), low) for word in words):
        return True
    if re.search(r"\b(?:sed|gsed|perl|ruby)\b[^\n;|]*?(?:-i\b|--in-place\b)", low):
        return True
    if re.search(r"\b(?:dd\b[^\n;|]*\bof=|open\s*\([^\n]*['\"][wa])", low):
        return True
    return False

def _escape_write_hit(text, protected=None, nested_analyzer=None):
    """탈출 토큰은 정본 쓰기 대상일 때만 차단한다."""
    raw = str(text or "")
    prot = protected if protected is not None else protected_list()
    if nested_analyzer:
        nested = re.findall(r"['\"]([^'\"]+)['\"]", raw)
        nested += re.findall(r"\{([^{}]+)\}", raw, re.S)
        for inner in nested:
            blocked, reason = nested_analyzer(inner, prot)
            if blocked:
                return reason
    hit = _raw_redirect_scan(raw, prot)
    if hit:
        return hit
    if _has_write_marker(raw) or re.search(r"(?i)-encodedcommand\b", raw):
        return _raw_scan(raw, prot)
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
    if tool == "PowerShell":
        return analyze_powershell(ti.get("command") or "", protected)
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
    WIN = r"C:\Users\이상윤\.cys\pack\soul.md"
    MSYS = r"/c/Users/이상윤/.cys/pack/soul.md"
    P.append(WIN)
    P.append(MSYS)
    BB_AMP = G + "/a&b/x.md"
    BB_SEMI = G + "/c;d/y.md"
    BB_PIPE = G + "/pipe|x.md"
    BB_GT = G + "/gt>x.md"
    WIN_AMP = r"C:\Users\이상윤\.cys\pack\a&b\x.md"
    P.extend((BB_AMP, BB_SEMI, BB_PIPE, BB_GT, WIN_AMP))
    fails = []
    results = {}
    def chk(name, data, want, prot=None):
        # prot 를 주면 그 목록으로 판정한다 — cwd 축(EE군)이 임시 정본 루트를 쓰기 위해서다.
        got, why = decide(data, prot if prot is not None else P)
        results[name.split(" ", 1)[0]] = got
        if got != want:
            fails.append("%s: 기대 block=%s 실제 %s (%s)" % (name, want, got, why))
    W = lambda p: {"tool_name": "Write", "tool_input": {"file_path": p}}
    E = lambda p: {"tool_name": "Edit",  "tool_input": {"file_path": p}}
    B = lambda c: {"tool_name": "Bash",  "tool_input": {"command": c}}
    PW = lambda c: {"tool_name": "PowerShell", "tool_input": {"command": c}}

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
    # ★B18~B23 = 공개 전 적대 검토에서 실측된 우회(첫 토큰만 보던 결함) — 이제 막힌다
    chk("B18 환경변수 접두 tee",   B("LANG=C tee %s/CLAUDE.md" % G), True)
    chk("B19 환경변수 접두 rm",    B("LANG=C rm %s/CLAUDE.md" % G), True)
    chk("B20 env 래퍼",           B("/usr/bin/env tee %s/CLAUDE.md" % G), True)
    chk("B21 command 래퍼",       B("command tee %s/CLAUDE.md" % G), True)
    chk("B22 sed 긴 옵션",         B("sed --in-place s/a/b/ %s/CLAUDE.md" % G), True)
    chk("B23 접두+래퍼 중첩",      B("LANG=C /usr/bin/env FOO=1 tee -a %s/soul.md" % G), True)

    # ── PowerShell P군: 정본 쓰기 대상은 모두 차단 ──
    chk("P1 Set-Content -Path", PW("Set-Content -Path %s/soul.md -Value x" % G), True)
    chk("P2 sc 별칭",           PW("sc %s/soul.md x" % G), True)
    chk("P3 Out-File -FilePath",PW("Out-File -FilePath %s/soul.md" % G), True)
    chk("P4 PowerShell >",      PW('"x" > %s/soul.md' % G), True)
    chk("P5 Remove-Item",       PW("Remove-Item %s/soul.md" % G), True)
    chk("P6 ri 별칭",           PW("ri %s/soul.md" % G), True)
    chk("P7 del 별칭",          PW("del %s/soul.md" % G), True)
    chk("P8 New-Item -Force",   PW("New-Item -Force -Path %s/soul.md" % G), True)
    chk("P9 Copy-Item 목적지",  PW("Copy-Item evil.md -Destination %s/soul.md" % G), True)
    chk("P10 IO.File",          PW(r'[IO.File]::WriteAllText("%s/soul.md","x")' % G), True)
    chk("P11 Bash 백슬래시",     B(r"rm C:\Users\이상윤\.cys\pack\soul.md"), True)

    # ── PowerShell Q군: 음성 대조군은 모두 통과 ──
    chk("Q1 Get-Content",        PW("Get-Content %s/CLAUDE.md" % G), False)
    chk("Q2 Select-String",      PW("Select-String x %s/CLAUDE.md" % G), False)
    chk("Q3 read | Out-File",    PW("Get-Content %s/CLAUDE.md | Out-File %s/out.txt" % (G, WK)), False)
    chk("Q4 작업 Set-Content",   PW("Set-Content %s/notes.md -Value x" % WK), False)
    chk("Q5 작업 Remove-Item",   PW("Remove-Item %s/scratch -Recurse" % WK), False)
    chk("Q6 Copy-Item 소스",     PW("Copy-Item %s/CLAUDE.md %s/backup.md" % (G, WK)), False)

    # ── 탈출 구문 R군: 실행-은닉 뒤의 정본 쓰기도 차단 ──
    chk("R1 PS 선두 &",          PW("& { Set-Content -Path '%s/soul.md' -Value evil }" % G), True)
    chk("R2 iex",                PW("iex \"Set-Content -Path '%s/soul.md' -Value evil\"" % G), True)
    chk("R3 Invoke-Command",     PW("Invoke-Command -ScriptBlock { Set-Content -Path '%s/soul.md' -Value evil }" % G), True)
    chk("R4 Start-Process",      PW("Start-Process powershell -ArgumentList \"Set-Content -Path '%s/soul.md' -Value evil\"" % G), True)
    chk("R5 Bash eval Windows",  B('eval "echo evil > %s"' % WIN), True)
    chk("R6 Bash sh msys",       B('sh -c "echo evil > %s"' % MSYS), True)
    chk("R7 PS icm",             PW("icm -ScriptBlock { Set-Content -Path '%s/soul.md' -Value evil }" % G), True)
    chk("R8 PS Start-Job",       PW("Start-Job -ScriptBlock { Set-Content -Path '%s/soul.md' -Value evil }" % G), True)
    chk("R9 PS &(gcm sc)",       PW("&(gcm sc) %s/soul.md evil" % G), True)
    chk("R10 PS InvokeScript",   PW("$ExecutionContext.InvokeCommand.InvokeScript(\"Set-Content -Path '%s/soul.md' -Value evil\")" % G), True)
    chk("R11 PS Start-ThreadJob",PW("Start-ThreadJob -ScriptBlock { Set-Content -Path '%s/soul.md' -Value evil }" % G), True)
    chk("R12 PS saps",           PW("saps -ArgumentList \"Set-Content -Path '%s/soul.md' -Value evil\"" % G), True)

    # ── 탈출 구문 S군: 읽기 또는 작업 파일 쓰기는 통과 ──
    chk("S1 iex 읽기",           PW("iex \"Get-Content %s/CLAUDE.md\"" % G), False)
    chk("S2 PS 작업 파일",       PW("& { Set-Content C:/Users/이상윤/cys-work/notes.md -Value x }"), False)
    chk("S3 Bash read→other",    B('eval "grep x %s > /c/Users/이상윤/cys-work/out.txt"' % WIN), False)

    # ── 구분자 토큰화 T군: 공백 없는 연결도 세그먼트별로 차단 ──
    chk("T1 세미콜론 touch",     B("echo x;touch %s/soul.md;echo y" % G), True)
    chk("T2 세미콜론 rm",        B("echo x;rm %s/soul.md" % G), True)
    chk("T3 붙은 pipe",          B("touch %s/soul.md|cat" % G), True)
    chk("T4 붙은 &&",            B("touch %s/soul.md&&echo x" % G), True)
    chk("T5 세미콜론 cp",        B("echo x;cp evil %s/soul.md" % G), True)
    chk("T6 PS 세미콜론",        PW("echo hi; Set-Content -Path %s/soul.md -Value x" % G), True)
    chk("T7 PS 세미콜론 ri",     PW("dir; ri %s/soul.md" % G), True)
    chk("T8 PS 붙은 세미콜론",    PW("echo hi;Set-Content -Path %s/soul.md -Value x" % G), True)
    chk("T9 PS 붙은 세미콜론 ri", PW("dir;ri %s/soul.md" % G), True)
    chk("T10 Bash WIN forward",   B("echo x;touch %s" % WIN.replace("\\", "/")), True)
    chk("T11 Bash MSYS",          B("echo x;touch %s" % MSYS), True)
    chk("T12 Bash WIN backslash", B("echo x;touch %s" % WIN), True)

    # 신규 V군: 분해된 리다이렉션·PowerShell 폴백은 정본 쓰기를 모두 차단해야 한다.
    chk("V1 >| 붙임",             B("echo evil>|%s/CLAUDE.md" % G), True)
    chk("V2 >| 띄움",             B("echo evil >| %s/CLAUDE.md" % G), True)
    chk("V3 printf >|",           B("printf x>|%s/CLAUDE.md" % G), True)
    chk("V4 &>",                 B("echo evil&>%s/CLAUDE.md" % G), True)
    chk("V5 &>>",                B("echo evil&>>%s/CLAUDE.md" % G), True)
    chk("V6 2>",                 B("echo evil 2>%s/CLAUDE.md" % G), True)
    chk("V7 2>>",                B("echo evil 2>>%s/CLAUDE.md" % G), True)
    chk("V8 >&",                 B("echo evil>&%s/CLAUDE.md" % G), True)
    chk("V9 2>|",                B("echo evil 2>|%s/CLAUDE.md" % G), True)

    # 신규 W군: 정상 파이프·정본 읽기→비정본 쓰기는 통과해야 한다.
    chk("W11 정상 pipe",          B("cat a|grep b"), False)
    chk("W12 read other",         B("grep x %s/CLAUDE.md > /tmp/out.txt" % G), False)
    chk("W13 read other >>>",     B("grep x %s/CLAUDE.md>>>/tmp/out.txt" % G), False)
    chk("W14 무관 clobber",       B("echo ok>|/tmp/work.txt"), False)
    chk("W15 PS icm read",        PW("icm -ScriptBlock { Get-Content %s/CLAUDE.md }" % G), False)

    # X군: 값 토큰이 우연히 '>'로 끝나도 뒤 명령을 놓치지 않고 차단.
    chk("X1 value> pipe rm",       B('echo "junk>" | rm %s/CLAUDE.md' % G), True)
    chk("X2 value> pipe touch",    B('echo "a>" | touch %s/CLAUDE.md' % G), True)
    chk("X3 value> pipe cp",       B("echo 'a>' | cp evil %s/CLAUDE.md" % G), True)
    chk("X4 value> pipe printf",   B('printf "%s>" | rm %s/CLAUDE.md' % ("%s", G)), True)
    chk("X5 value> amp rm",        B('echo "x>" & rm %s/CLAUDE.md' % G), True)
    chk("X6 value> PS pipe",       PW('echo "x>" | Set-Content -Path %s/CLAUDE.md -Value evil' % G), True)
    chk("X7 number> pipe rm",      B("echo 1> | rm %s/CLAUDE.md" % G), True)

    # Y군: 구분자 뒤 읽기/무관 쓰기는 계속 통과.
    chk("Y1 value> grep",          B('echo "junk>" | grep x'), False)
    chk("Y2 value> cat read",      B('echo "a>" | cat %s/CLAUDE.md' % G), False)
    chk("Y3 normal pipe",          B("cat a|grep b"), False)
    chk("Y4 unrelated clobber",    B("echo ok>|/tmp/work.txt"), False)
    chk("Y5 read other",           B("grep x %s/CLAUDE.md > /tmp/out.txt" % G), False)
    chk("X8 WIN forward",          B('echo "x>" | rm %s' % WIN.replace("\\", "/")), True)
    chk("X9 MSYS path",            B("echo 'a>' | touch %s" % MSYS), True)
    chk("X10 WIN backslash",       B('echo "x>" | rm %s' % WIN), True)
    chk("Y6 WIN forward read",     B('echo "junk>" | cat %s' % WIN.replace("\\", "/")), False)
    chk("Y7 MSYS read",            B("echo 'a>' | cat %s" % MSYS), False)
    chk("Y8 WIN backslash read",   B('echo "a>" | cat %s' % WIN), False)

    # Z군: operator run 정규화 후 누락 없는 정본 쓰기 차단.
    chk("Z1 fd 1>|",               B("printf x 1>|%s/CLAUDE.md" % G), True)
    chk("Z2 &>|",                  B("echo evil &>| %s/CLAUDE.md" % G), True)
    chk("Z3 quoted >",             B('echo ">" | rm %s/CLAUDE.md' % G), True)
    chk("Z4 quoted >>",            B('echo ">>" | rm %s/CLAUDE.md' % G), True)
    chk("Z5 quoted &",             B('echo "&" | rm %s/CLAUDE.md' % G), True)
    chk("Z6 single quoted >",      B("echo '>' | rm %s/CLAUDE.md" % G), True)
    chk("Z7 quoted pipe semi",     B('echo "|" ; rm %s/CLAUDE.md' % G), True)
    chk("Z8 fd 2>>",               B("2>>%s/CLAUDE.md" % G), True)
    chk("Z9 &>| attached",         B("&>|%s/CLAUDE.md" % G), True)

    # AA군: 인용/escape 리터럴과 정상 read·무관 write는 통과.
    chk("AA1 quoted > grep",       B('echo ">" | grep x'), False)
    chk("AA2 quoted junk read",    B('echo "junk>" | cat %s/CLAUDE.md' % G), False)
    chk("AA3 escaped >",           B(r"echo evil \> %s/CLAUDE.md" % G), False)
    chk("AA4 normal pipe",         B("cat a|grep b"), False)
    chk("AA5 fd clobber other",    B("echo ok 1>|/tmp/work.txt"), False)
    chk("AA6 read other",          B("grep x %s/CLAUDE.md > /tmp/out.txt" % G), False)

    # DD군: fd 복제(2>&1 류)는 **파일 쓰기가 아니다** — 꼬리 숫자는 파일명이 아니라 디스크립터다.
    #   2026-08-23 실측: `_redirect_targets` 가 `2>&1` 의 '1' 을 대상 파일로 잡아, 정본 디렉터리
    #   기준으로 정규화되며 정상 조회를 하루 3건 오차단했다(canon-check·canon-resign·조회).
    #   ★DD6~DD8 은 그 제외가 **진짜 쓰기를 뚫지 않는지** 지키는 음성 대조군이다(양성만큼 두껍게).
    chk("DD1 fd dup attached",     B("./canon-check.sh 2>&1 | tail -5"), False)
    chk("DD2 fd dup 1>&2",         B("echo hi 1>&2"), False)
    chk("DD3 fd dup >&2",          B("echo hi >&2"), False)
    chk("DD4 fd dup spaced",       B("cmd 2> &1"), False)
    chk("DD5 fd dup read canon",   B("grep x %s/CLAUDE.md 2>&1 | head -3" % G), False)
    chk("DD7 fd dup then write",   B("cmd 2>&1 > %s/CLAUDE.md" % G), True)
    chk("DD8 fd dup then append",  B("cmd 2>&1 >> %s/CLAUDE.md" % G), True)

    # EE군: ★**cwd 축** — 이 축이 없어서 2026-08-23 오차단 6건이 시험을 통째로 빠져나갔다.
    #   guard 는 상대경로를 `_canon()` 의 os.path.abspath 로 절대화한다 = **프로세스 cwd 기준**.
    #   그러므로 "cwd 가 정본 디렉터리일 때"는 **실제로 chdir 해야** 재현된다(JSON 필드로는 안 된다 —
    #   guard 는 cwd 를 입력에서 읽지 않는다). 위 DD군은 가상 루트로 판정만 보므로
    #   수리 전 코드에서도 통과했다 — 그게 A군이 결함을 놓친 기전이다.
    #   ★EE3~EE5 는 음성 대조군이다: cwd 가 정본이면 상대경로 쓰기·삭제는 **차단이 맞다**.
    import tempfile as _tf, shutil as _sh
    _cwd_root = _tf.mkdtemp(prefix="canon-cwd-axis-")
    _P_cwd = [_canon(_cwd_root) + "/"]
    _old_cwd = os.getcwd()
    try:
        os.chdir(_cwd_root)
        chk("EE1 fd dup 2>&1 (cwd=정본)",   B("./canon-check.sh 2>&1 | tail -5"), False, _P_cwd)
        chk("EE2 fd dup 1>&2 (cwd=정본)",   B("echo hi 1>&2"), False, _P_cwd)
        chk("EE3 상대 쓰기 (cwd=정본)",      B("echo x > out.txt"), True, _P_cwd)
        chk("EE4 상대 rm (cwd=정본)",        B("rm out.txt"), True, _P_cwd)
        chk("EE5 미확장 변수 (cwd=정본)",     B("cp a $SB/b.txt"), True, _P_cwd)
        chk("R2-REAL-3A git stdin message", B('cd ~/cys-terminal-jarvis && git add my-jarvis/gold/role-bootstrap.sh my-jarvis/scripts/fix_codex_wiring.py && git commit -q -F - <<\'EOF\'\nfeat(wiring): Code Mode on the Claude seats (blocks 52, 53, poll_event exit)\n\n- gold role-bootstrap.sh: exit early when the UserPromptSubmit input is Code Mode\n  background output (top-level "source":"poll_event"); javis_mission judged it\n  human, so it would have been recorded as an owner mission. REV 2026-11-17.1.\n- block 52: CLAUDE_CODE_EXPERIMENTAL_CODE_MODE=1 in ~/.claude and ~/.cys/claude\n  settings env, and onFailure "continue" on PreToolUse command hooks so a slow\n  or failed hook keeps the pre-Code-Mode meaning instead of refusing the call.\n- block 53: CSO capability gate judges `cd \'<abs dir>\' && <command>` as\n  <command> run in that directory (equivalence 340/340 against the live gate).\n\nOwner approved 2026-11-17 (P6). Review: codex r1 REVISE fixed, gemini r2 ACCEPT.\nEvidence: ~/_round/codemode_1117.\n\nCo-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>\nEOF\ngit log --oneline -1; git status --short | head -3'), False, _P_cwd)
        chk("R2-GIT-F1 git stdin variant", B("git commit -q -F - <<'EOF'\nmessage `<command>` > soul.md\nEOF"), False, _P_cwd)
        chk("R2-GIT-F2 git stdin variant", B("git commit -q -F- <<'EOF'\nmessage `<command>` > soul.md\nEOF"), False, _P_cwd)
        chk("R2-GIT-F3 git stdin variant", B("git commit -q --file=- <<'EOF'\nmessage `<command>` > soul.md\nEOF"), False, _P_cwd)
        chk("R2-GIT-F4 git stdin variant", B("git commit -q --file - <<'EOF'\nmessage `<command>` > soul.md\nEOF"), False, _P_cwd)

        chk("EE6 literal commit message (cwd=canon)",
            B("git commit -m \"$(cat <<'EOF'\necho x >> soul.md\nEOF\n)\""), False, _P_cwd)
    finally:
        os.chdir(_old_cwd)
        _sh.rmtree(_cwd_root, ignore_errors=True)

    # Effective-directory and literal-data regressions (Code Mode 2026-11-17).
    for name, command, want in [
        ("EF1 cd quoted &&", "cd '%s' && echo x >> soul.md" % G, True),
        ("EF2 cd semicolon", "cd '%s'; echo x >> soul.md" % G, True),
        ("EF3 cd or", "cd '%s' || echo x >> soul.md" % G, True),
        ("EF4 subshell", "(cd '%s' && echo x >> soul.md)" % G, True),
        ("EF5 pushd", "pushd '%s' && touch soul.md" % G, True),
        ("EF6 relative cd", "cd '%s/elsewhere' && cd .. && rm soul.md" % G, True),
        ("EF7 cd minus", "cd '%s' && cd '%s' && cd - && touch soul.md" % (G, WK), True),
        ("EF8 HOME", 'cd "$HOME/.canon" && echo x >> soul.md', True),
        ("EF9 tilde", 'cd ~/.canon && tee soul.md', True),
        ("EF10 variable", 'cd "$DEST" && echo x >> soul.md', True),
        ("EF11 substitution", 'cd "$(pwd)" && echo x >> soul.md', True),
        ("EF12 subshell restores", "(cd '%s' && cat soul.md); touch unrelated.txt" % G, False),
        ("EF13 safe cd", "cd '%s' && echo x >> soul.md" % WK, False),
        ("EF14 cd away", "cd '%s' && cd '%s' && touch soul.md" % (G, WK), False),
        ("EF15 read in canon", "cd '%s' && cat soul.md" % G, False),
        ("EF16 quoted fake heredoc", 'echo "<<\'EOF\'"\necho x >> %s/soul.md\nEOF\n' % G, True),
        ("EF17 unterminated heredoc", "cat <<'EOF'\necho x >> %s/soul.md\n" % G, True),
        ("EF18 real heredoc write", "cat >> %s/soul.md <<'EOF'\nhello\nEOF\n" % G, True),
        ("EF19 literal commit message", "cd '%s' && git commit -m \"$(cat <<'EOF'\necho x >> soul.md\ncd '$DEST' && rm soul.md\nEOF\n)\"" % G, False),
        ("EF20 HOME braces", 'cd "${HOME}/.canon" && touch soul.md', True),
        ("EF21 quoted tilde data", "printf '%s' '~/.canon'", False),
        ("EF22 cd redirect", "cd '%s' > %s/soul.md" % (WK,G), True),
        ("EF23 comment fake heredoc", "# <<'EOF'\necho x >> %s/soul.md\nEOF\n" % G, True),
        ("EF24 multiline quoted fake heredoc", "echo 'hello\n<<\"EOF\"\n'\necho x >> %s/soul.md\nEOF\n" % G, True),
        ("EF25 python executable heredoc", "python <<'EOF'\nopen('%s/soul.md','w').write('x')\nEOF\n" % G, True),
        ("EF26 bash executable heredoc", "bash <<'EOF'\necho x >> %s/soul.md\nEOF\n" % G, True),
        ("EF27 nested pushd unwind", "pushd '%s' && pushd '%s' && pushd /tmp && popd && popd && echo x >> soul.md" % (G,WK), True),
        ("EF28 pushd safe unwind", "pushd '%s' && popd && touch unrelated.txt" % G, False),
    ]:
        # HOME cases use a hermetic protected directory under the real home.
        chk(name, B(command), want, P + [HOME + '/.canon/'])

    # r2 accepted regression cases; staged before implementation.
    for label, command, want in [('J1', 'cat > /tmp/a.sh <<\'EOF\'\nrm /srv/agentops/soul.md\nEOF\nbash -c "sh /tmp/a.sh"', True), ('J4', "cat > /tmp/x <<'EOF'\n/srv/agentops/soul.md\nEOF\nxargs rm < /tmp/x", True), ('J9', "cat > /tmp/x <<'EOF'\n/srv/agentops/soul.md\nEOF\nxargs -a /tmp/x rm", True), ('I14', 'git commit -m "$(cat <<\'EOF\'\nx\nEOF\n)"; cat <<\'EOF\' > /tmp/a.py\nopen(\'/srv/agentops/soul.md\',\'w\')\nEOF\npython3 /tmp/a.py', True), ('I6', "python3 <<'EOF'\nimport os; os.remove('/srv/agentops/soul.md')\nEOF", True), ('I9', "python3 - <<'EOF' && echo done\nopen('/srv/agentops/soul.md','w')\nEOF", True), ('I11', "(python3 - <<'EOF'\nopen('/srv/agentops/soul.md','w')\nEOF\n)", True), ('NODE', "node - <<'EOF'\nconst fs=require('fs'); fs.rmSync('/srv/agentops/soul.md')\nEOF", True), ('API1', 'cd ~/.canon && python3 -c "import os; os.remove(\'soul.md\')"', True), ('API2', 'cd ~/.canon && python3 -c "import pathlib; pathlib.Path(\'soul.md\').write_text(\'x\')"', True), ('API3', 'cd ~/.canon && python3 -c "import os; os.rename(\'/tmp/x\',\'soul.md\')"', True), ('API4', "cd ~/.canon && python3 - <<'EOF'\nimport os; os.remove('soul.md')\nEOF", True), ('API5', 'cd ~/.canon && node -e "require(\'fs\').writeFileSync(\'soul.md\',\'x\')"', True), ('READ-STAGE', 'M=/srv/agentops/soul.md; S=/srv/work/staged.md; python3 - "$M" "$S" <<\'EOF\'\nimport pathlib, sys\np=pathlib.Path(sys.argv[1]); pathlib.Path(sys.argv[2]).write_text(p.read_text())\nEOF', False)]:
        chk("R2-" + label, B(command), want, [_canon(G) + "/", HOME + "/.canon/"])

    # r1 reviewer regressions, each added before the implementation fix.
    chk("RV-LEGACY-ENV-C helper isolation", B("env -C rm /srv/agentops/soul.md"), True, [_canon(G) + "/", HOME + "/.canon/"])
    chk("RV-ARG-EXEC unknown argument consumer", B("ssh localhost \"$(cat <<'EOF'\necho x > /srv/agentops/soul.md\nEOF\n)\""), True, [_canon(G) + "/", HOME + "/.canon/"])
    chk("RV-OUTER-PIPE compound stdout executor", B("(\ncat <<'EOF'\necho x > /srv/agentops/soul.md\nEOF\n) | sh"), True, [_canon(G) + "/", HOME + "/.canon/"])
    chk("RV-OUTER-PROC process-substitution executor", B("sh < <(\ncat <<'EOF'\necho x > /srv/agentops/soul.md\nEOF\n)"), True, [_canon(G) + "/", HOME + "/.canon/"])
    chk("RV-MASTER-READ variable source staged script", B("M=/srv/agentops/soul.md; python3 - \"$M\" <<'EOF'\nimport sys\nprint(sys.argv[1])\nEOF"), False, [_canon(G) + "/", HOME + "/.canon/"])
    chk("RV-ENV-SCOPE wrapped subshell restores cwd", B("(cd '%s' && env -C '%s' cat soul.md); touch notes.md" % (G,WK)), False, [_canon(G) + "/", HOME + "/.canon/"])
    for label, command, want in [('R1', "cat <<'EOF' | sh\necho x > /srv/agentops/soul.md\nEOF", True), ('R3', "cat <<'EOF' | python3\nopen('/srv/agentops/soul.md','w')\nEOF", True), ('R4', "cat <<'EOF' | xargs rm\n/srv/agentops/soul.md\nEOF", True), ('R5', 'D=/srv/agentops/soul.md; eval "rm $D"', True), ('R6', 'D=/srv/agentops; bash -c "rm $D/soul.md"', True), ('R7', 'cd /srv/agentops && eval "rm soul.md"', True), ('R9', "cd /srv/agentops && bash -c 'rm soul.md'", True), ('R11', "xargs rm <<'EOF'\n/srv/agentops/soul.md\nEOF", True), ('A30', "cd /srv/agentops && xargs rm <<'EOF'\nsoul.md\nEOF", True), ('V1', 'echo x > "$OUT"', False), ('V2', 'rm -f "$tmp"', False), ('V3', 'cp a.txt "$DEST/"', False), ('V4', 'echo x | tee "$LOG"', False), ('V5', 'git diff > "$TMPDIR/d.patch"', False), ('V6', 'touch "$(mktemp -d)/x"', False), ('V7', 'echo ok >> "$GITHUB_OUTPUT"', False), ('V8', 'mv "$a" "$b"', False), ('V9', 'echo x > `mktemp`', False), ('CD1', 'pushd /srv/work > /dev/null && touch x.txt', False), ('CD2', 'cd /srv/work 2>/dev/null && touch x.txt', False), ('CD3', 'cd -P /srv/work && touch x', False), ('CD4', 'cd -L -e -@ /srv/work 2>&1 && touch x', False), ('W1', "bash -c 'cd ~/.canon && echo x > soul.md'", True), ('W2', 'env -C ~/.canon touch soul.md', True), ('W3', 'env --chdir=~/.canon touch soul.md', True), ('W4', "cd ~/.canon && python3 - <<'EOF'\nopen('soul.md','w')\nEOF", True), ('W5', 'cd ~/.canon && python3 -c "open(\'soul.md\',\'w\')"', True), ('W6', "cd ~/.canon && cat <<'EOF' | sh\nrm soul.md\nEOF", True), ('W7', "sh -c 'cd ~/.canon && echo x > soul.md'", True), ('W8', "zsh -c 'cd ~/.canon && echo x > soul.md'", True), ('P1', "cat <<'EOF' > >(sh)\necho x > /srv/agentops/soul.md\nEOF", True), ('S1', 'cd ~/.canon; cd ~/cys-work; touch notes.md', True)]:
        chk("RV-" + label + " reviewer", B(command), want, [_canon(G) + "/", HOME + "/.canon/"])

    # BB군: 정본 경로 자체에 연산자 문자가 있어도 인용/escape 경로를 차단.
    chk("BB1 quoted amp path",      B('rm "%s"' % BB_AMP), True)
    chk("BB2 escaped amp path",     B(r"rm %s" % (G + "/a\\&b/x.md")), True)
    chk("BB3 single semi path",     B("rm '%s'" % BB_SEMI), True)
    chk("BB4 Write amp path",       W(BB_AMP), True)
    chk("BB5 pipe path",            B('rm "%s"' % BB_PIPE), True)
    chk("BB6 gt path",              B('rm "%s"' % BB_GT), True)
    chk("BB7 WIN amp path",         B('rm "%s"' % WIN_AMP), True)

    # CC군: 인용/escape 연산자는 비연산자로 유지되고 무관 작업은 통과.
    chk("CC1 quoted > grep",        B('echo ">" | grep x'), False)
    chk("CC2 quoted path read",     B('cat "%s"' % BB_AMP), False)
    chk("CC3 escaped >",            B(r"echo evil \> %s" % G), False)
    chk("CC4 quoted read other",    B('grep x "%s" > /tmp/out.txt' % BB_AMP), False)
    chk("CC5 unrelated amp write",  B('touch "/tmp/a&b.txt"'), False)
    chk("CC6 normal pipe",          B("cat a|grep b"), False)

    # ── 구분자 토큰화 U군: 연결된 읽기/무관 쓰기는 통과 ──
    chk("U1 세미콜론 cat",        B("echo x;cat %s/CLAUDE.md" % G), False)
    chk("U2 세미콜론 무관 touch", B("echo x;touch /tmp/other.txt"), False)
    chk("U3 붙은 read→other",     B("grep x %s/CLAUDE.md>>/tmp/out.txt" % G), False)
    chk("U4 PS 세미콜론 읽기",    PW("echo x;Get-Content %s/CLAUDE.md" % G), False)

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
    # ★A13~A15 = 접두 정규화가 **과차단으로 번지지 않는지** 보는 대조군
    chk("A13 환경변수 접두 읽기",   B("LANG=C cat %s/CLAUDE.md" % G), False)
    chk("A14 env 래퍼 무관 경로",   B("/usr/bin/env tee /tmp/out.txt"), False)
    chk("A15 접두 붙은 무관 rm",    B("LANG=C rm -rf /tmp/scratch"), False)

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

    def evidence(prefix):
        return " ".join("%s=%s" % (k, results[k]) for k in results if k.startswith(prefix))
    print("self-test evidence P: %s" % evidence("P"))
    print("self-test evidence A: %s" % evidence("A"))
    print("self-test evidence Q: %s" % evidence("Q"))
    print("self-test evidence R: %s" % evidence("R"))
    print("self-test evidence S: %s" % evidence("S"))
    print("self-test evidence T: %s" % evidence("T"))
    print("self-test evidence U: %s" % evidence("U"))
    print("self-test evidence V: %s" % evidence("V"))
    print("self-test evidence W: %s" % evidence("W"))
    print("self-test evidence X: %s" % evidence("X"))
    print("self-test evidence Y: %s" % evidence("Y"))
    print("self-test evidence Z: %s" % evidence("Z"))
    print("self-test evidence AA: %s" % evidence("AA"))
    print("self-test evidence BB: %s" % evidence("BB"))
    print("self-test evidence CC: %s" % evidence("CC"))
    case_count = len(results) + 1
    if fails:
        print("\n".join("  FAIL " + f for f in fails), file=sys.stderr)
        print("self-test: %d 실패 / %d 케이스" % (len(fails), case_count), file=sys.stderr)
        return 1
    print("self-test OK — %d 케이스(신규 T7·U4 포함)" % case_count)
    return 0

if os.environ.get("CANON_GUARD_SELF_TEST"):
    sys.exit(self_test())
main()
PYEOF
