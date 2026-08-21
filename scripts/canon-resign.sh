#!/usr/bin/env bash
# canon-resign.sh — 정본 재서명(정당한 변경의 확정). 편집과 재서명을 한 트랜잭션으로 묶는 짝은 canon-edit.sh.
# mindvirus-defense kit — 층 ② (무결성 워치) · MIT
#
# 설계 원칙:
#   ⑴ **사유 필수** — 근거 없는 서명은 서명이 아니다. --reason 없으면 거부(exit 4).
#   ⑵ **원장은 append-only** — resign-ledger.jsonl 은 open(...,'a') 로만 쓴다(지침 6-10).
#      베이스라인(baseline.tsv)은 원장이 아니라 *현재 상태 스냅샷*이므로 원자적 전량 교체가 맞다.
#   ⑶ **행위자 게이트** — 하위 노드(에이전트·검증자 등)의 재서명은 거부(exit 5). 정본 변경의 확정은 오케스트레이터
#      (orchestrator) 권한이다. 역할 미상(사람 셸)은 통과 — 사람이 직접 치는 명령까지 막지는 않는다.
#      역할 판정은 사이트마다 다르므로 CANON_ROLE / CANON_ROLE_CMD 로 플러그인한다.
#
# 사용:
#   canon-resign.sh --rebuild --reason "최초 베이스라인 서명"
#   canon-resign.sh ~/agents/CLAUDE.md --reason "ADR-12 반영(소유자 승인 2026-01-15)"
#   canon-resign.sh --all --reason "정기 재서명" # 현재 불일치 전부
#   canon-resign.sh --attest --reason "오케스트레이터 검토 확인"  # 해시 불변·검토 사실만 원장에 기록
#   canon-resign.sh --self-test
#
# 종료코드: 0 성공 | 3 설정오류 | 4 사유 누락/인자 오류 | 5 권한 거부
set -u

CANON_BIN="${CANON_BIN:-$(cd "$(dirname "$0")" 2>/dev/null && pwd)}"
CANON_HOME="${CANON_HOME:-$HOME/.canon}"
INVENTORY="${CANON_INVENTORY:-$CANON_HOME/inventory.conf}"
BASELINE="${CANON_BASELINE:-$CANON_HOME/baseline.tsv}"
LEDGER="${CANON_LEDGER:-$CANON_HOME/resign-ledger.jsonl}"

_py_path() {
  if command -v cygpath >/dev/null 2>&1; then
    cygpath -w "$1"
  else
    printf '%s' "$1"
  fi
}

PY="$(command -v python3 2>/dev/null || command -v python 2>/dev/null || printf '')"
[ -n "$PY" ] || { echo "canon-resign: python3 부재 — 중단" >&2; exit 3; }

# ── 행위자 게이트 ──────────────────────────────────────────────────
# 면제는 둘뿐이다: ⑴ --self-test ⑵ 테스트 스코프(CANON_RESIGN_TEST=1 이면서
#   CANON_BASELINE 이 **운영 베이스라인이 아닌** 경로일 때). ⑵의 조건이 핵심 —
#   운영 베이스라인을 겨냥한 서명은 환경변수로 우회되지 않는다.
# ★사이트 상수 — **운영 CANON_HOME**. 환경변수로 덮지 않는다(덮이면 아래 면제 조건이 무의미해진다).
#   설치 시 이 한 줄만 사이트 경로로 고친다. 이 스크립트 자신이 strict 인벤토리에 있으므로
#   누군가 이 줄을 고치면 ②가 그 사실을 잡는다.
CANON_PROD_HOME="$HOME/.canon"

# 역할은 **게이트와 무관하게 항상** 조회한다 — 면제 경로에서도 원장에 실제 행위자를 남겨야 한다.
#   ⑴ CANON_ROLE 이 있으면 그것 ⑵ 없으면 CANON_ROLE_CMD 를 실행한 표준출력 ⑶ 둘 다 없으면 미상.
#   예) CANON_ROLE_CMD="my-fleet whoami --role"   (한 줄로 역할명을 출력하는 아무 명령)
ROLE="${CANON_ROLE:-}"
if [ -z "$ROLE" ] && [ -n "${CANON_ROLE_CMD:-}" ]; then
  ROLE="$(sh -c "$CANON_ROLE_CMD" 2>/dev/null | head -1 | tr -d '\r\n' || printf '')"
fi
_gate_exempt=0
case " $* " in *" --self-test "*) _gate_exempt=1 ;; esac
if [ "${CANON_RESIGN_TEST:-}" = "1" ] && [ -n "${CANON_BASELINE:-}" ]; then
  case "$CANON_BASELINE" in
    "$CANON_PROD_HOME"/*) : ;;                # 운영 겨냥 — 면제 불가
    *) _gate_exempt=1 ;;
  esac
fi
# ⑶ 최초 부트스트랩: 베이스라인이 **아직 없고** --rebuild 일 때만.
#    근거 — 최초 서명은 "변경을 승인"하는 행위가 아니라 "현재 상태를 사진 찍는" 행위다.
#    그 사진의 값어치는 오케스트레이터가 그것을 검토(--attest)할 때 생긴다. 그리고 베이스라인이
#    이미 있으면 이 면제는 즉시 닫히므로, 하위 에이전트가 나중 편집을 세탁하는 데 쓸 수 없다.
#    ★봉쇄 조건 추가(2026-08-21 자기점검): 베이스라인 파일만 조건으로 두면 하위 에이전트가 그 파일을
#      지우고 다시 부트스트랩해 무단 변경을 세탁할 수 있다. 그래서 **원장에 오케스트레이터의 attest
#      기록이 한 번이라도 있으면 부트스트랩 면제는 영구히 닫힌다**(원장은 append-only라 지울 수 없다).
case " $* " in
  *" --rebuild "*)
    if [ ! -f "$BASELINE" ]; then
      if [ -f "$LEDGER" ] && grep -q '"action": *"attest"' "$LEDGER" 2>/dev/null; then
        : # 오케스트레이터가 이미 검토 확인했다 — 재부트스트랩 면제 없음
      else
        _gate_exempt=1
      fi
    fi ;;
esac
# 거부 대상 역할 — 공백 구분 glob 목록. 사이트에 맞게 CANON_DENY_ROLES 로 바꾼다.
CANON_DENY_ROLES="${CANON_DENY_ROLES:-worker* reviewer* planner* agent* sub-*}"
case "$_gate_exempt" in 1) : ;; *)
  for _pat in $CANON_DENY_ROLES; do
    case "$ROLE" in
      $_pat)
        echo "canon-resign DENY: role=$ROLE 은 정본 재서명 권한이 없다." >&2
        echo "  정본 변경은 오케스트레이터의 승인 사항이다 — 오케스트레이터에게 에스컬레이션하라(변경 내용 대조표 첨부)." >&2
        exit 5 ;;
    esac
  done
esac

mkdir -p "$CANON_HOME" 2>/dev/null
export CANON_HOME="$(_py_path "$CANON_HOME")"
export INVENTORY="$(_py_path "$INVENTORY")"
export BASELINE="$(_py_path "$BASELINE")"
export LEDGER="$(_py_path "$LEDGER")"
export CANON_ACTOR_ROLE="${ROLE:-}"
export CANON_VERIFY="$(_py_path "${CANON_VERIFY:-$CANON_BIN/canon-verify.sh}")"

exec "$PY" - "$@" <<'PYEOF'
import hashlib, json, os, re, sys, time, glob, tempfile

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

INVENTORY = _canon(os.environ["INVENTORY"])
BASELINE  = _canon(os.environ["BASELINE"])
LEDGER    = _canon(os.environ["LEDGER"])
ACTOR_ROLE = os.environ.get("CANON_ACTOR_ROLE") or "(no-role/human-shell)"

# canon-verify.sh 의 전개·해시 로직을 그대로 재사용한다(SOT 분산 차단).
sys.path.insert(0, _canon(os.path.dirname(os.environ["CANON_VERIFY"])))

EXCLUDE_MARKERS = (".bak", ".new", ".user", ".lock")

def excluded(path):
    base = os.path.basename(path)
    if base.startswith(".") or base.endswith("~") or base == ".DS_Store":
        return True
    return any(m in base for m in EXCLUDE_MARKERS)

def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

def read_inventory(path=None):
    entries, errors = [], []
    p = path or INVENTORY
    if not os.path.isfile(p):
        return entries, ["inventory 부재: %s" % p]
    with open(p, encoding="utf-8") as f:
        for ln, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue
            parts = [x for x in line.split("\t") if x != ""]
            if len(parts) < 2:
                errors.append("%s:%d 형식 오류" % (p, ln)); continue
            tier, sel = parts[0].strip(), parts[1].strip()
            if tier not in ("strict", "append", "watch", "watch-soft"):
                errors.append("%s:%d 알 수 없는 tier '%s'" % (p, ln, tier)); continue
            entries.append((tier, _canon(sel)))
    return entries, errors

def expand(entries):
    out = {}
    for tier, sel in entries:
        if tier in ("watch", "watch-soft"):
            if not os.path.isdir(sel):
                continue
            for root, dirs, files in os.walk(sel):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for fn in sorted(files):
                    p = os.path.join(root, fn)
                    if fn.endswith(".md") and not excluded(p):
                        out.setdefault(_canon(p), tier)
        else:
            hits = sorted(glob.glob(sel)) if any(c in sel for c in "*?[") else [sel]
            for p in hits:
                if os.path.isfile(p) and not excluded(p):
                    out[_canon(p)] = tier
    return out

def read_baseline(path=None):
    rows = {}
    p = path or BASELINE
    if not os.path.isfile(p):
        return rows
    with open(p, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 5:
                continue
            rows[parts[1]] = {"tier": parts[0], "sha": parts[2],
                              "size": int(parts[3]), "signed_at": parts[4]}
    return rows

def write_baseline(rows, path=None):
    """원자적 전량 교체(tmp+rename). 베이스라인은 원장이 아니라 현재 상태 스냅샷이다."""
    p = path or BASELINE
    d = os.path.dirname(p) or "."
    fd, tmp = tempfile.mkstemp(dir=d, prefix=".baseline.", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write("# canon baseline v1 — 생성: canon-resign.sh (손편집 금지)\n")
            f.write("# tier\tpath\tsha256\tsize\tsigned_at\n")
            for k in sorted(rows):
                r = rows[k]
                f.write("%s\t%s\t%s\t%d\t%s\n" % (r["tier"], k, r["sha"], r["size"], r["signed_at"]))
        os.replace(tmp, p)
    except BaseException:
        try: os.unlink(tmp)
        except OSError: pass
        raise

def ledger_append(recs, path=None):
    """★append-only. 절대 read-modify-write 하지 않는다(지침 6-10)."""
    p = path or LEDGER
    with open(p, "a", encoding="utf-8") as f:      # 'a' 고정 — 'w' 금지
        for r in recs:
            f.write(json.dumps(r, ensure_ascii=False) + "\n")
        f.flush(); os.fsync(f.fileno())

def now():
    return time.strftime("%Y-%m-%dT%H:%M:%S%z")

def parse_args(argv):
    reason, targets = None, []
    rebuild = all_diff = attest = False
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--reason":
            i += 1
            if i >= len(argv): return None, None, None, None, None, "--reason 값 누락"
            reason = argv[i]
        elif a.startswith("--reason="):
            reason = a.split("=", 1)[1]
        elif a == "--rebuild":
            rebuild = True
        elif a == "--all":
            all_diff = True
        elif a == "--attest":
            attest = True
        elif a.startswith("-"):
            return None, None, None, None, None, "알 수 없는 옵션: %s" % a
        else:
            targets.append(_canon(a))
        i += 1
    return reason, targets, rebuild, all_diff, attest, None

def do_attest(reason):
    """오케스트레이터 검토 확인(attestation) — 해시를 바꾸지 않고 '내가 이 베이스라인을 읽고 인정했다'를
    원장에 남긴다. 부트스트랩 사진(하위 에이전트가 찍은 것)이 정당 정본이 되는 유일한 경로다."""
    if not os.path.isfile(BASELINE):
        print("canon-resign --attest: 베이스라인이 없다 — 먼저 --rebuild", file=sys.stderr)
        return 3
    with open(BASELINE, "rb") as f:
        digest = hashlib.sha256(f.read()).hexdigest()
    rows = read_baseline()
    rec = dict(ts=now(), actor=ACTOR_ROLE, action="attest", file=BASELINE, tier="-",
               old_sha="-", new_sha=digest, size=len(rows), reason=reason)
    ledger_append([rec])
    print("canon-resign --attest: 베이스라인 %d행 검토 확인 기록" % len(rows))
    print("  baseline sha256 = %s" % digest)
    print("  actor = %s · 사유 = %s" % (ACTOR_ROLE, reason))
    return 0

def main(argv):
    reason, targets, rebuild, all_diff, attest, err = parse_args(argv)
    if err:
        print("canon-resign: %s" % err, file=sys.stderr); return 4
    if not reason or not reason.strip():
        print("canon-resign: --reason 필수 — 근거 없는 서명은 서명이 아니다.", file=sys.stderr)
        print('  예) canon-resign.sh ~/agents/CLAUDE.md --reason "ADR-12 반영(소유자 승인)"',
              file=sys.stderr)
        return 4
    if attest:
        return do_attest(reason)
    if not (rebuild or all_diff or targets):
        print("canon-resign: 대상 없음 — 파일 지정 / --all / --rebuild 중 하나 필요", file=sys.stderr)
        return 4

    entries, inv_err = read_inventory()
    for e in inv_err:
        print("ERR " + e, file=sys.stderr)
    if inv_err:
        return 3
    current = expand(entries)
    base = read_baseline()

    if rebuild:
        sel = sorted(current)
    elif all_diff:
        sel = []
        for p in sorted(current):
            try:
                if base.get(p, {}).get("sha") != sha256_file(p):
                    sel.append(p)
            except OSError:
                pass
        for p in sorted(base):
            if p not in current and not os.path.isfile(p):
                sel.append(p)          # 삭제분 정리
    else:
        sel = targets
        unknown = [p for p in sel if p not in current and p not in base]
        if unknown:
            print("canon-resign: 인벤토리 밖 경로 — 서명 불가:", file=sys.stderr)
            for u in unknown:
                print("  %s" % u, file=sys.stderr)
            print("  (인벤토리에 먼저 추가하라: %s)" % INVENTORY, file=sys.stderr)
            return 4

    recs, changed, removed = [], 0, 0
    for p in sel:
        tier = current.get(p) or base.get(p, {}).get("tier", "strict")
        old = base.get(p, {}).get("sha", "-")
        if not os.path.isfile(p):
            if p in base:
                del base[p]; removed += 1
                recs.append(dict(ts=now(), actor=ACTOR_ROLE, action="unsign", file=p,
                                 tier=tier, old_sha=old, new_sha="-", size=0, reason=reason))
            continue
        new = sha256_file(p); size = os.path.getsize(p)
        if old == new and p in base:
            continue
        base[p] = {"tier": tier, "sha": new, "size": size, "signed_at": now()}
        changed += 1
        recs.append(dict(ts=now(), actor=ACTOR_ROLE, action="sign", file=p, tier=tier,
                         old_sha=old, new_sha=new, size=size, reason=reason))

    if not recs:
        print("canon-resign: 변경 없음 — 서명할 것이 없다(이미 일치).")
        return 0

    ledger_append(recs)          # ★원장 먼저(append-only) → 그다음 스냅샷 교체
    write_baseline(base)
    print("canon-resign: 서명 %d건 · 해제 %d건 · 사유=%s" % (changed, removed, reason))
    for r in recs:
        print("  %-6s %s" % (r["action"], r["file"]))
        print("         %s -> %s" % (r["old_sha"][:16], r["new_sha"][:16]))
    print("  원장: %s (append-only)" % LEDGER)
    print("  스냅샷: %s (%d행)" % (BASELINE, len(base)))
    return 0

def self_test():
    import tempfile, shutil
    global INVENTORY, BASELINE, LEDGER
    d = tempfile.mkdtemp(prefix="canon-resign-test-")
    fails = []
    try:
        docs = os.path.join(d, "docs"); os.makedirs(docs)
        f1 = os.path.join(docs, "CLAUDE.md"); open(f1, "w").write("v1\n")
        INVENTORY = os.path.join(d, "inv.conf")
        BASELINE  = os.path.join(d, "baseline.tsv")
        LEDGER    = os.path.join(d, "ledger.jsonl")
        open(INVENTORY, "w").write("strict\t%s\n" % f1)

        # ① --reason 없으면 거부
        if main([f1]) != 4: fails.append("①사유 누락이 거부되지 않음")
        # ② 대상 없으면 거부
        if main(["--reason", "x"]) != 4: fails.append("②대상 없음이 거부되지 않음")
        # ③ rebuild 성공 + 베이스라인/원장 생성
        if main(["--rebuild", "--reason", "최초"]) != 0: fails.append("③rebuild 실패")
        if not os.path.isfile(BASELINE): fails.append("③baseline 미생성")
        n1 = sum(1 for _ in open(LEDGER))
        if n1 != 1: fails.append("③원장 1행이어야(실제 %d)" % n1)
        # ④ 변경 없으면 무동작
        if main([f1, "--reason", "재서명"]) != 0: fails.append("④무변경 처리 실패")
        if sum(1 for _ in open(LEDGER)) != 1: fails.append("④무변경인데 원장이 늘어남")
        # ⑤ 변경 후 재서명 → 원장 append(전량 재기록 아님)
        open(f1, "w").write("v2 새 규약\n")
        if main([f1, "--reason", "오너 승인 개정"]) != 0: fails.append("⑤재서명 실패")
        lines = open(LEDGER, encoding="utf-8").read().strip().split("\n")
        if len(lines) != 2: fails.append("⑤원장이 append되지 않음(%d행)" % len(lines))
        r0 = json.loads(lines[0])
        if r0.get("reason") != "최초": fails.append("⑤첫 원장 줄이 훼손됨(append-only 위반)")
        r1 = json.loads(lines[1])
        if r1.get("old_sha", "")[:4] == "-" or r1.get("reason") != "오너 승인 개정":
            fails.append("⑤재서명 레코드 필드 오류: %s" % r1)
        # ⑥ 인벤토리 밖 경로 거부
        out = os.path.join(d, "outside.md"); open(out, "w").write("x")
        if main([out, "--reason", "y"]) != 4: fails.append("⑥인벤토리 밖 경로가 거부되지 않음")
        # ⑦ 삭제 파일 --all → unsign
        os.remove(f1)
        if main(["--all", "--reason", "삭제 정리"]) != 0: fails.append("⑦--all 실패")
        if read_baseline().get(f1): fails.append("⑦삭제분이 베이스라인에 남음")
        last = json.loads(open(LEDGER, encoding="utf-8").read().strip().split("\n")[-1])
        if last.get("action") != "unsign": fails.append("⑦unsign 레코드 없음")
    finally:
        shutil.rmtree(d, ignore_errors=True)
    if fails:
        print("\n".join("  FAIL " + x for x in fails), file=sys.stderr)
        print("self-test: %d 실패" % len(fails), file=sys.stderr); return 1
    print("self-test OK — 7 배터리(사유필수·대상필수·rebuild·무변경·append원장보존·범위밖거부·unsign)")
    return 0

if "--self-test" in sys.argv:
    sys.exit(self_test())
sys.exit(main(sys.argv[1:]))
PYEOF
