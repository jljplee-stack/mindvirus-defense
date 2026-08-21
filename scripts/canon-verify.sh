#!/usr/bin/env bash
# canon-verify.sh — 정본(자동 로드) 파일 무결성 대조기. 토큰 0·결정론·읽기 전용.
# mindvirus-defense kit — 층 ② (무결성 워치) · MIT
#
# 왜 존재하는가: 공개 연구(에이전트 간 신념 전염)와 실운영 사고(위조 지시 메시지 10건·3일간)가
#   같은 곳을 가리킨다 — **자동 로드 정본에 한 문단이 박히면 매 세션 자동 주입되고
#   재부팅·컨텍스트 초기화를 살아남는다.**
#   그 파일들이 "내가 서명한 그대로인가"를 사람 눈이 아니라 해시로 판정한다.
#
# 사용:
#   canon-verify.sh              # 사람용 리포트 + 종료코드
#   canon-verify.sh --json       # 기계용 JSON
#   canon-verify.sh --list       # 인벤토리 전개 결과만(베이스라인 불요)
#   canon-verify.sh --self-test  # 내장 배터리(정상/변조/추가/삭제/append)
#
# 종료코드:  0 = 일치(clean)   1 = NOTICE만(추가·순수append)   2 = ALERT(무단 변경/삭제)
#            3 = 설정·베이스라인 오류(판정 불가 — 이것도 사람이 봐야 한다)
set -u

# ── 설정(전부 환경변수로 덮을 수 있다 — 사이트 고정값은 canon.env 에 둔다) ──
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
if [ -z "$PY" ]; then
  echo "canon-verify: python3 부재 — 판정 불가(fail-loud)" >&2
  exit 3
fi

export CANON_HOME="$(_py_path "$CANON_HOME")"
export INVENTORY="$(_py_path "$INVENTORY")"
export BASELINE="$(_py_path "$BASELINE")"
export LEDGER="$(_py_path "$LEDGER")"
exec "$PY" - "$@" <<'PYEOF'
import hashlib, json, os, re, sys, glob, time

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

EXCLUDE_MARKERS = (".bak", ".new", ".user", ".lock", ".promote.lock", "~", ".DS_Store")

def excluded(path):
    base = os.path.basename(path)
    if base.startswith("."):
        return True
    for m in EXCLUDE_MARKERS:
        if m in base[1:] if m.startswith(".") else base.endswith(m):
            return True
    # ".bak-20260727" 같은 중간 삽입형까지 흡수
    for m in (".bak", ".new", ".user", ".lock"):
        if m in base:
            return True
    return False

def sha256_file(path, nbytes=None):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        if nbytes is None:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        else:
            left = nbytes
            while left > 0:
                chunk = f.read(min(1 << 20, left))
                if not chunk:
                    return None          # 파일이 baseline보다 짧다 = 순수 append 아님
                left -= len(chunk)
                h.update(chunk)
    return h.hexdigest()

def read_inventory():
    """-> (entries, errors). entries = [(tier, selector)]"""
    entries, errors = [], []
    if not os.path.isfile(INVENTORY):
        return entries, ["inventory 부재: %s" % INVENTORY]
    with open(INVENTORY, encoding="utf-8") as f:
        for ln, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.lstrip().startswith("#"):
                continue          # #PROPOSE 포함 — 주석은 전부 비활성
            parts = line.split("\t")
            parts = [p for p in parts if p != ""]
            if len(parts) < 2:
                errors.append("%s:%d 형식 오류(TAB 구분 2필드 필요): %s" % (INVENTORY, ln, line))
                continue
            tier, selector = parts[0].strip(), parts[1].strip()
            if tier not in ("strict", "append", "watch", "watch-soft"):
                errors.append("%s:%d 알 수 없는 tier '%s'" % (INVENTORY, ln, tier))
                continue
            entries.append((tier, _canon(selector)))
    return entries, errors

def expand(entries):
    """인벤토리 -> {abspath: tier}. 결정론 순서."""
    out = {}
    for tier, sel in entries:
        if tier in ("watch", "watch-soft"):
            if not os.path.isdir(sel):
                continue
            for root, dirs, files in os.walk(sel):
                dirs[:] = sorted(d for d in dirs if not d.startswith("."))
                for fn in sorted(files):
                    p = os.path.join(root, fn)
                    if not fn.endswith(".md") or excluded(p):
                        continue
                    out.setdefault(_canon(p), tier)
        else:
            hits = sorted(glob.glob(sel)) if any(c in sel for c in "*?[") else [sel]
            for p in hits:
                if not os.path.isfile(p) or excluded(p):
                    continue
                out[_canon(p)] = tier      # 명시 지정은 watch 상속을 덮는다
    return out

def read_baseline():
    """-> (rows, errors). rows = {path: {tier, sha, size, signed_at}}"""
    rows, errors = {}, []
    if not os.path.isfile(BASELINE):
        return rows, ["baseline 부재: %s (canon-resign.sh --rebuild 로 최초 서명 필요)" % BASELINE]
    with open(BASELINE, encoding="utf-8") as f:
        for ln, raw in enumerate(f, 1):
            line = raw.rstrip("\n")
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 5:
                errors.append("%s:%d 필드 수 오류(5 필요, %d)" % (BASELINE, ln, len(parts)))
                continue
            tier, path, sha, size, signed_at = parts
            rows[path] = {"tier": tier, "sha": sha, "size": int(size), "signed_at": signed_at}
    return rows, errors

def last_signed(path, fallback):
    """서명 원장에서 이 파일의 마지막 정당 서명 시각(없으면 baseline 값)."""
    if not os.path.isfile(LEDGER):
        return fallback
    ts = fallback
    try:
        with open(LEDGER, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    rec = json.loads(line)
                except ValueError:
                    continue
                if rec.get("file") == path:
                    ts = rec.get("ts", ts)
    except OSError:
        pass
    return ts

def added_tail(path, offset, max_lines=6):
    """append tier: baseline 이후 새로 붙은 부분의 앞 몇 줄(경보 본문용)."""
    try:
        with open(path, "rb") as f:
            f.seek(offset)
            data = f.read(4096)
        text = data.decode("utf-8", "replace")
        lines = [l for l in text.splitlines() if l.strip()]
        return lines[:max_lines]
    except OSError:
        return []

def verify():
    entries, inv_err = read_inventory()
    base, base_err = read_baseline()
    errors = inv_err + base_err
    current = expand(entries)

    findings = []     # {level, kind, path, tier, expect, actual, signed_at, note}
    for path in sorted(set(list(current.keys()) + list(base.keys()))):
        in_cur = path in current
        in_base = path in base
        tier = current.get(path) or base.get(path, {}).get("tier", "strict")

        if in_base and not in_cur:
            if os.path.isfile(path):
                continue                      # 인벤토리에서 빠졌을 뿐(설정 변경) — 판정 대상 아님
            findings.append(dict(level="ALERT", kind="DELETED", path=path, tier=tier,
                                 expect=base[path]["sha"], actual="-",
                                 signed_at=base[path]["signed_at"], note="정본 파일이 사라졌다"))
            continue

        if in_cur and not in_base:
            level = "ALERT" if tier in ("strict",) else "NOTICE"
            try:
                actual = sha256_file(path)
                size = os.path.getsize(path)
            except OSError as e:
                errors.append("읽기 실패 %s: %s" % (path, e)); continue
            findings.append(dict(level=level, kind="ADDED", path=path, tier=tier,
                                 expect="-", actual=actual, signed_at="-",
                                 note="베이스라인에 없는 새 정본 파일(%d bytes)" % size))
            continue

        # 양쪽에 존재 — 내용 대조
        b = base[path]
        try:
            actual = sha256_file(path)
            size = os.path.getsize(path)
        except OSError as e:
            errors.append("읽기 실패 %s: %s" % (path, e)); continue
        if actual == b["sha"]:
            continue                          # clean

        if tier == "append":
            prefix = sha256_file(path, b["size"]) if size >= b["size"] else None
            if prefix == b["sha"]:
                tail = added_tail(path, b["size"])
                findings.append(dict(level="NOTICE", kind="APPENDED", path=path, tier=tier,
                                     expect=b["sha"], actual=actual, signed_at=b["signed_at"],
                                     note="순수 append (+%d bytes) | 추가분: %s"
                                          % (size - b["size"], " / ".join(tail) or "(빈 줄)")))
                continue
            findings.append(dict(level="ALERT", kind="REWRITTEN", path=path, tier=tier,
                                 expect=b["sha"], actual=actual, signed_at=b["signed_at"],
                                 note="append 대상인데 **기존 내용이 바뀌었다**(전량 재기록/중간 수정)"))
            continue

        lvl = "NOTICE" if tier == "watch-soft" else "ALERT"
        findings.append(dict(level=lvl, kind="MODIFIED", path=path, tier=tier,
                             expect=b["sha"], actual=actual, signed_at=b["signed_at"],
                             note="%s (%d bytes)" % ("변경 감지" if lvl == "NOTICE" else "무단 변경", size)))

    for f in findings:
        f["last_signed"] = last_signed(f["path"], f.get("signed_at", "-"))
    return findings, errors, current, base

def code_of(findings, errors):
    if errors:
        return 3
    if any(f["level"] == "ALERT" for f in findings):
        return 2
    if findings:
        return 1
    return 0

def main(argv):
    if "--list" in argv:
        entries, err = read_inventory()
        for e in err:
            print("ERR " + e, file=sys.stderr)
        cur = expand(entries)
        for p in sorted(cur):
            print("%s\t%s" % (cur[p], p))
        print("# 총 %d개 파일 (활성 인벤토리 %d줄)" % (len(cur), len(entries)))
        return 3 if err else 0

    findings, errors, cur, base = verify()
    rc = code_of(findings, errors)

    if "--json" in argv:
        print(json.dumps({"exit": rc, "checked": len(cur), "baseline_rows": len(base),
                          "findings": findings, "errors": errors},
                         ensure_ascii=False, indent=2))
        return rc

    print("== canon-verify == %s" % time.strftime("%Y-%m-%dT%H:%M:%S%z"))
    print("대상 %d개 · 베이스라인 %d행" % (len(cur), len(base)))
    for e in errors:
        print("  [ERR]    %s" % e)
    if not findings and not errors:
        print("  [CLEAN]  전 항목 서명 일치")
    for f in findings:
        print("  [%s] %s  %s" % (f["level"].ljust(6), f["kind"].ljust(9), f["path"]))
        print("           tier=%s  기대=%s  실측=%s" % (f["tier"], f["expect"][:16], f["actual"][:16]))
        print("           마지막 정당 서명=%s" % f["last_signed"])
        print("           %s" % f["note"])
    print("exit=%d (0=clean 1=notice 2=ALERT 3=설정오류)" % rc)
    return rc

# ── 내장 배터리 ─────────────────────────────────────────────────────
def self_test():
    import tempfile, shutil, subprocess
    global INVENTORY, BASELINE, LEDGER
    base_dir = tempfile.mkdtemp(prefix="canon-verify-test-")
    fails = []
    try:
        canon = os.path.join(base_dir, "canon"); os.makedirs(canon)
        docs  = os.path.join(base_dir, "docs");  os.makedirs(docs)
        memd  = os.path.join(base_dir, "mem");   os.makedirs(memd)
        d1 = os.path.join(docs, "CLAUDE.md");  open(d1, "w").write("rule one\n")
        idx = os.path.join(memd, "MEMORY.md"); open(idx, "w").write("- [a](a.md)\n")
        m1 = os.path.join(memd, "a.md");       open(m1, "w").write("body a\n")

        INVENTORY = os.path.join(canon, "inventory.conf")
        BASELINE  = os.path.join(canon, "baseline.tsv")
        LEDGER    = os.path.join(canon, "ledger.jsonl")
        open(INVENTORY, "w").write(
            "strict\t%s\nappend\t%s\nwatch\t%s\n" % (d1, idx, memd))

        def sign():
            ents, _ = read_inventory()
            cur = expand(ents)
            with open(BASELINE, "w") as f:
                for p in sorted(cur):
                    f.write("%s\t%s\t%s\t%d\tSIGNED\n"
                            % (cur[p], p, sha256_file(p), os.path.getsize(p)))
        sign()

        # ① 정상
        fnd, err, _, _ = verify()
        if fnd or err: fails.append("①정상인데 finding 발생: %s %s" % (fnd, err))

        # ② strict 변조 → ALERT/MODIFIED
        open(d1, "a").write("INJECTED PARAGRAPH\n")
        fnd, _, _, _ = verify()
        if not any(f["kind"] == "MODIFIED" and f["level"] == "ALERT" for f in fnd):
            fails.append("②strict 변조가 ALERT/MODIFIED로 안 잡힘: %s" % fnd)
        sign()

        # ③ append 순수 추가 → NOTICE/APPENDED
        open(idx, "a").write("- [b](b.md)\n")
        fnd, _, _, _ = verify()
        if not any(f["kind"] == "APPENDED" and f["level"] == "NOTICE" for f in fnd):
            fails.append("③순수 append가 NOTICE/APPENDED로 안 잡힘: %s" % fnd)

        # ④ append 대상의 기존 내용 재기록 → ALERT/REWRITTEN
        open(idx, "w").write("- [HIJACK](x.md)\n- [b](b.md)\n")
        fnd, _, _, _ = verify()
        if not any(f["kind"] == "REWRITTEN" and f["level"] == "ALERT" for f in fnd):
            fails.append("④append 전량 재기록이 ALERT/REWRITTEN으로 안 잡힘: %s" % fnd)
        sign()

        # ⑤ watch 새 파일 → NOTICE/ADDED
        m2 = os.path.join(memd, "c.md"); open(m2, "w").write("new memory\n")
        fnd, _, _, _ = verify()
        if not any(f["kind"] == "ADDED" and f["level"] == "NOTICE" and f["path"] == _canon(m2) for f in fnd):
            fails.append("⑤watch 새 파일이 NOTICE/ADDED로 안 잡힘: %s" % fnd)
        sign()

        # ⑥ watch 기존 파일 수정 → ALERT/MODIFIED
        open(m1, "w").write("body a TAMPERED\n")
        fnd, _, _, _ = verify()
        if not any(f["kind"] == "MODIFIED" and f["level"] == "ALERT" and f["path"] == _canon(m1) for f in fnd):
            fails.append("⑥watch 기존 파일 수정이 ALERT로 안 잡힘: %s" % fnd)
        sign()

        # ⑦ 삭제 → ALERT/DELETED
        os.remove(m1)
        fnd, _, _, _ = verify()
        if not any(f["kind"] == "DELETED" and f["level"] == "ALERT" for f in fnd):
            fails.append("⑦삭제가 ALERT/DELETED로 안 잡힘: %s" % fnd)

        # ⑧ 종료코드 매핑
        if code_of([], []) != 0: fails.append("⑧clean이 0이 아님")
        if code_of([{"level": "NOTICE"}], []) != 1: fails.append("⑧notice가 1이 아님")
        if code_of([{"level": "ALERT"}], []) != 2: fails.append("⑧alert가 2가 아님")
        if code_of([], ["x"]) != 3: fails.append("⑧error가 3이 아님")

        # ⑧-b watch-soft: 기존 파일 수정은 NOTICE, 삭제는 ALERT
        open(INVENTORY, "w").write(
            "strict\t%s\nappend\t%s\nwatch-soft\t%s\n" % (d1, idx, memd))
        open(m2, "w").write("new memory\n")
        sign()
        open(m2, "w").write("new memory TAMPERED\n")
        fnd, _, _, _ = verify()
        if not any(f["kind"] == "MODIFIED" and f["level"] == "NOTICE" for f in fnd):
            fails.append("⑧-b watch-soft 수정이 NOTICE가 아님: %s" % fnd)
        os.remove(m2)
        fnd, _, _, _ = verify()
        if not any(f["kind"] == "DELETED" and f["level"] == "ALERT" for f in fnd):
            fails.append("⑧-b watch-soft 삭제가 ALERT가 아님: %s" % fnd)
        open(INVENTORY, "w").write(
            "strict\t%s\nappend\t%s\nwatch\t%s\n" % (d1, idx, memd))
        sign()

        # ⑨ #PROPOSE 줄은 비활성이어야 한다
        open(INVENTORY, "a").write("#PROPOSE strict\t%s\n" % os.path.join(docs, "nope.md"))
        ents, _ = read_inventory()
        if any("nope.md" in s for _, s in ents):
            fails.append("⑨#PROPOSE 줄이 활성화됨(비활성이어야)")
    finally:
        shutil.rmtree(base_dir, ignore_errors=True)

    if fails:
        print("\n".join("  FAIL " + x for x in fails), file=sys.stderr)
        print("self-test: %d 실패" % len(fails), file=sys.stderr)
        return 1
    print("self-test OK — 11 배터리(정상·strict변조·append정상·append재기록·watch추가·watch수정·삭제·종료코드·watch-soft수정NOTICE·watch-soft삭제ALERT·PROPOSE비활성)")
    return 0

if "--self-test" in sys.argv:
    sys.exit(self_test())
sys.exit(main(sys.argv[1:]))
PYEOF
