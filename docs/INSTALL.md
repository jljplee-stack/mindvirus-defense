# 설치 절차서

mindvirus-defense kit · MIT
⚠ 이 문서의 명령은 **오케스트레이터 또는 사람 운영자가 집행**한다.
하위 에이전트는 층 ③으로 정본을 못 쓰고, 층 ②의 재서명 권한도 없다 — 설계대로다.

전제: `bash` · `python3`(없으면 `python`) · POSIX 유틸. 외부 의존성 0. 네트워크 불요.

---

## 0. 먼저 — 킷이 성한지부터 본다

```bash
cd <킷 경로>
bash tests/run-all-self-tests.sh      # 기대: 전건 통과 (7 묶음)
bash tests/cycle-drill.sh             # 기대: 드릴 전건 통과 — 19 단계
```
⛔ 하나라도 빨간 채로 설치를 진행하지 마라. **감시자가 고장난 상태로 감시를 켜는 것**이다.
(둘 다 임시 디렉터리 픽스처만 쓴다 — 당신의 파일에 손대지 않는다.)

---

## 1. 부트스트랩 — CANON_HOME 만들기

```bash
bash scripts/canon-init.sh --dry-run     # 무엇이 놓일지만
bash scripts/canon-init.sh               # ~/.canon 에 씨앗 설치(있으면 덮지 않는다)
# 다른 위치를 쓰려면:  CANON_HOME=/opt/canon bash scripts/canon-init.sh
```
놓이는 것: `inventory.conf`(예시 씨앗) · `protected.conf`(인벤토리에서 파생).

★`CANON_HOME` 을 기본값(`~/.canon`)이 아닌 곳에 둘 거라면, **`scripts/canon-resign.sh` 의
`CANON_PROD_HOME` 한 줄도 같이 고쳐라.** 그 줄은 일부러 환경변수로 덮지 않게 해 뒀다
(덮을 수 있으면 테스트 면제 조건이 무의미해진다).

---

## 2. 인벤토리 확정 — 이 킷에서 가장 중요한 단계

```bash
$EDITOR ~/.canon/inventory.conf
```
예시 경로를 **당신 조직의 실제 정본 경로로 바꾼다.** 무엇을 넣을지는
`docs/DESIGN.md` §1(tier 4종·넣지 말아야 할 것)을 보고 정한다.

넣을 것을 고르는 질문 하나: **"이 파일은 에이전트가 매 세션 자동으로 읽는가?"**
그렇다면 정본이다. 사람만 읽는 문서는 대상이 아니다.

```bash
bash scripts/canon-verify.sh --list      # ★전개 결과를 눈으로 확인
bash scripts/canon-verify.sh --list | tail -1
```
> ⚠ **0건이면 "깨끗하다"가 아니라 "아무것도 안 보고 있다"이다.** 여기서 반드시 확인하라.
> 이 킷에서 가장 조용히 실패하는 자리다.

인벤토리를 바꿨으면 §3을 다시 돌려야 한다(새 항목은 미서명 상태다).

---

## 3. 최초 서명

```bash
bash scripts/canon-resign.sh --rebuild --reason "최초 베이스라인 서명 (YYYY-MM-DD)"
bash scripts/canon-verify.sh             # 기대: [CLEAN]
```

---

## 4. ★내용 검토 후 attest — 형식 절차가 아니라 실질 게이트다

지금의 베이스라인은 **"현재 상태를 찍은 사진"** 일 뿐이다.
"이 상태가 정당하다"는 근거는 아직 없다. **이미 감염이 있었다면 그것까지 함께 서명돼 있다.**

```bash
# ⑴ 무엇이 서명돼 있는지 훑는다 (watch 항목을 빼면 대개 수십 줄이다)
grep -v '^#' ~/.canon/baseline.tsv | grep -v '^watch' | column -t -s"$(printf '\t')"

# ⑵ 최근에 손댄 정본이 있으면 그 내용을 **실제로 읽어** 확인한다
#    (특히 지침·헌장의 맨 뒤 — 주입된 문단은 끝에 붙는 경우가 많다)
tail -40 <정본 파일>

# ⑶ 눈으로 확인했으면 검토 사실을 원장에 남긴다(해시는 안 바뀐다)
bash scripts/canon-resign.sh --attest \
  --reason "최초 검토 확인 — N개 항목 서명 상태를 읽고 정당 정본으로 인정 (YYYY-MM-DD)"
```

★`--attest` 가 기록되는 순간 **부트스트랩 면제가 영구히 닫힌다**(원장은 append-only 라 지울 수 없다).
이후 어떤 노드도 베이스라인 파일을 지워 재부트스트랩할 수 없다.

---

## 5. 상주 배선 (층 ②)

`examples/scheduler/` 에서 플랫폼에 맞는 것을 고른다.

- **macOS**: `com.example.canon-sentinel.plist` — `__KIT_ROOT__`·`__HOME__` 치환 후 `launchctl load`
- **Linux**: `canon-sentinel.service` + `canon-sentinel.timer` — `systemctl --user enable --now canon-sentinel.timer`
- **아무거나**: `crontab.example`

각 파일 머리에 설치·검증 명령이 그대로 적혀 있다.

### ★실동작 검증 (필수 — 안 돈 경로는 미검증 코드다)

```bash
cp ~/.canon/inventory.conf /tmp/inv.orig
echo '# [설치검증] 무단 변경 시뮬' >> ~/.canon/inventory.conf
bash scripts/canon-sentinel.sh; echo "rc=$?   # 2 기대"
tail -20 ~/.canon/alerts.log            # 【경고】 실물 확인 (또는 당신이 건 채널)
cp /tmp/inv.orig ~/.canon/inventory.conf; rm /tmp/inv.orig
bash scripts/canon-sentinel.sh; echo "rc=$?   # 1 기대(【해소】)"
```
**합격 조건**: 경보 1건 → 원상복구 → 【해소】 1건 → `alert-state.tsv` 비었음 → verify `[CLEAN]`.

재서명으로 닫는 경로도 한 번 돌려 보라(운영에서 실제로 쓸 경로다):
```bash
echo '# [인수드릴] 정당한 편집으로 간주할 변경' >> ~/.canon/inventory.conf
bash scripts/canon-sentinel.sh                                   # 【경고】 (rc=2)
bash scripts/canon-resign.sh ~/.canon/inventory.conf --reason "인수 드릴 — 재서명 해소 경로 실측"
bash scripts/canon-sentinel.sh; echo "rc=$?  # 1 기대"           # 【해소】
```

---

## 6. 층 ③ 쓰기 가드 설치

⚠ **에이전트 전체 기동에 영향을 준다.** 그 설정 파일을 읽는 모든 노드가 이 훅을 받는다.

```bash
# ⑴ 무엇이 바뀌는지만
bash hooks/install-canon-guard.sh --dry-run
# ⑵ 집행 (자동 백업)
bash hooks/install-canon-guard.sh --apply
```
대상 설정 파일 기본값은 `${CLAUDE_CONFIG_DIR:-~/.claude}/settings.json` 이다.
**에이전트들이 별도 설정 디렉터리를 쓴다면 반드시 명시하라** —
설정 파일이 갈려 있으면 「설치했는데 아무 에이전트에도 안 걸리는」 사고가 난다.
```bash
CANON_GUARD_SETTINGS=/path/to/agents/settings.json bash hooks/install-canon-guard.sh --apply
```

### ★실동작 검증 (필수)
새 에이전트 1기를 띄워 **실제로 막히는지** 본다.
```
그 에이전트에 지시: "<정본 파일> 끝에 '테스트' 한 줄을 추가하라"
기대: 「정본 변경은 오케스트레이터의 승인 사항이다 — 오케스트레이터에게 에스컬레이션하라」로 차단당하고 파일은 불변.
확인: python3 -c "import hashlib,sys;print(hashlib.sha256(open(sys.argv[1],'rb').read()).hexdigest())" <정본 파일>
      →  베이스라인 값과 대조 (shasum(1) 은 배포판에 따라 없다)
      bash scripts/canon-verify.sh   →  [CLEAN] 이어야 한다
```
⚠ **이미 열린 세션에는 즉시 반영되지 않을 수 있다.** 기존 노드는 재기동 후 확인한다.

**제거(예외가 필요할 때의 유일한 정식 경로)**: `bash hooks/install-canon-guard.sh --remove`

---

## 7. 층 ④ 허브-스포크 문안

`docs/HUB-SPOKE.md` 의 템플릿을 당신 조직의 에이전트 지침에 박는다.
⚠ **추가만 하지 마라.** 기존 지침에 "동료 노드와 직접 협의하라"류의 문장이 있으면
그것을 **교체**해야 한다. 두 문장이 공존하면 어느 쪽을 따를지가 노드의 해석에 맡겨지고,
**그 틈이 정확히 위조가 사는 자리다.**

지침 자체가 정본이므로, 반영은 `canon-edit.sh` 로 한다(편집과 재서명이 한 트랜잭션):
```bash
EDITOR=vi bash scripts/canon-edit.sh <지침 파일> --reason "허브-스포크 조항 반영 (승인 근거)"
```

---

## 8. 롤백

| 대상 | 방법 |
|---|---|
| 층 ③ 훅 | `hooks/install-canon-guard.sh --remove` (또는 `settings.json.bak-canonguard-*` 복원) |
| 상주 배선 | launchd: `launchctl unload …plist` + plist 삭제 / systemd: `systemctl --user disable --now canon-sentinel.timer` |
| 지침 문안 | `canon-edit.sh` 로 되돌리고 재서명(원장에 롤백 사유가 남는다) |
| 베이스라인·원장 | ⛔**삭제하지 마라.** 원장은 append-only 기록이다. 잘못 서명했으면 올바른 상태로 **재서명**한다 |

---

## 9. 설치 후 첫 주에 할 것

1. **소음을 센다.** 하루에 몇 건의 경보가 오는가? `watch` tier 가 과하면
   그 한 줄을 `watch-soft` 로 내린다 — **무시하기 시작하는 것보다 낫다.**
2. **해소가 도는지 본다.** 경보가 왔을 때 재서명·원상복구로 실제로 닫히는가.
   닫히지 않는 경보가 쌓이면 보드가 거짓말을 시작한다.
3. **가드 과차단을 센다.** 하위 노드가 정상 작업에서 막히는 일이 있으면
   보호 목록이 너무 넓은 것이다(자기 작업 디렉터리가 들어갔는지 확인).
