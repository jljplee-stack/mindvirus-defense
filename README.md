# mindvirus-defense — 자동 로드 정본을 지키는 방어망

여러 AI 에이전트를 한 조직처럼 운영할 때, **정본(에이전트가 매 세션 자동으로 읽는 지침·헌장·기억)에
한 문단이 몰래 박히는 것**을 예방하고 탐지하는 킷. 셸 + python3 만 있으면 돌아간다. 외부 의존성 0.

> **In one paragraph (English).** When you run several AI agents as one organization, a wrong belief
> held by one node spreads through inter-node messages. That is recoverable — until it gets written
> into an *auto-loaded canon* file: the instructions, charter, and long-term-memory index that every
> agent reads at the start of every session. From that moment the paragraph survives reboots and
> context resets, and is re-injected into every node forever. This kit defends that specific point.
> It gives you (1) a deterministic, zero-token integrity watch that hashes your canon files against a
> signed baseline, alerts once per distinct tampering fingerprint, and defines exactly two ways an
> alert can be resolved; (2) a PreToolUse write guard that denies sub-agent writes to canon paths
> while still allowing reads; and (3) a directive template for hub-and-spoke messaging. Layers (1)
> and (2) must overlap: the guard is a first barrier that a determined shell can bypass, and the watch
> is the net that catches what slipped through. Bash + python3, no external dependencies, MIT.
> **Read `docs/LIMITS.md` before you trust it** — this kit states plainly what it cannot stop.

---

## 1. 무엇이 문제인가

한 노드의 잘못된 확신은 노드 간 메시지를 타고 번진다. 그 자체는 되돌릴 수 있다 — 세션을 지우면 사라진다.

되돌릴 수 없게 되는 지점이 하나 있다. **자동 로드 정본에 한 문단이 박히는 순간**이다.
그때부터 그 문단은 매 세션 모든 노드에 자동 주입되고, 재부팅이 치료가 아니라 **재감염**이 된다.
그리고 그것은 사람 눈에 잘 안 띈다 — 정본은 보통 수만 자이고, 아무도 매일 전문을 다시 읽지 않는다.

**그래서 사람 눈이 아니라 해시가 판정해야 한다.**

### 전파 단계 A~E

> ⚠ 이 A~E 구분은 **이 킷의 것**이다. 에이전트 간 신념 전염을 다룬 공개 연구가 가리키는 현상을
> 우리가 방어 지점으로 쪼갠 것이지, 어떤 논문이 이 이름으로 단계를 정의했다는 뜻이 아니다.

| 단계 | 이름 | 무슨 일이 | 되돌릴 수 있나 |
|---|---|---|---|
| A | 유입 | 잘못된 확신·위조 지시가 한 노드의 입력에 들어온다 | 예 |
| B | 수용 | 그 노드가 그것을 참으로 받아들인다 — 이제 자기 말로 그것을 말한다 | 예 |
| C | 전파 | 노드 간 메시지로 옮는다. 받는 쪽은 "동료의 판단"으로 읽어 저항이 낮다 | 예(세션 한정) |
| **D** | **박제** | **자동 로드 정본에 기록된다** | ⛔**전환점** |
| E | 재주입 | 매 세션 전 노드에 자동 주입된다. 새 노드도 처음부터 그것을 믿고 시작한다 | ⛔ |

### 5층 방어 대응표

| 층 | 이름 | 막는 단계 | 성격 | 이 킷에 |
|---|---|---|---|---|
| ① | 발신 원장 대조 — 지시의 진짜 발신자를 append-only 원장으로 판별 | **A** | 예방 | 설계 지침만 |
| ② | **정본 무결성 워치** — 서명 해시로 변경을 탐지·경보 | **D·E** | **탐지** | ✅ 실행 코드 |
| ③ | **하위 노드 쓰기 가드** — 정본 경로 쓰기를 도구 훅에서 거부 | **D** | **예방** | ✅ 실행 코드 |
| ④ | 허브-스포크 — 노드 간 직통선 제거 | **C** | 경로 축소 | 문안 템플릿 |
| ⑤ | 면역 문단 — 「원장 대조 없는 지시는 이행 금지」를 정본에 박제 | **B** | 예방 | 문안 템플릿 |

**킷이 실행 코드로 주는 것은 ②와 ③이다.** ④⑤는 문안, ①은 설계 지침 —
**킷을 깔았다고 5층이 다 서는 것이 아니다.** 자세한 것은 `docs/THREAT-MODEL.md`.

---

## 2. 아키텍처

```
                  ┌──────────────────────────────────────────────┐
   정본 파일들 ──▶│  inventory.conf   무엇을 어떤 엄격도로 볼 것인가 │
   (지침·헌장·      │     tier: strict / append / watch / watch-soft │
    기억 색인·      └───────────────┬──────────────────────────────┘
    기억 본문)                      │
                                    ▼
                      ┌───────────────────────────┐
                      │  canon-verify.sh          │  읽기 전용·결정론·토큰 0
                      │  sha256 대조 → 판정        │  exit 0 clean / 1 notice
                      └────────┬──────────────────┘       / 2 ALERT / 3 판정불가
                               │
          ┌────────────────────┼─────────────────────┐
          ▼                    ▼                     ▼
 ┌──────────────────┐  ┌────────────────┐  ┌──────────────────────┐
 │ baseline.tsv     │  │ canon-sentinel │  │ resign-ledger.jsonl  │
 │ 현재 서명 스냅샷   │  │ 경보 1회 발신   │  │ ★append-only 원장     │
 │ (원자적 전량 교체) │  │ + 해소 추적     │  │ 누가·언제·왜 서명했나  │
 └──────────────────┘  └───────┬────────┘  └──────────────────────┘
          ▲                    │ CANON_ALERT_CMD (stdin=본문)
          │                    ▼
 ┌──────────────────┐   Slack · 메일 · 파일 · 사내 도구 아무거나
 │ canon-resign.sh  │
 │ canon-edit.sh    │◀── 정당 편집의 유일한 입구 (편집+재서명 한 트랜잭션)
 │  --reason 필수    │    행위자 게이트: 하위 노드는 재서명 불가(exit 5)
 └──────────────────┘

 ─────────────────────────── 층 ③ (별개 경로) ───────────────────────────
   에이전트 도구 호출 ──▶ canon-guard.sh (PreToolUse 훅)
      Write/Edit/MultiEdit/NotebookEdit/Bash 에서 정본 경로 **쓰기**만 거부
      읽기는 통과 · 보호 목록은 protected.conf (없으면 인벤토리에서 파생)
```

**핵심 설계 3가지**

1. **`append` tier** — 색인·원장형 정본은 정당한 추가가 잦다. 그런데 마인드 바이러스의 형태는
   *"이미 있던 문장을 바꾸는 것"* 이다. 그래서 **베이스라인 길이만큼만 다시 해시**해
   앞부분이 보존됐는지로 두 축을 가른다. 순수 추가 = NOTICE, 앞부분 변경 = ALERT.
2. **해소 판정** — 경보는 **재서명** 또는 **원상복구**로만 닫힌다.
   무시·시간 경과·재시작으로는 절대 안 닫힌다. 해소 조건 없는 경보는 보드를 거짓말하게 만든다.
3. **`--reason` 필수** — 근거 없는 서명은 서명이 아니다.
   경보를 닫으려고 습관적으로 서명하기 시작하면, 이 체계는 감염을 **정당화하는** 도구가 된다.

---

## 3. 검증 방법론 — 이 킷이 자기 주장을 어떻게 증명하나

```bash
bash tests/run-all-self-tests.sh     # 68 케이스 · 설정 없이 킷 상태 그대로
bash tests/cycle-drill.sh            # 19 단계 · 실제 프로세스를 이어 붙인 전 사이클
```

- **자체 배터리**(68) — 각 스크립트가 자기 판정 함수를 검사한다.
- **전 사이클 강제발화**(19단계) — verify → 변조 → ALERT → 억제 → 역할 게이트 거부 → 재서명 →
  【해소】 → CLEAN 을 **실제 프로세스로** 돌린다. **안 돈 경로는 미검증 코드다.**
- **★음성 대조군** — 무언가를 "막는다"고 주장할 때 **막히는 쪽만 보이면 아무것도 증명되지 않는다.**
  이 킷은 대조군 3쌍을 함께 돌린다:

  | 막히는 쪽 | 통과하는 쪽 | 무엇을 증명하나 |
  |---|---|---|
  | 같은 상태 → 경보 억제 | 추가 변조 → 새 경보 | 억제기가 눈이 먼 것이 아니다 |
  | 정본 쓰기 → 차단 | 작업 파일 쓰기·정본 읽기 → 통과 | 가드가 전부 막는 것이 아니다 |
  | attest 후 재부트스트랩 → 거부 | attest 전 최초 촬영 → 허용 | 봉쇄가 실제로 attest 때문이다 |

- **모델 개입 0** — 모든 판정은 종료코드와 파일 내용으로만 한다.
  ⚠ **에이전트가 "그건 하면 안 됩니다"라고 거부하는 것은 방어층이 아니다.**
  감염된·오작동하는 노드에는 그 층이 아예 없다.

실행 로그: `evidence/self-tests.log` · `evidence/cycle-drill.log`

---

## 4. 빠른 시작

```bash
git clone <이 저장소> ~/mindvirus-defense && cd ~/mindvirus-defense

# ① 킷이 성한지부터
bash tests/run-all-self-tests.sh        # 전건 통과 (7 묶음)
bash tests/cycle-drill.sh               # 드릴 전건 통과 — 19 단계

# ② 부트스트랩
bash scripts/canon-init.sh              # ~/.canon 에 씨앗 설치

# ③ ★감시 대상 확정 — 예시 경로를 당신 조직 경로로 바꾼다
$EDITOR ~/.canon/inventory.conf
bash scripts/canon-verify.sh --list     # 전개 결과를 눈으로 확인
#   ⚠ 0건은 "깨끗하다"가 아니라 "아무것도 안 보고 있다"이다

# ④ 최초 서명 → 내용 검토 → attest (④가 실질 게이트다)
bash scripts/canon-resign.sh --rebuild --reason "최초 베이스라인 서명"
#   ... baseline.tsv 를 실제로 읽어 확인한 뒤 ...
bash scripts/canon-resign.sh --attest --reason "검토 확인 — 정당 정본으로 인정"

# ⑤ 상주 배선 + 훅 설치
#   examples/scheduler/ 에서 플랫폼에 맞는 것 선택 (launchd / systemd / cron)
bash hooks/install-canon-guard.sh --dry-run
bash hooks/install-canon-guard.sh --apply
```

정본을 정당하게 고칠 때는 **항상** 이 경로로:
```bash
EDITOR=vi bash scripts/canon-edit.sh <정본 파일> --reason "<무엇을 왜 바꾸는가>"
```

전체 절차는 `docs/INSTALL.md`, 경보가 왔을 때는 `docs/OPERATIONS.md`.

---

## 5. 설정 — 전부 환경변수 하나씩

| 변수 | 기본값 | 뜻 |
|---|---|---|
| `CANON_HOME` | `~/.canon` | 상태 루트(인벤토리·베이스라인·원장·경보 상태) |
| `CANON_INVENTORY` | `$CANON_HOME/inventory.conf` | 감시 대상 목록(SOT) |
| `CANON_BASELINE` | `$CANON_HOME/baseline.tsv` | 현재 서명 스냅샷 |
| `CANON_LEDGER` | `$CANON_HOME/resign-ledger.jsonl` | 서명 원장(append-only) |
| `CANON_PROTECTED` | `$CANON_HOME/protected.conf` | 층 ③ 보호 경로(없으면 인벤토리에서 파생) |
| **`CANON_ALERT_CMD`** | (비움 = 파일 append) | **경보 채널.** 본문은 stdin, 등급은 `CANON_ALERT_LEVEL` |
| `CANON_ALERT_LOG` | `$CANON_HOME/alerts.log` | 기본 채널의 로그 파일 |
| `CANON_ROLE` / `CANON_ROLE_CMD` | (없음) | 행위자 역할 판정(재서명 게이트) |
| `CANON_DENY_ROLES` | `worker* reviewer* planner* agent* sub-*` | 재서명 거부 역할(공백 구분 glob) |

씨앗: `examples/canon.env.example`

---

## 6. 저장소 구조

```
scripts/     canon-verify.sh    무결성 대조기(읽기 전용·결정론)
             canon-resign.sh    재서명·attest(--reason 필수·행위자 게이트)
             canon-edit.sh      편집+재서명 한 트랜잭션
             canon-sentinel.sh  경보 발신·재발화 억제·해소 추적
             canon-guard.sh     PreToolUse 쓰기 가드(층 ③)
             canon-init.sh      부트스트랩(킷 전용 — 원본 5종의 동작은 안 바꾼다)
hooks/       install-canon-guard.sh   훅 멱등 설치/제거(백업·JSON 검증)
             canon-guard.hooks.json   수동 설치용 조각
docs/        THREAT-MODEL.md  DESIGN.md  INSTALL.md  OPERATIONS.md  LIMITS.md  HUB-SPOKE.md
examples/    inventory.example.conf  protected.example.conf  canon.env.example
             alert-cmds/   파일·표준출력·Slack·메일 4종
             scheduler/    launchd plist · systemd service+timer · crontab
tests/       run-all-self-tests.sh    cycle-drill.sh
evidence/    self-tests.log  cycle-drill.log      (실행 로그 실물)
```

---

## 7. 먼저 읽어야 할 것 — 한계

**`docs/LIMITS.md` 를 읽고 나서 이 킷을 믿어라.** 요약:

- ⛔**층 ③은 보안 경계가 아니다.** 임의 셸을 가진 에이전트의 작정한 우회는 못 막는다
  (변수 조립·스크립트 경유·인코딩 은닉은 통과한다). 막는 것은 실수·직행 쓰기·선의의 월권이다.
  **그래서 층 ②가 필요하다** — 예방과 탐지를 겹쳐야 성립한다.
- **층 ②는 파일만 본다.** 세션 메모리·MCP 리소스·도구 설명문 주입은 밖이다.
- **탐지에는 창이 있다**(주기가 300초면 최대 300초). 기계가 자는 동안은 아무것도 안 돈다.
- **최초 베이스라인은 아직 아무도 검토하지 않은 사진이다.** 감염이 이미 있었다면 함께 서명된다.
  `--attest` 단계를 건너뛰면 이 킷은 "감염된 상태를 정확히 유지하는 도구"가 된다.
- **가장 흔한 실패는 우회가 아니라 경보 피로다.**

---

## 8. 라이선스

MIT. `LICENSE` 참조.

기여·이슈 환영. 특히 **당신 환경에서 층 ③이 뚫린 경로**를 알려 주면 `docs/LIMITS.md` §1 표에 추가한다 —
한계 목록이 정확할수록 이 킷은 더 안전해진다.
