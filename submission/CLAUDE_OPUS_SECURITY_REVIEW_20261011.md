# Claude Opus 보안 검토 — 실행 증거와 재현 확인

> 이 문서는 수정 전 발견 기록이다. 후속 수정과 재검증은 `CLAUDE_OPUS_REMEDIATION_20261011.md`를 따른다.

## 실행 기록

- 검토일: 2026-10-11
- 실행 도구: Claude Code 2.1.287. `--model opus --effort high`로 실행했고, 응답 이벤트의 실제 모델은 `claude-opus-5-5`였습니다.
- 소요 시간: 608.53초. Read로 읽은 경로는 55개이며, 일부 파일은 필요한 구간만 읽었습니다. 상세 범위는 아래 Claude 원문에 있습니다.
- 검토 대상: 현재 서명된 제출 소스 ZIP의 격리 사본. 제품 소스 143개와 manifest 1개입니다. 비밀키·실제 DB·암호화 백업은 제공하지 않았습니다.
- 허용 도구: Read, Glob, Grep. Claude는 명령 실행·파일 수정·외부 자료 조회를 하지 않았습니다. 사본의 검토 전후 해시가 일치합니다.
- 참고 가이드: Claude는 기존 `FULL_GUIDE_*.md` 검토 기록을 읽었습니다. 원본 가이드 PDF 5개를 이번 검토에서 다시 읽은 것은 아닙니다.
- 결과: **Critical 0 / High 0 / Medium 1 / Low 4 / 정보성 7**. 정적 검토 결과이며 CVE 스캔 집계와 구분합니다.
- 이번 작업에서는 제품 코드를 수정하지 않았습니다. 아래 발견 사항은 아직 미조치 상태입니다.

## Codex의 추가 확인

| 항목 | 확인 결과와 한계 |
|---|---|
| M1: 공유 요청 제한 저장소의 전역 상한 | 재현 확인. 별도 합성 DB에서 상한을 3행으로 줄이고 공개 검증 요청 3개로 채우자 관리자 요청이 같은 창과 다음 창에서 모두 거부됐습니다. 실제 1만 행 원격 부하 공격을 실행한 결과는 아닙니다. |
| L1: IPv6 site-local 주소 누락 | 현재 검증된 Docker 이미지의 Python 3.12.15에서 `fec0::1`의 `is_global=True`, `is_reserved=False`, `is_site_local=True`와 현재 필터 통과를 확인했습니다. 네트워크를 끈 컨테이너로 주소 판정만 검사했으며 내부 서버 접속은 시도하지 않았습니다. |
| L2: 백업 롤백 식별 정보 부족 | 코드에서 인증된 생성 시점·세대 정보가 없음을 확인했습니다. 오래된 백업이 폐기 전 상태를 되살리는 동작은 기존 복구 시험에 이미 기록돼 있습니다. 이번에는 실제 운영 백업을 다시 복원하지 않았습니다. |
| L3: 레거시 키 경로 충돌 | 유효한 입력 `aa-b`/`c`와 `aa`/`b-c`가 같은 `aa-b-c.pem` 경로가 되는 것을 확인했습니다. Claude 원문의 `a`는 기관 ID 최소 길이 조건을 만족하지 않으므로 예시는 이 값으로 정정합니다. 실제 개인키를 읽거나 변경하지 않았습니다. |
| L4: CRL 만료 시 전체 앱 시작 실패 | 코드 동작을 확인했습니다. 유효한 CRL을 시작 조건으로 요구하는 기존 정책의 가용성 위험입니다. 분석 기능만 차단하는 권고는 보안 정책과 함께 검토해야 합니다. 실제 운영 CRL을 만료시키거나 서비스를 재시작하지 않았습니다. |

우선 수정 대상은 M1의 그룹 간 용량 간섭과 L1의 주소 필터 누락입니다. L2·L3는 복구·키 관리 보완으로 이어집니다. L4는 기존 시작 정책을 유지할지 기능별로 실패를 분리할지 결정이 필요합니다.

Claude의 OS High 8종 평가는 제출된 인벤토리·스캔·실행 증거의 일관성을 확인한 것입니다. 이번 검토는 최신 취약점 DB를 새로 조회하지 않았습니다. 휠에 포함된 네이티브 라이브러리의 검사 누락 등 정보성 지적은 추가 조사 대상이며, 확인된 CVE로 집계하지 않습니다.

## 증거 식별자

- 검토 소스 ZIP SHA-256: `cbfe5847b1006adb18dbd627d78012b6f480e8e83f602594e999f1a3e2259306` (검토 후 동일)
- Claude 원문 SHA-256: `a238eae72c6566c5d5a96436b4909bfc0c2878f8732637894a662e5e8a6f4d8b`
- 실제 모델: `claude-opus-5-5` / 요청 effort: `high`

---

## Claude 원문

아래 원문은 문장을 보존했습니다. 파일 링크의 대상만 현재 작업 경로로 바꿨으며, 예시 정정과 재현 결과는 위 표를 우선합니다.

# OnjeonQR 독립 보안 검토 보고서 (정적 검토)

**결론:** Critical·High 등급 발견은 없습니다. Medium 1건, Low 4건, 정보성 7건을 보고합니다. 이는 이번 범위에서 고위험 결함을 찾지 못했다는 뜻이며, 제품 전체가 안전하다는 보증은 아닙니다. 아래 등급 집계는 Trivy가 보고한 CVE 건수와 별개의 수치입니다.

---

## 1. 범위와 방법

- **검토 방식:** Read, Glob, Grep만 사용한 읽기 전용 정적 검토입니다. 시험·빌드·컨테이너는 실행하지 않았습니다. 문서에 적힌 실행 결과는 "제출된 증거"로 구분해 인용합니다.
- **전체를 읽은 파일**
  - 백엔드: `src/onjeon/` 아래 `api.py`, `crypto.py`, `storage.py`, `analyzer.py`, `cli.py`, `__init__.py`
  - 프런트엔드: `App.tsx`, `CitizenView.tsx`, `IssuerView.tsx`, `QrReader.ts`, `api.ts`, `main.tsx`, `index.html`, `vite.config.ts`, `public/sw.js`, `dist/index.html`
  - 배포·CI: `Dockerfile`, `compose.yaml`, `compose.security.yaml`, `.dockerignore`, `.gitignore`, `.github/workflows/ci.yml`
  - 스크립트: `secure_profile.py`, `run_tls_server.py`, `create_local_tls_fixture.py`, `check_docker_runtime.py`, `check_encrypted_docker_backup.py`, `build_submission.py`, `verify_submission.py`, `check_recovery.py`, `check_legacy_credentials.py`, `run_security_demo.py`, `prepare_demo.py`, `lock_dependencies.py`, `zap_local_plan.yaml`
  - 제출 문서: `SECURITY_CHECKLIST_49`, `GUIDE_SECURITY_REVIEW`, `SECURITY_CONDITIONS_REVIEW`, `SECURITY_CONDITIONS_TLS`, `DOCKER_IMAGE_SCAN.md`, `DOCKER_RUNTIME_CHECK.md/json`, `DOCKER_BACKUP_CHECK.json`, `TEST_REPORT`, `OPERATION_SECURITY`, `RECOVERY_CHECK`, `RELEASE_VERIFICATION`, `FULL_GUIDE_01/02/03/04_05`
  - 시험: `tests/test_storage.py` 전체
- **일부만 읽은 파일**
  - `tests/test_api.py`: 1–140행, 330–529행
  - `tests/test_analyzer.py`: 150–224행, 그리고 전체 시험 이름 목록
  - `DOCKER_IMAGE_SCAN.json`: 최종 Alpine 결과(7745행~), `final_runtime_observation`, `previous_eight_high_resolution`
  - `demo_flow.py`, `evaluate_product.py`, `generate_supply_chain.py`: 비밀 접근, subprocess, 네트워크 사용 여부만 grep으로 확인
  - 빌드된 dist JS: 현재 소스와 일치하는지 표본 문자열로 확인
- **읽지 않은 파일:** `test_network.py`, `test_operational_tools.py`, 프런트 시험, SBOM, `SUPPLY_CHAIN_VALIDATION`, `SECURITY_CONDITIONS_BACKEND/TOOLS`, `package-lock`, `requirements` lock, `RELEASE_SIGNATURE.json`(스냅숏에 없음)

---

## 2. 발견 사항 (우선순위 순)

### M1 (Medium): 요청 제한 상태가 전역으로 공유되어 관리자까지 저비용으로 잠글 수 있음

**위치**
- [storage.py:72-73](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/src/onjeon/storage.py:72>): 보존 300초, 전체 1만 행
- [storage.py:103-104](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/src/onjeon/storage.py:103>): 오래된 행 정리
- [storage.py:124-126](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/src/onjeon/storage.py:124>): 1만 행에 도달하면 새 출처를 모두 거부
- [api.py:281-297](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/src/onjeon/api.py:281>): 요청 그룹 분류와 제한 호출

**원인.** 1만 행 상한은 `admin`, `issuer`, `verify`, `analyze` 네 그룹이 함께 씁니다. 카운터 키에 분 단위 창(window)이 들어 있어서, 모든 클라이언트는 매분 새 행이 필요합니다. 그런데 판정에는 현재 분의 행만 쓰이는데도, 지난 행이 5분간 남아 표를 차지합니다.

**변형 B: 직접 노출된 배포 (새로 보고하는 코드 문제)**
- **선행 조건:** IPv6로 서비스에 도달 가능하고, 공격자가 /48 정도의 주소 대역을 가진 경우. 터널 서비스로 무료로 얻을 수 있습니다. IPv4라면 약 2,000개 주소 풀이 필요합니다.
- **공격 흐름:**
  1. 공격자가 분당 약 2,000개의 서로 다른 /64에서 아무 보호 경로로 요청을 1건씩 보냅니다(약 33 rps). 제한 판정이 인증과 본문 검사보다 먼저 일어나므로 잘못된 요청이어도 행이 생깁니다.
  2. 5분 안에 1만 행이 찹니다.
  3. 이후 현재 분에 행이 없는 모든 출처가 429를 받습니다. 정상 사용자와 관리자도 매분 새 행이 필요하므로 사실상 전원이 거부됩니다.
  4. 매분 경계에 오래된 행이 빠지면 공격자가 버스트로 그 자리를 먼저 채워 상태를 유지합니다.
- **영향:** 시민 검증, 기관 발급·폐기, 관리자의 키 폐기·기관 비활성화가 모두 중단됩니다. 사고가 났을 때 대응 수단이 막히는 셈입니다. 무결성과 기밀성에는 영향이 없습니다.

**변형 A: 프록시 뒤 배포 (조건은 공개됨, 영향 분석은 누락)**
- `compose.yaml`은 `127.0.0.1`에만 바인딩하고 프록시 헤더를 신뢰하지 않습니다(`--no-proxy-headers`). 따라서 실제 배포에는 프록시가 필요하고, 그러면 모든 사용자가 같은 출처로 집계됩니다.
- 공격자 1명이 `/admin/*`에 토큰 없이 분당 31회만 보내도 실제 관리자가 그 분 동안 429를 받습니다. 시민 분석은 서비스 전체에서 분당 10회, 검증은 분당 60회로 묶입니다.
- README는 "프록시 집계"만 언급하고 관리자 잠금 영향은 다루지 않습니다.

**함께 있는 쓰기 잠금 문제**
- 모든 공개 요청이 SQLite에 쓰기 트랜잭션을 열고, 잠금 대기는 1초입니다([storage.py:110](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/src/onjeon/storage.py:110>)).
- `issue_qr`는 키 복호화와 PNG 생성 동안 쓰기 잠금을 쥐고 있습니다([api.py:516-562](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/src/onjeon/api.py:516>)).
- 그래서 부하가 몰리면 정상 요청도 "제한기 사용 불가" 429로 거부됩니다.

**시험 커버리지**
- `test_shared_rate_counter_privacy_expiry_and_capacity_fail_closed`는 상한을 3으로 줄여 거부 동작만 확인합니다.
- `test_issuer_flood_does_not_exhaust_admin_bucket`은 같은 출처 안에서 그룹이 분리되는지만 봅니다.
- 그룹을 넘어 전역 상한이 소진되는 상황은 시험하지 않습니다.
- `CLAUDE_REVIEW.md:14`의 "관리자·기관 요청 분리"는 출처별 버킷에만 맞는 말이고, 전역 상한에는 해당하지 않습니다.

**권장 수정**
1. 현재 분보다 이전 창의 행을 즉시 삭제합니다(`window_started_at < 현재 창`). 이 행들은 판정에 쓰이지 않으므로 지워도 우회가 생기지 않으며, 점유량이 약 1/5로 줄어듭니다.
2. 상한을 그룹별로 나누거나 `admin`/`issuer`용 여유분을 따로 확보합니다.
3. 관리자 API를 별도 리스너나 네트워크 허용목록으로 분리합니다.
4. 프록시를 쓸 경우 신뢰할 프록시 CIDR을 지정하고 `forwarded_allow_ips`를 설정합니다.
5. `verify` 그룹으로 상한을 채운 뒤에도 관리자 요청이 성공하는지 확인하는 회귀 시험을 추가합니다.

**확신도:** 동작 메커니즘은 높음. 실제 악용 가능성은 IPv6 노출 여부에 따라 중간.

---

### L1 (Low): SSRF 필터가 IPv6 site-local 대역(fec0::/10)을 막지 않음

**위치:** [analyzer.py:108-117](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/src/onjeon/analyzer.py:108>)

**원인.** Python의 `ipaddress` 모듈은 사설 대역 목록에 `fe80::/10`(link-local)과 `fc00::/7`(ULA)만 넣고, 폐기된 `fec0::/10`은 넣지 않습니다. `fec0::/10`은 예약 대역 `FE00::/9` 범위에도 들어가지 않습니다. 그래서 `fec0::1`은 `is_global`이 True이고 `is_reserved`는 False가 되어, 코드의 공개 주소 검사를 통과할 것으로 판단합니다.

- **선행 조건:** 서버 네트워크에 `fec0::/10` 경로가 실제로 있는 레거시 환경. 드문 경우입니다.
- **공격 흐름:** 공격자가 자기 도메인의 AAAA 레코드를 `fec0::내부호스트`로 설정 → `/analyze` 요청 → 서버가 내부 호스트 443 포트로 TLS 연결 후 HEAD 요청을 보냅니다.
- **영향 완화 요소:** HEAD 요청만 보내고, 443 포트로만 연결하며, TLS 호스트명 검증이 필요해서 실제 영향은 내부 서비스가 존재하는지 탐지하는 수준입니다.
- **시험:** `test_multicast_and_translation_addresses_are_blocked`의 매개변수에 `fec0::` 주소가 없습니다.
- **권장 수정:** `address.is_site_local`을 명시적으로 차단하거나, IPv6는 `2000::/3`만 허용하는 방식으로 바꿉니다. 시험 매개변수도 추가합니다.
- **확신도:** 중간. 대상 런타임(Python 3.12.15)에서 `ipaddress.ip_address("fec0::1").is_global`을 직접 실행해 확인하시길 권합니다.

---

### L2 (Low): 암호화 백업에 인증된 시점 정보가 없어 롤백을 감지할 수 없음

**위치:** [secure_profile.py:200-204](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/scripts/secure_profile.py:200>), [secure_profile.py:250-252](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/scripts/secure_profile.py:250>), [secure_profile.py:260-301](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/scripts/secure_profile.py:260>)

**원인.** AES-GCM의 AAD(추가 인증 데이터)가 고정 헤더뿐이고, 백업 묶음에는 생성 시각, 순번, 감사 로그 최대 ID 같은 정보가 없습니다.

- **선행 조건:** 운영자가 실수로 오래된 백업을 복원하는 경우. 또는 백업 저장소에 쓰기 권한은 있지만 백업 키는 없는 공격자가 최신 백업을 예전의 정상 백업으로 바꿔치기하는 경우.
- **공격 흐름:** 오래된 백업을 복원하면 다음이 조용히 되살아납니다.
  - 폐기된 QR이 다시 trusted로 판정됨
  - 교체 전의 유출된 기관 토큰
  - 폐기된 서명 키
- **이미 공개된 부분:** `check_recovery.py`가 이 현상을 재현합니다(`stale_backup_revives_subsequently_revoked_qr`). `RECOVERY_CHECK.md`에는 "백업 이후 변경을 재적용"하라는 절차가 있습니다.
- **코드 차원의 문제:** 그 절차를 실행하려면 백업 시점을 알아야 하는데, 현재 코드는 신뢰할 수 있는 시점 정보를 제공하지 않습니다. 파일 수정 시각(mtime)은 인증되지 않은 값입니다.
- **권장 수정:**
  1. 백업 묶음에 `created_at`, `max(audit_events.id)`, DB 해시를 넣어 함께 인증하고, 복원 결과에 출력합니다.
  2. 백업 ID를 AAD에 묶습니다.
  3. 외부에 단조 증가하는 순번을 기록하고, 더 오래된 백업은 `--allow-rollback` 옵션 없이는 복원을 거부합니다.
  4. 폐기 내역을 추가 전용 저널로 따로 보관하고, 복원 후 자동으로 재적용합니다.
- **확신도:** 높음.

---

### L3 (Low): 레거시 평면 키 경로가 기관 간에 충돌할 수 있음

**위치:** [api.py:196-200](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/src/onjeon/api.py:196>). 또한 `signing_keys.public_key`에 고유 제약이 없습니다([storage.py:24-31](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/src/onjeon/storage.py:24>)).

**원인.** 레거시 경로 `{기관ID}-{키버전}.pem`은 두 값 모두에 하이픈이 허용되어 모호합니다. 예를 들어 기관 `a-b`의 키 `c`와 기관 `a`의 키 `b-c`가 모두 `a-b-c.pem`이 됩니다. 중첩 경로 파일이 없으면 이 레거시 경로로 넘어갑니다.

- **선행 조건:** 관리자가 다른 기관의 공개키를 등록하는 실수. 관리자는 신뢰된 주체이므로 외부 공격 경로는 아닙니다.
- **영향:** 한 기관의 개인키 파일로 다른 기관 명의의 QR에 서명할 수 있게 됩니다. production 모드에서도 이 fallback이 켜져 있습니다.
- **권장 수정:** production에서는 레거시 fallback을 끄거나, 기관 간 공개키 중복을 금지합니다.
- **확신도:** 메커니즘은 높음. 악용 가능성은 낮음.

---

### L4 (Low): CRL이 만료되면 핵심 서비스 전체가 시작되지 않음

**위치:** [api.py:226-227](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/src/onjeon/api.py:226>), [analyzer.py:69-72](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/src/onjeon/analyzer.py:69>)

**원인.** CRL은 서명 없는 URL 분석기에만 필요합니다. 그런데 production에서는 앱 시작 시점에 CRL이 유효해야 하므로, CRL이 만료되면 서명 QR 검증, QR 폐기, 관리자 API까지 함께 내려갑니다.

- **선행 조건:** CRL 갱신이 늦어진 상태에서 재시작(배포, 장애, 재부팅)이 일어나는 경우. `compose.yaml`이 `restart: unless-stopped`이므로 재시작이 반복되는 루프에 빠집니다. 로컬 프로필의 시험 CRL은 2일 뒤 만료됩니다.
- **영향:** 사고 대응이 필요한 시점에 폐기 API를 쓸 수 없습니다.
- **참고:** 서비스가 이미 실행 중일 때는 요청 단위로 `blocked/tls_invalid`를 반환하며 안전하게 실패하는 처리가 이미 있습니다. 시작 시점만 문제입니다.
- **권장 수정:** 시작할 때는 설정 형식만 검사하고, CRL이 만료됐으면 분석 기능만 끈 채로 시작합니다. health 응답에 degraded 상태와 경보를 내보냅니다.
- **확신도:** 높음.

---

### 정보성 (취약점으로 집계하지 않음)

1. **소스 ZIP 경로 검사가 운영체제에 따라 다르게 동작:** [verify_submission.py:19-21](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/scripts/verify_submission.py:19>)은 `Path(name)`을 씁니다. POSIX에서는 `..\x`나 `C:/x` 같은 이름이 통과합니다. 1차 방어선은 서명 검증이지만 `PurePosixPath`와 `PureWindowsPath`로 이중 검사하는 편이 낫습니다.
2. **Docker 빌드 재현 불가:** [Dockerfile:13](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/Dockerfile:13>)의 `zlib=1.3.2-r1` 고정은 Alpine 저장소가 구버전을 보관하지 않으므로 나중에 빌드가 실패하거나 다른 이미지가 나옵니다. 검사를 마친 digest `1e5f37…` 그대로 배포하고, 다시 빌드하면 재검사해야 합니다.
3. **TLS 서버 키에 같은 암호 재사용:** `ONJEON_KEY_PASSWORD`를 기관 서명키와 TLS 서버 키 암호에 함께 씁니다([create_local_tls_fixture.py:47-48](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/scripts/create_local_tls_fixture.py:47>), [run_tls_server.py:23](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/scripts/run_tls_server.py:23>)). 시험 프로필 범위입니다.
4. **데모 스크립트가 운영 DB를 건드릴 수 있음:** [prepare_demo.py:15](<C:/Users/ekffu/Desktop/(26.09.22)소개딩/코딩/scripts/prepare_demo.py:15>)는 환경 변수 설정을 그대로 쓰고 발급 토큰을 화면에 출력합니다. 운영 환경 변수가 잡힌 셸에서 실행하면 운영 DB에 데모 기관이 생깁니다.
5. **오래된 문서 주장:** `FULL_GUIDE_02.md:56`과 `FULL_GUIDE_03.md:64`는 "요청 제한이 단일 프로세스 메모리"라고 적었지만, 현재 코드는 SQLite 공유 카운터입니다.
6. **`compose.yaml`의 비밀 환경 변수:** `docker inspect`로 비밀이 보일 수 있습니다. 이미 공개된 조건이므로 새 발견이 아닙니다.
7. **빌드 단계 npm 설치 스크립트:** Docker 웹 빌드 단계의 `npm ci`가 의존성의 설치 스크립트를 실행합니다. lock 파일의 무결성 검증이 있어 위험은 낮습니다. `--ignore-scripts` 적용을 검토해 볼 만합니다.

---

## 3. 오탐 점검: 확인했지만 문제가 없던 영역

- **QR 서명과 정규화**
  - base64url 정규형 확인, 원문이 정규화 JSON과 같아야 함, 정확히 8개 필드, bool이 int로 섞이지 않게 차단, 서명 64바이트 확인
  - 중복 JSON 키는 재인코딩 결과가 원문과 달라져 거부됨
  - 발급 DB의 payload 해시를 대조하므로, 서명 키가 유출되어도 DB에 발급 기록이 없는 위조 QR은 trusted가 되지 않음
- **인가와 경쟁 조건**
  - 발급·폐기·관리자 변경이 모두 `BEGIN IMMEDIATE` 안에서 인증과 상태 변경을 함께 처리
  - 검증은 하나의 일관된 스냅숏을 읽음
  - 관리자 토큰은 바이트 단위 상수 시간 비교
  - production에서는 레거시 토큰 해시를 거부
- **SQL과 경로 조작**
  - 모든 값이 매개변수로 바인딩됨. 마이그레이션의 f-string은 고정된 열 목록에서만 생성
  - 키 경로는 ID와 버전 정규식으로 제한. `issue_qr`는 DB에 등록된 기관 ID만 사용
  - 복원 시 `issuer_key_relative`가 경로 탈출을 막음
- **SSRF 보호:** fec0 대역을 제외하면 다음이 모두 갖춰져 있습니다.
  - DNS 결과 전체가 공개 주소여야 함
  - 검사한 IP로 연결을 고정해 DNS 재바인딩 차단
  - 원래 호스트명으로 SNI와 인증서 검증
  - 리디렉션마다 재검사, 443 포트와 HEAD 요청만 사용
  - `X-Forwarded-For` 위조 불가(`--no-proxy-headers`)
- **CRL 처리**
  - CRL 번들에 CA 인증서를 섞어 신뢰를 넓힐 수 없음
  - 원격에서 CRL을 내려받지 않음
  - 연결마다 다시 읽어 갱신이 반영됨
  - 체인 전체 해지 검사(`VERIFY_CRL_CHECK_CHAIN`)
- **프런트엔드**
  - `innerHTML`, `dangerouslySetInnerHTML`, localStorage/sessionStorage, 쿠키, `window.open` 사용 없음
  - trusted 결과에만 HTTPS 링크를 만들고 `noopener`/`no-referrer` 적용
  - CSP와 `form-action 'self'` 적용
  - 오래된 요청 응답 무시(generation 확인과 abort), 5분 유휴 해제(시계가 뒤로 간 경우 포함)
  - 탭 숨김·페이지 이탈 시 카메라 트랙 종료
  - 서비스워커는 아무것도 캐시하지 않음
- **배포와 공급망**
  - Dockerfile: 비루트 UID 10001, 비밀 파일 미포함
  - CI: 액션을 SHA로 고정, `contents: read`
  - 릴리스 검증은 외부에서 받은 지문이 필수이고, 서명 대상 데이터에 도메인 분리 적용

---

## 4. 기존 OS High 8종 해결 주장과 스캔 한계

**증거의 일관성 (제출 JSON 기준)**
- 최종 이미지 digest `1e5f37…`이 스캔, 실행 점검, 백업 점검 결과에서 모두 일치합니다.
- APK 인벤토리 38개가 문서의 개별 주장과 맞습니다.
  - util-linux 계열은 `libuuid`만 남아 있고 libmount와 util-linux판 nsenter는 없습니다. `mount`와 `nsenter`는 BusyBox로 연결됩니다.
  - acl, systemd, perl 패키지가 없습니다.
  - ncurses는 `6.6_p20260516`이고 `infocmp`가 없습니다.
- 최종 OS 스캔 결과는 0행입니다.

**평가**
- 7건(CVE-2026-76642, -78408, -78409, -78410, -54369, -16742, -9538)은 해당 구성요소가 이미지에 없다는 근거로 타당합니다. 다만 정확한 표현은 "패치함"이 아니라 "최종 이미지에 해당 없음"입니다. 문서의 "해결" 표현은 이 의미로 읽어야 합니다.
- CVE-2025-69720은 버전 비교(수정 버전 이후)와 `infocmp` 부재에 근거합니다. 업스트림 수정이 실제 포함되었는지는 외부 자료에 의존하며, 이번 정적 검토에서는 직접 확인하지 못했습니다(네트워크 미사용).

**지적할 한계**
1. **Alpine 미수정 취약점은 보이지 않음:** Trivy의 Alpine 검사는 secfixes(수정된 항목) 기준이라, 아직 수정되지 않은 취약점은 나타나지 않습니다. busybox 1.37.0, musl 1.2.6, sqlite 3.53.4, krb5 1.22.2, openssl 3.5.9 등에 남아 있을 수 있는 미수정 CVE가 검출 0에 가려질 수 있습니다. 문서에 공개는 되어 있지만, "차단 판단 통과"는 이 범위 안에서만 성립합니다.
2. **휠에 번들된 네이티브 라이브러리는 미검사 (문서에 명시 안 됨):** cryptography가 정적으로 포함한 OpenSSL 4.0.3과 Pillow가 번들한 라이브러리(`pillow.libs`)는 APK나 Trivy의 Python 패키지 매칭으로 검사되지 않습니다. 다만 신뢰할 수 없는 이미지를 파싱하는 경로가 없어 실제 도달 가능성은 낮습니다.
3. **웹 빌드 단계 이미지와 CPython 표준 라이브러리는 미검사:** 이 부분은 문서에 공개되어 있습니다.
4. **참고용 CVE 수치 (이 보고서의 등급 집계와 별개)**
   - Bookworm: 278행, 고유 ID 121개
   - Trixie 제품 이미지: 164행, 고유 ID 71개(High 8)
   - Alpine 최종: 0

---

## 5. 남은 환경 조건 (새 코드 취약점이 아님)

- **S05 (중요정보 암호화):** 공개 도메인 TLS 종단, 백업 키의 별도 매체 보관이 미확인입니다. 현재 백업 키와 키 암호가 같은 프로필 폴더에 있습니다.
- **S11 (인증서 해지):** 운영 CRL의 확보, 갱신, 역행 방지와 공개 WebPKI 지원 범위가 미확인입니다. CRL이 없는 사이트는 차단되는 쪽으로 안전하게 실패합니다. `compose.security.yaml`은 시험 CA만 신뢰하므로 공개 사이트 분석이 불가능합니다. 이 영역에서 코드 수준의 우려는 L4 하나입니다.
- **S15 (배포 무결성):** 발행자 신원, 지문 배포 경로, CI runner 신뢰가 미확인입니다. 스냅숏에 서명 JSON이 없어 실제 서명은 검증하지 못했습니다.
- **기타:** 프록시의 클라이언트 IP 신뢰 범위와 여러 호스트 간 공유 제한은 운영 과제로 남습니다. 다만 그 영향은 M1에서 별도로 다뤘습니다.

---

## 6. 다음 조치 (우선순위 순)

1. **M1:** 이전 창 카운터 즉시 삭제, 그룹별 상한 또는 관리자 여유분 확보, 관리자 API 네트워크 분리, 전역 상한 소진 회귀 시험 추가
2. **L1:** `is_site_local` 차단과 `fec0::1` 시험 추가. Python 3.12.15에서 `is_global` 결과 확인
3. **L2:** 백업 묶음에 인증된 시점 정보 추가, 백업 ID를 AAD에 묶기, 롤백 거부 옵션, 폐기 저널 도입
4. **L4:** CRL 만료를 앱 시작 실패에서 분리(분석 기능만 끄고 degraded 표시)
5. **L3:** production에서 레거시 키 경로 제거 또는 공개키 고유 제약 추가
6. **공급망:**
   - 검사한 digest로 배포 고정
   - NVD/OSV 업스트림 버전 기준 보완 검사(Alpine 미수정 취약점, 휠 번들 라이브러리)
   - 문서의 "해결"을 "해당 없음"으로 정정
7. **문서 정정:** `FULL_GUIDE_02:56`, `FULL_GUIDE_03:64`, `CLAUDE_REVIEW:14`

**등급 집계 (CVE 수와 별개):** Critical 0 · High 0 · Medium 1 · Low 4 · 정보성 7
