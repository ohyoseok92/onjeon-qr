# 참고가이드 5종과 보안 설계 점검

점검일은 2026-10-11이다. 교육자료의 참고가이드 5종을 공식 KISA에서 내려받아 **총 1,307 PDF쪽 전체**를 처음부터 순서대로 읽고 현재 소스·배포·공급망에 대조했다. 본문·표·코드 예제·진단 정탐/오탐·참고목록·부록을 포함하며, 빈 쪽과 주요 그림은 렌더로 확인했다. 원본·전체 추출 텍스트·버전·다운로드 주소·SHA256은 상위 `참고자료/`에 보관했다. 교육자료 후반의 보안약점 49개는 [SECURITY_CHECKLIST_49.md](SECURITY_CHECKLIST_49.md)에 각각 기록했다.

49개 항목의 최종 상태는 **구현 확인36개·비적용10개·조건부3개**다. 기존 조건부7개를 모두 추가 점검했다. 자원 권한·무작위 비밀 생성·구형 토큰의 운영 거부·공유 요청 제한은 실제 실행에서 확인했고, 공개 HTTPS·운영 CRL 갱신·발행자 신원과 서명 신뢰는 조건부로 남는다. [SECURITY_CONDITIONS_REVIEW.md](SECURITY_CONDITIONS_REVIEW.md)에 항목별 근거가 있다. 이 집계는 공식 진단 약점 수가 아니다.

최종 시험의 수치·명령·경고·생략은 [TEST_REPORT.md](TEST_REPORT.md)를 기준으로 한다. 실제 로컬 TLS/HTTP 시험은 인증서 검증·IP 정책·HEAD/redirect 로직을 실행하며 자체서명·호스트명 불일치·내부망 이동·설치 주소·느린 헤더를 대조한다. DNS와 소켓 라우팅만 로컬 서버로 전환해 외부 서버에 접속하지 않는다. 루프백 ZAP 등의 실행 범위는 [DAST_CHECK.md](DAST_CHECK.md), 개발 PC·계정·Docker/TLS의 실제 조회 및 미확인은 [OPERATION_SECURITY.md](OPERATION_SECURITY.md), 임시 DB·키의 실제 복구는 [RECOVERY_CHECK.md](RECOVERY_CHECK.md)에 있다.

## 가이드별 적용 범위

PDF 쪽 번호는 뷰어의 첫 페이지부터 세는 번호다. 본문 인쇄 쪽 번호가 다를 때는 괄호로 함께 적었다.

| 참고가이드 | 전체 읽기 범위·기록 | 온전QR에 적용한 확인·수정 |
| --- | --- | --- |
| 소프트웨어 개발보안 가이드 2021 | PDF1~381쪽 전체. [FULL_GUIDE_01.md](FULL_GUIDE_01.md) | 보호대상·신뢰경계·요구사항 추적·설계20항목·구현49약점·예제·부록을 대조. 인증 실패 기록과 키·세션·인가·운영 조건을 보완. |
| 소프트웨어 보안약점 진단가이드 2021 | PDF1~612쪽 전체. [FULL_GUIDE_02.md](FULL_GUIDE_02.md) | 설계/구현 진단절차·20설계/49약점·정탐/오탐의 데이터흐름·예외/자원·전체 부록을 대조. 인증 실패 추적·CRL/OCSP 조건·느린 body·유휴 연결·CI/ZIP 증적 누락 발견을 전달하고 수정 근거를 연결. |
| Python 시큐어코딩 가이드 2023 개정 | PDF1~177쪽 전체. [FULL_GUIDE_03.md](FULL_GUIDE_03.md) | 46항목·언어/프레임워크별 예제·부록을 현재 FastAPI/React에 적용. 각 redirect의 IDN/유사주소·인코딩 확장자·제어문자 검증 보완, dense QR 회전 해독과 UI 경합 검증. 제외한 직접 메모리3항목도 교육49표에 포함. |
| SW 공급망 보안 가이드라인 v1.0, 2024.05.25 최종수정본 | PDF1~100쪽 전체. [FULL_GUIDE_04_05.md](FULL_GUIDE_04_05.md) | 참여자·7공격경로·SBOM/국내 필드·활용 사례·자가점검30항목·부록을 확인. SBOM의 lock 일치/관계/라이선스, CI bootstrap 범위, 개발 PC·저장소·복구를 확대 점검. |
| SW 공급망 보안 강화 로드맵 2026.06 | PDF1~37쪽 전체. [FULL_GUIDE_04_05.md](FULL_GUIDE_04_05.md) | 배경·비전·9추진과제·일정·요약 전체를 대조. 전주기 개발보안·구성요소 가시성·접수/대응·신뢰성/복원력의 운영 조건을 기록. 정책 추진계획을 현재 제품의 법적 의무·인증 완료로 단정하지 않음. |

## 보안 요구사항 추적

| 요구사항 | 보호 대상·위협 | 구조·구현 근거 | 검증 근거 |
| --- | --- | --- | --- |
| R01 기관별 인가 | 다른 기관 QR·활동 기록 열람/폐기 | 관리자/기관 토큰 분리; SQL 기관 ID 경계; 대시보드·발급·폐기에서 DB 권한 검사 | `test_dashboard_and_revoke_enforce_institution_token_isolation` |
| R02 QR 무결성·실제 발급 검증 | 위조·변조·미등록 키·QR·폐기 재사용 | 정규화 JSON·Ed25519·정확한 타입/길이·발급 해시 대조·키/기관/QR 폐기·만료 | `test_tampering_and_unknown_format_are_blocked`, `test_admin_recovery_controls` |
| R03 개인키·토큰 보호 | 키 파일·DB 탈취·재사용 | 암호화 PKCS8 개인키; 비밀환경 분리; 솔트 hash 기관토큰; 재발급; 제출 허용목록 | `test_key_encryption_and_password_validation`, `test_legacy_issuer_hash_survives_then_rotates_to_salted_format` |
| R04 분석 요청 경계 | SSRF·DNS 재바인딩·리다이렉트 내부망 | `analyzer.py:29/52/64/86` HTTPS/443·전체 공개 IP·IPv6 우회주소 정책·검사IP 연결·TLS hostname 검증·각 이동 재검사; `:140` 모든 홉 IDN/유사주소·인코딩 설치확장자·제어문자 검사 | IPv6/부정형 redirect·각홉 신호/제어문자·실제 내부redirect 회귀 |
| R05 자원·가용성 | 대용량 입력·느린 전송·연결 고갈·무한 이동 | `api.py:224` 수신 전 rate·실제16KiB·5초수신·reader32슬롯; 분석/DNS각4슬롯·실제 DNS완료까지 슬롯 유지·전체10초·이동3회 | `test_slow_asgi_body_times_out_with_security_headers_and_cancels_receive`, `test_asgi_body_readers_are_bounded_and_slots_released`, `test_rate_limit_rejects_before_asgi_body_read`, DNS/실제 TLS timeout 회귀 |
| R06 인증·폐기 경쟁조건 | 인가 직후 토큰/키 변경·대시보드 상태 불일치 | 쓰기 트랜잭션 안 인증/상태변경·읽기 snapshot·원자적 키 생성 | `test_issuance_holds_write_transaction_during_signing`, `test_verification_reads_a_coherent_snapshot_during_revocation` |
| R07 시민 개인정보 | QR 원문·이동주소·행동기록 유출 | 시민 스캔 DB 비저장·검증 오류 원문 비노출·no-store·서비스워커 비캐시 | `test_issue_verify_revoke_and_no_citizen_history`, `test_validation_and_unexpected_errors_do_not_echo_private_input` |
| R08 사용자의 이동 결정 | 미서명 주소 자동 이동·XSS | 결과를 React 텍스트로 표시; 신뢰 서명에만 HTTPS 링크; 클릭 이동; no-referrer/noopener | API의 URL 경계 시험과 실제 브라우저 화면 확인 |
| R09 공급망·재현성 | 의존성 변조·알려진 CVE·빌드 오염 | npm integrity lock·Python runtime/dev SHA256 hash lock·전체 SHA CI action·Docker base digest·보안 점검·SBOM2종·제출 manifest | 최종 `TEST_REPORT.md` 및 SBOM/lock/CI 파일; 실제 build/run·소스 hash 일치 확인; DOCKER_RUNTIME_CHECK.md |
| R10 관리자 변경 추적 | 키/토큰/기관 상태 조작·감사기록 누락 | `api.py:191` `_audit_admin`: 등록·키변경/활성/폐기·토큰변경·기관비활성/활성7종을 상태변경과 같은 DB 트랜잭션에 기록. URL·토큰·키본문 비저장 | 관리자 감사/rollback/불성공 기록 회귀3종 |
| R11 인증 실패 추적 | 인증 반복·실패 이력 누락·로그 정보 유출 | `api.py:295/358`, `storage.py:62/70/88`: 관리자/기관401/403/429만 고정사건·코드·등록기관·시간·일/프로세스 HMAC출처·분 횟수 저장, 7일/1만행·관리자만 조회. 기록 실패에도 거부 유지와 제한된 고정 로그 | `test_security_failure_audit_is_private_bounded_and_admin_only`, `test_failure_audit_aggregates_and_changes_source_each_day`, `test_issuer_rate_limit_is_audited_and_audit_failure_preserves_denial`, `test_security_event_retention_maximum_and_aggregation` |
| R12 세션·카메라 상태 정리 | 공유단말 토큰 잔류·응답 경합·카메라 잔류 | `IssuerView.tsx:49/56` 연결해제/unmount·요청generation/abort·5분유휴와background복귀재검사; 시민 input변경·visibility/pagehide 카메라 종료, 비밀 영속저장/서비스워커 캐시 부재 | `security-flows.test.tsx` 유휴/요청경합/키입력 시간갱신, `qr-decoder.test.tsx` 픽셀해독. 서버토큰 만료/물리제로화·실물기종시험은 별도 조건 |

SBOM의 형식·부품 수·purl·구성 관계·hash·라이선스와 실제 lock 일치 검증은 [SUPPLY_CHAIN_VALIDATION.md](SUPPLY_CHAIN_VALIDATION.md) 및 JSON 보고서를 기준으로 한다. 라이선스 전문과 고지는 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) 및 `licenses/`에 연결한다. Python 설치의 다운로드 무결성은 runtime/dev SHA256 lock, npm은 package-lock integrity로 검증한다. SBOM·lock 존재만으로 모든 코드의 무해성·법적 사용조건 충족·배포자 인증을 보증하지 않는다. 실제 컨테이너 build/run과 OS 전체 Trivy 검사를 수행했다. 베이스 변경·보안 패키지 갱신·pip 제거 후 결과와 남은 취약점은 [DOCKER_IMAGE_SCAN.md](DOCKER_IMAGE_SCAN.md)에 있다. 릴리스 서명은 외부 신뢰 지문이 필수이며 실제 최종 ZIP의 분리 서명을 제공한다.

CI는 무제한 pip 업그레이드와 editable 설치/build isolation을 제거하고 hash lock 설치 후 `PYTHONPATH=src`로 시험한다. setup-python이 제공하는 Python/pip, setup-node의 Node/npm, GitHub runner는 빌드 신뢰 기반으로 남는다. 소스 ZIP은 중첩 프런트 fixture·전수읽기 기록·운영/복구/DAST·SBOM/라이선스 증적을 포함하도록 허용목록을 보완했다. 최종 ZIP/hash 검사는 `TEST_REPORT.md`를 따른다.

`Dockerfile`은 두 base image digest와 runtime hash lock을 고정한다. 실제 Docker29.8.0에서 이미지 빌드·TLS1.3 발급/검증/폐기·재시작 상태/한도 유지, UID/GID10001·DB/HMAC/키0600·디렉터리0700·CapEff0·NoNewPrivs1·read-only root와5개 비밀 bind 쓰기 거부를 확인했다. 이미지와 현재 소스의 hash도 일치한다. 실제 결과는 [DOCKER_RUNTIME_CHECK.md](DOCKER_RUNTIME_CHECK.md), JSON과 암호화 복구 증거를 따른다. 공개 배포 환경의 통제가 완료됐다는 뜻은 아니다.

## 공급망 가이드 표24의 30개 항목

가이드의 취지를 요약해 프로젝트에 맞춘 점검 질문으로 적었다. `운영 확인 필요`는 개발 PC·계정·조직·실배포 상태를 코드만으로 확인할 수 없는 항목이다. 다음 표는 실제 lock/SBOM 산출물과 소스 검토를 기준으로 하며 설치·audit·전체 실행 결과는 최종 시험보고서와 함께 확인한다.

| 번호·단계 | 점검 주제 | 판정·근거 | 후속 확인 |
| --- | --- | --- | --- |
| 1 설계 | 보안 역할·책임 | 운영 확인 필요. 이번 변경은 구현·검증 담당을 분리했으나 운영 책임자·승인/사고 담당자 지정 문서는 없음. | 서비스 운영 전에 책임·연락 경로 명시. |
| 2 설계 | 개발자 보안교육 | 조건부. 사용자 사전교육 수료와 5개 가이드 검토를 이번 점검의 입력으로 사용. 조직 전체 교육 이력은 미확인. | 참여자별 교육·공유 기록 보관. |
| 3 설계 | 공급망 고려·형상관리·SBOM | 확인. runtime/dev SHA256 lock·CI·공급망 검토 문서·CycloneDX SBOM2종 존재. | 릴리스와 SBOM 버전 연결. |
| 4 설계 | 개발 PC·엔드포인트 보안 | 운영 확인 필요. `OPERATION_SECURITY.md`에서 Defender 활성·HotFix 기록을 조회했으나 최신 패치 충족/장치 무해성을 보증하지 않으며 BitLocker 상태는 권한 오류로 미확인. | 실제 운영 장치·디스크 암호화·패치 충족 추가 확인. |
| 5 설계 | 주요 보안항목 문서 | 확인. `SECURITY.md`, 49항목 표, 위 요구사항 추적표에 보호대상·인가·키·기밀/무결성/가용성 기록. | 기능 변경 시 동시 갱신. |
| 6 개발 | 시큐어코딩 | 확인. 입력 바인딩·권한·TLS·서명·예외·자원 수동 점검과 Bandit을 함께 수행. | 최종 소스에 재검증. |
| 7 개발 | 배포 기본 보안설정 | 조건부. production 문서 비활성·키 암호 필수·헤더, loopback 개발, Docker nonroot·compose 제한 설정을 소스로 확인. | 로컬 HTTPS 이미지 build/run·권한은 확인. 실배포 도메인 TLS·계정 권한·공개 포트는 별도 확인. |
| 8 개발 | 외부 라이브러리 무결성·유해성 | 조건부. npm integrity, Python SHA256 lock, 감사도구 적용. | CVE 무검출로 악성성 부재를 보증할 수 없으며 패키지 출처·갱신 검토 지속. |
| 9 개발 | 저장소 인가 | 운영 확인 필요. CI contents:read·비밀 제외, private 저장소·collaborator1명 조회. 계정 MFA는 유효값 없음, 브랜치보호/ruleset은403으로 집행 상태 미확인(`OPERATION_SECURITY.md`). | 계정 MFA·승인/보호 정책의 실제 집행 확인. |
| 10 개발 | 지속 취약점 점검 | 확인. GitHub CI의 Bandit·pip-audit·npm audit, 수동 49항목 표. | 이번 원격 CI 실행 여부는 로컬 실행과 구별. |
| 11 개발 | 빌드 자동 보안시험 | 확인. CI에 pytest·Bandit·pip-audit·프런트 빌드·npm audit 포함. | 실패 gate 유지. |
| 12 개발 | 언어·도구 보안옵션 | 조건부. TypeScript strict, production app 설정, 검증된 TLS·암호 API·hash 설치 사용. | 컨테이너·호스트 자원/권한 제한은 실제 실행 확인. |
| 13 개발 | 빌드·보안시험 산출물 보관 | 확인. dist·제출 ZIP/hash·TEST_REPORT·SBOM을 릴리스 대상으로 관리. | 릴리스마다 결과·버전 고정. |
| 14 개발 | SBOM 구성요소 취약점 확인 | 조건부. pip-audit·npm audit와 lock/SBOM 대조, 실제 이미지의 OS/Python Trivy 검사와 보완 후 재검사. 기존High8종 해결·최종검출0. `SUPPLY_CHAIN_VALIDATION.md`·`DOCKER_IMAGE_SCAN.md`·최종 시험보고서. | Alpine 미수정 CVE 탐지 한계와 신규 CVE 추적은 운영에서 계속 확인. |
| 15 개발 | 심각한 취약점 유효성 검증 | 조건부. audit 발견 시 advisory·실사용 경로·업데이트 확인 후 수정/재시험. | 새 심각 취약점은 배포 전에 영향도와 완화·제거 근거 기록. |
| 16 개발 | SBOM 이력 보관 | 운영 확인 필요. 현재 릴리스 SBOM은 생성·보관 대상. 장기간 이력 보관 정책 없음. | 지원하는 모든 릴리스의 SBOM·hash·시험기록 보관. |
| 17 공급 | 코드 무결성 자료 전달 | 확인. 제출 ZIP의 MANIFEST.sha256와 ZIP SHA256. | 신뢰할 수 있는 별도 전달 경로 또는 릴리스 서명 필요. 내부 hash만으로 발행자 인증 불가. |
| 18 공급 | 소스·의존성 안전 보관 | 조건부. 형상관리·lock·비밀 제외·허용목록 제출. | 저장소 접근통제·백업 복구·보존기간 확인. |
| 19 공급 | 구성·취약점·라이선스 정보 제공 | 조건부. SBOM2종·취약점 보고·라이선스 전문/고지·검증보고서를 제출 대상으로 연결. 세부 근거는 `SUPPLY_CHAIN_VALIDATION.md`, `THIRD_PARTY_NOTICES.md`. | 실제 배포/수정/재배포 형태별 고지·라이선스 의무는 승인 필요. 문서 존재만으로 법적 적합성 완료로 판정하지 않음. |
| 20 도입 | 공급망 요구·관리 매뉴얼 | 조건부. README·보안 설계·이 표로 설치/재시험 기준 제공. | 실제 기관에 납품할 때 업데이트·담당자·지원기간 합의. |
| 21 도입 | 계약 보안요구 이행 | 비적용. 아직 실제 납품계약 확인 없음. | 계약이 생기면 승인/인수 조건 확인. |
| 22 도입 | 인수 시 무결성 검증 | 확인. `scripts/verify_submission.py`로 ZIP manifest를 검사. | 배포 이미지 provenance·서명 및 외부 기대 hash와 대조. |
| 23 운영 | 공개 CVE 모니터링 | 조건부. CI 재실행 시 audit로 알려진 취약점 확인. 예약 모니터는 없음. | 릴리스 전과 의존성 변경 시 실행, 운영 주기·담당자 지정. |
| 24 운영 | 개발자에게 취약점 조치 요청 | 운영 확인 필요. 현재 단일 프로젝트의 개발 수정·재시험 경로는 존재. | 공개 취약점 접수 경로·처리 담당자·회신 기한 명시. |
| 25 운영 | 외부 SW SBOM 확보 | 조건부. npm/Python 의존성의 metadata·lock으로 자체 SBOM 생성. 별도 구매 SW 없음. | 외부 제품 도입 시 공급사 SBOM 요청. |
| 26 운영 | 외부 코드 취약점 점검 | 조건부. 의존성 advisory 감사 수행; 모든 외부 라이브러리 소스 전수 수동 검토는 수행하지 않음. | 위험도가 큰 구성요소는 추가 검토. |
| 27 운영 | 운영 SW 지속 점검 | 운영 확인 필요. 로컬 회귀·CI 근거는 있고 실제 공개 운영이 아직 미검증. | 운영 취약점 점검·패치 주기 지정. |
| 28 유지보수 | 영향평가·대응방안 | 조건부. 키 폐기·토큰 재발급·기관 비활성화·QR 폐기와 7종 관리행위 원자적 감사 기록 구현. | 보안 사건과 공급망 CVE 대응의 담당자·판정·공지·복구 절차 확정. |
| 29 유지보수 | 신속 패치 절차 | 조건부. lock 갱신→audit→회귀→build→SBOM/manifest 재생성 경로 확보. | 실서비스 업데이트·되돌리기·데이터 migration 복구 시험. |
| 30 유지보수 | 배포·업데이트 서버 관리 | 운영 확인 필요. 로컬 Docker의 실제 image 실행·HTTPS·인증·권한 제한은 확인했으며 조직 운영 서버의 패치·원격 접속 통제는 미확인. | 운영 전 인프라 점검. |

공급망 30개 항목의 상태는 **확인 8개·조건부 14개·운영 확인 필요 7개·비적용 1개**다. 공급망 표의 판정은 소스·로컬 산출물과 조직·운영 통제를 함께 대조한 결과이며 보안약점49개 판정과는 별도 집계다.

## 수정 사항과 잔여 위험

이번 코드검토에서 확인한 문제는 원래 상태와 수정 이후를 구분한다. 과거 시험 결과를 현재 소스의 실행 결과로 사용하지 않는다.

| 발견 사항 | 수정한 내용 | 재검증 경로 |
| --- | --- | --- |
| 키 PEM이 평문으로만 생성됨 | `ONJEON_KEY_PASSWORD` 암호화 PKCS8 지원; production은 암호 필수; 설정된 암호와 평문 키 불일치 거절 | `tests/test_crypto.py`와 production 설정 시험 |
| 기관 토큰 hash에 솔트 없음 | 새 토큰별32bytes(256bit) 솔트·SHA256, 상수시간·손상값 거절. 이전16bytes솔트/무솔트는 production에서 거부, 관리자의 명시적 토큰 재발급으로 전환 | salted hash·legacy rotation·malformed hash 시험 |
| 인증·서명과 DB 상태의 시점 분리 | 쓰기 잠금 안 권한/키/상태 검사와 변경, 읽기 snapshot 사용 | 발급과 키/토큰 변경 경쟁, 검증과 폐기 경쟁 시험 |
| Pydantic 검증 오류가 입력을 되돌림 | 입력·ctx를 제거한 검증 응답, 예기치 않은 500 고정응답과 보안 헤더 | private input 비노출·모든 에러 응답 헤더 시험 |
| Content-Length 값만으로 크기 판단 | 수신한 실제 바이트까지 16KiB 상한·길이 일치 검사 | 큰 body·위조 Content-Length·chunked 거절 시험 |
| bool protocol version이 Python int와 같게 취급됨 | QR version의 정확한 int 타입 검사 | `test_boolean_protocol_version_is_rejected` |
| DNS 작업·느린 응답의 자원 소모 | DNS 슬롯은 실제 종료까지 유지, 전체10초 예산·연결/헤더 타이머·소켓 정리 | DNS saturation·timeout 및 실제 로컬 TLS 헤더 timeout 시험 |
| IPv6 전환/매핑 주소·부정형 이동값 우회 | multicast/reserved/IPv4 mapped/NAT64/6to4/Teredo 차단, 잘못된 redirect URL의 안전 차단 | `test_multicast_and_translation_addresses_are_blocked`, `test_malformed_redirect_is_blocked` |
| 관리자 상태변경의 감사기록 누락 | 등록·키변경/활성/폐기·토큰변경·기관비활성/활성 7종 상태변경과 감사기록을 같은 트랜잭션으로 묶음. 감사 실패 시 전체 rollback | 관리자 감사 3개 회귀시험 |
| 인증 실패 기록 부재 | 관리자/기관 실패·429를 원문 없이 HMAC출처·등록기관·시간·분횟수로 제한 저장, 7일/1만행·관리자조회·기록장애 시 거부 유지 | 실패/집계/개인정보/보존/장애 회귀 |
| body를 읽은 뒤 rate 제한·수신시간/동시상한 부재 | rate를 먼저 검사하고 실제16KiB·수신5초·비차단32슬롯·finally반납 | 실제 ASGI 느린 수신·32동시/33번째429·사전rate 회귀 |
| 시작 URL만 위험 신호 검사 | 모든 홉의 IDN/유사기관 도메인·한 번 percent decode 설치확장자와 Cc/Cf/Cs 차단 | 각홉 IDN/유사주소·encoded APK·숨은문자 회귀 |
| 회전된 dense QR 해독 실패 | ZXing 실패 때1280px 상한 jsqr 보조 해독; 결과는 서버 서명/기관 검증을 계속 요구 | 실제 발급형식 QR 픽셀 0/90/180/270도 해독 시험 |
| CSP form-action 누락 | 고정 CSP에 `form-action 'self'` 추가 | 응답헤더 회귀와 최종 루프백 `DAST_CHECK.md` |
| CI/제출 증적의 누락·lock 외 설치 | pip upgrade/editable 제거·PYTHONPATH 시험, 중첩 fixture/FULL_GUIDE/라이선스/운영 보고서를 ZIP 허용목록에 추가 | 최종 시험·공급망 검증·ZIP manifest 재검사 |
| 기관 화면에 유휴 종료 없음 | 5분유휴 때 상태·토큰·진행요청 제거, 늦은응답/generation격리, background복귀시 만료 재검사 | 프런트 유휴중 pending요청·늦은응답·키입력 갱신 회귀 |

실제 서비스의 HTTPS 종료, Windows/컨테이너 ACL, 비밀환경·DB/백업 권한, 도메인 소유 확인, 다중 서버 속도 제한, 운영 장치 보안, 저장소 계정·승인 정책, 장기 취약점 대응과 배포/복구는 배포 전에 확인해야 한다. 로컬 제품 시험과 코드 검토만으로 완료 판정을 내릴 수 없다.

미서명 URL 분석은 대상 서버에 HEAD 요청을 보내므로 주소에 추적용 식별자가 있으면 대상 서버가 요청 사실을 알 수 있다. 이 분석은 위험 신호를 찾는 기능이며 기관 발급 인증이나 목적지 본문 안전성 판정이 아니다. 시민 스캔 기록은 DB에 저장하지 않지만 프록시·웹서버의 별도 로그 정책은 운영에서 확인해야 한다.

정적·의존성 검사·전체 회귀는 `TEST_REPORT.md`, 루프백 ZAP의 정확한 대상·인증/크롤링 범위·알림/한계는 `DAST_CHECK.md`를 기준으로 한다. 외부 공개 서비스 전체 침투시험·실기관 연동·모든 조직/운영 인프라 실사·실물 카메라 시험은 완료로 표시하지 않는다. 임시 DB·암호화 키의 실제 복구는 `RECOVERY_CHECK.md`에서 확인했지만 생산 RPO/RTO·키 백업 권한/승인·최신 폐기 재적용은 운영 확인이 남는다.

## 조건부 항목 추가 실증

[SECURITY_CONDITIONS_BACKEND.md](SECURITY_CONDITIONS_BACKEND.md), [SECURITY_CONDITIONS_TOOLS.md](SECURITY_CONDITIONS_TOOLS.md), [SECURITY_CONDITIONS_TLS.md](SECURITY_CONDITIONS_TLS.md)에 공유 카운터·유휴 정리·구형 토큰 거부·실제 NTFS·AES-GCM·외부 지문 검증·CRL 체인 시험을 기록했다. 컨테이너의 중지 시점 DB/기관별 암호화 키/HMAC키를 실제 백업·복구했고, 복구 앱 운영 시작과 인증까지 확인했다. 기존30개 공급망 항목 집계는 조직·운영 요건을 포함하므로 Docker 로컬 시험만으로 운영 완료로 바꾸지 않았다.
