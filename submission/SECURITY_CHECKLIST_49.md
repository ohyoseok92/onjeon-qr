# 교육자료 보안약점 49개 점검표

점검일: 2026-10-11. 대상: 온전QR Python/FastAPI·SQLite API, React 브라우저 앱, URL 분석기, 키 생성 도구, 빌드·배포 설정.

교육자료 PDF 18~25쪽의 7개 분류와 49개 항목을 빠짐없이 대조했다. `구현 확인`은 소스의 방어 구조를 확인했다는 뜻이며 제품 전체의 안전 보증이 아니다. `비적용`은 현재 구현에 해당 기능이 없거나 언어 특성상 직접 적용되지 않는 항목이다. `조건부`는 구현과 함께 명시한 운영 조건을 충족해야 한다. 시험 이름은 재현 경로이며 최종 실행 결과는 `TEST_REPORT.md`를 기준으로 한다. 수동 검토와 자동 점검을 함께 사용하며 자동 도구의 무검출을 취약점 부재로 해석하지 않는다.

코드 위치는 저장소 기준 `파일:행`과 함수명을 함께 적었다. 후속 수정으로 행이 이동하면 함수명으로 찾을 수 있다. 참고자료의 정확한 원본·버전·SHA256은 프로젝트 상위 `참고자료/MANIFEST.json`과 ZIP의 `submission/GUIDE_SOURCES.json`에 있다. 가이드 5종 **총 1,307 PDF쪽**의 본문·예제·부록을 순서대로 읽었으며 빈 쪽과 주요 그림은 렌더로 확인했다. 읽은 범위와 제품 대조는 [개발보안 381쪽](FULL_GUIDE_01.md), [진단 612쪽](FULL_GUIDE_02.md), [Python 177쪽](FULL_GUIDE_03.md), [공급망 100쪽·로드맵 37쪽](FULL_GUIDE_04_05.md)에 기록했다. Python 가이드가 제외한 3개 항목도 교육자료 목록에 따라 별도로 확인했다. 오래된 예제의 시간 시드 난수·비밀번호 해시·역직렬화·인증서 처리 조각은 그대로 안전한 구현으로 채택하지 않았다.

| 코드 근거 | 현재 위치 |
| --- | --- |
| 입력 모델·표시문자·도메인·목적지 정책 | `src/onjeon/api.py:65` `InstitutionInput`, `:109` `_safe_display_text`, `:126` `_domains`, `:133` `_destination_host` |
| 토큰 솔트·검사·키 경로 | `src/onjeon/api.py:155` `_hash_token`, `:162` `_verify_token`, `:180` `_key_path` |
| production·검증예외·크기/속도·보안헤더 | `src/onjeon/api.py:199` `create_app`, `:220` `validation_error`, `:224` `protected_request`, `:295` `disable_cache` |
| 관리자/기관 인증과 발급·폐기·조회·검증 | `src/onjeon/api.py:342` `require_admin`, `:346` `require_issuer`, `:479` `issue_qr`, `:540` `revoke_qr`, `:560` `institution_dashboard`, `:613` `verify_qr` |
| 관리자 감사·인증 실패/429 추적 | `src/onjeon/api.py:191` `_audit_admin`, `:363` 등록부터 `:466` 키 폐기까지 7종; `:295` 실패 기록, `:358` 관리자 보안사건 조회 |
| canonical·QR 구조·키 암호화·원자적 생성 | `src/onjeon/crypto.py:16`, `:41`, `:63`, `:74`, `:81` |
| DB 권한·실패 집계/보존·트랜잭션 | `src/onjeon/storage.py:62` `_prune_security_events`, `:70` `record_security_event`, `:88` `security_event_summary`, `:99` `initialize`, `:129` `database` |
| URL·DNS/IP 정책·직접 TLS 연결·자원제한 | `src/onjeon/analyzer.py:29` `_parse_url`, `:52` `_is_public_address`, `:64` `_resolve_public`, `:86` `_PinnedHTTPSConnection`, `:106` `_head`, `:140` `_risk_signals`, `:154` `analyze_url`, `:164` `_analyze_url` |
| 시민 결과·카메라·기관 연결/유휴해제·브라우저 링크 | `frontend/src/CitizenView.tsx:36`, `:57`; `frontend/src/IssuerView.tsx:27`, `:49` `disconnect`, `:56` 유휴 effect; `frontend/src/api.ts:15` `trustedHref`, `frontend/src/QrReader.ts:5` `QrReader` |
| 서비스워커·빌드 허용목록·배포 설정 | `frontend/public/sw.js:1`, `scripts/build_submission.py:12`, `Dockerfile:1`, `compose.yaml:1` |

수동 검색은 `src/`, `frontend/src/`, `frontend/public/` 범위에서 코드 실행(eval/exec)·pickle/marshal·unsafe YAML·쉘 실행·HTML 직접 삽입·쿠키/브라우저 저장소·LDAP/XML·직접 메모리 API를 대조했다. 해당 위험 API를 사용하는 경로는 발견하지 못했으며 비적용 행의 근거로 사용했다. 검색 무검출만으로 판정하지 않고 입력→사용→응답의 실제 흐름도 확인했다.

최종 API·storage·crypto·analyzer·network·브라우저 시험의 명령·수치·경고·생략은 [TEST_REPORT.md](TEST_REPORT.md)를 기준으로 한다. `tests/test_network.py`는 실제 로컬 TLS/HTTP 서버에서 자체서명·호스트명 불일치·내부망 이동·설치 주소·느린 헤더를 확인하며 인증서/IP 정책을 유지한 채 DNS·소켓 목적지만 로컬 시험 서버로 전환한다. 루프백 동적 점검은 [DAST_CHECK.md](DAST_CHECK.md), 환경 확인과 미확인은 [OPERATION_SECURITY.md](OPERATION_SECURITY.md), 실제 임시 백업·복구와 오래된 폐기 상태의 위험은 [RECOVERY_CHECK.md](RECOVERY_CHECK.md)를 따른다.

## 입력데이터 검증 및 표현 — 17개

| ID | 교육자료 항목 | 판정 | 확인 근거·시험 | 남은 조건 |
| --- | --- | --- | --- | --- |
| I01 | SQL 삽입 | 구현 확인 | `src/onjeon/api.py:363` 이후 모든 외부 값 질의에 `?` 바인딩 사용. `storage.py:99` 마이그레이션의 f-string은 고정 열 이름 목록에서만 생성. 기관 격리 시험 `test_dashboard_and_revoke_enforce_institution_token_isolation`. | 새 질의도 값 바인딩 유지. |
| I02 | 코드 삽입 | 비적용 | `src/onjeon`·브라우저 소스에서 외부 문자열을 `eval`, `exec`, 동적 import 코드로 실행하지 않음. `crypto.py:41`은 제한된 JSON 구조만 읽음. | 스크립트 실행 기능 추가 시 재점검. |
| I03 | 경로 조작 및 자원 삽입 | 구현 확인 | `api.py:40`의 기관·키 ID 허용문자, `api.py:180` `_key_path`; `cli.py` 동일 검증. 네트워크 URL은 `_parse_url`과 공개 IP 검사. 정적 파일은 FastAPI `StaticFiles`. | 키 디렉터리 자체와 파일을 공격자가 변경하지 못하도록 ACL 설정. |
| I04 | 크로스사이트 스크립트 | 구현 확인 | React는 이름·목적·주소를 텍스트로 출력하며 HTML 삽입 API를 사용하지 않음. `api.py:109` 표시 제어문자 제한, CSP의 `form-action 'self'` 포함. `frontend/src/api.ts:15` 목적지 재검증. `test_unsafe_display_text_and_missing_key_rejected`, `test_api_and_docs_headers`, 루프백 [DAST_CHECK.md](DAST_CHECK.md). | 루프백 점검이 실배포 CSP·브라우저/기종별 전체 검증을 대신하지 않음. |
| I05 | 운영체제 명령어 삽입 | 비적용 | 제품 API·분석기에서 쉘 명령 실행 API를 사용하지 않음. 빌드·시험 명령은 개발자 도구이며 HTTP 입력에서 호출하지 않음. | 외부 명령 실행 기능 추가 시 인자 분리·쉘 배제. |
| I06 | 위험한 형식 파일 업로드 | 비적용 | 서버의 파일 업로드·저장 API 없음. 카메라 QR 해독은 브라우저에서 수행. 서버로 QR 텍스트만 전송. | 파일 업로드를 추가하면 형식·크기·저장위치 재설계. |
| I07 | 신뢰되지 않는 URL 주소로 자동접속 연결 | 구현 확인 | 시민 화면은 검증된 `trusted` 결과에만 사용자가 누를 목적지 링크를 표시. 미서명 QR에는 링크 없음. `CitizenView.tsx`, `api.ts:15`; 서버 `_destination_host`는 등록된 정확한 HTTPS 호스트만 허용. `test_unofficial_destinations_rejected`. | 검증 뒤 목적지 서버의 미래 리다이렉트·본문까지 신뢰를 보증하지 않음. |
| I08 | 부적절한 XML 외부 개체 참조 | 비적용 | 제품 입력은 JSON/문자열이며 XML 파서·외부 엔티티 로더 없음. QR PNG 생성은 출력 기능. | XML 입력·SVG 업로드 추가 시 재점검. |
| I09 | XML 삽입 | 비적용 | 제품에 XPath/XQuery/XML 생성·조회 없음. | XML 연동 추가 시 인자·문맥별 처리 필요. |
| I10 | LDAP 삽입 | 비적용 | LDAP 연동·디렉터리 검색 없음. | 기관 SSO/LDAP 도입 시 재점검. |
| I11 | 크로스사이트 요청 위조 | 구현 확인 | 중요 변경 API는 `Authorization: Bearer` 헤더를 요구하며 쿠키 인증·세션 자동첨부를 사용하지 않음. 브라우저 원본과 API는 동일 출처이며 외부 출처 CORS를 개방하지 않음. `test_issuer_authorization_and_expiry_bounds`. | 쿠키 세션으로 변경하면 CSRF 토큰·Origin 검사 필요. |
| I12 | 서버사이드 요청 위조 | 구현 확인 | `analyzer.py:29`, `:52`, `:64`, `:86`: HTTPS/443, 모든 DNS 결과 공개 IP 검사, multicast/reserved/IPv6 mapped/NAT64/6to4/Teredo 거절, 검사 IP 연결과 SNI 인증서 검사, 이동마다 재검사. `_risk_signals`는 각 홉 IDN/유사주소·percent decode 설치확장자를 검사하며 Cc/Cf/Cs·공백·역슬래시 URL 차단. HEAD만 실행. IPv6·부정형 redirect·각홉 신호·제어문자·실제 내부redirect 회귀. | 외부 HEAD 요청의 관찰·추적 가능성, 공개 IP의 서비스 악용은 별도 운영 통제. |
| I13 | HTTP 응답분할 | 구현 확인 | 사용자 문자열을 응답 헤더·Location에 복사하지 않음. JSON 응답과 고정 보안 헤더 사용. 목적지·표시문자 제어문자 차단. `test_png_generation_and_url_parser_edge_cases`, `test_actual_body_limit_and_error_security_headers`. | 프록시도 헤더 길이·중복 헤더 정책 적용. |
| I14 | 정수형 오버플로우 | 구현 확인 | Python 정수는 가변 정밀도. 만료는 timezone 포함, 현재 이후 30일 이내; QR의 시간 필드는 정확한 `int` 타입으로 검사. `test_issuer_authorization_and_expiry_bounds`, `test_boolean_protocol_version_is_rejected`. | 네이티브 의존성은 별도 취약점 점검. |
| I15 | 보안 기능 결정에 사용되는 부적절한 입력값 | 구현 확인 | 서버의 토큰·기관·키 폐기·발급 해시·시간·정확한 도메인으로 판정. 클라이언트 verdict나 스캔 원문의 주장만으로 신뢰하지 않음. `crypto.py:41` 정규화·정확한 필드/타입 검사. `test_tampering_and_unknown_format_are_blocked`. | 기관 자격·도메인 소유권을 등록 운영자가 확인해야 함. |
| I16 | 메모리 버퍼 오버플로우 | 비적용(직접 코드) | Python 가이드 PDF 11쪽이 언어 특성상 제외한 항목. 직접 C/C++·ctypes 메모리 접근 없음. QR 4096자·요청 16KiB 제한. | Pillow·cryptography·브라우저 QR 라이브러리 등 네이티브/외부 구현은 SCA 범위로 남음. |
| I17 | 포맷 스트링 삽입 | 구현 확인 | 서버가 외부 입력을 포맷 템플릿·로깅 포맷으로 실행하지 않음. SQL 바인딩, React 텍스트 출력. 고정 f-string 위치를 수동 확인. | 향후 로깅도 고정 포맷 사용. |

## 보안기능 — 16개

| ID | 교육자료 항목 | 판정 | 확인 근거·시험 | 남은 조건 |
| --- | --- | --- | --- | --- |
| S01 | 적절한 인증 없는 중요 기능 허용 | 구현 확인 | `api.py` `require_admin`/`require_issuer`: 기관 등록·키 관리·기관 상태는 관리자, 발급·폐기·대시보드는 기관 토큰 필요. `test_issuer_authorization_and_expiry_bounds`, `test_admin_recovery_controls`. | 실제 기관 등록 전 자격·소유 확인 필요. |
| S02 | 부적절한 인가 | 구현 확인 | 기관 토큰을 대상 기관 DB 행과 대조. 대시보드·폐기 쿼리에 기관 ID 포함, 비활성 기관 거절. `test_dashboard_and_revoke_enforce_institution_token_isolation`. | 관리자 계정의 운영 권한·담당자 변경은 별도 관리. |
| S03 | 중요한 자원에 대한 잘못된 권한 설정 | 구현 확인 | 실제 Docker UID/GID10001, 디렉터리0700·DB/HMAC/기관키0600, CapEff0·NoNewPrivs1·rootfs/비밀 bind 쓰기 거부. 새 운영 프로필·백업의 NTFS는 현재 사용자/SYSTEM만 허용. `DOCKER_RUNTIME_CHECK.json`, `SECURITY_CONDITIONS_TOOLS.md`. | 확인한 로컬 프로필·컨테이너 범위. 기존 개발 폴더 전체 ACL을 운영 권한으로 간주하지 않으며 다른 호스트의 권한은 별도 확인. |
| S04 | 취약한 암호화 알고리즘 사용 | 구현 확인 | `crypto.py` Ed25519 서명과 검증된 cryptography 라이브러리 사용. SHA256은 토큰/발급문서 해시. 키 파일 암호화는 `BestAvailableEncryption`. | 라이브러리 지원·취약점 점검 유지. |
| S05 | 암호화되지 않은 중요정보 | 조건부 | PKCS8 암호화 키, 실제 TLS1.3 발급·검증·폐기, AES-256-GCM으로 컨테이너 DB/기관키/HMAC 백업·복구. 비밀 bind5개는 read-only, Docker inspect 환경에 자격값 없음. `DOCKER_BACKUP_CHECK.json`, `SECURITY_CONDITIONS_TOOLS.md`. | 공개 TLS1.3와 MYBOX 암호화 백업·PC 키/체크포인트 분리, 다운로드 복구 확인. 관리자 실조회에서 PC C: BitLocker 꺼짐을 확인했으며 키 보관 매체 암호화가 남음. 공개 운영 보고서 참조. |
| S06 | 하드코드된 중요정보 | 구현 확인 | 관리자 토큰·키 암호·데이터 경로는 환경에서 로드. 발급 토큰은 `secrets.token_urlsafe(32)`로 생성. 예시·시험 토큰은 데모용이며 배포값으로 사용 금지. 제출 비밀 파일 제외. | 생성된 `.secrets`, `.env`와 demo credential 파일을 저장소·제출물에 포함하지 않도록 점검. |
| S07 | 충분하지 않은 키 길이 사용 | 구현 확인 | Ed25519의 32바이트 공개/개인키·64바이트 서명 길이 검사. 발급 토큰 생성 원본 난수 32바이트. `test_signing_key_mismatch_fails_closed`. | 관리자 토큰도 무작위 생성 사용. |
| S08 | 적절하지 않은 난수 값 사용 | 구현 확인 | cryptography 키 생성, `secrets.token_urlsafe(32)`, `uuid4` QR ID 사용. 보안값을 `random`·시간 시드로 생성하지 않음. | OS 난수 공급·의존성 건전성 유지. |
| S09 | 취약한 비밀번호 허용 | 구현 확인 | 운영 프로필은 관리자·키 암호·릴리스 암호를 각각 CSPRNG48bytes로 생성. production은32자·최소8종 문자,16자 이하 반복·알려진 예시 패턴 거부. `SECURITY_CONDITIONS_BACKEND.md`, 운영도구9시험. | 문자열 검사만으로 엔트로피를 보증하지 않는다. 생성한 비밀의 접근권한·수명·운영 교체를 관리해야 함. |
| S10 | 부적절한 전자서명 확인 | 구현 확인 | `api.py` `verify_qr`: 등록된 기관/키와 유효 상태, Ed25519 서명, DB 발급 해시, QR 폐기·시간·목적지를 모두 확인해야 trusted. `test_tampering_and_unknown_format_are_blocked`, `test_key_rotation_keeps_old_qr_verifiable`, `test_admin_recovery_controls`. | 기존 신뢰 QR 복제는 서명만으로 방지할 수 없으며 폐기 상태는 온라인 조회. |
| S11 | 부적절한 인증서 유효성 검증 | 구현 확인 | production CRL-only PEM 필수, CA/호스트/유효기간과 VERIFY_CRL_CHECK_CHAIN. 실제 root→intermediate→leaf 정상·leaf/CA폐기·서명변조·CRL누락/만료/미래·호스트/CA오류·갱신 후 차단. `SECURITY_CONDITIONS_TLS.md`. | 실제 qr.ohs92.com 체인과 YE1 shard66의 승인 issuer4·CRL 확보/서명/역행/갱신, 5분 peer 인증서 감시를 확인. 새로운 issuer/shard는 등록 전 차단. CRL_OPERATIONS.md와 공개 운영 보고서 참조; 전체 WebPKI/OCSP 완료 아님. |
| S12 | 사용자하드디스크에저장되는쿠키를통한정보노출 | 비적용 | 제품 쿠키 인증·Set-Cookie 없음. 토큰과 스캔 결과는 브라우저 메모리 상태에서만 사용. 서비스워커도 요청을 캐시하지 않음. | 브라우저 저장 기능 추가 시 비밀정보 제외. |
| S13 | 주석문 안에 포함된 시스템 주요 정보 | 구현 확인 | 소스·빌드 설정 주석 수동 검색. 설명·공개 경로·시험값만 포함하며 실제 비밀정보를 소스 주석으로 작성하지 않음. | 최종 ZIP의 Gitleaks·금지경로/확장자·전체파일 SHA256 실행은 `TEST_REPORT.md` 기준. 신규 변경마다 재검사. |
| S14 | 솔트 없이 일방향 해시 함수 사용 | 구현 확인 | 신규 기계토큰은32bytes 솔트·256bit 토큰·SHA256·상수시간 비교. production은16bytes 솔트/무솔트 호환을 거부, 관리자의 명시적 토큰 회전 후 신규형식만 허용. 실제 현재 개발 DB의 구형/손상 자격0개(기관행도0). `check_legacy_credentials.py`, `SECURITY_CONDITIONS_BACKEND.md`. | 다른 DB를 가져오면 읽기 전용 형식 점검 후 관리자 회전 필요. 자동으로 기존 자격을 변경하지 않음. 사람 비밀번호 도입 시 별도 KDF 설계. |
| S15 | 무결성 검사 없는 코드 다운로드 | 조건부 | hash-lock·npm integrity·CI SHA·Docker base digest로 실제 이미지 build/run, 이미지 소스 hash 일치. 최종 ZIP은 manifest와 암호화 Ed25519 릴리스키의 분리 서명; 검증은 외부 신뢰 지문 필수, 변조·공격자 키 대체 거부. 기존OS High8종을 Alpine 교체·취약 구성요소 제거/수정으로 해결하고 최종OS38/Python21 검출0. `SECURITY_CONDITIONS_TOOLS.md`, `DOCKER_RUNTIME_CHECK.json`, `DOCKER_IMAGE_SCAN.md`. | 계정 소유자가 승인한 기존 키 지문을 별도 HTTPS와 GitHub variable에 등록, hosted runner 실제 CI285개 통과. 최종 승인 SHA/릴리스 gate는 ZIP 밖 OPERATIONS_RELEASE_CHECK.json 참조. GitHub 계정 MFA가 꺼져 있어 사용자 설정이 남음. Alpine 미수정 CVE 탐지 한계·신규 취약점 점검 지속. manifest/동봉 공개키만으로 발행자 인증 불가. |
| S16 | 반복된 인증시도 제한 기능 부재 | 구현 확인 | 본문 전 관리자/기관30·verify60·analyze10회/UTC분, SQLite BEGIN IMMEDIATE의 공유 카운터와 DB 밖 지속 HMAC키. 실제2프로세스60허용/20거절·재시작429, Docker 재시작/XFF변경도429. 감사7일·카운터5분의 기본60초 유휴정리 실제61초 확인. `SECURITY_CONDITIONS_BACKEND.md`, `DOCKER_RUNTIME_CHECK.json`. | 고정분 경계 버스트는 존재. 동일 로컬 SQLite를 공유하는 워커 범위이며 여러 호스트에는 중앙 저장소 필요. proxy_headers=False 기준 출처 집계; 실제 프록시의 IP신뢰·경보 담당자는 별도 운영 조건. |

## 시간 및 상태 — 2개

| ID | 교육자료 항목 | 판정 | 확인 근거·시험 | 남은 조건 |
| --- | --- | --- | --- | --- |
| T01 | 경쟁조건: 검사 시점과 사용 시점 (TOCTOU) | 구현 확인 | `storage.py:129` 쓰기 `BEGIN IMMEDIATE`, 읽기 snapshot. 발급·폐기의 권한/키/데이터 검사는 같은 트랜잭션에서 수행. `test_issuance_holds_write_transaction_during_signing`, `test_verification_reads_a_coherent_snapshot_during_revocation`; 키 생성 `O_EXCL`. | 키 파일 외부 변경은 OS ACL로 제한. 검증 응답 뒤 발생한 폐기는 그 응답에 소급 반영되지 않음. |
| T02 | 종료되지 않는 반복문 또는 재귀함수 | 구현 확인 | 실제 body16KiB·수신5초·reader32슬롯·사전rate검사, QR/JSON 깊이 오류 차단. 분석 전체10초·이동3회·DNS/HEAD시간·각4슬롯. DNS 실제 완료까지 슬롯 유지. 느린body/reader고갈/사전rate의 실제 ASGI 시험과 DNS saturation·실제 TLS 느린헤더 시험. | 프록시/TLS 수신 이전·다중 프로세스의 전체 연결 제한은 별도. OS DNS 강제 취소 한계는 작업 수 제한으로 격리. |

## 에러처리 — 3개

| ID | 교육자료 항목 | 판정 | 확인 근거·시험 | 남은 조건 |
| --- | --- | --- | --- | --- |
| E01 | 오류 메시지 정보 노출 | 구현 확인 | `api.py` validation handler는 원문·토큰·입력값을 되돌리지 않음. 최상위 500은 고정 메시지, DB/키 경로·스택 비노출. `test_validation_and_unexpected_errors_do_not_echo_private_input`, `test_actual_body_limit_and_error_security_headers`. | 배포 access/error log에서도 원문·Authorization 기록 금지. |
| E02 | 오류 상황 대응 부재 | 구현 확인 | 잘못된 QR은 blocked, 키 오류는 422/503, TLS 오류 blocked, 분석 불가 warning. 프런트 요청 실패·카메라 권한/지원 실패 처리. DB는 rollback/finally close. `test_signing_key_mismatch_fails_closed`, `test_bad_certificate_is_blocked`. | 실제 인프라의 장애 알림·복구·백업 복구 시험 필요. |
| E03 | 부적절한 예외 처리 | 구현 확인 | 예상 가능한 파싱·TLS·네트워크·키 오류를 구분하고 신뢰 결과로 대체하지 않음. DB exception은 rollback 후 재전파; 최상위 응답에서 내부 예외 은닉. `test_validation_and_unexpected_errors_do_not_echo_private_input`. | 내부 장애 관측은 민감정보를 제외한 별도 운영 로깅 필요. |

## 코드오류 — 5개

| ID | 교육자료 항목 | 판정 | 확인 근거·시험 | 남은 조건 |
| --- | --- | --- | --- | --- |
| C01 | Null Pointer 역참조 | 구현 확인 | DB `fetchone()` 결과·선택적 인증·hostname·카메라 ref·결과 객체를 사용 전 확인. `test_issuer_authorization_and_expiry_bounds`, `test_signing_key_mismatch_fails_closed`; 클라이언트의 선택적 결과 접근 확인. | 네이티브 라이브러리 내부는 별도 SCA 범위. |
| C02 | 부적절한 자원 해제 | 구현 확인 | `storage.py` DB finally close, `crypto.py` 파일 context, `analyzer.py` TLS/HTTP finally close·타이머 취소·세마포어 반환. 시민 카메라 controls.stop·track.stop 처리. | 브라우저 이동·권한 실패 경로를 실제 장치에서도 확인. |
| C03 | 해제된 자원 사용 | 비적용(직접 코드) | Python 가이드 PDF 11쪽에서 제외한 항목. 직접 포인터·수동 메모리 해제 없음. DB는 context scope에서 결과를 복사하고 종료 후 닫힌 connection을 외부 반환하지 않음. | cryptography·Pillow 등 네이티브 의존성 취약점 관리. |
| C04 | 초기화되지 않은 변수 사용 | 비적용(직접 코드) | Python 가이드 PDF 11쪽에서 제외한 항목. Python 초기화 없이 값 참조는 예외이며 직접 미초기화 메모리 접근 없음. 응답·목록·타이머·브라우저 ref/state 초기값 수동 확인. | 새 예외 분기에서 값 사용 순서 재검토. |
| C05 | 신뢰할 수 없는 데이터의 역직렬화 | 구현 확인 | `crypto.py:41` JSON만 파싱하며 크기·canonical·필드·타입을 검사. pickle/marshal/unsafe YAML 사용 없음. 이후 서명·발급 기록 대조 전 trusted 불가. `test_tampering_and_unknown_format_are_blocked`, `test_boolean_protocol_version_is_rejected`. | JSON 구조 제약과 parser 의존성 관리 유지. |

## 캡슐화 — 4개

| ID | 교육자료 항목 | 판정 | 확인 근거·시험 | 남은 조건 |
| --- | --- | --- | --- | --- |
| N01 | 잘못된 세션에 의한 데이터 정보 노출 | 구현 확인 | 매 요청 기관 인가·기관별DB·no-store·서비스워커 비캐시·시민기록 비저장. `IssuerView.tsx:49` 상태/토큰/발급결과 제거·abort/generation, `:56` 5분유휴해제 및 background복귀 재검사. 기관 격리·감사 시험과 프런트 유휴중 진행요청/늦은응답·키입력 시간갱신 시험. | UI해제는 서버토큰 무효화/만료가 아님. 토큰 수명·회전·폐기 정책, JS물리제로화/단말dump는 별도 조건. |
| N02 | 제거되지 않고 남은 디버그 코드 | 구현 확인 | production은 docs/redoc/openapi 비활성. 개발 Vite는 loopback 바인딩. `test_production_mode_disables_api_docs`; 데모·시험 스크립트는 별도 도구. | 공개 배포에 `ONJEON_ENV=production`, reload/debug 비활성 확인. |
| N03 | Public 메서드로부터 반환된 Private 배열 | 구현 확인 | 대시보드는 허용 필드의 새 dict/list만 반환. 기관의 `issuer_token_hash`·키 비밀·내부 DB connection은 응답에서 제외. `test_dashboard_tracks_issue_revoke_and_preserves_scan_privacy`. | 새 응답에도 SELECT * 결과 직접 반환 금지. |
| N04 | Private 배열에 Public 데이터 할당 | 구현 확인 | 입력 모델을 검증하고 DB 저장값·응답·설정 분리. 공유 전역 사용자 배열에 클라이언트 배열의 참조를 보관하지 않음. `Settings` frozen dataclass, 파싱 후 페이로드 구조 검사. | 전역 캐시/기관 설정 편집 기능 추가 시 복사·검증 점검. |

## API 오용 — 2개

| ID | 교육자료 항목 | 판정 | 확인 근거·시험 | 남은 조건 |
| --- | --- | --- | --- | --- |
| A01 | DNS lookup에 의존한 보안결정 | 구현 확인 | DNS 응답만으로 기관/사용자를 인증하지 않음. 서명·토큰·DB로 인증하고 URL 분석에서는 모든 IP 정책검사 후 해당 IP에 TLS 연결, 원래 hostname 인증서 검사. `test_ipv4_is_preferred_after_all_addresses_are_checked`, `test_bad_certificate_is_blocked`. | 등록된 도메인의 소유·DNS 관리 건전성은 운영자가 확인. |
| A02 | 취약한 API 사용 | 구현 확인 | 안전한 secrets·cryptography·인자화 sqlite·검증된 TLS·JSON API 사용. eval/exec/pickle/shell=True/검증 없는 TLS API 없음. Bandit·pip-audit·npm audit 결과는 최종 시험보고서에 기록. | 도구 탐지 범위 밖 논리 결함·신규 취약점은 수동 검토와 정기 재점검 필요. |

49개 항목을 모두 검토했다. 상태별로 **구현 확인37개, 비적용10개(언어 특성상 직접 코드 비적용3개 포함), 조건부2개**다. 기존 조건부7개를 모두 추가 점검하고 S03·S09·S14·S16은 로컬 구현과 실행 근거를 확인했다. S11은 실제 승인 CRL 운영까지 확인했다. S05 공개 TLS/백업 분리와 S15 릴리스/CI 통제도 실증했으며 남은 조건은 PC 키 보관 매체 암호화와 GitHub MFA다. [공개 운영 보고서](OPERATIONS_COMPLETION_20261011.md)를 따른다. [조건부 재점검](SECURITY_CONDITIONS_REVIEW.md)에 실제 실행과 미확인을 구분했다. 이 수치는 발견 취약점 수나 대회 공식 진단 결과가 아니다.
