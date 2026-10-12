# 로컬 검증 결과

## 2026-10-11 공개 운영 후속 확인

공개 TLS·실제 CRL 갱신/감시·MYBOX 다운로드 복구·원격 CI를 적용했다. 현재 집계는 **구현 확인37·비적용10·조건부2**이며 GitHub MFA와 PC C: 암호화가 남았다. 최신 결과는 [공개 운영 보고서](OPERATIONS_COMPLETION_20261011.md)를 따른다. 아래 로컬 점검의 미확인·집계 수치는 당시 기록이다.

실행일: 2026-10-11(한국시간). Windows11, Python3.12.10, Node24.14.1. 기존 결과에서 조건부7개 보완·실제 Docker·동시 시작 경합 수정 후 최종 결과로 갱신했다. 가이드5종 총1,307쪽의 전체 본문·예제·부록과 독립 수동 검토를 포함한다.

## 공개 운영 추가 후 원격 검증 (2026-10-11)

[GitHub CI 38142893078](https://github.com/ohyoseok92/onjeon-qr/actions/runs/38142893078)에서 **Python285개 통과, 경고1개, 생략0개, 26.06초**와 **브라우저15개 통과**, 웹 빌드, hash-lock 설치, pip/npm 알려진 취약점0건을 확인했다. npm 의존성을 함께 설치해 Linux 파생 시험의 공급망 교차 검사 생략도 실행했다. CI는 서비스 운영 서버와 분리된 GitHub hosted Ubuntu24.04를 사용한다.

확장 Bandit `src scripts` 결과는 **High0/Medium4/Low38**이다. Medium은 컨테이너 내부 서버의 0.0.0.0 바인딩2건과 복구 검사 도구의 테이블명 SELECT2건이다. 외부 게시를 compose의 호스트 loopback으로 제한하고, 테이블명은 고정 목록 또는 허용문자 검사 후 사용하는 흐름을 수동 확인했다. Low는 주로 시험 도구의 assert와 인자 분리 subprocess 사용이다. `src` CI 검사는0건이다. 이를 전체 취약점 무검출로 확대하지 않는다. 웹 빌드의 QR reader 청크 크기 경고는 남는다.

실제 공개 TLS·발급/검증/폐기·인증서 갱신 dry-run·CRL 자동 갱신/감시·MYBOX 다운로드 복구 결과는 `OPERATIONS_COMPLETION_20261011.md`와 개별 JSON을 따른다. 최종 ZIP 서명·독립 승인 해시·릴리스 gate 결과는 ZIP 밖 `OPERATIONS_RELEASE_CHECK.json`에 기록한다.

## Claude Opus 지적 수정 직후 검증 (공개 운영 이전)

이 절과 아래 기존 표는 공개 운영 도구를 추가하기 전 실행 기록으로 보존한다.

| 검사 | 수정 후 결과 |
|---|---|
| 실제 최신 이미지의 Linux 전체 pytest | **176 passed, 1 skipped, 1 warning**, 25.43초. UID10001·네트워크 없음·읽기 전용 rootfs의 파생 시험 컨테이너. POSIX 권한 시험 통과; npm 의존성이 없는 공급망 통합 시험만 생략 |
| Windows 수정된 기존 4개 시험 모음 | **120 passed, 1 skipped, 1 warning**,91.79초. API/분석기/저장소/운영 도구 포함 |
| Windows 새 결함 회귀 모음 | **12 passed, 1 warning**,135.93초. 실제 NTFS 보호 프로필과 암호화 체크포인트, 경로 변경/외부 재연결, 인증 동시성/health 캐시 포함 |
| 서비스 Bandit / git diff --check | 각각 종료0. 알려진 줄바꿈 안내는 남음 |
| 실제 최신 Docker 암호화 백업 | v2 AES-GCM + 인증 생성 시각/세대/감사ID/DBhash + HMAC 체크포인트. DB 전체 행·기관 암호화 키10개·HMAC 일치, Windows 복구 production API/관리자200, 기존 컨테이너 healthy 복귀와 평문 staging 제거 |
| 실제 최신 Docker TLS 실행 | 이미지1b5c6bed…, TLS1.3·healthy·현재 소스 hash 일치·암호화 키 발급/trusted/폐기/blocked·재시작 후 폐기/한도 유지·비루트/권한/비밀 bind 검사 통과 |
| 최신 이미지 패키지 검사 | 같은 당일 공개 DB, OS38/Python21, 모든 심각도 검출0. Alpine 미수정 취약점과 휠 번들 네이티브 라이브러리 범위 제한 유지 |

첫 설치 백업의 기본 거부/명시 승인과 구형 사본을 새 체인으로 자동 등록하지 않음도 추가 확인했다.

백업에 DB의 고정 설치 ID를 추가하고 스냅숏·세대 할당을 직렬화해 다른 staging 경로에서도 같은 체인을 확인했다. 인증 분류는 역할별8개 동시성 상한을 적용하고 슬롯 포화에서 DB/토큰 평가 없이 거부·예외 후 슬롯 복구를 확인했다. health는100회 요청에서도 캐시가 CRL 재파싱을 제한하고5초 뒤 상태를 갱신함을 확인했다.

M1은 공개/인증 실패 그룹 포화에도 정상 관리자·기관 한도가 유지됨과 구형 CHECK 마이그레이션의 사용한 한도 보존을 확인했다. L1은 fec0 DNS 응답을 연결 전에 차단했다. L2는 이전·v1 백업 기본 거부, 최신 복구, 명시적 예외, 메타데이터/신뢰 체크포인트 변조 거부를 확인했다. L3는 유효한 기관 ID의 레거시 충돌이 production에서 발급·활성화·교체를 거부하고 중첩 키는 정상 동작함을 확인했다. L4는 CRL 만료 상태에서 health의 degraded 표시, 서명 QR 발급·검증·폐기 유지, URL TLS 차단, CRL 갱신 후 재시작 없는 상태 회복과 손상된 CRL의 시작 거부를 확인했다.

웹 소스·lock·OS 패키지는 이번에 바꾸지 않았다. 기존 화면15개 결과와 공급망 감사는 아래 기록을 따른다. 새 Docker 이미지는 다시 빌드·실행·패키지 검사했다. Claude의 독립 후속 검토 결과는 별도 `CLAUDE_OPUS_REMEDIATION_20261011.md`를 따른다.

## 수정 전 검증 기록

| 검사 | 당시 결과 |
| --- | --- |
| 최종 원본 Python 전체 pytest | **135개 통과, 1개 생략, 경고1개**,94.34초. 이전 회귀에서 동시 초기화 실패를 재현·수정하고 새 DB/구형 DB Barrier 동시 시작4회 추가 |
| 최종 Alpine Linux 전체 pytest | **135개 통과, 1개 생략, 경고1개**,23.16초. zlib1.3.2-r1을 적용한 최종 배포 이미지1e5f37f…의 파생 시험 컨테이너, 실제 POSIX권한 시험 통과. npm 설치가 없는 공급망 통합시험1개 생략 |
| npm test --prefix frontend | **15개 통과**,2파일,4.93초. 최종 코드의 화면과 실제 픽셀4회전 회귀 |
| npm run build --prefix frontend | TypeScript·Vite 성공. 카메라 지연 청크543.26KB/압축154.24KB 크기 안내1개 |
| python -m bandit -r src -q | 종료0, 보고된 문제 없음 |
| pip-audit requirements-dev.lock / requirements-runtime.lock | 두 검사 모두 알려진 취약점 없음 |
| npm audit --prefix frontend --audit-level=high | 개발 의존성 포함 취약점0 |
| python -m pip check | 의존성 충돌 없음 |
| 운영 lock pip install --dry-run --ignore-installed --require-hashes | 앞선 단계20개 해시/해석 성공; 이후 Python runtime lock 변경 없음 |
| scripts/demo_flow.py | 발급→trusted→폐기→blocked 재현 |
| scripts/evaluate_product.py | 합성 서명100/100·URL 정책100/100, 별도 정상50건 기준 확인 |
| scripts/check_recovery.py | 실제 임시 DB/암호화 키/HMAC 복구11결과 true,0.834초. 오래된 백업의 폐기 상태 후퇴도 재현 |
| scripts/generate_supply_chain.py | Python20/frontend8, 실제 관계27/11, 버전·참조·누락0, 라이선스 원문30개 |
| scripts/validate_sbom_schema.py | 별도 jsonschema4.25.1 도구 환경, 공식 CycloneDX1.5 schema 두 SBOM 통과 |
| ZAP2.17.0 local Automation Framework | 최신 source 서버19:24 재검사 seed6개·spider20 URL·작업 종료0; high/medium/low0, info3종5사례 |
| Docker build/up/runtime | Engine29.8.0, digest/hash-lock 빌드·TLS1.3 healthy·UID10001·0700/0600·CapEff0·NoNewPrivs1·쓰기 거부·재시작/XFF에도429·현재 소스 hash 일치 |
| Docker 이미지 Trivy0.75.0 | 공식 Alpine 교체·zlib1.3.2-r1 갱신 후 OS38/Python21패키지 모든 심각도 검출0. Trixie High44행(고유8개)의 개별 제거·수정 근거와 Alpine의 미수정 취약점 탐지 한계는 DOCKER_IMAGE_SCAN.md/json |
| Gitleaks8.30.1 dir --redact --max-archive-depth 1 | 최종 소스 ZIP 내부 포함 검사 탐지0; 공식 배포 체크섬 검증 도구 |
| scripts/verify_submission.py | 최종 ZIP 금지경로·비밀확장자·중복/상위경로·전체 SHA256 검사. 실제 최종 결과와 파일 수·해시는 분리 서명 검증 결과를 따른다 |
| git diff --check | 공백 오류 없음; Windows 줄바꿈 안내 |
| scripts/secure_profile.py 운영도구 | 실제 NTFS·암호화 PKCS8·외부 지문/변조/공격자 키 거부·AES-GCM/WAL/중첩 키/HMAC/경로 경계9시험 통과 |
| scripts/check_encrypted_docker_backup.py | 최종 Alpine 컨테이너 DB+기관 암호화 키8개+HMAC를 AES-GCM 백업·복구. 새 보호 프로필로 반복 복구 격리, 전체 행·키 동일, Windows 복구 production API 시작·인증200, staging 제거 |

## 추가 시험의 실제 범위

기관/관리자 인증 실패401/403·제한429·감사 장애·보존일/행수·분집계·출처 변경·원문 비저장을 확인했다. 새32바이트솔트와 기존16바이트솔트/무솔트 전환, 비ASCII 관리자 자격증명 거부도 포함한다. 실제 ASGI receive 지연은5초에408로 취소했고,32개 수신 중33번째는 receive 호출 없이429였다. 횟수 초과 요청도 본문을 읽지 않았다.

기존 실제 로컬 TLS/HTTP5건과 추가 CRL 체인 시험은 자체서명·호스트 불일치 인증서, 내부망 이동 연결 전 차단, 설치 주소 위험신호, 느린 헤더 제한을 확인한다. DNS·소켓 라우팅만 로컬 fixture로 전환하며 TLS/호스트/IP 검사는 유지한다. 이동 뒤 IDN/유사도메인·인코딩된 설치 확장자·숨은 문자 URL도 회귀에 포함한다.

화면 시험은 오래된 응답 무시·trusted 링크 경계·카메라 대기/해독기 준비 중 중단·발급 경합·연결 해제·5분 유휴·활동 시 연장·백그라운드 지연 후 만료를 확인한다. 실제 서명 QR 픽셀은0/90/180/270도에서 해독했다. 이미지 공급만 시험 환경으로 대체했으며 실물 카메라 성능 시험은 아니다.

압축 해제본의 첫 화면 시험은 SDK의 최초 변환 지연으로 카메라 상태 시험1개가 시간 초과했다. 상태/권한 시험의 해독기 경계를 직접 제어하도록 mock을 옮겼고, 실제 픽셀 해독4건은 별도 파일에서 실제 라이브러리로 유지했다. 수정 후 해제본15개가 모두 통과했다. 실제 브라우저에서 늦은 모듈 로드·권한 응답을 취소하는 제품의 세대 검사도 유지한다. ZIP의 중첩 QR fixture·전체 읽기 기록·schema·라이선스·화면 증거 포함을 확인했다.

공급망 시험3건은 설치 metadata·lock·실제 관계와 라이선스 복사 hash를 대조하고 변조된 lock 거부를 확인한다. Windows의 metadata에 Linux marker를 적용한 회귀에서 활성19개·비활성colorama를 구분했다. 그 marker 회귀 자체는 실제 Linux 실행이 아니다. 별도로 실제 Linux Docker에서 runtime hash lock 설치·pip check·현재 소스 일치·권한을 확인했다. npm 생산 SBOM에서 React 계열3개가 빠지는 문제는 전체 설치 SBOM과 lock의 생산8개로 재구성했다. 원본·공식 스키마·전문 라이선스와 근거를 제출에 포함한다.

## 브라우저와 동적 진단

앞선 운영 빌드 시연에서 가상 기관 연결·목록/집계·발급·폐기·시민 재검증,390×844 가로 넘침 없음과 오류0을 확인했다. 최종 빌드와 수정 API의 임시 loopback8001 서버에서는 서명 QR trusted·공식 링크, 내부 주소 차단·링크 없음, console error/warn0을 재확인했다. screenshots/final-blocked.png가 마지막 차단 화면이다. 실제 카메라 권한은 열지 않았다.

ZAP에서 발견한 CSP form-action 누락은 수정·헤더 회귀·재검사로 확인했다. 최종 seed 검사는 모두 성공했다. active 요청의429는 탐색 범위를 줄일 수 있고 JavaScript 전체 DOM/인증 변경/외부 URL 분석은 제외했다. React 번들 주석 추정·SPA·User-Agent 정보 알림은 수동 검토했다. 자세한 범위는 DAST_CHECK.md에 있다.

## 해석과 미검증

정적 검사 범위를 새 도구3종까지 넓힌 Bandit 결과는 별도로 검토했다. 서비스 src는 지적0이다. 도구에는26개 알림이 남는다: 복구 시험의 assert22개, 고정된 내부 테이블 이름의 count SQL1개, 고정 인자로 로컬 npm을 호출하는 subprocess 관련3개다. 요청 입력이 해당 SQL/명령을 구성하는 경로는 없다. 복구 시험은 Python -O에서 잘못 성공하지 않도록 실행 자체를 거부하고, lock 파서는 최적화로 제거되지 않는 명시적 예외 검사를 사용한다. 이 도구 알림을 숨기거나 서비스 취약점 수로 합산하지 않았다.

최신 공유 SQLite 제한 적용 후 합성 로컬 검증100회 p50은16.697ms, p95는22.346ms였다. 카메라·실제망·TLS·운영 부하를 포함하지 않으며 합성 URL 결과로 실운영 탐지율95%/오탐률5%를 주장하지 않는다.

생략1개는 Windows에서 POSIX0600/0700 권한 작동을 입증할 수 없어 건너뛴 시험이다. 실제 Linux 컨테이너에서 DB/키/HMAC0600·디렉터리0700·UID10001을 따로 관찰했다. 경고1개는 Starlette TestClient의 httpx 사용 중단 예고다. 빌드 청크 안내는 해독기 지연 로드 크기이며 성능은 별도 확인한다.

49항목은 구현36·비적용10·조건부3이다. 기존 조건부7개를 모두 재점검하고 공개 도메인 TLS/백업 매체 분리(S05), 운영 CRL 확보·갱신·antirollback(S11), 발행자 신원·외부 지문 배포/CI 신뢰(S15)는 미확인으로 남긴다. Docker build/run·NTFS·로컬 TLS·무작위 비밀·구형 토큰 운영 거부·공유 제한·암호화 복구는 실증했다. 실물 휴대폰·실제 기관/도메인 승인·공개 서버 진단은 별도 범위다. 환경 미확인은 OPERATION_SECURITY.md, 백업 후 상태 후퇴는 RECOVERY_CHECK.md에 있다. 공식 외부 진단이나 보안 인증 결과가 아니다.

## 추가 실행에서 발견한 실패와 수정

최종 회귀 첫 실행은131 passed·1 failed·1 skipped였다. 실제 두 프로세스 동시 초기화에서 SQLite WAL 전환/DDL 경합을 Barrier로 재현했다. BUSY/LOCKED만 총5초 상한으로 재시도하고 CREATE·ALTER·index·정리를 단일 BEGIN IMMEDIATE 트랜잭션으로 묶었다. 새 DB·구형 DB 각2회와 재시작 회귀를 추가한 뒤 전체135 passed·1 skipped로 통과했다. 수정한 소스로 Docker를 다시 빌드하고 실제 소스 hash·HTTPS·재시작 한도도 재검증했다.

기본60초 유휴 정리는 실제61.011초·HTTP0회·만료행0을 확인했다. 첫 수동 하네스의 sqlite connection 미종료로 빈 합성 임시DB1개가 남았고, 자동 승인 검토가 삭제 명령을 거부했다(상세 사유 반환 없음). 실제 기관·키·토큰은 없다. 수정한 하네스의 새 실행은 종료·임시 자료 정리까지 성공했다. 실패 원본 임시DB는 원본/제출 ZIP에 포함하지 않는다.

새 운영 도구의 Bandit low4개는 고정 PowerShell/icacls subprocess 경로·argv(shell=False)를 문맥 검토한 결과다. 앞선 복구/공급망 도구26개 알림과 서비스 src의 지적0은 별도 범위다. 새로운 TLS 진입점·Docker 검사도 독립 수동 리뷰를 거쳤다. 호스트 TLS 키 로그 차단·정확한 포트/비밀 bind 검사를 보완했다.

Gitleaks의 첫 추가 검사에서 여러 위치 인자를 주자 CLI가 작업 루트로 범위를 넓혀 도구·생성한 비밀 프로필·시험 자료까지 스캔했다. redaction을 켠 상태였으며 이 결과를 소스 ZIP 검사로 사용하지 않았다. 단일 인자로 제출 ZIP만 지정하고 내부 압축 깊이1로 다시 검사해 탐지0을 확인했다.

앞선 Trixie 이미지의 OS High 고유8개는 이번 Alpine 교체에서 취약 구성요소 제거·수정 버전으로 해결했다. BusyBox의 mount/nsenter와 util-linux의 libuuid처럼 이름·원본이 겹치는 구성요소는 실제 구현·파일·버전을 대조했다. 단순 패키지명 변경이나 검사 예외로 완료 처리하지 않았다. Trivy의 Alpine 검사는 미수정 취약점을 모두 탐지하지 못하므로, 최신 검사0과 기존8종 개별 해결을 구분해 해석한다.
