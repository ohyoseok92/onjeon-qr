# 온전 QR

## 공개 시연과 운영 상태

서비스: https://qr.ohs92.com. 실제 공개 TLS·CRL 운영·MYBOX 암호화 백업 왕복 복구·원격 CI를 검증했다. GitHub MFA와 PC C: 암호화는 남아 있다. 자세한 실행 범위와 증거는 [운영 보고서](submission/OPERATIONS_COMPLETION_20261011.md)를 따른다. 아래 로컬 시연·초기 점검 기록의 공개 배포 미확인은 후속 보고서로 갱신한다.

제출용 개발기획서를 바탕으로 만든 시제품입니다. 기관이 등록된 정확한 도메인의 HTTPS 주소를 Ed25519로 서명해 QR을 발급합니다. 시민 화면은 서명, 발급 기록, 유효기간, 폐기 상태를 확인한 뒤에만 목적지를 보여 줍니다. 미서명 QR은 별도 주소 분석으로 위험 신호를 표시하지만 기관 인증이나 안전 판정으로 취급하지 않습니다. 현재 코드는 가상 기관을 이용한 로컬 시험용입니다.

## 구현 범위

- 관리자 등록: 기관 이름, 공식 도메인, 공개키와 키 버전을 등록합니다. 기관별 발급 토큰은 등록 응답에서 한 번만 반환하며 DB에는 해시만 저장합니다.
- 기관 발급: 등록 도메인에 속한 HTTPS 주소만 서명합니다. 발급 응답으로 `onqr:v1:` 형식의 QR 원문과 선택적인 PNG를 제공합니다.
- 시민 검증: 유효한 서명과 발급 기록을 확인합니다. 변조, 미등록 발급자, 만료, 폐기, 도메인 정책 위반은 `blocked`로 응답하고 이동할 주소를 제공하지 않습니다.
- 폐기와 키 교체: 기관 토큰으로 QR을 폐기합니다. 관리자는 발급 토큰을 재발급하고, 기관을 비활성화하며, 키를 교체·재활성화·폐기할 수 있습니다. 키 활성화 전에 로컬 서명키와 공개키의 일치를 확인합니다.
- 기관 관리 화면: 인증 후 발급 목록, 유효·폐기·만료 건수, 상태 필터와 폐기 확인을 제공합니다. QR 원문 복사, PNG 저장과 시민 화면 검증을 지원합니다.
- 감사: 발급·폐기와 기관 등록·키 변경·토큰 재발급·기관 활성화 변경을 상태 변경과 같은 트랜잭션으로 기록합니다. 기관·관리자의 인증 실패와 제한 이벤트는 원문 IP 대신 일/프로세스별 식별값을 사용해 7일·10,000행 범위로 기록합니다. 시민의 검증 요청과 스캔 위치는 저장하지 않습니다. 감사표에는 URL·토큰·QR 원문도 없습니다.
- 웹 화면: React 시민 검증 화면과 기관 발급 화면을 제공합니다. ZXing과 jsqr로 회전된 QR 해독을 지원하고, 붙여 넣기도 제공합니다. 검증 전에는 링크를 열지 않으며 기관 토큰은 브라우저 저장소에 보관하지 않습니다. 기관 화면은 5분 동안 사용하지 않으면 연결을 해제합니다.
- 미서명 URL 분석: HTTPS 여부, 공개 IP, TLS 연결, 최대 3회 리다이렉트, 등록 도메인 이탈, 유사 도메인과 설치 파일 징후를 확인합니다. HEAD 요청만 보내며 각 이동 지점의 DNS를 다시 검사하고 확인한 IP에 직접 연결합니다. 결과는 항상 경고 또는 차단이며 링크를 제공하지 않습니다.
- 남용 방지: 본문 길이 16 KiB, 수신 전체 5초·동시 수신 32개, 분석 10회/분, 서명 검증 60회/분, 발급·관리 각 30회/분을 제한합니다. 인증에 실패한 관리·기관 요청은 별도 그룹에서 각 30회/분을 적용해 정상 인증 요청의 몫을 소진하지 않습니다. 횟수 제한은 본문 수신 전에 적용하고 분석 동시 실행은 4개까지 허용합니다. SQLite 카운터는 `admin`, `issuer`, `verify`, `analyze`, `admin_auth`, `issuer_auth`의 고정 6개 그룹별 최대 10,000행이며 지난 분의 행을 삭제합니다. HMAC 출처·분별 횟수만 남기고 같은 DB를 공유하는 워커와 재시작에 걸쳐 유지합니다. 원시 IP·시민 스캔 원문은 저장하지 않습니다.

인증 분류는 앱 인스턴스마다 관리자·기관 각각 최대 8개를 동시에 처리하며, 포화된 역할의 다음 요청은 토큰 비교나 기관 DB 조회 전에 `429 / Authentication checks busy`로 거부합니다. 역할별 슬롯은 독립적입니다. 실패·정상 요청을 구분하려면 토큰을 먼저 평가해야 하므로 실패 한도에 도달한 뒤에도 인증 평가 자체가 분당 30회로 제한되지는 않습니다. 잘못된 토큰은 429여도 정상 토큰은 정상 한도 내에서 처리할 수 있습니다. 운영 토큰은 높은 엔트로피로 생성하며 여러 워커의 인증 평가 총량과 앞단 연결 제한은 별도 운영 조건입니다.

서명키 PEM은 DB 밖의 `.secrets` 디렉터리에 둡니다. 운영 모드는 `.secrets/<기관ID>/<키버전>.pem` 중첩 경로만 사용합니다. `<기관ID>-<키버전>.pem` 형식의 레거시 파일은 로컬 데모에서만 호환하며, 운영 모드에서 중첩 키가 없으면 발급·키 활성화·교체를 거부합니다. `ONJEON_KEY_PASSWORD`를 설정하면 암호화된 PKCS8로 생성하며 운영 모드는 무작위 관리자 토큰·키 암호와 CRL-only 번들 설정을 요구합니다. 최소32자 검사 외에 짧은 반복·알려진 예시 패턴도 거부합니다. 기존 평문 키는 설정만 바꿔도 자동 암호화되지 않으므로 운영 전 새 암호화 키로 교체해야 합니다. `.secrets`, `.env`, `data`, 가상환경은 제출 압축본에서 제외합니다. 제출 압축본은 `.gitignore`에만 의존하지 않고 허용 목록 방식으로 만듭니다. 실제 기관 운영에는 기관 승인 절차, 키 보관 서비스, HTTPS 배포와 별도 보안 진단이 더 필요합니다.

## 설치와 시험

Python 3.12, Node.js 24, PowerShell 기준입니다.

```powershell
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install --require-hashes -r requirements-dev.lock
$env:PYTHONPATH = Join-Path (Get-Location) 'src'
npm ci --prefix frontend
& .\.venv\Scripts\python.exe -m pytest -q
& .\.venv\Scripts\python.exe -m pip check
& .\.venv\Scripts\python.exe scripts\demo_flow.py
cd frontend
npm test
npm run build
cd ..
```

데모는 임시 DB와 임시 서명키로 가상 기관을 등록한 다음 QR을 발급·검증·폐기합니다. 출력 이미지는 `demo-output/signed-qr-demo.png`입니다. 데모가 끝나면 임시 DB가 삭제되므로 이 이미지는 사후 검증에 사용할 수 없습니다. 실제 기관이나 공식 QR로 오해하지 않도록 가상 기관 이름을 사용합니다.

브라우저 시연용 기관은 `scripts/prepare_demo.py`로 만들 수 있습니다. 아래 실행 예의 첫 세 명령을 같은 PowerShell 세션에서 실행하면 기관 ID, 발급 토큰, 유효한 QR 원문과 이미지가 출력됩니다. 토큰이 화면 공유나 녹화에 노출되지 않게 주의하세요. 목적지는 실제 서비스가 아닌 `demo.example.org`입니다.

```powershell
$env:ONJEON_ADMIN_TOKEN = & .\.venv\Scripts\python.exe -c 'import secrets; print(secrets.token_urlsafe(32))'
$env:ONJEON_KEY_PASSWORD = & .\.venv\Scripts\python.exe -c 'import secrets; print(secrets.token_urlsafe(32))'
& .\.venv\Scripts\python.exe scripts\prepare_demo.py
& .\.venv\Scripts\uvicorn.exe --factory onjeon.api:create_default_app --host 127.0.0.1 --port 8000
```

Python 운영·개발 의존성은 `requirements-runtime.lock`·`requirements-dev.lock`의 버전과 SHA256으로, 웹 의존성은 `frontend/package-lock.json`의 무결성 값으로 고정했습니다. `.github/workflows/ci.yml`은 Python 시험·Bandit·pip-audit와 웹 회귀 시험·빌드·npm audit를 실행합니다. 로컬에서도 같은 점검을 실행할 수 있습니다.

```powershell
& .\.venv\Scripts\python.exe -m bandit -r src -q
& .\.venv\Scripts\python.exe -m pip_audit --local --skip-editable
cd frontend
npm audit --audit-level=high
```

## 로컬 API 실행

관리자 토큰을 환경변수로 제공해야 앱이 시작합니다. 아래 명령은 현재 PowerShell 세션에만 임의 토큰을 설정합니다.

```powershell
$env:ONJEON_ADMIN_TOKEN = & .\.venv\Scripts\python.exe -c 'import secrets; print(secrets.token_urlsafe(32))'
$env:ONJEON_KEY_PASSWORD = & .\.venv\Scripts\python.exe -c 'import secrets; print(secrets.token_urlsafe(32))'
& .\.venv\Scripts\uvicorn.exe --factory onjeon.api:create_default_app --host 127.0.0.1 --port 8000
```

빌드된 웹 화면은 `http://127.0.0.1:8000/`, API 명세는 `http://127.0.0.1:8000/docs`에서 확인할 수 있습니다. 기관 등록 전에 `& .\.venv\Scripts\python.exe -m onjeon.cli demo-city v1`로 키를 만들고, 출력된 공개키를 등록 요청에 넣습니다. 등록 응답의 `issuer_token`은 다시 표시되지 않으므로 안전하게 보관해야 합니다. 기관을 등록한 뒤 기관 발급 화면에서 QR을 발급하고 시민 검증 화면에서 확인합니다. 카메라는 HTTPS 또는 localhost에서만 사용할 수 있습니다.

## 컨테이너 실행과 보안 자료

Docker 엔진을 복구해 digest 고정 이미지의 실제 빌드·실행을 확인했습니다. 일반 `compose.yaml`은 관리자·키 암호 환경변수와 `ONJEON_TLS_CRL_BUNDLE` 호스트 경로가 필요합니다. 자격값이 Docker 설정 환경에 노출되지 않는 로컬 HTTPS 프로필은 다음처럼 별도 비밀 파일을 읽습니다. 프로필은 새로운 경로에만 생성하며 기존 비밀을 덮어쓰지 않습니다.

```powershell
& .\.venv\Scripts\python.exe scripts\secure_profile.py create
& .\.venv\Scripts\python.exe scripts\create_local_tls_fixture.py
docker compose -f compose.security.yaml up --build -d --wait
& .\.venv\Scripts\python.exe scripts\check_docker_runtime.py
```

현재 작업공간에는 이미 프로필을 생성했으므로 `create`를 재실행하지 않습니다. 컨테이너는 `127.0.0.1:8443`의 HTTPS만 공개하며 UID10001·read-only root·cap_drop ALL·no-new-privileges와 별도 DB/키 볼륨을 사용합니다. CA는 OS에 설치하지 않은 시험용이며 인증서·CRL은2일 후 만료됩니다. CLI 검사만 해당 CA를 명시적으로 신뢰합니다. 공개 서비스에는 실제 도메인 인증서와 유지되는 CRL 정책을 준비해야 합니다. [실제 Docker 증거](submission/DOCKER_RUNTIME_CHECK.md), [조건부7개 재점검](submission/SECURITY_CONDITIONS_REVIEW.md)을 참고하세요.

- [교육자료 49개 보안약점 점검표](submission/SECURITY_CHECKLIST_49.md)
- [KISA 가이드 5개 대조 결과](submission/GUIDE_SECURITY_REVIEW.md)
- [시험 결과](submission/TEST_REPORT.md), [제품 합성 평가](submission/PRODUCT_EVALUATION.md)
- [Python SBOM](submission/SBOM.python.cdx.json), [웹 SBOM](submission/SBOM.frontend.cdx.json)

## 판정 경계와 운영 전 작업

기관 관리자 등록과 복구 기능은 API에서 제공합니다. 미서명 URL 분석기는 URL이나 시민 스캔 이력을 저장하지 않습니다. HEAD 응답이 없거나 연결에 실패하면 분석 미완료 경고를 표시합니다. 일부 서버는 HEAD를 지원하지 않으므로 본문이나 이후 브라우저 동작까지 확인했다는 뜻은 아닙니다. 보조 분석 결과는 기관 인증과 분리해 표시합니다.

`onqr:v1:` 텍스트는 기본 카메라 앱에서 바로 열리는 웹 주소가 아닙니다. 시민이 이 서비스의 화면에서 QR을 읽어야 합니다. 서명이 확인된 URL도 접속 후 다른 사이트로 이동할 수 있으므로 화면에 이 한계를 경고로 표시합니다.

폐기 상태를 매번 서버에서 확인하므로 오프라인 검증은 제공하지 않습니다.

운영 배포 시 `ONJEON_ENV=production`과 관리자·키 비밀, `ONJEON_TLS_CRL_BUNDLE` 설정이 필요합니다. CRL 형식과 시간 구간은 정상이나 현재 시점에서 만료되었거나 아직 발효하지 않았다면 URL 분석만 차단하고 `/health`에 `degraded`와 `url_analysis` 사유를 표시합니다. 서명 QR 검증·발급과 관리 기능은 유지하며, 정상 CRL로 갱신하면 다음 분석·상태 조회부터 회복합니다. 설정 누락·손상·CA 인증서 혼입·잘못된 시간 구간·운영 TLS 키 로그 설정은 앱 시작을 거부합니다. 분석 연결은 계속 CRL 체인 검사를 강제하므로 대상 발급자의 CRL 누락이나 인증서 폐기도 차단합니다.

현재 컨테이너는 `proxy_headers=False`로 전달 헤더를 신뢰하지 않으며 프록시가 있으면 요청 출처가 프록시로 집계됩니다. 실패한 인증 요청은 별도 그룹으로 분리했지만 같은 프록시 뒤의 정상 사용자들은 같은 정상 요청 한도를 공유합니다. 실제 프록시 IP의 신뢰 범위를 확인한 뒤 출처 전달을 설계해야 합니다. 같은 로컬 SQLite를 공유하는 다중 워커의 제한·재시작은 검증했고, 여러 호스트에는 중앙 제한 저장소가 필요합니다. `ONJEON_FRONTEND_DIST`로 웹 빌드 경로를 지정할 수 있습니다. 제출 준비 현황은 [submission/README.md](submission/README.md)에 있습니다.

구현에 사용한 API 문서는 [FastAPI 보안 도구](https://fastapi.tiangolo.com/reference/security/), [Ed25519 서명](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/), [qrcode](https://pypi.org/project/qrcode/), [Python SQLite](https://docs.python.org/3.12/library/sqlite3.html), [ZXing 브라우저](https://github.com/zxing-js/browser)입니다.
