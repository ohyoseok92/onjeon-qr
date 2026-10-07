# 온전 QR

제출용 개발기획서를 바탕으로 만든 시제품입니다. 기관이 등록된 정확한 도메인의 HTTPS 주소를 Ed25519로 서명해 QR을 발급합니다. 시민 화면은 서명, 발급 기록, 유효기간, 폐기 상태를 확인한 뒤에만 목적지를 보여 줍니다. 미서명 QR은 별도 주소 분석으로 위험 신호를 표시하지만 기관 인증이나 안전 판정으로 취급하지 않습니다. 현재 코드는 가상 기관을 이용한 로컬 시험용입니다.

## 구현 범위

- 관리자 등록: 기관 이름, 공식 도메인, 공개키와 키 버전을 등록합니다. 기관별 발급 토큰은 등록 응답에서 한 번만 반환하며 DB에는 해시만 저장합니다.
- 기관 발급: 등록 도메인에 속한 HTTPS 주소만 서명합니다. 발급 응답으로 `onqr:v1:` 형식의 QR 원문과 선택적인 PNG를 제공합니다.
- 시민 검증: 유효한 서명과 발급 기록을 확인합니다. 변조, 미등록 발급자, 만료, 폐기, 도메인 정책 위반은 `blocked`로 응답하고 이동할 주소를 제공하지 않습니다.
- 폐기와 키 교체: 기관 토큰으로 QR을 폐기합니다. 관리자는 발급 토큰을 재발급하고, 기관을 비활성화하며, 키를 교체·재활성화·폐기할 수 있습니다. 키 활성화 전에 로컬 서명키와 공개키의 일치를 확인합니다.
- 감사: 발급·폐기 사건만 기록합니다. 시민의 검증 요청과 스캔 위치는 저장하지 않습니다. 감사표에는 URL 원문도 없습니다.
- 웹 화면: React 시민 검증 화면과 기관 발급 화면을 제공합니다. ZXing으로 카메라 QR을 읽고, 붙여 넣기도 지원합니다. 검증 전에는 링크를 열지 않으며 기관 토큰은 브라우저 저장소에 보관하지 않습니다.
- 미서명 URL 분석: HTTPS 여부, 공개 IP, TLS 연결, 최대 3회 리다이렉트, 등록 도메인 이탈, 유사 도메인과 설치 파일 징후를 확인합니다. HEAD 요청만 보내며 각 이동 지점의 DNS를 다시 검사하고 확인한 IP에 직접 연결합니다. 결과는 항상 경고 또는 차단이며 링크를 제공하지 않습니다.
- 남용 방지: 본문 길이 16 KiB, 분석 10회/분, 서명 검증 60회/분, 발급·관리 각 30회/분을 클라이언트 IP별로 제한합니다. 분석 동시 실행은 4개까지 허용합니다. 카운터는 프로세스 메모리에만 남습니다.

서명키 PEM은 DB 밖의 `.secrets` 디렉터리에 둡니다. `.secrets`, `.env`, `data`, 가상환경은 제출 압축본에서 제외합니다. 이 폴더는 Git 저장소가 아니므로 `.gitignore`만 믿고 폴더 전체를 압축하면 안 됩니다. 실제 기관 운영에는 기관 승인 절차, 키 보관 서비스, HTTPS 배포와 별도 보안 진단이 더 필요합니다.

## 설치와 시험

Python 3.12, Node.js 24, PowerShell 기준입니다.

```powershell
py -3.12 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements-dev.lock
& .\.venv\Scripts\python.exe -m pip install --no-deps -e .
& .\.venv\Scripts\python.exe -m pytest -q
& .\.venv\Scripts\python.exe -m pip check
& .\.venv\Scripts\python.exe scripts\demo_flow.py
cd frontend
npm ci
npm run build
cd ..
```

데모는 임시 DB와 임시 서명키로 가상 기관을 등록한 다음 QR을 발급·검증·폐기합니다. 출력 이미지는 `demo-output/signed-qr-demo.png`입니다. 데모가 끝나면 임시 DB가 삭제되므로 이 이미지는 사후 검증에 사용할 수 없습니다. 실제 기관이나 공식 QR로 오해하지 않도록 가상 기관 이름을 사용합니다.

브라우저 시연용 기관은 `scripts/prepare_demo.py`로 만들 수 있습니다. 아래 실행 예의 첫 두 명령을 같은 PowerShell 세션에서 실행하면 기관 ID, 발급 토큰, 유효한 QR 원문과 이미지가 출력됩니다. 토큰이 화면 공유나 녹화에 노출되지 않게 주의하세요. 목적지는 실제 서비스가 아닌 `demo.example.org`입니다.

```powershell
$env:ONJEON_ADMIN_TOKEN = & .\.venv\Scripts\python.exe -c 'import secrets; print(secrets.token_urlsafe(32))'
& .\.venv\Scripts\python.exe scripts\prepare_demo.py
& .\.venv\Scripts\uvicorn.exe --factory onjeon.api:create_default_app --host 127.0.0.1 --port 8000
```

의존성 버전은 `requirements-dev.lock`과 `frontend/package-lock.json`에 고정했습니다. `.github/workflows/ci.yml`은 Python 시험·Bandit·pip-audit와 웹 빌드·npm audit를 실행합니다. 로컬에서도 같은 보안 점검을 실행할 수 있습니다.

```powershell
& .\.venv\Scripts\python.exe -m bandit -r src -q
& .\.venv\Scripts\python.exe -m pip_audit --local --skip-editable
cd frontend
npm audit --omit=dev --audit-level=high
```

## 로컬 API 실행

관리자 토큰을 환경변수로 제공해야 앱이 시작합니다. 아래 명령은 현재 PowerShell 세션에만 임의 토큰을 설정합니다.

```powershell
$env:ONJEON_ADMIN_TOKEN = & .\.venv\Scripts\python.exe -c 'import secrets; print(secrets.token_urlsafe(32))'
& .\.venv\Scripts\uvicorn.exe --factory onjeon.api:create_default_app --host 127.0.0.1 --port 8000
```

빌드된 웹 화면은 `http://127.0.0.1:8000/`, API 명세는 `http://127.0.0.1:8000/docs`에서 확인할 수 있습니다. 기관 등록 전에 `& .\.venv\Scripts\python.exe -m onjeon.cli demo-city v1`로 키를 만들고, 출력된 공개키를 등록 요청에 넣습니다. 등록 응답의 `issuer_token`은 다시 표시되지 않으므로 안전하게 보관해야 합니다. 기관을 등록한 뒤 기관 발급 화면에서 QR을 발급하고 시민 검증 화면에서 확인합니다. 카메라는 HTTPS 또는 localhost에서만 사용할 수 있습니다.

## 판정 경계와 운영 전 작업

기관 관리자 등록과 복구 기능은 API에서 제공합니다. 미서명 URL 분석기는 URL이나 시민 스캔 이력을 저장하지 않습니다. HEAD 응답이 없거나 연결에 실패하면 분석 미완료 경고를 표시합니다. 일부 서버는 HEAD를 지원하지 않으므로 본문이나 이후 브라우저 동작까지 확인했다는 뜻은 아닙니다. 보조 분석 결과는 기관 인증과 분리해 표시합니다.

`onqr:v1:` 텍스트는 기본 카메라 앱에서 바로 열리는 웹 주소가 아닙니다. 시민이 이 서비스의 화면에서 QR을 읽어야 합니다. 서명이 확인된 URL도 접속 후 다른 사이트로 이동할 수 있으므로 화면에 이 한계를 경고로 표시합니다.

폐기 상태를 매번 서버에서 확인하므로 오프라인 검증은 제공하지 않습니다.

운영 배포 시 `ONJEON_ENV=production`으로 API 문서 화면을 끄고 TLS 종료 프록시에서 HTTPS와 접속량 제한을 설정해야 합니다. 프록시 뒤에서는 Uvicorn의 `--proxy-headers --forwarded-allow-ips=<신뢰하는 프록시 IP>`를 지정해야 IP별 제한이 정확히 작동합니다. 설치형 배포에서는 `ONJEON_FRONTEND_DIST`로 빌드된 웹 디렉터리를 지정할 수 있습니다. SQLite와 메모리 속도 제한은 단일 인스턴스 시연용입니다. 다중 서버 운영에는 공유 DB와 중앙 속도 제한 저장소가 필요합니다. 제출 준비 현황은 [submission/README.md](submission/README.md)에 기록했습니다.

구현에 사용한 API 문서는 [FastAPI 보안 도구](https://fastapi.tiangolo.com/reference/security/), [Ed25519 서명](https://cryptography.io/en/stable/hazmat/primitives/asymmetric/ed25519/), [qrcode](https://pypi.org/project/qrcode/), [Python SQLite](https://docs.python.org/3.12/library/sqlite3.html), [ZXing 브라우저](https://github.com/zxing-js/browser)입니다.
