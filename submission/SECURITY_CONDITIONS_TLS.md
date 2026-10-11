# S11 인증서 해지 확인: 구현과 실제 TLS 시험

검토일: 2026-10-11. 범위는 서버가 외부 URL을 검사할 때 사용하는 TLS 클라이언트다. 제품의 인증서 검증과 CRL 차단 동작은 로컬 TLS 연결에서 확인했다. 실제 운영 사이트의 모든 발급자 CRL을 확보하고 계속 갱신하는 배포 절차는 별도 운영 확인 대상이다.

## 공식 문서와 구현 판단

Python의 기본 인증서 검증은 CRL을 요구하지 않는다. `VERIFY_CRL_CHECK_CHAIN`을 적용하면 상대 인증서 체인 전체에 CRL 검사를 요구하며, 올바른 발급자 CRL이 없으면 검증에 실패한다. CRL은 `load_verify_locations()`로 로드해야 한다. [Python 3.12 ssl 공식 문서](https://docs.python.org/3.12/library/ssl.html#ssl.VERIFY_CRL_CHECK_CHAIN)

CRL의 서명이 맞다는 사실만으로 그 CRL을 신뢰할 수는 없다. 따라서 직접 작성한 서명 비교로 인증서 체인 검증을 대신하지 않았다. `cryptography`는 PEM 파싱과 시간대가 있는 `last_update_utc`·`next_update_utc` 검사에 사용하고, 발급자 신뢰·서명·체인·폐기는 OpenSSL의 실제 TLS 검증에 맡겼다. [cryptography X.509 공식 문서](https://cryptography.io/en/stable/x509/reference/#cryptography.x509.CertificateRevocationList.is_signature_valid)

조회한 문서는 Python 3.12.15와 cryptography 50.0.2 문서다. 실제 시험 환경은 Python 3.12.10, OpenSSL 3.0.16, cryptography 50.0.2다.

## 적용한 통제

| 통제 | 구현·증적 |
|---|---|
| 운영 모드 CRL 필수 | `ONJEON_ENV=production`에서 번들 설정이 없으면 `SSLCertVerificationError` 발생. API startup은 `tls_configuration_status()`로 구성 상태를 검사하고 요청 시에는 `build_tls_context()`를 사용한다. 정상 형식 CRL의 만료·미래 발효만 URL 분석 degraded로 분리한다. `analyzer.py:36`, `analyzer.py:48`, `api.py:228` |
| 기존 TLS 검증 유지 | 시스템 CA 신뢰, `CERT_REQUIRED`, `check_hostname=True`, TLS 1.2 이상을 유지. 실제 서버 인증서의 신뢰·호스트명·기간을 검사 |
| 정적 CRL만 사용 | 운영자가 제공한 로컬 PEM 경로만 읽음. 인증서의 CRL Distribution Point나 사용자가 넣은 URL에서 CRL을 내려받지 않음 |
| CRL 설정 검증 | 4 MiB 상한, 일반 파일, 최소 1개 CRL, CRL PEM 외 내용 거부. 인증서·개인키·임의 텍스트를 섞어 신뢰 루트를 추가할 수 없음 |
| CRL 기간 검증 | URL 분석은 모든 CRL이 `lastUpdate <= 현재 UTC < nextUpdate`일 때만 연결한다. 정상 시간 구간의 만료·미래 발효는 분석을 차단하고 상태 조회에 사유를 표시한다. nextUpdate 누락·nextUpdate가 lastUpdate 이하인 구성은 startup도 거부 |
| 체인 전체 해지 검사 | `context.verify_flags |= ssl.VERIFY_CRL_CHECK_CHAIN`. 서버와 중간 CA의 CRL 발급자·서명·폐기를 TLS handshake에서 검사. 관련 CRL이 없으면 실패 |
| 갱신 반영 | TLS 연결마다 파일을 다시 읽고 컨텍스트를 만듦. 유효했던 번들을 폐기·만료 번들로 교체하면 다음 검사부터 차단 |
| 읽는 도중 교체 감지 | 설정 파싱과 OpenSSL 로드 후 읽은 바이트가 달라지면 실패. 파일 쓰기 권한 통제와 원자적 게시도 운영에서 필요 |
| 실패 시 차단 | 설정 또는 인증서 검증 실패는 `blocked / tls_invalid`. 기본 TLS로 재시도하지 않으며 해당 연결에 HEAD를 보내지 않음 |
| 분석 가용성과 QR 기능 분리 | 정상 형식 CRL의 시간 문제이면 앱은 시작하고 `/health`에 `status=degraded`, `url_analysis.available=false`·`crl_expired` 또는 `crl_not_yet_valid`를 표시한다. QR 검증·발급·관리 기능은 유지한다. 정상 번들로 갱신하면 다음 분석·상태 조회부터 회복 |
| 오류 노출 제한 | 구성 오류는 고정 문구만 사용하고 하위 예외 체인을 숨김. 사용자 응답에 CRL 원문·파일 경로·인증서 오류 상세를 싣지 않음 |
| TLS 비밀 로그 차단 | 운영 모드에서 `SSLKEYLOGFILE`이 설정돼 있으면 컨텍스트를 만들기 전에 실패. 실제 시험에서 키 로그 파일 미생성 확인 |

코드: [analyzer.py](../src/onjeon/analyzer.py), [api.py](../src/onjeon/api.py). 최초 연결과 모든 리디렉션은 같은 TLS 정책을 사용한다. 공개 IP 검사, 고정 IP 연결, 호스트명 SNI, HEAD 전용 요청, 시간 제한도 유지한다.

## 실제 연결 시험

시험은 임시로 만든 `root CA → intermediate CA → inspection.example.org` 체인과 로컬 TLS 서버를 사용했다. DNS 결과와 소켓 목적지만 테스트 서버로 바꾸고, 제품의 SSLContext·handshake·HEAD·리디렉션 코드는 그대로 실행했다. 인증서·CRL 오류를 흉내 내는 `_head` 모의 객체로 아래 결과를 만들지 않았다. 외부 서비스로 요청을 보내지 않았다.

| 사례 | 관찰 결과 |
|---|---|
| 정상 체인 + 두 발급자의 유효 CRL | TLS 성공, HEAD 1회. 서명 없는 QR이므로 최종 결과는 여전히 `warning / unsigned_qr` |
| 서버 인증서가 중간 CA CRL에 폐기됨 | `blocked / tls_invalid`, HEAD 0회 |
| 중간 CA 인증서가 루트 CA CRL에 폐기됨 | `blocked / tls_invalid`, HEAD 0회. leaf 전용 검사에 그치지 않음 |
| 다른 키로 서명한 중간 CA CRL | 파싱·시각 검사는 통과하지만 실제 TLS 서명 검증에서 차단, HEAD 0회 |
| 루트 CA CRL 누락 | 실제 TLS에서 차단, HEAD 0회 |
| 중간 CA CRL 누락 | 실제 TLS에서 차단, HEAD 0회 |
| 만료 CRL | 연결 전에 차단, HEAD 0회 |
| 미래에 발효하는 CRL | 연결 전에 차단, HEAD 0회 |
| 만료된 서버 인증서 | 실제 TLS에서 차단, HEAD 0회 |
| 인증서와 다른 호스트명 | 실제 TLS에서 차단, HEAD 0회 |
| 신뢰 저장소에 없는 루트 CA | 실제 TLS에서 차단, HEAD 0회 |
| 첫 연결 정상 → CRL에 서버 인증서 폐기 추가 | 첫 HEAD만 관찰. 다음 실제 TLS 연결은 차단 |
| 첫 연결 정상 → CRL 만료 버전으로 교체 | 첫 HEAD만 관찰. 다음 검사는 소켓 연결 전에 차단 |
| 운영 모드 CRL 환경변수 누락 | SSLContext 생성 전에 실패. API startup 거부 시험도 별도로 존재 |
| 빈·임의 텍스트·손상 PEM·인증서 혼합·4 MiB 초과·없는 경로 | 고정 구성 오류. 네트워크 연결로 진행하지 않음 |
| 운영 모드 TLS 키 로그 환경변수 | 실패하며 지정한 로그 파일을 만들지 않음 |
| 정상 형식 CRL의 만료·미래 발효와 API 가용성 | URL 분석은 연결 전에 차단. 구성 상태 조회는 고정 사유를 반환하며 QR·관리 기능을 유지하는 회귀 사례는 최신 API 시험 기록 참조 |
| 만료 CRL 뒤에 손상 PEM·CA 인증서를 추가한 경우 | 시간 문제로 완화하지 않고 전체 구성 검증 실패. 만료를 이용해 혼합·손상 번들을 허용하지 않음 |

핵심 증적: [tests/test_network.py](../tests/test_network.py) `crl_tls_server:142`, `test_actual_tls_chain_and_crl_validation:254`, `test_crl_refresh_is_enforced_on_the_next_actual_probe:269`; [tests/test_analyzer.py](../tests/test_analyzer.py) 구성 거부 시험. 기존 자체서명·호스트명 불일치·내부 주소 리디렉션·설치 응답·헤더 시간 제한 시험도 함께 통과했다.

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/test_analyzer.py tests/test_network.py
.\.venv\Scripts\python.exe -m bandit -q src/onjeon/analyzer.py
```

최초 CRL 구현 검토에서는 대상 시험 49개 통과와 analyzer Bandit 검출 0건을 확인했다. 이후 가용성 분리·시간 구간·혼합 구성 회귀가 추가되었으므로 현재 시험 수와 실행 결과는 최신 [TEST_REPORT.md](TEST_REPORT.md) 및 운영 검증 문서를 따른다. 이 문서 정정은 현재 코드와 시험 사례의 정렬이며 새로운 외부 재검토 통과를 뜻하지 않는다. 정적 분석 검출 0건을 보안 보증으로 해석하지 않는다.

## 설정과 기능 영향

운영 설정 예시다. 파일 자체는 운영 CA가 발행한 실제 CRL이어야 한다.

```text
ONJEON_ENV=production
ONJEON_TLS_CRL_BUNDLE=/run/onjeon/tls/issuer-crls.pem
```

PEM 파일에는 `-----BEGIN X509 CRL-----` 블록만 이어 붙인다. 루트 신뢰는 시스템 CA 저장소에서 관리하며, 필요한 사설 루트는 운영에서 신뢰 저장소에 설치하거나 표준 `SSL_CERT_FILE`로 지정한다. CRL 번들에 CA 인증서를 섞어 신뢰를 확대하는 방식은 거부한다.

정상 형식의 CRL이 현재 만료되었거나 아직 발효하지 않았다면 앱 전체를 종료하지 않는다. URL 분석은 `blocked / tls_invalid`로 유지하고, production `/health`는 HTTP 200 본문의 `degraded`와 `url_analysis` 사유로 기능 상태를 알린다. QR 서명 검증·발급·관리 작업은 별도의 신뢰기관 키와 DB를 사용하므로 유지한다. 운영 감시는 HTTP 성공 코드만 보지 말고 상태 본문을 확인해야 한다. 정상 CRL을 원자적으로 게시하면 재시작 없이 다음 상태 조회·분석부터 회복한다.

번들 누락·손상·과대 크기·읽기 오류·CA/개인키 혼입·잘못된 시간 구간과 운영 `SSLKEYLOGFILE`은 startup을 거부한다. 시간 문제 완화는 정상 구성의 기간 상태에만 적용하며, 외부 URL 연결에 사용하는 엄격한 TLS 컨텍스트에는 적용하지 않는다. 대상 체인에 필요한 CRL의 누락·잘못된 서명·폐기 여부는 실제 handshake에서도 계속 검사한다.

임의 공개 사이트를 검사할 때 그 사이트 체인에 맞는 최신 CRL이 없으면 HTTPS 연결이 차단된다. 해당 사이트를 안전하다고 판정하거나 기본 TLS로 우회하지 않는다. 따라서 이 기능을 운영하려면 검사 대상의 발급자와 CRL 확보 가능성을 먼저 확인해야 한다. 모든 WebPKI 발급자에 대해 CRL이 자동 확보된다고 주장할 수 없다. OCSP와 OCSP stapling은 구현하거나 시험하지 않았다.

로컬 개발 모드에서 CRL 경로를 생략하면 기존 CA·호스트명·기간 검증만 수행한다. 이 실행 모드는 인증서 해지 확인 완료로 분류하지 않는다. 경로를 지정한 경우에는 개발 모드에도 같은 CRL 검사를 적용한다.

## 운영에서 아직 확인해야 하는 조건

1. 실제 검사 대상의 전체 인증서 체인을 확보하고, 필요한 발급자의 최신 CRL이 빠짐없이 배포되는지 확인한다. 로컬 시험 CA의 정상 결과는 운영 대상의 CRL 분포를 증명하지 않는다.
2. CRL 발급기관의 공식 경로에서 별도 운영 작업으로 취득하고, 서명·발급자·CRL 번호·시각을 검토해 원자적으로 게시한다. 제품의 요청 처리 경로에는 원격 취득을 넣지 않는다.
3. 서비스 계정이 번들을 수정하지 못하도록 읽기 전용 마운트와 파일 권한을 적용한다. CRL 번호 역행 방지, 갱신 알림, 만료 전 여유 시간, CA 변경 대응을 운영 절차로 확인한다. 제품은 유효 기간 안의 이전 CRL을 영속적으로 기억해 역행을 탐지하지 않는다.
4. 호스트 시각 동기화와 CRL 갱신 실패 경보를 운영 환경에서 확인한다. 만료·미래 발효이면 URL 분석이 차단되고 health가 degraded로 바뀌므로 상태 본문과 갱신 사유를 감시한다. 정상 CRL로 복구한 뒤 분석 회복을 확인한다. QR·관리 기능의 유지와 URL 검사 준비 상태를 같은 지표로 취급하지 않는다.
5. 공개 HTTPS 종단 인증서 발급·갱신·키 보호는 외부 URL 검사와 구별해 확인한다. 해당 증적은 운영 TLS 종단 검증 보고서를 따른다.

**판정:** 인증서 신뢰·호스트명·기간·발급자 서명·체인 전체 CRL·폐기·구성 실패 차단은 제품 구현과 실제 로컬 TLS에서 확인했다. 운영 CRL 확보·배포·지속 갱신 및 전체 공개 WebPKI 지원은 이 시험으로 확인하지 않았다.

## 로컬 Docker TLS 프로필의 독립 수동 검토

추가로 `scripts/run_tls_server.py`, `scripts/create_local_tls_fixture.py`, `scripts/check_docker_runtime.py`, `compose.security.yaml`, `Dockerfile`, `compose.yaml` 및 의존하는 `secure_profile.py`와 `.dockerignore`를 읽었다. 실행 결과는 루트 담당자가 수집하는 [DOCKER_RUNTIME_CHECK.json](DOCKER_RUNTIME_CHECK.json)을 따른다. 이 절의 설정 검토만으로 이미지 실행 성공을 주장하지 않는다.

검토한 로컬 보안 프로필은 호스트의 `127.0.0.1:8443`만 게시한다. 서버 인증서 키는 암호화 PKCS8이며, CA·인증서·키·CRL·환경 파일을 읽기 전용으로 마운트한다. 이미지에는 `.secrets`를 넣지 않고 UID/GID 10001, 읽기 전용 루트, 모든 capability 제거, `no-new-privileges`, 메모리·프로세스 상한을 설정한다. 파일 생성은 기존 파일을 덮어쓰지 않고 Windows의 현재 사용자·SYSTEM 전용 ACL을 검사한다.

이 프로필의 CA는 OS 전역 신뢰 저장소에 설치되지 않는다. 시험 클라이언트와 시험 컨테이너가 명시적으로 그 CA 파일을 읽는다. CA 서명 키도 보관하지 않으며 인증서·CRL은 짧은 기간만 유효하므로, 공개 서비스의 인증서 발급이나 CRL 지속 갱신을 증명하는 자료로 사용할 수 없다. Docker의 HTTPS healthcheck와 기본 검사 클라이언트는 인증서 신뢰·호스트명을 검사하지만 CRL flag를 적용하지 않는다. 따라서 그 요청의 성공 자체를 S11 해지 검사 증적으로 분류하지 않는다. S11의 폐기 차단 증거는 앞의 제품 analyzer 실제 TLS 시험이다.

컨테이너 설정에 자격 값이 없다는 확인은 파일 마운트를 사용하는 `compose.security.yaml`에 한정한다. 일반 `compose.yaml`은 관리 토큰과 키 암호를 환경변수로 주입하므로 같은 주장을 적용할 수 없다.

독립 검토에서 검사 클라이언트의 `SSLKEYLOGFILE` 처리와 실제 Docker 마운트 증적 보완을 요청했다. 최신 `check_docker_runtime.py`는 시작 시 TLS 키 로그 설정을 거부하고, `8443/tcp → 127.0.0.1:8443`의 정확한 바인딩 및 5개 비밀 bind mount의 `RW=False`를 검사하도록 수정됐다. 이 확인은 소스 재검토 결과이며 최종 실행 결과는 Docker 증적을 따른다.

health 상태 확인은 앱별 잠금/5초 캐시로 처리하며 CRL 갱신 표시에 최대5초 지연이 있다. URL 분석의 TLS 검증은 이 캐시를 사용하지 않아 만료·설정 교체를 매 요청 차단한다.
