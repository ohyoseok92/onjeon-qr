# CRL 갱신·감시 운영 도구

작성일: 2026-10-11. `scripts/crl_operations.py`는 운영자가 별도 경로로 받은 로컬 CRL만 검증하고 게시한다. 임의 URL, 인증서 CDP, QR 주소에서 CRL을 내려받지 않는다. 외부 URL의 인증서 체인 신뢰·호스트명·폐기 검사는 기존 analyzer의 OpenSSL TLS 연결이 계속 담당한다.

## 구현한 검증

- 최초 설치에는 `--approve-initial-installation`과 독립적으로 확인한 발급자 **인증서 전체의 SHA256 fingerprint**가 필요하다. 후보 인증서 자체에서 읽은 값을 확인 없이 승인하면 신뢰 확인이 되지 않는다.
- 발급자 CA의 기간, BasicConstraints CA, KeyUsage CRLSign, RSA 2048비트 이상·EC 256비트 이상 또는 Ed25519/Ed448 키를 검사한다. CA 파일의 인증서 집합과 승인 pin 집합이 정확히 일치해야 한다.
- CRL issuer 이름·AKI·발급자 SKI와 실제 서명을 확인한다. SHA1·MD5 서명을 거부한다. 필수 CRL Number와 `lastUpdate <= 현재 UTC < nextUpdate`를 검사한다.
- 승인한 각 발급자의 직접 발급 완전 CRL 또는 명시적으로 승인한 범위의 완전 CRL이 필요하다. `--approved-distribution-point`로 승인한 정확한 URI 한 개와 critical IDP의 `onlyContainsUserCerts=True`를 갖는 직접 leaf shard를 지원한다. 같은 issuer의 여러 shard는 각각 별도로 승인하고 함께 게시할 수 있다. `--approve-ca-only-crls`를 명시하면 URI·상대 이름 없이 `onlyContainsCACerts=True`인 critical IDP 완전 CA CRL도 허용한다. delta·indirect·일부 reason만 있는 CRL, 기타 범위 조합은 거부한다.
- 갱신 시 issuer pin·인증서 종류·scope URI별로 CRL 번호 증가와 발행 시각 유지·증가를 요구한다. 같은 번호의 다른 CRL, 과거 번호·발행 시각, 승인 CA·scope identity 집합 교체를 거부한다. 신규 번호로 올바르게 서명한 완전 CRL은 CA가 공표한 현재 폐기 집합으로 신뢰한다. CA가 만료 인증서를 정리해 serial을 제거하는 것은 허용하며, `removeFromCRL` entry·delta는 계속 거부한다. 로컬 파일 변조나 과거 번들 복원으로 이 정리를 대신할 수 없다. CA 교체나 새 shard 추가에는 새 신뢰 범위 승인이 필요하다.
- 4 MiB 크기 제한, CRL PEM 외 내용·CA 혼합 거부, 중복 issuer/scope·중복 폐기 serial 검사로 게시 입력을 제한한다. 기존 번들이 체크포인트와 다르면 새 갱신을 거부한다.

`--issued-certificate`를 주면 PEM leaf 인증서의 기간·발급자 서명과 CRL Distribution Point를 확인한다. leaf는 승인한 issuer의 전체 인증서 CRL 또는 정확히 일치하는 user shard로만 검증 범위를 인정한다. CA-only CRL은 leaf 검증 범위로 인정하지 않는다. 서버의 전체 인증서 체인 대신 leaf 한 장씩 이 옵션을 반복한다. 이 검사는 게시 범위 확인이며 실제 TLS chain·호스트명 검증을 대체하지 않는다.

CRL 서명만으로 공개 인증서의 신뢰를 확정할 수 없다. 발급자 pin의 신뢰는 운영자가 독립적으로 확인하며, 실제 상대 체인 검증은 기존 TLS 정책에 남긴다. [cryptography X.509 공식 문서](https://cryptography.io/en/stable/x509/reference/#cryptography.x509.CertificateRevocationList.is_signature_valid), [Python SSL CRL 검사 문서](https://docs.python.org/3.12/library/ssl.html#ssl.VERIFY_CRL_CHECK_CHAIN)

## 게시 실패와 rollback 처리

체크포인트는 서비스와 백업 파일에서 분리한 전용 custody 디렉터리에 둔다. SQLite에는 승인 pin·scope URI·CA-only 승인 여부, 번들 SHA256, issuer와 scope별 CRL 번호·발행 시각·폐기 serial, 게시 generation과 복구 후보를 저장하고 별도 32바이트 키로 HMAC 인증한다. 디렉터리는 POSIX 0700·파일 0600 또는 Windows 현재 사용자/SYSTEM 전용 ACL을 요구한다. 기존 custody는 최초 설치 명령으로 덮어쓰지 않는다. 체크포인트나 키가 없어지거나 인증이 맞지 않으면 실패한다. 기존 v1 전체 CRL 체크포인트는 인증한 history를 보존하며 읽고, 다음 갱신에 scope 형식을 반영한다.

갱신은 SQLite `BEGIN IMMEDIATE`로 직렬화하고, 인증한 `pending` 후보를 먼저 영속화한다. 같은 디렉터리의 임시 파일을 flush한 뒤 `os.replace`로 번들을 원자적으로 바꾸고 `active` 상태를 기록한다. 교체 실패 시 이전 번들 바이트가 유지된다. 교체 후 체크포인트 완료 전에 중단되면 `pending`이 남으며, `check`와 다음 `update`는 준비 상태를 거부한다. `recover`는 인증한 최신 후보만 다시 검증해 게시하고 완료한다. 이미 바뀐 번들을 과거 것으로 되돌려 복구하지 않는다.

키와 체크포인트를 함께 과거 상태로 복원할 권한을 가진 운영자까지 로컬 HMAC으로 막을 수는 없다. custody는 별도 신뢰 매체에 보관하고 접근 권한·백업 generation을 관리해야 한다. 승인된 발급자 인증서도 만료되면 갱신·검사가 실패하므로 CA 교체를 미리 준비해야 한다.

## CLI 사용

아래는 Linux 배포용 경로 예시다. 실제 운영 디렉터리·승인 CA 파일·pin은 운영 환경에 맞춰 지정한다. Python 실행 환경에는 제품의 고정된 cryptography 의존성이 있어야 한다.

```sh
python scripts/crl_operations.py initialize \
  --custody /secure-custody/onjeon-crl \
  --bundle /srv/onjeon/tls/client-crls.pem \
  --issuers /secure-custody/approved-crl-issuers.pem \
  --candidate /secure-inbox/verified-full-crls.pem \
  --issuer-pin VERIFIED_CA_CERT_SHA256 \
  --approve-initial-installation

python scripts/crl_operations.py update \
  --custody /secure-custody/onjeon-crl \
  --bundle /srv/onjeon/tls/client-crls.pem \
  --issuers /secure-custody/approved-crl-issuers.pem \
  --candidate /secure-inbox/new-full-crls.pem

python scripts/crl_operations.py check \
  --custody /secure-custody/onjeon-crl \
  --bundle /srv/onjeon/tls/client-crls.pem \
  --issuers /secure-custody/approved-crl-issuers.pem \
  --minimum-remaining-seconds 86400

python scripts/crl_operations.py recover \
  --custody /secure-custody/onjeon-crl \
  --bundle /srv/onjeon/tls/client-crls.pem \
  --issuers /secure-custody/approved-crl-issuers.pem
```

issuer가 여러 개면 `--issuer-pin`을 반복한다. 최초 설치 대상에 다른 번들이 이미 있으면 덮어쓰지 않는다. 출력에는 비밀 키나 원본 CRL을 싣지 않는다. `check` 종료 코드 0은 승인된 범위에서 준비 완료, 2는 만료·미래 발효·갱신 임박, 1은 구성·무결성·게시 상태 오류다. 기본적으로 nextUpdate까지 24시간 미만이면 `refresh_required`다.

Let’s Encrypt의 user shard와 CA-only 완전 CRL을 함께 쓰는 승인된 프로필에서는 최초 명령에 `--approved-distribution-point http://ye1.c.lencr.org/66.crl --approve-ca-only-crls --issued-certificate /secure-inbox/leaf.pem`를 추가한다. URI와 CA-only 승인 여부는 최초 checkpoint에 고정되므로 이후 update/recover/check에 승인 옵션을 다시 주지 않는다. leaf 증서는 이후에도 `--issued-certificate`로 검사할 수 있다. 자동 fetch 도구가 있다면 사전에 승인한 고정 URI만 사용해야 하며 이 게시 도구는 URI를 취득하지 않는다. Let’s Encrypt의 CRL shard와 IDP profile은 [공식 CP/CPS](https://letsencrypt.org/documents/isrg-cp-cps-v5.8/)에서 확인했다.

## 배포 연결과 운영 검사

배포 전에 `check`를 실행해 종료 코드 0을 요구하고, 운영 타이머에서 주기적으로 재실행해 실패를 경보 대상으로 삼는다. 만료 전에 승인한 공급 채널의 새로운 완전한 CRL을 확보한 뒤 `update`한다. 아래 실제 등록 기록은 `qr.ohs92.com`에 적용한 승인 범위와 실행 결과다.

Docker에는 **TLS 디렉터리 전체를 read-only bind mount**해야 한다. CRL 파일 하나만 bind하면 호스트의 원자적 파일 교체 후 컨테이너가 이전 inode를 계속 읽을 수 있다. 운영 갱신 담당자는 디렉터리·번들을 쓸 수 있어야 하며, 서비스 UID는 읽기만 가능해야 한다. custody 디렉터리·HMAC 키·승인 CA 파일은 앱 컨테이너에 마운트하지 않는다. 게시 디렉터리에는 CRL만 두고 서버 개인키와 분리한다. 보호된 0700 디렉터리와 0600 파일을 컨테이너가 읽을 수 있도록 운영 갱신 계정과 서비스 UID/마운트 권한을 배포 시 명시적으로 맞춰야 한다.

제품 `/health`는 최대 5초 캐시로 CRL 기간 문제를 표시하지만 체크포인트를 읽지 않는다. 따라서 이 도구의 `check` 결과를 배포 gate와 운영 준비 상태에 연결해야 rollback·pending 상태도 감시할 수 있다. analyzer의 실제 URL 분석은 매번 strict CRL TLS 정책을 적용한다.

이 도구는 지정한 발급자 집합에 대한 운영 통제를 구현한다. 아래 실운영 검증은 등록한 공인 서비스의 체인과 CRL에 적용되며, 임의 공개 WebPKI의 모든 발급자를 포함하지 않는다. 승인한 issuer의 CRL이 없는 사이트는 기존 `VERIFY_CRL_CHECK_CHAIN` 정책에 따라 URL 분석이 차단된다.

## 실제 공인 서비스 등록·실행 결과

2026-10-11 서버에서 다음 운영 절차를 적용하고 실행했다. 공개 접속의 시스템 CA·TLS 1.3·상태·보안 헤더 결과는 [PUBLIC_TLS_CHECK.json](PUBLIC_TLS_CHECK.json), 실제 공개 QR 발급·검증·폐기와 URL 분석 결과는 [PUBLIC_RUNTIME_CHECK.json](PUBLIC_RUNTIME_CHECK.json)에 기록했다. 타이머·NTP·갱신 hook·경보 실행 결과는 서버 작업 담당자가 확인해 이 절에 반영했다.

| 항목 | 적용 및 관찰 결과 |
|---|---|
| 공인 서비스 | `https://qr.ohs92.com`, 공인 인증서로 시스템 CA 검증 성공 |
| 실제 인증서 체인 | `YE1 → Root YE (ISRG X2 cross-sign) → ISRG Root X2 (ISRG X1 cross-sign) → ISRG Root X1` |
| issuer 승인 | 4개 CA 인증서를 Let’s Encrypt 공식 HTTPS 원본과 독립적으로 대조한 SHA256 fingerprint로 등록 |
| leaf scope | `http://ye1.c.lencr.org/66.crl`, critical IDP의 정확한 URI·`onlyContainsUserCerts=True` 확인 |
| CA CRL scope | Root YE·ISRG X2·ISRG X1의 critical IDP는 URI·상대 이름 없이 `onlyContainsCACerts=True`. 명시적 CA-only 승인을 체크포인트에 저장 |
| CRL 원본 취득 | `https://ye1.c.lencr.org/66.crl`, `http://ye.c.lencr.org/`, `http://x2.c.lencr.org/`, `http://x1.c.lencr.org/`의 고정 등록 URL만 취득 |
| 보호와 게시 | `/srv/onjeon-qr/profile/tls/revocations.pem`과 `sources.json` 사용. 초기 generation 1, 인증한 체크포인트는 별도 `ops-custody/crl`에 저장하고 앱에 마운트하지 않음 |
| CRL 갱신 | `onjeon-crl-refresh.timer`를 매시간 실행하도록 enable/active 확인. 해당 service 실제 종료 상태 success·코드 0 |
| 실제 analyzer | 공개 서비스 자신의 HTTPS URL 검사에서 CRL 전체 체인 검증을 통과하고 `warning / unsigned_qr` 반환. 서명 없는 URL을 기관 인증으로 인정하지 않음 |
| 인증서 자동 갱신 | 기존 Certbot 갱신 timer active. `certbot renew --dry-run --run-deploy-hooks` 성공, nginx 구성 검사·reload hook 성공 |
| 운영 감시 | `onjeon-health-check.timer` 5분 간격 enable/active. service 실제 success·코드 0, 승인 issuer 4개 확인 |
| 감시 시점의 유효 기간 | 인증서 잔여 7,771,168초, CRL 최소 잔여 775,884초. 각각 3일·2시간 기준을 충족한 당시 값 |
| 시간 동기화 | 실제 호스트 `NTPSynchronized=yes`. 감시 service의 ExecStartPre에서도 동기화 완료를 요구 |
| 실패 경보 | 합성 실패 transient unit의 `OnFailure=onjeon-operation-alert.service`를 실제 실행해 journal의 고정 경보 메시지 발생 확인. 외부 push·메일 전송은 설정하지 않음 |

CA CRL 중 HTTPS 취득이 해당 서버에서 TLS 오류를 내는 경로는 위 고정 HTTP 공개 CRL 경로를 사용했다. 자격 증명·쿠키·기관 정보는 전송하지 않는다. CRL 진위는 HTTP 응답 자체가 아니라 승인한 CA 키의 실제 서명·scope·기간·번호와 인증한 rollback 체크포인트로 검증한다. 과거 번호 응답 재전송·위조·범위 변경은 게시 검증을 통과하지 못하며, 취득 실패는 기본 TLS로 우회하지 않고 경보를 발생시킨다.

## 운영 감시와 갱신 후 범위 변경

`scripts/check_operational_health.py`는 프록시 없이 고정 호스트 `qr.ohs92.com`의 `/health`만 GET한다. 시스템 CA·SNI·호스트명 검증을 거친 **실제 peer 인증서 DER**를 읽으므로, Certbot 갱신 뒤 단일 파일 bind mount에 남는 과거 inode를 기준으로 검사하지 않는다. Authorization·사용자 자격 증명은 보내지 않으며 `SSLKEYLOGFILE`이 있으면 연결 전에 실패한다. 리디렉션과 HTTP 오류를 거부하고 상태 본문을 4 KiB 이하로 제한한다.

감시는 `status=ok`·`url_analysis.available=true`, 인증서 기간·3일 여유, 승인 issuer의 실제 서명, 등록 CRL coverage·폐기 상태, CRL 2시간 여유를 검사한다. CA 체인에 있는 중간 CA도 승인 issuer 서명과 CA CRL coverage·폐기 상태를 검사한다. 공개 취득 URI와 leaf CDP는 HTTP/HTTPS의 같은 호스트·경로를 등록 원본으로 연결하며, CRL 게시 단계의 IDP scope 검증은 원문 URI를 정확히 비교한다. 감시 컨테이너에는 공개 TLS 디렉터리와 운영 스크립트만 읽기 전용으로 마운트하며 개인키·HMAC 키·체크포인트는 제공하지 않는다.

Certbot이 같은 승인 issuer·shard의 인증서를 갱신하면 실제 peer 기준 검사와 nginx reload가 이어진다. 갱신으로 issuer나 shard가 바뀌면 기존 승인을 자동 확대하지 않고 감시가 실패해 journal 경보를 남긴다. 이때 공식 CA HTTPS 원본으로 새 인증서 fingerprint와 체인을 대조하고, 새 고정 CRL URL·IDP·기간·서명을 확인한 뒤 신뢰 범위를 명시적으로 승인한다. 기존 checkpoint를 삭제하거나 동일 custody에 최초 설치를 다시 실행해 history를 지우지 않는다. 승인한 새 범위는 별도 custody의 명시적 최초 설치 절차로 등록하고 검사 성공 후 배포하며, 이전 custody와 승인 기록은 보존한다. 승인되지 않은 issuer·scope는 계속 실패 시 차단한다.

신규 운영 감시 회귀는 실제 서명 합성 인증서·CRL을 사용해 정상 상태, 누락·degraded 상태, issuer/shard 변경, 등록됐지만 누락된 coverage, 폐기 leaf, 인증서·CRL 갱신 여유, 과거 local 인증서 불일치와 고정 요청·프록시 무시·key log·리디렉션·HTTP 오류를 검사했다. Linux에서 **12 passed / 0.41초**, Bandit 검출 0건이다. 실제 공인 서버의 service·timer 성공은 위 실운영 기록으로 별도 확인했다.

## 회귀시험

`tests/test_crl_operations.py`는 합성 EC CA와 실제 서명 CRL을 사용한다. 승인 누락·잘못된 pin, 정상 갱신·재시작, 위조 서명, delta·unsupported scope CRL, 번호·AKI 누락, 만료·미래 발효, rollback·같은 번호 변조, 신규 권위 CRL의 만료 serial 정리, explicit removeFromCRL 거부, 교체 실패와 교체 후 중단 복구, 체크포인트 변조·삭제, 게시 파일 rollback, 만료 임박, PEM 신뢰 주입, issuer coverage 누락, 다른 게시 경로, 동시 갱신 시 generation 단일 할당과 POSIX 권한 완화 거부를 검사한다. user shard 승인·정확한 URI·종류·leaf CDP 일치, 동일 issuer 복수 shard의 독립 번호, CA-only 별도 승인·leaf 적용 거부와 v1 인증 history 보존도 확인한다.

최종 단독 실행: Linux Python 3.12 이미지에서 비특권 UID 10001, network none, read-only rootfs, capability 제거, no-new-privileges, PID 128·메모리 1 GiB 제한으로 **36 passed / 0.71초**. Windows에서는 최초 전체 CRL 버전의 같은 보호 도우미로 실제 ACL을 검사한 정상 게시·갱신과 실패 후 복구 **2 passed / 91.92초**를 확인했다. shard·CA-only 확장은 Linux에서 확인했다. Bandit 검사는 검출 없이 종료 코드 0이다. 원본 CA 개인키·실제 운영 CRL·기존 fixture를 덮어쓰지 않았다.
