# 운영 조건 검증 도구

검토일: 2026-10-11. 대상은 이 프로젝트의 새 `.secrets/operation-profile`이며, 기존 사용자 자격증명은 교체하지 않았다. 비밀값·비밀 파일 내용·개인 SID는 이 보고서에 넣지 않았다. 실행 도구는 `scripts/secure_profile.py`, 회귀 시험은 `tests/test_operational_tools.py`다.

## S09 — 무작위 운영 비밀값

`secrets.token_urlsafe(48)`로 관리자 토큰, 기관 키 암호, 릴리스 키 암호를 각각 생성했다. 각 값은 서로 다른 48바이트 무작위 입력에서 나온 64문자이며, 값을 stdout에 출력하지 않는다. `.secrets/`는 Git 제외 경로다. 기존 프로필이나 출력 파일이 있으면 덮어쓰지 않고 실패한다.

운영 환경 파일은 `application/production.env`에 있다. `compose.security.yaml`은 그 파일만 읽기 전용으로 마운트하며, 컨테이너의 TLS 진입점이 프로세스 메모리에서 읽는다. 명령줄 인수·Docker inspect 환경·보고서에 토큰을 넣지 않는다. 일반 compose의 환경변수 주입은 다른 범위다. 생성 방식이 무작위라는 사실과 별도로 API의 production 설정에서 반복값·짧은 반복 패턴·알려진 예시 비밀을 거부함을 확인했다. 길이와 문자 종류 검사만으로 임의의 기존 문자열이 가진 엔트로피를 보증하지 않는다.

## S05 — 권한과 인증된 암호화 백업

실제 Windows NTFS에서 프로필 루트와 `application`, `key-custody`, `backups` 디렉터리의 상속을 끊고 **현재 사용자와 SYSTEM 두 주체만 FullControl**을 갖도록 적용했다. 파일은 보호된 부모의 두 규칙을 상속한다. 디렉터리 권한을 먼저 설정·검사한 뒤 비밀을 쓴다. 초기 권한 검사에서 다른 기본 규칙을 감지해 생성을 중단했고, `icacls`로 DACL만 수정한 후 다시 확인했다. OS 관리자 권한의 소유권 탈취까지 막는다는 뜻은 아니다.

POSIX에서는 디렉터리 `0700`, 파일 `0600`을 설정하고 검사한다. 이 세션에서는 Windows 실물 ACL을 확인했으며 Linux의 실제 파일 권한 확인은 Docker 담당자의 실행 기록과 함께 판단한다.

백업 데이터는 AES-256-GCM으로 암호화한다. 암호화마다 12바이트 nonce를 무작위 생성하고 형식 헤더를 추가 인증 데이터로 사용한다. 256비트 백업 키는 `key-custody/backup-key.bin`에만 있으며 백업 파일에 넣지 않는다. 변조·잘못된 키·잘못된 형식은 복구에 실패한다. [cryptography AEAD 문서](https://cryptography.io/en/latest/hazmat/primitives/aead/)

백업에는 SQLite online backup API로 얻은 커밋된 스냅샷, DB 옆 `.rate-limit-hmac`, 기관별 `기관ID/키버전.pem` 구조의 암호화 PKCS8 키를 포함한다. 메모리 스냅샷을 사용해 평문 백업 임시 파일을 쓰지 않는다. WAL 헤더는 [SQLite deserialize 공식 지침](https://sqlite.org/c3ref/deserialize.html)에 따라 복구 가능한 rollback 형식으로 바꾸고, 커밋된 WAL 행이 복구되는지 시험했다. 복구 전에 `PRAGMA integrity_check`를 확인한다.

복구는 보호된 `backups/`에 새 DB와 `<DB파일명>.keys/기관ID/키버전.pem`, `.rate-limit-hmac`를 쓴다. 기관별 경로는 정확히 두 단계만 허용하며 절대 경로·상위 경로·역슬래시·추가 하위 경로를 거부한다. 기존 파일을 덮어쓰지 않는다. 기관 키 암호와 관리자 토큰은 백업 안에 넣지 않으므로 해당 환경 파일은 별도로 보존해야 한다.

여기서 키 보관 범위는 같은 호스트의 별도 보호 디렉터리다. 암호화 백업만 다른 저장소로 옮겨도 복구 키는 같이 옮기지 않으며, 실제 재해 복구용 독립 매체나 비밀 관리 서비스에 키를 보관하는 운영 결정은 따로 필요하다. DB 스냅샷은 SQLite 트랜잭션과 일관되지만 DB와 외부 키 파일 전체의 원자성까지 보증하지 않으므로, 운영 백업 시 발급·키 변경을 잠시 중지해야 한다.

## S15 — 릴리스 서명과 외부 신뢰 지문

이 로컬 운영 프로필에서 Ed25519 릴리스 키를 새로 생성했고 개인키는 암호화 PKCS8로 저장했다. 키 암호도 보호된 `key-custody` 안에 있으며 공용 제출물에 포함하지 않는다. [cryptography 키 직렬화 문서](https://cryptography.io/en/latest/hazmat/primitives/asymmetric/serialization/)

서명은 ZIP의 SHA-256, 크기, 파일명과 버전이 담긴 정규화 payload에 릴리스 전용 도메인 구분자를 붙여 계산한다. 검증 명령은 **외부에서 신뢰한 공개키 지문을 반드시 인수로 받아** 공개키 일치, 서명, ZIP 내용 일치를 모두 확인한다. 지문은 Ed25519 원시 공개키 32바이트의 SHA-256이다. 서명 JSON 내부의 지문만 보고 신뢰하지 않는다.

이 키는 이번 프로젝트의 로컬 릴리스 검증용으로 생성한 것이다. 법적 발행자 신원이나 기존 기관의 인증서를 입증하는 키는 아니다. 수신자는 기대 지문을 제출 ZIP·서명 파일과 독립된 신뢰 채널에서 확인해야 한다. 최종 ZIP에 대한 실제 서명·검증 결과는 ZIP을 마지막으로 만든 뒤 추가 기록한다.

## 명령

아래 명령은 프로젝트 루트에서 실행한다. 공개 서명 파일은 ZIP 외부에 둔다.

```powershell
.venv/Scripts/python.exe scripts/secure_profile.py inspect
.venv/Scripts/python.exe scripts/secure_profile.py backup <DB경로> --name state.onbackup --issuer-key-directory <기관키루트>
.venv/Scripts/python.exe scripts/secure_profile.py restore .secrets/operation-profile/backups/state.onbackup --name recovered.sqlite3
.venv/Scripts/python.exe scripts/secure_profile.py sign submission/OE-1_onjeon_source.zip submission/RELEASE_SIGNATURE.json
.venv/Scripts/python.exe scripts/secure_profile.py verify submission/OE-1_onjeon_source.zip submission/RELEASE_SIGNATURE.json --expected-fingerprint <독립채널에서확인한64자리지문>
```

`create`는 새 프로필을 처음 만들 때만 사용한다. 기존 자격증명이 있으면 실패하며 초기화나 자동 교체를 하지 않는다. 도구는 오류 시 비밀 내용이나 암호화 예외 원문을 출력하지 않는다.

## 검증 범위

시험은 실제 파일 권한 확인과 암호화 PKCS8 암호 필요 여부, 기존 프로필 보존, 정상 릴리스 검증·내용 변조·서명 위조·외부 지문 누락·공격자 키 교체 거부, AES-GCM nonce 변경·잘못된 키·변조 거부, 커밋된 WAL 행과 중첩 기관 키·HMAC 키의 복구, 복구 덮어쓰기 거부와 경로 경계를 확인한다. 실행 결과와 실제 운영 프로필의 권한 요약은 `SECURITY_CONDITIONS_TOOLS.json`에 기록한다.
