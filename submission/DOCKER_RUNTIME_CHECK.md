# Docker 실제 실행·권한·HTTPS 확인

확인일: 2026-10-11. 상세 결과는 `DOCKER_RUNTIME_CHECK.json`·`DOCKER_BACKUP_CHECK.json`에 있다. 시험 프로필은 기존 개발 DB와 분리한 가상 기관만 사용한다.

## 엔진 복구와 이미지

Docker Desktop은 오래된 AF_UNIX 소켓을 옮기지 못해 시작 중 멈췄다. WSL에서 `/bin/true`를 실제 실행해 WSL 부팅은 정상임을 확인했다. Docker 프로세스를 종료한 뒤 소켓용 `Docker/run`과 `docker-secrets-engine` 폴더를 보존 이름으로 옮기고 Desktop을 다시 시작했다. 이번에 확인한 secrets-engine 폴더에는 소켓1개만 있었다. 디스크·WSL 배포판·기존 이미지·볼륨·사용자 비밀은 삭제하거나 초기화하지 않았다. 보존 폴더도 삭제하지 않았다. Docker 서비스 시작은 현재 권한으로 거부됐지만 WSL 엔진은 서비스 변경 없이 시작됐다. 반복 장애의 Windows 원인까지 해결했다는 의미는 아니다.

Docker Engine29.8.0에서 `compose.security.yaml` 이미지 빌드와 healthy 실행에 성공했다. Node24·Python3.12 베이스 digest, npm lock integrity, Python runtime SHA256 설치를 실제 사용했다. 앞선 Debian13 Trixie의 High8종을 해결하려고 최종 런타임을 공식 Python3.12.15/Alpine3.24.2로 교체했다. zlib도1.3.2-r1로 보안 갱신했다. glibc 휠을 복사하지 않고 기존 해시 잠금에서 musllinux 바이너리 휠만 설치했다. 빌드 중 `pip check`를 통과한 뒤 실행에 필요 없는 pip·ensurepip를 제거했다. Vite 카메라 청크543KB 안내는 남는다. 최종 이미지 ID와 소스 hash 일치는 JSON 증거를 따른다. OS 검사와 기존8종의 개별 해결 근거·검사 범위 한계는 `DOCKER_IMAGE_SCAN.md/json`에 기록한다.

## 실제 관찰

| 확인 | 결과 |
|---|---|
| 공개 포트 | `8443/tcp`가 정확히 `127.0.0.1:8443`에만 바인딩 |
| HTTPS | 실제 TLS1.3, 명시한 시험 CA만 신뢰. 미신뢰 CA·호스트명 불일치는 검증 실패 |
| 서비스 | health200·화면200·production docs404·무인증 관리자401·HSTS |
| 제품 흐름 | 관리자 등록→암호화 기관키로 발급→trusted→폐기→blocked |
| 재시작 | 같은 UTC분 안에서 분석10회 후429, 재시작·XFF변경 후도429. 폐기 상태 유지 |
| 실행 계정 | 실제 UID/GID10001 |
| 파일 권한 | DB/요청 제한HMAC/기관키0600, data/.secrets 디렉터리0700 |
| 프로세스 권한 | 실제 CapEff0·NoNewPrivs1 |
| 쓰기 통제 | rootfs 새 파일 생성 거부, 실제 기존 비밀 bind에 write-only open 거부 |
| 비밀 주입 |5개 bind 모두 RW=False, 해당 프로필의 Docker inspect 환경에 관리자 토큰·키 암호 없음 |
| 자원 제한 |512MiB·PID128·CPU1 설정. 부하 한계 시험은 별도 |
| 일치·의존성 | 이미지 내 소스 hash=현재 소스, 빌드 중 `pip check` 충돌 없음, 실행 이미지의 pip·ensurepip 없음 |

첫 재시작 한도 시험은 Windows의 IPv6 localhost 재시도 지연으로 UTC분이 넘어가 실패했다. DB 카운터에서 정상 창 전환임을 확인했다. 검사 클라이언트를127.0.0.1 연결+localhost SNI로 바꾸고 분 경계 검사를 추가해 재검증했다. 제품의 제한을 느슨하게 바꾸지 않았다. 독립 리뷰 지적에 따라 호스트 `SSLKEYLOGFILE`도 검사 시작 전에 거부한다.

## 실제 암호화 백업·복구

발급·키 변경이 멈춘 컨테이너 중지 시점에 DB·기관별 암호화 키·HMAC키를 보호된 NTFS staging으로 내보냈다. 원본 컨테이너는 내보내기 직후 healthy로 재시작했다. AES-256-GCM 백업을 복구한 뒤 전체 DB행·중첩 기관키·HMAC키가 일치했고, 복구 앱도 production으로 시작해 health·관리자 인증을 통과했다. 백업 ACL은 현재 사용자/SYSTEM만 허용한다. 평문 staging은 경로 경계를 확인한 뒤 제거했다. 정확한 파일 수와 암호화 결과는 JSON을 따른다.

기존 Trixie의 DB·암호화 기관키·HMAC 볼륨을 그대로 사용해 Alpine의 실제 SQLite3.53.4 앱이 시작했다. 새 이미지의 정지 상태 백업을 Windows SQLite로 복구해 DB행·키·HMAC 일치와 운영 API 인증을 다시 확인했다. 재검사마다 새 보호 프로필을 만들어 이전 복구 자료와 HMAC을 덮어쓰지 않는다.

백업 키·키 암호는 bundle에 넣지 않으며 보호된 별도 key-custody 폴더에 있다. 별도 호스트/매체에 분리 보관한 결과는 아니다. 복구한 시험 DB·암호화 키는 비밀 프로필 내부에 남아 있으며 ZIP에 포함하지 않는다. 오래된 백업의 폐기 상태 후퇴는 `RECOVERY_CHECK.md`에 따라 재개 전에 점검해야 한다.

## 재현과 범위

```powershell
docker compose -f compose.security.yaml up --build -d --wait
.\.venv\Scripts\python.exe scripts/check_docker_runtime.py
.\.venv\Scripts\python.exe scripts/check_encrypted_docker_backup.py
```

처음에는 `secure_profile.py create`·`create_local_tls_fixture.py`로 새 비밀 프로필을 만들어야 한다. 기존 파일을 덮어쓰지 않는다. 백업 검사 스크립트는 매번 새로운 보호 프로필을 만들어 복구를 격리한다. `secure_profile.py restore`를 직접 쓸 때는 대상 DB/키/HMAC이 없는 새 프로필·격리 위치를 준비해야 한다.

시험 CA는 OS에 설치하지 않았다. CA 개인키는 보관하지 않고, 서버 인증서·CRL은2일 후 만료된다. 브라우저의 인증서 경고를 무시하는 시연을 요구하지 않는다. 공개 도메인 인증서·조직 운영 CRL 배포·프록시 정책은 별도 운영 작업이다. 일반 `compose.yaml`은 자격 환경변수를 주입하므로 Docker inspect에 보일 수 있다. 환경에 자격이 없다는 증거는 `compose.security.yaml` 범위다.

## Opus 지적 수정 후 재실행

새 이미지0d92379c…로 같은 볼륨을 유지해 다시 빌드·healthy 실행했다. 현재 소스 hash 일치, TLS1.3, 발급→trusted→폐기→blocked와 재시작 후 한도·폐기 유지, 실제 UID·모드·capability·비밀 bind 통제를 다시 확인했다. 최신 값은 JSON 증거를 따른다. 암호화 복구 도구는 생성 시각·세대·감사 ID·DB hash가 인증된 v2 묶음과 별도 HMAC 체크포인트를 사용한다. 이전 세대는 기본 거부하며 백업 뒤 보안 변경은 복구 절차에서 재적용해야 한다.

후속 발견 재수정 뒤 최종 이미지는1b5c6bed…다. 같은 볼륨을 유지해 다시 실행하고 현재 source hash·TLS1.3·발급/폐기·재시작 제한·파일권한을 재검증했다. DB에 고정 설치 ID가 있으며 새 복구 도구는 그 ID로 경로와 무관하게 체크포인트를 연결한다. 최신 암호화 백업·복구 수치는 JSON을 따른다.
