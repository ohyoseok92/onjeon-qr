# 공개 운영 적용과 남은 계정·PC 조건

확인일: 2026-10-11. 사용자가 승인한 기존 서버와 도메인에 온전QR을 배포하고, MYBOX 암호화 백업을 실제로 업로드·다운로드·복구했다. 제품 시연용 단일 서버 범위의 결과다.

## 적용·실행한 항목

| 항목 | 실제 확인 |
|---|---|
| 공개 서비스 | https://qr.ohs92.com — 시스템 CA·호스트명 검증, TLS 1.3, 보안 헤더, health와 URL 분석 준비 상태 통과 |
| 발급·검증·폐기 | 공개 HTTPS API에서 발급→trusted→폐기→blocked, 무인증 관리자 접근 거부, 시험 기관 비활성화 |
| 서버 격리 | UID10001, 읽기 전용 rootfs, ALL capability 제거, no-new-privileges, 192MiB/0.5CPU/64PID 제한. HTTP 원본은 호스트 127.0.0.1:8002에만 게시 |
| 앞단 제한 | 전용 Nginx에 TLS1.2 이상, 16KiB 본문, 수신 시간·IP별 요청/연결 제한, 전달 IP 헤더 제거, access log 비활성 적용. 기존 서비스 healthy 유지 |
| 인증서 갱신 | Certbot timer 활성, 해당 인증서 dry-run 및 nginx 검사·reload hook 성공. 현재 인증서 만료 2027-01-09 |
| CRL 운영 | 실제 Let's Encrypt 체인 issuer 4개와 YE1 shard66 등록, 서명·범위·시각·역행 검사, 매시간 갱신 성공. 앱에는 읽기 전용 공개 TLS 자료만 마운트 |
| 운영 감시 | NTP 동기화 확인. 공개 TLS·실제 peer 인증서·등록 CRL·health를 5분마다 검사. 합성 실패로 OnFailure와 고정 journal 경보 발생 확인 |
| 백업 분리 | 실제 서버 DB·암호화 발급키·HMAC을 AES-256-GCM으로 백업해 MYBOX에 보관. 키·암호·최신 체크포인트는 PC의 현재 사용자/SYSTEM 보호 폴더에 보관 |
| 다운로드 복구 | 99,403 bytes와 SHA256 일치. 내려받은 파일로 최신 체크포인트·DB 전체 행·키·HMAC·독립 SSH 원본 해시 대조 및 격리 production API 확인. 폐기/비활성 QR blocked 유지 |
| 임시 자료 | 이번 백업의 서버·PC 평문 staging과 격리 복구 프로필 제거. 생산 DB·볼륨과 PC 키 원본 보존 |
| 원격 CI | [실행 38142893078](https://github.com/ohyoseok92/onjeon-qr/actions/runs/38142893078), commit 9794d5e06b8125c3e6847f5b1947cfb698947287: Python285개·브라우저15개 통과, Bandit src0건, pip/npm 알려진 취약점0건 |
| 릴리스 신뢰 | 기존 승인 서명키 지문을 GitHub variable과 [별도 HTTPS 승인 채널](https://qr.ohs92.com/.well-known/onjeon-release.json)에 등록. 최종 태그·ZIP 해시·자산 검증 결과는 ZIP 밖의 `OPERATIONS_RELEASE_CHECK.json`과 승인 채널에서 확인 |

증거: `PUBLIC_TLS_CHECK.json`, `PUBLIC_RUNTIME_CHECK.json`, `MYBOX_BACKUP_CHECK.json`, `CRL_OPERATIONS.md`, `BACKUP_CUSTODY.md`, `RELEASE_OPERATIONS.md`.

## 실제로 확인된 남은 조건

1. **GitHub 2단계 인증 꺼짐.** 로그인된 계정 설정 화면에서 확인했다. 인증 앱 등록·6자리 코드 입력·복구 코드 보관은 사용자가 직접 완료해야 한다. 완료 후 설정 화면을 다시 확인한다.
2. **PC C: 암호화와 보호 꺼짐.** 사용자가 승인한 관리자 읽기 전용 조회에서 ConversionStatus0, EncryptionPercentage0, ProtectionStatus0, EncryptionMethod0과 API 반환0을 확인했다. 전체 디스크 암호화는 부팅과 개인 파일에도 영향을 주므로, 복구 키의 PC 외부 보관을 정하고 적용을 승인한 뒤 진행한다. 조회만 수행했고 암호화·보호자 추가·재시작은 실행하지 않았다.

교육자료49개는 현재 **구현 확인37개·비적용10개·조건부2개**다. S11은 실제 등록 범위의 실행으로 구현 확인으로 갱신했다. S05의 공개 TLS·백업 분리는 통과했지만 PC 키 보관 매체의 암호화가 남았으며, S15의 릴리스·CI 통제와 별개로 계정 MFA가 남았다. 두 항목을 완료했다고 표시하지 않는다.

## 유지·복구 범위

현재 CRL 정책은 등록한 issuer와 shard 범위다. 다른 발급자나 새 shard는 승인·등록 전 URL 분석이 차단된다. 인증서 회전은 감시에서 감지하며 새 공개 CA 자료의 독립 확인이 필요하다. 일반 WebPKI 전체 지원과 OCSP 완료를 주장하지 않는다. 경보는 서버 journal에 기록하며 외부 push 알림은 설정하지 않았다.

MYBOX 보관과 이번 복구는 실제로 검증했다. 정기 MYBOX 업로드가 자동화된 상태는 아니다. 기관·키·토큰·QR의 보안 상태를 바꾼 후에는 새 백업과 최신 체크포인트를 보관해야 한다. 복구는 격리 환경에서 최신 변경을 재적용하고 관리자 자격을 교체한 뒤 승인한다. 이번 시험은 생산 서버를 과거 상태로 전환하지 않았다.

운영 담당과 취약점 접수는 저장소 소유자 `ohyoseok92`와 해당 비공개 저장소의 issue를 기준으로 한다. 패치 후 회귀·의존성 감사·이미지 검사·SBOM·ZIP 재생성·재서명과 새 승인 해시 등록을 수행한다. 실제 공공기관 참여·공식 보안 인증·다중 서버 운영은 현재 시연 범위에 포함하지 않는다.
