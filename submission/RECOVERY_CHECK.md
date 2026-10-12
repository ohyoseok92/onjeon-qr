# SQLite 백업·복구 실증

이 검증은 임시 DB·무작위 토큰·암호화된 임시 발급키만 사용했다. 생산 데이터·키·환경 비밀은 읽거나 출력하지 않았다. SQLite 온라인 backup API로 WAL의 커밋 상태까지 일관된 스냅숏을 만들고, 같은 API로 새 DB에 복구했다.

기관·키 버전·발급 QR 메타데이터·폐기·토큰 교체·관리 감사·인증 실패 감사와 DB 인덱스/시퀀스를 포함한 전체 덤프가 복구 직후 동일했다. integrity_check와 foreign_key_check도 통과했다. 실제 API에서 유효 QR 판정, QR 폐기, 키 폐기, 교체 전 토큰 거부, 새 토큰 발급 성공을 확인했다.

## 키와 외부 설정 복구

DB 백업에는 개인키와 관리자 토큰, 키 암호, 요청 제한의 HMAC키가 포함되지 않는다. 테스트는 별도 암호화 키 파일과 `.rate-limit-hmac`를 복사하고 동일한 임시 암호·관리자 설정을 주입했다. HMAC키와 DB카운터 복구를 함께 확인했다. 개인키가 없는 복구 서버는 발급을503으로 거부했다. 기존 QR 검증은 DB의 등록 공개키만 필요하므로 계속 작동했다. 운영 복구에는 개인키의 암호화 백업, HMAC키, 암호/KMS, 서버 설정을 별도 승인·권한·보존 정책으로 관리해야 한다. 이 스크립트는 네트워크를 사용하지 않는 개발 모드로 실행하며 생산 CRL 환경 설정은 별도 TLS 실증에서 확인한다.

## 오래된 백업의 위험과 복구 순서

### 암호화 복구 도구의 후속 보완 (2026-10-11)

`secure_profile.py`는 이제 v2 백업에 UTC 생성 시각, 무작위 백업 ID, 동일 DB 설치 식별자의 세대, 스냅숏 감사 로그 최대 ID, DB SHA256을 포함해 AES-GCM으로 함께 인증한다. 백업 파일과 분리된 `key-custody/backup-checkpoints.sqlite3`에는 HMAC 인증 최신 체크포인트를 저장한다. 최신 체크포인트와 일치하지 않는 이전 세대·등록되지 않은 백업, 인증 메타데이터가 없는 v1 백업은 기본 복원을 거부하며 복구 파일을 만들지 않는다. 감사 ID가 이전 체크포인트보다 작은 원본을 새 세대라고 다시 백업하는 것도 거부한다. 세대는 이 보호 프로필에서 DB 안의 고정 설치 식별자별로 관리한다. 초기화 트랜잭션에서 무작위 식별자를 한 번 생성하며 복사·복구·임시 경로 변경에도 보존한다. 식별자 테이블이 존재하지만 행이 없거나 손상되면 자동 교체하지 않는다. 테이블이 없는 구형 DB의 초기화는 새 ID를 만들 수 있으므로 백업의 새 체인은 별도 승인을 요구한다. 스냅숏과 세대 부여도 같은 체크포인트 잠금 안에서 직렬화한다.

체크포인트를 잃은 재해 복구에는 독립 채널에서 보관한 `--expected-backup-id`가 필요하다. 파일 또는 해당 설치의 행이 없을 때 이 외부 ID로 체크포인트를 다시 연결하고 결과에 그 사실을 표시한다. 알고 있는 최신 체크포인트가 존재하면 외부 ID만으로 이전 세대를 우회할 수 없다. 승인된 이전 세대 또는 v1 복구에는 `--allow-rollback`을 명시해야 하며 결과에 예외 승인과 이후 보안 변경 재적용 필요를 표시한다. 모든 경로에서 기존 DB·키·HMAC를 덮어쓰지 않는다.

이 메타데이터는 **백업 뒤에 일어난 폐기를 자동으로 복원하지 않는다**. 생성 시각·감사 ID를 기준으로 이후 QR/키 폐기, 기관 비활성화, 토큰 교체를 승인된 기록에서 재적용한 뒤 서비스를 재개해야 한다. 공격자가 key-custody의 키와 체크포인트까지 되돌릴 수 있는 환경에서는 로컬 기록만으로 역행을 막을 수 없다. 키·체크포인트·최신 백업 ID를 백업 저장소와 별도 신뢰 매체에서 보관하는 운영 조건은 남는다. 새 프로필/키로 옮길 때는 독립 기록에서 최신 백업 ID와 설치 식별자를 확인해야 한다. 경로 기반의 구형 v2 체크포인트는 기본 복구를 거부하고 명시적 예외 승인이 필요하다.

회귀시험은 이전 세대 기본 거부와 파일 미생성, 최신 세대 복구, 명시적 이전 복구, v1 기본 거부, 감사 ID 역행 재백업 거부, 인증 DB 해시 불일치·외부 ID 불일치·체크포인트 HMAC 변조 거부를 확인한다. 아래 기존 SQLite 복구 시험은 메타데이터가 없는 개발용 원시 스냅숏의 위험을 보여주는 기록으로 보존한다. 최신 암호화 도구의 실제 컨테이너 복구 증거는 `DOCKER_BACKUP_CHECK.json`을 따른다.

폐기 이전 백업을 복구하면 이후 폐기한 QR이 다시 trusted로 판정되는 사실을 실제 API로 재현했다. DB 복구만으로 최신 폐기·기관 비활성·키 폐기·토큰 회전 상태가 보장되지는 않는다. 복구 중 발급/검증 서비스를 격리하고, 백업 이후 승인된 변경을 재적용하거나 관련 기관·키·QR을 우선 비활성/폐기한 뒤 재발급해야 한다. 최신 상태를 확인하기 전 공개 서비스를 열면 안 된다.

운영에서는 DB backup API를 사용하거나 프로세스 종료 상태에서 WAL 처리까지 포함하는 승인된 절차를 사용해야 한다. 실행 중 본체 sqlite3 파일만 복사하는 절차는 이 검증으로 보장하지 않는다. 백업 접근 권한·암호화·오프사이트 보관·보존기간·복구 승인·정기 복구 훈련은 운영자가 검증해야 한다. 임시 환경의 성공을 생산 환경 RPO/RTO 달성으로 해석하지 않는다.

## 실제 실행 결과

```json
{
  "recorded_at": "2026-10-11T19:20:53.531205+09:00",
  "data_origin": "synthetic; temporary SQLite databases, random credentials and encrypted Ed25519 keys",
  "backup_method": "sqlite3.Connection.backup, WAL-aware; restore through the same API",
  "environment": {
    "python": "3.12.10",
    "system": "Windows"
  },
  "elapsed_seconds": 0.834,
  "restored_rows": {
    "institutions": 1,
    "signing_keys": 2,
    "issued_qrs": 3,
    "audit_events": 10,
    "security_events": 1,
    "rate_counters": 3
  },
  "results": {
    "complete_database_equivalence": true,
    "sqlite_integrity": true,
    "foreign_key_integrity": true,
    "current_revocation_preserved": true,
    "key_revocation_preserved": true,
    "rotated_credentials_preserved": true,
    "restored_signing_key_issues_successfully": true,
    "missing_signing_key_returns_503": true,
    "public_key_verification_without_private_key": true,
    "shared_rate_key_and_counters_restored": true,
    "stale_backup_revives_subsequently_revoked_qr": true
  },
  "network": "No external network requests; in-process real API via TestClient"
}
```

### 최초 설치 백업 승인

체크포인트에 처음 등록하는 설치의 백업은 기본 거부한다. 신뢰할 수 있는 새 설치임을 확인한 운영자만 CLI `backup ... --new-installation` 또는 API `approve_new_installation=True`로 승인한다. 결과에는 `new_installation_explicitly_approved=true`를 기록한다. 이미 등록된 설치의 다음 백업에는 이 옵션이 필요 없다. 구형 DB 또는 ID 테이블을 잃은 사본에서 initialize를 실행해 새 ID를 만들더라도 자동으로 신뢰 체인에 등록되지 않는다. 이 옵션을 신뢰 기록 유실이나 폐기 상태 복구의 우회 수단으로 사용해서는 안 된다. 실제 복구 검사 도구는 실행마다 별도 합성 시험 프로필을 만들기 때문에 최초 등록을 명시 승인한다.

같은 설치 ID의 복제본이 독립적으로 변경될 때 감사 MAX(id)만으로 전체 계보를 증명하지는 않는다. 운영 백업은 지정된 원본 또는 승인된 정지 시점의 내보내기에서만 만들고, 임의로 갈라진 복제본을 후속 운영 백업으로 등록하지 않는다. 별도 변경/폐기 기록과 운영 승인 조건은 계속 적용한다. 복구 산출물은 서비스에 자동 연결하지 않으며 도구 오류 시 남은 비공개 산출물을 정상 복구로 사용하지 않는다.
