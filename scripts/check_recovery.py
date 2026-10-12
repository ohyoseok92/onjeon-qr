"""Exercise SQLite online backup/restore with ephemeral state and encrypted keys only."""

from __future__ import annotations

import json
import os
import platform
import secrets
import shutil
import sqlite3
import sys
import tempfile
import time
from contextlib import closing
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from onjeon.api import Settings, create_app
from onjeon.crypto import create_private_key


def backup(source: Path, destination: Path) -> None:
    # SQLite's API takes a consistent snapshot, including committed WAL data.
    with closing(sqlite3.connect(source)) as origin, closing(sqlite3.connect(destination)) as target:
        origin.backup(target)


def snapshot(path: Path) -> str:
    with closing(sqlite3.connect(path)) as db:
        return "\n".join(db.iterdump())


def run() -> dict:
    if not __debug__:
        raise RuntimeError("Recovery checks require assertions; do not run with Python -O")
    started = time.perf_counter()
    with tempfile.TemporaryDirectory(prefix="onjeon-recovery-") as temporary, patch.dict(
        os.environ, {"ONJEON_ENV": "development", "ONJEON_KEY_PASSWORD": secrets.token_urlsafe(48)}, clear=False,
    ):
        root = Path(temporary)
        admin = secrets.token_urlsafe(32)
        settings = Settings(root / "source" / "state.sqlite3", root / "source" / "keys", admin)
        public = create_private_key(settings.key_directory / "city-v1.pem")
        client = TestClient(create_app(settings))
        headers = {"Authorization": "Bearer " + admin}
        registered = client.post("/admin/institutions", headers=headers, json={
            "institution_id": "city", "name": "Synthetic recovery institution",
            "official_domains": ["city.example.org"], "key_version": "v1", "public_key": public,
        })
        assert registered.status_code == 201
        original_token = registered.json()["issuer_token"]
        def issue(token: str, target: TestClient = client):
            return target.post("/institutions/city/qrs", headers={"Authorization": "Bearer " + token}, json={
                "destination": "https://city.example.org/recovery", "purpose": "Synthetic recovery",
                "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            })
        old_qr = issue(original_token)
        assert old_qr.status_code == 201
        second_public = create_private_key(settings.key_directory / "city-v2.pem")
        assert client.post("/admin/institutions/city/keys", headers=headers, json={
            "key_version": "v2", "public_key": second_public,
        }).status_code == 201
        assert client.post("/admin/institutions/city/keys/v1/revoke", headers=headers).status_code == 200
        rotated = client.post("/admin/institutions/city/token", headers=headers)
        assert rotated.status_code == 200
        token = rotated.json()["issuer_token"]
        active = issue(token)
        revoked = issue(token)
        assert active.status_code == revoked.status_code == 201
        stale_backup = root / "stale.sqlite3"
        backup(settings.database_path, stale_backup)
        assert client.post("/institutions/city/qrs/" + revoked.json()["qr_id"] + "/revoke",
                           headers={"Authorization": "Bearer " + token}).status_code == 200
        assert client.post("/admin/institutions/city/disable", headers=headers).status_code == 200
        assert client.post("/admin/institutions/city/enable", headers=headers).status_code == 200
        assert client.get("/institutions/city/dashboard").status_code == 401
        assert client.post("/verify", json={"qr_text": revoked.json()["qr_text"]}).json()["reason"] == "revoked"
        fresh_backup = root / "fresh.sqlite3"
        backup(settings.database_path, fresh_backup)
        fresh_dump = snapshot(fresh_backup)

        restored_path = root / "restored" / "state.sqlite3"
        restored_path.parent.mkdir()
        backup(fresh_backup, restored_path)
        restored_keys = root / "restored" / "keys"
        shutil.copytree(settings.key_directory, restored_keys)
        shutil.copy2(settings.database_path.parent / ".rate-limit-hmac", restored_path.parent / ".rate-limit-hmac")
        restored_settings = Settings(restored_path, restored_keys, admin)
        restored = TestClient(create_app(restored_settings))
        assert snapshot(restored_path) == fresh_dump  # All tables, rows, indexes, sequence values.
        assert secrets.compare_digest((settings.database_path.parent / ".rate-limit-hmac").read_bytes(),
                                      (restored_path.parent / ".rate-limit-hmac").read_bytes())
        with closing(sqlite3.connect(restored_path)) as db:
            assert db.execute("PRAGMA integrity_check").fetchone() == ("ok",)
            assert db.execute("PRAGMA foreign_key_check").fetchall() == []
            counts = {table: db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0]
                      for table in ("institutions", "signing_keys", "issued_qrs", "audit_events", "security_events", "rate_counters")}
        assert restored.post("/verify", json={"qr_text": active.json()["qr_text"]}).json()["status"] == "trusted"
        assert restored.post("/verify", json={"qr_text": revoked.json()["qr_text"]}).json()["reason"] == "revoked"
        assert restored.post("/verify", json={"qr_text": old_qr.json()["qr_text"]}).json()["reason"] == "key_revoked"
        assert issue(original_token, restored).status_code == 403
        assert issue(token, restored).status_code == 201
        missing_keys = TestClient(create_app(Settings(restored_path, root / "absent-keys", admin)))
        assert issue(token, missing_keys).status_code == 503
        # Verification uses registered public keys; absence of signing secrets does not erase prior trust.
        assert missing_keys.post("/verify", json={"qr_text": active.json()["qr_text"]}).json()["status"] == "trusted"

        stale_path = root / "stale-restored.sqlite3"
        backup(stale_backup, stale_path)
        shutil.copy2(settings.database_path.parent / ".rate-limit-hmac", stale_path.parent / ".rate-limit-hmac")
        stale = TestClient(create_app(Settings(stale_path, restored_keys, admin)))
        assert stale.post("/verify", json={"qr_text": revoked.json()["qr_text"]}).json()["status"] == "trusted"
        return {
            "recorded_at": datetime.now(timezone(timedelta(hours=9))).isoformat(),
            "data_origin": "synthetic; temporary SQLite databases, random credentials and encrypted Ed25519 keys",
            "backup_method": "sqlite3.Connection.backup, WAL-aware; restore through the same API",
            "environment": {"python": platform.python_version(), "system": platform.system()},
            "elapsed_seconds": round(time.perf_counter() - started, 3),
            "restored_rows": counts,
            "results": {"complete_database_equivalence": True, "sqlite_integrity": True,
                        "foreign_key_integrity": True, "current_revocation_preserved": True,
                        "key_revocation_preserved": True, "rotated_credentials_preserved": True,
                        "restored_signing_key_issues_successfully": True, "missing_signing_key_returns_503": True,
                        "public_key_verification_without_private_key": True,
                        "shared_rate_key_and_counters_restored": True,
                        "stale_backup_revives_subsequently_revoked_qr": True},
            "network": "No external network requests; in-process real API via TestClient",
        }


def main() -> None:
    result = run()
    payload = json.dumps(result, ensure_ascii=False, indent=2)
    report = """# SQLite 백업·복구 실증

이 검증은 임시 DB·무작위 토큰·암호화된 임시 발급키만 사용했다. 생산 데이터·키·환경 비밀은 읽거나 출력하지 않았다. SQLite 온라인 backup API로 WAL의 커밋 상태까지 일관된 스냅숏을 만들고, 같은 API로 새 DB에 복구했다.

기관·키 버전·발급 QR 메타데이터·폐기·토큰 교체·관리 감사·인증 실패 감사와 DB 인덱스/시퀀스를 포함한 전체 덤프가 복구 직후 동일했다. integrity_check와 foreign_key_check도 통과했다. 실제 API에서 유효 QR 판정, QR 폐기, 키 폐기, 교체 전 토큰 거부, 새 토큰 발급 성공을 확인했다.

## 키와 외부 설정 복구

DB 백업에는 개인키와 관리자 토큰, 키 암호, 요청 제한의 HMAC키가 포함되지 않는다. 테스트는 별도 암호화 키 파일과 `.rate-limit-hmac`를 복사하고 동일한 임시 암호·관리자 설정을 주입했다. HMAC키와 DB카운터 복구를 함께 확인했다. 개인키가 없는 복구 서버는 발급을503으로 거부했다. 기존 QR 검증은 DB의 등록 공개키만 필요하므로 계속 작동했다. 운영 복구에는 개인키의 암호화 백업, HMAC키, 암호/KMS, 서버 설정을 별도 승인·권한·보존 정책으로 관리해야 한다. 이 스크립트는 네트워크를 사용하지 않는 개발 모드로 실행하며 생산 CRL 환경 설정은 별도 TLS 실증에서 확인한다.

## 오래된 백업의 위험과 복구 순서

폐기 이전 백업을 복구하면 이후 폐기한 QR이 다시 trusted로 판정되는 사실을 실제 API로 재현했다. DB 복구만으로 최신 폐기·기관 비활성·키 폐기·토큰 회전 상태가 보장되지는 않는다. 복구 중 발급/검증 서비스를 격리하고, 백업 이후 승인된 변경을 재적용하거나 관련 기관·키·QR을 우선 비활성/폐기한 뒤 재발급해야 한다. 최신 상태를 확인하기 전 공개 서비스를 열면 안 된다.

운영에서는 DB backup API를 사용하거나 프로세스 종료 상태에서 WAL 처리까지 포함하는 승인된 절차를 사용해야 한다. 실행 중 본체 sqlite3 파일만 복사하는 절차는 이 검증으로 보장하지 않는다. 백업 접근 권한·암호화·오프사이트 보관·보존기간·복구 승인·정기 복구 훈련은 운영자가 검증해야 한다. 임시 환경의 성공을 생산 환경 RPO/RTO 달성으로 해석하지 않는다.

## 실제 실행 결과

```json
""" + payload + "\n```\n"
    target = Path(__file__).resolve().parents[1] / "submission" / "RECOVERY_CHECK.md"
    target.write_text(report, encoding="utf-8")
    print(payload)


if __name__ == "__main__":
    main()
