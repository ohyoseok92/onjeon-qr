"""Verify an actual stopped-container snapshot, encrypted backup and API restore.

The original container is restarted immediately after the consistent export.
Staging is inside the private profile and is erased after verification.
"""
import hashlib
import json
import os
import re
import secrets
import shutil
import sqlite3
import subprocess
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path

from fastapi.testclient import TestClient
from onjeon.api import Settings, create_app
from secure_profile import PROFILE, ROOT, backup_database, restore_database, load_profile, create_profile, protect_directory, verify_private

COMPOSE = ["docker", "compose", "-f", "compose.security.yaml"]


def command(arguments: list[str]) -> str:
    result = subprocess.run(arguments, cwd=ROOT, capture_output=True, text=True, timeout=60)
    if result.returncode:
        raise RuntimeError("Docker backup command failed")
    return result.stdout.strip()


def require(condition: bool, name: str) -> None:
    if not condition:
        raise RuntimeError("Encrypted backup verification failed: " + name)


def content(database: Path) -> dict:
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        names = [row[0] for row in connection.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")]
        return {name: connection.execute('SELECT * FROM "' + name + '" ORDER BY rowid').fetchall()
                for name in names if re.fullmatch(r"[a-z_]+", name)}


def main() -> None:
    load_profile()
    suffix = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S") + "-" + secrets.token_hex(3)
    # A restore has its own adjacent HMAC key. Each run needs a fresh protected
    # profile so that repeat verification never replaces a prior restored state.
    restore_profile = PROFILE / "backups" / ("restore-profile-" + suffix)
    create_profile(restore_profile)
    stage = PROFILE / "backups" / ("staging-" + suffix)
    stage.mkdir(mode=0o700)
    protect_directory(stage)
    cid = command(COMPOSE + ["ps", "-q", "app"])
    require(bool(cid), "container running")
    try:
        command(COMPOSE + ["stop", "app"])
        try:
            command(["docker", "cp", cid + ":/app/data", str(stage / "data")])
            command(["docker", "cp", cid + ":/app/.secrets", str(stage / "keys")])
        finally:
            command(COMPOSE + ["up", "-d", "--wait", "--wait-timeout", "45"])
        for path in stage.rglob("*"):
            verify_private(path)
        database = stage / "data/onjeon.sqlite3"
        archive = restore_profile / "backups/container-state.onbackup"
        restored = restore_profile / "backups/restored.sqlite3"
        backup_result = backup_database(database, archive, profile=restore_profile, issuer_key_directory=stage / "keys", approve_new_installation=True)
        restore_result = restore_database(archive, restored, profile=restore_profile)
        require(content(database) == content(restored), "all database rows retained")
        require((stage / "data/.rate-limit-hmac").read_bytes() == (restored.parent / ".rate-limit-hmac").read_bytes(), "rate-limit key retained")
        restored_keys = restored.with_name(restored.name + ".keys")
        source_keys = {p.relative_to(stage / "keys").as_posix(): p.read_bytes() for p in (stage / "keys").rglob("*.pem")}
        require(source_keys == {p.relative_to(restored_keys).as_posix(): p.read_bytes() for p in restored_keys.rglob("*.pem")}, "all nested issuer keys retained")
        require(not archive.read_bytes().startswith(b"SQLite format 3"), "backup is encrypted")
        values = dict(line.split("=", 1) for line in (PROFILE / "application/production.env").read_text().splitlines())
        values.update(ONJEON_TLS_CRL_BUNDLE=str(PROFILE / "tls-local/revocations.pem"))
        previous = {key: os.environ.get(key) for key in values}
        try:
            os.environ.update(values)
            with TestClient(create_app(Settings(restored, restored_keys, values["ONJEON_ADMIN_TOKEN"]))) as client:
                require(client.get("/health").status_code == 200, "restored production API starts")
                require(client.get("/admin/security-events", headers={"Authorization": "Bearer " + values["ONJEON_ADMIN_TOKEN"]}).status_code == 200, "restored admin authentication")
        finally:
            for key, value in previous.items():
                if value is None:
                    os.environ.pop(key, None)
                else:
                    os.environ[key] = value
        report = {"verified_at_utc": datetime.now(timezone.utc).isoformat(), "container_stopped_during_snapshot": True,
                  "restore_uses_fresh_private_profile": True,
                  "source_image_id": command(["docker", "inspect", cid, "--format", "{{.Image}}"]),
                  "original_container_restarted_healthy": True, "backup": backup_result, "restore": restore_result,
                  "all_snapshot_rows_match_before_restored_api_start": True, "all_nested_encrypted_keys_match": True,
                  "hmac_key_matches": True, "restored_production_api_health_and_admin": True,
                  "archive_acl": verify_private(archive), "archive_sha256": hashlib.sha256(archive.read_bytes()).hexdigest()}
    finally:
        # Resolve and constrain the exact recursive deletion to our new staging
        # directory. It contains this run's synthetic export, never user data.
        require(stage.resolve().parent == (PROFILE / "backups").resolve() and not stage.is_symlink(), "staging deletion boundary")
        shutil.rmtree(stage)
    report["plaintext_staging_removed"] = not stage.exists()
    (ROOT / "submission/DOCKER_BACKUP_CHECK.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
