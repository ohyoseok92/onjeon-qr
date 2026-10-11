"""Regression checks for the independently reported security defects."""
import json
import secrets
import sqlite3
import ssl
from contextlib import closing
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa
from fastapi.testclient import TestClient

from onjeon import api, analyzer
from onjeon.crypto import b64url_encode, create_private_key
from scripts import secure_profile as secure


@pytest.fixture(scope="module")
def recovery_profile(tmp_path_factory):
    profile = tmp_path_factory.mktemp("opus-recovery") / "profile"
    secure.create_profile(profile)
    return profile


def synthetic_database(path):
    with closing(sqlite3.connect(path)) as db:
        db.execute("CREATE TABLE evidence(value TEXT)")
        db.execute("CREATE TABLE audit_events(id INTEGER PRIMARY KEY, action TEXT, institution_id TEXT NOT NULL DEFAULT 'synthetic', qr_id TEXT, occurred_at INTEGER NOT NULL DEFAULT 0)")
        db.execute("CREATE TABLE backup_identity(singleton INTEGER PRIMARY KEY, installation_id TEXT NOT NULL)")
        db.execute("INSERT INTO backup_identity VALUES (1, ?)", (secrets.token_hex(32),))
        db.execute("INSERT INTO evidence VALUES ('before revocation')")
        db.execute("INSERT INTO audit_events(id, action) VALUES (1, 'issued')")
        db.commit()


def test_backup_authenticated_generation_refuses_stale_state_before_writing(recovery_profile, tmp_path):
    profile = recovery_profile
    source = tmp_path / "generation.sqlite3"
    synthetic_database(source)
    old, latest = (profile / "backups" / name for name in ("old-generation.onbackup", "latest-generation.onbackup"))
    first = secure.backup_database(source, old, profile, approve_new_installation=True)["metadata"]
    with closing(sqlite3.connect(source)) as db:
        db.execute("UPDATE evidence SET value='revoked'")
        db.execute("INSERT INTO audit_events(id, action) VALUES (2, 'revoked')")
        db.commit()
    second = secure.backup_database(source, latest, profile)["metadata"]
    assert second["generation"] == first["generation"] + 1
    assert first["audit_event_max_id"] == 1 and second["audit_event_max_id"] == 2
    assert first["backup_id"] != second["backup_id"]
    assert second["database_sha256"] != first["database_sha256"]
    assert datetime.fromisoformat(second["created_at_utc"]).utcoffset() == timedelta(0)
    assert second["created_at_utc"].encode() not in latest.read_bytes()
    refused = profile / "backups/refused-stale.sqlite3"
    with pytest.raises(ValueError, match="trusted recovery checkpoint"):
        secure.restore_database(old, refused, profile, expected_backup_id=first["backup_id"])
    assert not refused.exists() and not refused.with_name(refused.name + ".keys").exists()
    restored = profile / "backups/latest-generation.sqlite3"
    result = secure.restore_database(latest, restored, profile, expected_backup_id=second["backup_id"])
    assert result["metadata"] == second and not result["rollback_explicitly_allowed"]
    with closing(sqlite3.connect(restored)) as db:
        assert db.execute("SELECT value FROM evidence").fetchone() == ("revoked",)
    override = secure.restore_database(old, profile / "backups/approved-old.sqlite3", profile, allow_rollback=True)
    assert override["rollback_explicitly_allowed"] and override["post_backup_security_changes_must_be_replayed"]


def test_backup_refuses_relabeling_older_audit_state_and_legacy_requires_override(recovery_profile, tmp_path):
    profile = recovery_profile
    source = tmp_path / "legacy.sqlite3"
    synthetic_database(source)
    archive = profile / "backups/legacy-source.onbackup"
    secure.backup_database(source, archive, profile, approve_new_installation=True)
    key = (profile / "key-custody/backup-key.bin").read_bytes()
    bundle = json.loads(secure.decrypt_backup_bytes(archive.read_bytes(), key))
    with closing(sqlite3.connect(source)) as db:
        db.execute("DELETE FROM audit_events")
        db.commit()
    relabeled = profile / "backups/relabeled-old.onbackup"
    with pytest.raises(ValueError, match="older than the trusted audit"):
        secure.backup_database(source, relabeled, profile)
    assert not relabeled.exists()
    bundle["format"] = "onjeon-state-backup-v1"
    bundle.pop("metadata")
    legacy = profile / "backups/legacy-v1.onbackup"
    secure.private_write(legacy, secure.encrypt_backup_bytes(json.dumps(bundle).encode(), key))
    with pytest.raises(ValueError, match="Legacy backup"):
        secure.restore_database(legacy, profile / "backups/legacy-denied.sqlite3", profile)
    result = secure.restore_database(legacy, profile / "backups/legacy-approved.sqlite3", profile, allow_rollback=True)
    assert result["metadata"] is None and result["rollback_explicitly_allowed"]


def test_authenticated_metadata_digest_and_checkpoint_tampering_fail_closed(recovery_profile, tmp_path):
    profile = recovery_profile
    source = tmp_path / "tampering.sqlite3"
    synthetic_database(source)
    archive = profile / "backups/tamper-source.onbackup"
    metadata = secure.backup_database(source, archive, profile, approve_new_installation=True)["metadata"]
    key = (profile / "key-custody/backup-key.bin").read_bytes()
    bundle = json.loads(secure.decrypt_backup_bytes(archive.read_bytes(), key))
    bundle["metadata"]["database_sha256"] = "0" * 64
    altered = profile / "backups/incorrect-digest.onbackup"
    secure.private_write(altered, secure.encrypt_backup_bytes(json.dumps(bundle).encode(), key))
    with pytest.raises(ValueError, match="authenticated digest"):
        secure.restore_database(altered, profile / "backups/digest-denied.sqlite3", profile, allow_rollback=True)
    with pytest.raises(ValueError, match="external recovery trust"):
        secure.restore_database(archive, profile / "backups/wrong-anchor.sqlite3", profile, expected_backup_id="0" * 64)
    checkpoint = profile / "key-custody/backup-checkpoints.sqlite3"
    with closing(sqlite3.connect(checkpoint)) as db:
        db.execute("UPDATE checkpoints SET mac=? WHERE source_id=?", ("0" * 64, metadata["source_id"]))
        db.commit()
    with pytest.raises(ValueError, match="checkpoint authentication"):
        secure.restore_database(archive, profile / "backups/checkpoint-denied.sqlite3", profile)
    assert not (profile / "backups/checkpoint-denied.sqlite3").exists()


def test_staging_path_changes_keep_one_backup_chain_and_refuse_old_revocations(recovery_profile, tmp_path):
    profile = recovery_profile
    old_source, new_source = tmp_path / "staging-a.sqlite3", tmp_path / "staging-b.sqlite3"
    synthetic_database(old_source)
    first_archive = profile / "backups/staging-first.onbackup"
    first = secure.backup_database(old_source, first_archive, profile, approve_new_installation=True)["metadata"]
    with closing(sqlite3.connect(old_source)) as source, closing(sqlite3.connect(new_source)) as target:
        source.backup(target)
    with closing(sqlite3.connect(new_source)) as db:
        db.execute("UPDATE evidence SET value='revoked in new staging path'")
        db.execute("INSERT INTO audit_events(id, action) VALUES (2, 'revoked')")
        db.commit()
    second = secure.backup_database(new_source, profile / "backups/staging-second.onbackup", profile)["metadata"]
    assert first["installation_id"] == second["installation_id"]
    assert first["source_id"] == second["source_id"] and second["generation"] == first["generation"] + 1
    with pytest.raises(ValueError, match="trusted recovery checkpoint"):
        secure.restore_database(first_archive, profile / "backups/staging-old-denied.sqlite3", profile)
    with pytest.raises(ValueError, match="older than the trusted audit"):
        secure.backup_database(old_source, profile / "backups/path-change-cannot-relabel.onbackup", profile)
    assert not (profile / "backups/path-change-cannot-relabel.onbackup").exists()


def test_backup_requires_identity_and_audit_and_external_reanchor_is_explicit(recovery_profile, tmp_path):
    profile = recovery_profile
    source = tmp_path / "required-identity.sqlite3"
    synthetic_database(source)
    archive = profile / "backups/reanchor-source.onbackup"
    metadata = secure.backup_database(source, archive, profile, approve_new_installation=True)["metadata"]
    with closing(sqlite3.connect(profile / "key-custody/backup-checkpoints.sqlite3")) as db:
        db.execute("DELETE FROM checkpoints WHERE source_id=?", (metadata["source_id"],))
        db.commit()
    with pytest.raises(ValueError, match="trusted recovery checkpoint"):
        secure.restore_database(archive, profile / "backups/untracked-denied.sqlite3", profile)
    result = secure.restore_database(archive, profile / "backups/externally-reanchored.sqlite3", profile, expected_backup_id=metadata["backup_id"])
    assert result["checkpoint_reanchored_from_external_id"] and not result["rollback_explicitly_allowed"]
    with closing(sqlite3.connect(source)) as db:
        db.execute("DROP TABLE audit_events")
        db.commit()
    with pytest.raises(ValueError, match="security audit checkpoint"):
        secure.backup_database(source, profile / "backups/no-audit-denied.onbackup", profile)
    with closing(sqlite3.connect(source)) as db:
        db.execute("DROP TABLE backup_identity")
        db.commit()
    with pytest.raises(ValueError, match="installation identity"):
        secure.backup_database(source, profile / "backups/no-identity-denied.onbackup", profile)


def test_first_backup_of_reinitialized_legacy_copy_requires_explicit_baseline_approval(recovery_profile, tmp_path):
    profile = recovery_profile
    source = tmp_path / "legacy-copy.sqlite3"
    synthetic_database(source)
    archive = profile / "backups/new-baseline.onbackup"
    secure.backup_database(source, archive, profile, approve_new_installation=True)
    # A pre-migration copy or deleted identity table gets a different ID during
    # initialize, but that must never silently enroll it as a trusted new chain.
    with closing(sqlite3.connect(source)) as db:
        db.execute("DROP TABLE backup_identity")
        db.commit()
    api.initialize(source)
    denied = profile / "backups/unapproved-reinitialized.onbackup"
    with pytest.raises(ValueError, match="explicit new-installation approval"):
        secure.backup_database(source, denied, profile)
    assert not denied.exists()
    result = secure.backup_database(source, profile / "backups/approved-reinitialized.onbackup", profile, approve_new_installation=True)
    assert result["new_installation_explicitly_approved"]
    assert secure.restore_database(profile / "backups/approved-reinitialized.onbackup", profile / "backups/approved-reinitialized.sqlite3", profile)["restored"]


def test_invalid_operator_tokens_cannot_poison_authenticated_lanes(tmp_path, monkeypatch):
    monkeypatch.setattr(api.time, "time", lambda: 1800000000)
    settings = api.Settings(tmp_path / "state.sqlite3", tmp_path / "keys", secrets.token_urlsafe(48))
    client = TestClient(api.create_app(settings))
    registered = client.post("/admin/institutions", headers={"Authorization": "Bearer " + settings.admin_token}, json={
        "institution_id": "city", "name": "Synthetic city", "official_domains": ["city.example.org"],
        "key_version": "v1", "public_key": b64url_encode(ed25519.Ed25519PrivateKey.generate().public_key().public_bytes_raw())})
    assert registered.status_code == 201
    token = registered.json()["issuer_token"]
    for path in ("/admin/security-events", "/institutions/city/dashboard"):
        for _ in range(30):
            assert client.get(path, headers={"Authorization": "Bearer wrong-token"}).status_code == 403
        assert client.get(path, headers={"Authorization": "Bearer wrong-token"}).status_code == 429
    assert client.get("/admin/security-events", headers={"Authorization": "Bearer " + settings.admin_token}).status_code == 200
    assert client.get("/institutions/city/dashboard", headers={"Authorization": "Bearer " + token}).status_code == 200


def test_expired_crl_keeps_signed_qr_admin_online_and_recovers_without_restart(tmp_path, monkeypatch):
    original_time = api.time
    clock = [original_time.monotonic()]
    monkeypatch.setattr(api, "time", SimpleNamespace(time=original_time.time, monotonic=lambda: clock[0]))
    monkeypatch.setenv("ONJEON_ENV", "production")
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", secrets.token_urlsafe(48))
    issuer = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, "Synthetic availability issuer")])
    now = datetime.now(timezone.utc)
    path = tmp_path / "crl.pem"
    def publish(next_update):
        crl = (x509.CertificateRevocationListBuilder().issuer_name(name).last_update(now - timedelta(days=2))
               .next_update(next_update).sign(issuer, hashes.SHA256()))
        path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    publish(now - timedelta(days=1))
    monkeypatch.setenv("ONJEON_TLS_CRL_BUNDLE", str(path))
    settings = api.Settings(tmp_path / "state.sqlite3", tmp_path / "keys", secrets.token_urlsafe(48))
    public = create_private_key(settings.key_directory / "city/v1.pem")
    with TestClient(api.create_app(settings)) as client:
        assert client.get("/health").json() == {"status": "degraded", "url_analysis": {"available": False, "reason": "crl_expired"}}
        registered = client.post("/admin/institutions", headers={"Authorization": "Bearer " + settings.admin_token}, json={
            "institution_id": "city", "name": "Synthetic city", "official_domains": ["city.example.org"],
            "key_version": "v1", "public_key": public})
        assert registered.status_code == 201
        token = registered.json()["issuer_token"]
        issued = client.post("/institutions/city/qrs", headers={"Authorization": "Bearer " + token}, json={
            "destination": "https://city.example.org/pay", "purpose": "Synthetic availability",
            "expires_at": (now + timedelta(days=1)).isoformat()})
        assert issued.status_code == 201
        assert client.post("/verify", json={"qr_text": issued.json()["qr_text"]}).json()["status"] == "trusted"
        with pytest.raises(ssl.SSLCertVerificationError):
            analyzer.build_tls_context()
        monkeypatch.setattr(analyzer, "_resolve_public", lambda *args, **kwargs: "93.184.216.34")
        assert client.post("/analyze", json={"qr_text": "https://city.example.org/pay"}).json()["reason"] == "tls_invalid"
        publish(now + timedelta(days=1))
        clock[0] += api.TLS_HEALTH_CACHE_SECONDS + 0.1
        assert client.get("/health").json() == {"status": "ok", "url_analysis": {"available": True, "reason": "ready"}}
        assert client.post("/institutions/city/qrs/" + issued.json()["qr_id"] + "/revoke", headers={"Authorization": "Bearer " + token}).status_code == 200
        assert client.post("/verify", json={"qr_text": issued.json()["qr_text"]}).json()["status"] == "blocked"
        path.write_bytes(b"malformed CRL")
        clock[0] += api.TLS_HEALTH_CACHE_SECONDS + 0.1
        assert client.get("/health").json()["url_analysis"]["reason"] == "crl_configuration_invalid"
    with pytest.raises(ssl.SSLCertVerificationError):
        api.create_app(settings)
