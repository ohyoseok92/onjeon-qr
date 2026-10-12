import base64
import json
import secrets
import sqlite3
from contextlib import closing

import pytest
from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from scripts import secure_profile as secure


@pytest.fixture(scope="module")
def private_profile(tmp_path_factory):
    path = tmp_path_factory.mktemp("secure-tools") / "profile"
    result = secure.create_profile(path)
    return path, result


def test_profile_protects_real_permissions_and_preserves_existing_secrets(private_profile):
    profile, created = private_profile
    environment = profile / "application/production.env"
    before = environment.read_bytes()
    values = dict(line.split("=", 1) for line in before.decode("ascii").splitlines())
    assert len(values["ONJEON_ADMIN_TOKEN"]) == len(values["ONJEON_KEY_PASSWORD"]) == 64
    assert values["ONJEON_ADMIN_TOKEN"] != values["ONJEON_KEY_PASSWORD"]
    assert created["release_key_encrypted"]
    for path in [profile, *[p for p in profile.rglob("*") if p.is_file()]]:
        assert secure.verify_private(path)
    with pytest.raises(FileExistsError):
        secure.create_profile(profile)
    assert environment.read_bytes() == before
    encrypted = (profile / "key-custody/release-private.pem").read_bytes()
    with pytest.raises((ValueError, TypeError)):
        serialization.load_pem_private_key(encrypted, password=None)


def test_release_verification_rejects_tampering_missing_anchor_and_valid_attacker_key(private_profile, tmp_path):
    profile, created = private_profile
    artifact = tmp_path / "release.zip"
    artifact.write_bytes(b"PK\x03\x04synthetic-release-artifact")
    document_path = tmp_path / "signature.json"
    secure.sign_release(artifact, document_path, profile)
    expected = created["public_key_fingerprint_sha256"]
    assert secure.verify_release(artifact, document_path, expected)["verified"]
    with pytest.raises(ValueError, match="externally trusted"):
        secure.verify_release(artifact, document_path, "")
    artifact.write_bytes(artifact.read_bytes() + b"tampered")
    with pytest.raises(ValueError, match="signed digest"):
        secure.verify_release(artifact, document_path, expected)
    artifact.write_bytes(b"PK\x03\x04synthetic-release-artifact")
    document = json.loads(document_path.read_text(encoding="utf-8"))
    document["signature_base64"] = base64.b64encode(b"\x00" * 64).decode("ascii")
    forged = tmp_path / "forged.json"
    forged.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(InvalidSignature):
        secure.verify_release(artifact, forged, expected)
    attacker = Ed25519PrivateKey.generate()
    document["public_key_pem"] = attacker.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii")
    document["public_key_fingerprint_sha256"] = secure.fingerprint(attacker.public_key())
    document["signature_base64"] = base64.b64encode(attacker.sign(secure.canonical(document["payload"]))).decode("ascii")
    forged.write_text(json.dumps(document), encoding="utf-8")
    with pytest.raises(ValueError, match="external trust anchor"):
        secure.verify_release(artifact, forged, expected)


def test_authenticated_backup_uses_fresh_nonce_and_rejects_wrong_key_and_modified_bytes():
    key = secrets.token_bytes(32)
    plaintext = b"Synthetic private recovery data"
    first, second = (secure.encrypt_backup_bytes(plaintext, key) for _ in range(2))
    assert first != second
    assert plaintext not in first
    assert secure.decrypt_backup_bytes(first, key) == plaintext
    with pytest.raises(InvalidTag):
        secure.decrypt_backup_bytes(first, secrets.token_bytes(32))
    with pytest.raises(InvalidTag):
        secure.decrypt_backup_bytes(first[:-1] + bytes([first[-1] ^ 1]), key)
    with pytest.raises(ValueError):
        secure.decrypt_backup_bytes(b"invalid header" + first, key)


def test_sqlite_wal_snapshot_encrypts_and_recovers_committed_data_without_overwriting(private_profile, tmp_path):
    profile, _ = private_profile
    source = tmp_path / "source.sqlite3"
    backup = profile / "backups/fixture.onbackup"
    restored = profile / "backups/restored.sqlite3"
    source_hmac = tmp_path / ".rate-limit-hmac"
    source_hmac.write_bytes(secrets.token_bytes(32))
    issuer_keys = tmp_path / "issuer-keys"
    issuer_keys.mkdir()
    (issuer_keys / "demo-city").mkdir()
    source_issuer_key = issuer_keys / "demo-city/v1.pem"
    source_issuer_key.write_bytes((profile / "key-custody/release-private.pem").read_bytes())
    with closing(sqlite3.connect(source)) as database:
        database.execute("PRAGMA journal_mode=WAL")
        database.execute("CREATE TABLE evidence(value TEXT)")
        database.execute("CREATE TABLE backup_identity(singleton INTEGER PRIMARY KEY, installation_id TEXT NOT NULL)")
        database.execute("INSERT INTO backup_identity VALUES (1, ?)", (secrets.token_hex(32),))
        database.execute("CREATE TABLE audit_events(id INTEGER PRIMARY KEY, action TEXT)")
        database.execute("INSERT INTO evidence VALUES (?)", ("synthetic WAL recovery evidence",))
        database.commit()
        result = secure.backup_database(source, backup, profile, issuer_key_directory=issuer_keys, approve_new_installation=True)
        assert result["backed_up"] and result["rate_limit_hmac_included"]
        assert result["encrypted_issuer_key_count"] == 1
    assert b"synthetic WAL recovery evidence" not in backup.read_bytes()
    assert secure.restore_database(backup, restored, profile)["integrity_check"] == "ok"
    assert (restored.parent / ".rate-limit-hmac").read_bytes() == source_hmac.read_bytes()
    assert (restored.with_name(restored.name + ".keys") / "demo-city/v1.pem").read_bytes() == source_issuer_key.read_bytes()
    with closing(sqlite3.connect(restored)) as database:
        assert database.execute("SELECT value FROM evidence").fetchone() == ("synthetic WAL recovery evidence",)
    before = restored.read_bytes()
    with pytest.raises(FileExistsError):
        secure.restore_database(backup, restored, profile)
    assert restored.read_bytes() == before


@pytest.mark.parametrize("value", ["../outside.pem", "demo-city/../../outside.pem", "/demo-city/v1.pem", "demo-city/subdir/v1.pem", "demo-city/v1.pem\\outside"])
def test_restored_issuer_key_paths_cannot_escape_or_change_the_product_directory_shape(value):
    with pytest.raises(ValueError):
        secure.issuer_key_relative(value)
