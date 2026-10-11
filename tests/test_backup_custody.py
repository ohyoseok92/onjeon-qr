import hashlib
import json
import os
import sqlite3
from contextlib import closing

import pytest

from onjeon import storage
from scripts import backup_custody as custody
from scripts import secure_profile as secure


@pytest.fixture(scope="module")
def sources(tmp_path_factory):
    root = tmp_path_factory.mktemp("custody-source")
    profile = root / "profile"
    secure.create_profile(profile)
    source = root / "state.sqlite3"
    storage.initialize(source)
    storage.load_rate_key(source)
    # Real product schema; all values are synthetic and never printed.
    with closing(sqlite3.connect(source)) as connection:
        connection.execute("INSERT INTO institutions VALUES ('demo-city', 'Demo', 'example.org', 'synthetic-not-a-credential', 0)")
        connection.execute("INSERT INTO signing_keys VALUES ('demo-city', 'v1', 'synthetic-public-key', 1, NULL)")
        connection.execute("INSERT INTO issued_qrs VALUES ('qr-one', 'demo-city', 'synthetic-hash', 'test', 1, 100, 'v1', NULL)")
        connection.commit()
    keys = root / "issuer-keys"
    (keys / "demo-city").mkdir(parents=True)
    (keys / "demo-city/v1.pem").write_bytes((profile / "key-custody/release-private.pem").read_bytes())
    archive = profile / "backups/state.onbackup"
    secure.backup_database(source, archive, profile, issuer_key_directory=keys, approve_new_installation=True)
    authority = profile / "backups/authoritative.sqlite3"
    with closing(sqlite3.connect(source)) as origin, closing(sqlite3.connect(":memory:")) as copy:
        origin.backup(copy)
        data = copy.serialize()
        secure.private_write(authority, data[:18] + b"\x01\x01" + data[20:])
    return profile, archive, authority, source, keys


def parents(tmp_path):
    result = [tmp_path / "archive-destination", tmp_path / "custody-destination"]
    for path in result:
        path.mkdir(mode=0o700)
        secure.protect_directory(path)
    return result


def simulated_media(monkeypatch, profile, destinations):
    mapping = {profile: "disk-a", destinations[0]: "disk-b", destinations[1]: "disk-c"}
    def identity(path):
        for parent, disk in mapping.items():
            if path == parent or path.is_relative_to(parent):
                return {"kind": "physical-disk", "identity": disk}
        raise ValueError("Unknown synthetic medium")
    monkeypatch.setattr(custody, "medium_identity", identity)


def test_export_matches_encrypted_archive_and_all_recovery_material(sources, tmp_path, monkeypatch):
    profile, archive, _, _, _ = sources
    destinations = parents(tmp_path)
    simulated_media(monkeypatch, profile, destinations)
    originals = {path: path.read_bytes() for path in profile.rglob("*") if path.is_file()}
    result = custody.export_custody(archive, *destinations, profile)
    assert result["independent_media_verified"] and result["copy_bytes_verified"]
    assert result["service_recovery_authorized"] is False
    name = result["output_directory_name"]
    assert (destinations[0] / name / "state.onbackup").read_bytes() == archive.read_bytes()
    exported = destinations[1] / name
    for file in ["application/production.env", "key-custody/backup-key.bin", "key-custody/release-private.pem", "key-custody/release-passphrase", "key-custody/release-public.pem"]:
        assert (exported / file).read_bytes() == (profile / file).read_bytes()
        assert secure.verify_private(exported / file)
    key = (exported / "key-custody/backup-key.bin").read_bytes()
    record = json.loads((exported / "recovery-record.json").read_bytes())
    with secure._backup_checkpoints(exported) as connection:
        assert secure._read_checkpoint(connection, record["backup_metadata"]["source_id"], key) == record["backup_metadata"]
    assert all(path.read_bytes() == contents for path, contents in originals.items())
    second = custody.export_custody(archive, *destinations, profile)
    assert second["output_directory_name"] != name
    assert "synthetic-not-a-credential" not in json.dumps(result)


def test_same_disk_and_same_remote_host_alias_are_rejected_before_writes(sources, tmp_path, monkeypatch):
    profile, archive, _, _, _ = sources
    destinations = parents(tmp_path)
    monkeypatch.setattr(custody, "medium_identity", lambda path: {"kind": "physical-disk", "identity": "same-disk"})
    with pytest.raises(ValueError, match="medium independent"):
        custody.export_custody(archive, *destinations, profile)
    assert not any(destinations[0].iterdir()) and not any(destinations[1].iterdir())
    with pytest.raises(ValueError, match="same host"):
        custody._independent({"kind": "physical-disk", "identity": "a"}, {"kind": "remote-host", "identity": "10.0.0.2,10.0.0.3"}, {"kind": "remote-host", "identity": "10.0.0.3"})


def test_two_media_key_with_source_reports_colocation_and_optional_strict_mode():
    local = {"kind": "physical-disk", "identity": "disk-a"}
    archive = {"kind": "remote-host", "identity": "203.0.113.1"}
    result = custody._independent(local, archive, local)
    assert result["key_and_archive_separated"] and result["archive_off_host_verified"]
    assert result["source_and_key_custody_separated"] is False
    with pytest.raises(ValueError, match="three independent"):
        custody._independent(local, archive, local, require_three_media=True)


def test_network_identity_normalizes_ipv4_mapped_aliases(monkeypatch):
    monkeypatch.setattr(custody.socket, "getaddrinfo", lambda *args: [(None, None, None, None, ("::ffff:127.0.0.1", 0))])
    assert custody._addresses("synthetic-host") == {"127.0.0.1"}


def test_remote_transport_requires_observed_smb_encryption(monkeypatch):
    monkeypatch.setattr(secure, "_powershell", lambda script: {"count": 1, "encrypted": False})
    with pytest.raises(ValueError, match="encrypted SMB"):
        custody._require_encrypted_smb("synthetic-server", "synthetic-share")
    monkeypatch.setattr(secure, "_powershell", lambda script: {"count": 0, "encrypted": True})
    with pytest.raises(ValueError, match="encrypted SMB"):
        custody._require_encrypted_smb("synthetic-server", "synthetic-share")
    monkeypatch.setattr(secure, "_powershell", lambda script: {"count": 1, "encrypted": True})
    custody._require_encrypted_smb("synthetic-server", "synthetic-share")


def test_stale_archive_and_tampering_rejected_before_export(sources, tmp_path, monkeypatch):
    profile, archive, _, source, keys = sources
    destinations = parents(tmp_path)
    simulated_media(monkeypatch, profile, destinations)
    old = profile / "backups/old.onbackup"
    secure.private_write(old, archive.read_bytes())
    latest = profile / "backups/latest.onbackup"
    secure.backup_database(source, latest, profile, issuer_key_directory=keys)
    with pytest.raises(ValueError, match="latest backup"):
        custody.export_custody(old, *destinations, profile)
    changed = profile / "backups/tampered.onbackup"
    secure.private_write(changed, latest.read_bytes()[:-1] + bytes([latest.read_bytes()[-1] ^ 1]))
    with pytest.raises(Exception):
        custody.export_custody(changed, *destinations, profile)
    assert not any(destinations[0].iterdir()) and not any(destinations[1].iterdir())


def test_recovery_requires_independent_snapshot_and_detects_later_revocation(sources, tmp_path):
    _, _, authority, _, _ = sources
    restored = tmp_path / "restored.sqlite3"
    restored.write_bytes(authority.read_bytes())
    if os.name == "nt":
        secure.protect_directory(tmp_path)
    else:
        tmp_path.chmod(0o700)
        restored.chmod(0o600)
    expected = hashlib.sha256(authority.read_bytes()).hexdigest()
    result = custody.verify_recovery_security(restored, authority, expected)
    assert result["institution_key_qr_and_credentials_state_verified"]
    assert result["service_recovery_authorized"] is False
    with pytest.raises(ValueError, match="independent trust anchor"):
        custody.verify_recovery_security(restored, authority, "0" * 64)
    with closing(sqlite3.connect(restored)) as connection:
        connection.execute("UPDATE issued_qrs SET revoked_at=123 WHERE qr_id='qr-one'")
        connection.commit()
    with pytest.raises(ValueError, match="differs"):
        custody.verify_recovery_security(restored, authority, expected)
    wal = authority.with_name(authority.name + "-wal")
    secure.private_write(wal, b"synthetic-live-WAL")
    try:
        with pytest.raises(ValueError, match="frozen WAL-merged"):
            custody.verify_recovery_security(restored, authority, expected)
    finally:
        wal.unlink()


@pytest.mark.parametrize("mutation", [
    "UPDATE institutions SET disabled=1",
    "UPDATE institutions SET issuer_token_hash='synthetic-rotated-token-hash'",
    "UPDATE signing_keys SET revoked_at=123, active=0",
    "UPDATE backup_identity SET installation_id='" + "0" * 64 + "'",
])
def test_recovery_detects_disabled_institution_token_key_and_installation_changes(sources, tmp_path, mutation):
    _, _, authority, _, _ = sources
    secure.protect_directory(tmp_path)
    restored = tmp_path / "restored.sqlite3"
    secure.private_write(restored, authority.read_bytes())
    expected = hashlib.sha256(authority.read_bytes()).hexdigest()
    with closing(sqlite3.connect(restored)) as connection:
        connection.execute(mutation)
        connection.commit()
    with pytest.raises(ValueError, match="differs"):
        custody.verify_recovery_security(restored, authority, expected)


def test_missing_destination_and_overlapping_trees_rejected(sources, tmp_path):
    profile, archive, _, _, _ = sources
    destinations = parents(tmp_path)
    with pytest.raises(FileNotFoundError):
        custody.export_custody(archive, tmp_path / "absent", destinations[1], profile)
    with pytest.raises(ValueError, match="overlap"):
        custody.export_custody(archive, profile / "backups", destinations[1], profile)


@pytest.mark.skipif(os.name == "nt", reason="Windows directory symlink creation requires unavailable privilege")
def test_symlinked_parent_is_rejected(sources, tmp_path, monkeypatch):
    profile, archive, _, _, _ = sources
    destinations = parents(tmp_path)
    linked = tmp_path / "linked"
    linked.symlink_to(destinations[0], target_is_directory=True)
    simulated_media(monkeypatch, profile, destinations)
    with pytest.raises(ValueError, match="Redirected"):
        custody.export_custody(archive, linked, destinations[1], profile)
