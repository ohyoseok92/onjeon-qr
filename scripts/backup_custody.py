"""Export verified recovery material to independent media; never print secrets.

Existing destination parents must already be private. A fresh child is created on
each medium; failed/partial exports remain private and are never called complete.
"""
from __future__ import annotations

import argparse
import base64
import ctypes
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import socket
import sqlite3
import stat
from contextlib import closing
from pathlib import Path

try:
    from scripts import secure_profile as secure
except ModuleNotFoundError:
    import secure_profile as secure


def _regular(path: Path) -> Path:
    """Reject redirected ancestors as well as redirected leaf files."""
    absolute = path.absolute()
    for item in (absolute, *absolute.parents):
        value = item.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, "st_file_attributes", 0) & 0x400:
            raise ValueError("Redirected custody paths are forbidden")
    if not path.is_file():
        raise ValueError("Expected a regular custody file")
    return absolute


def _private_directory(path: Path) -> Path:
    absolute = path.absolute()
    for item in (absolute, *absolute.parents):
        value = item.lstat()
        if stat.S_ISLNK(value.st_mode) or getattr(value, "st_file_attributes", 0) & 0x400:
            raise ValueError("Redirected custody directories are forbidden")
    if not absolute.is_dir():
        raise ValueError("Custody destination parent must already exist")
    secure.verify_private(absolute)
    return absolute


def _addresses(host: str) -> set[str]:
    result = set()
    for item in socket.getaddrinfo(host, None):
        address = ipaddress.ip_address(item[4][0].split("%", 1)[0])
        mapped = getattr(address, "ipv4_mapped", None)
        result.add(str(mapped or address))
    return result


def _require_encrypted_smb(host: str, share: str) -> None:
    server, name = host.replace("'", "''"), share.replace("'", "''")
    result = secure._powershell(
        "$c=@(Get-SmbConnection -ServerName '" + server + "' | Where-Object {$_.ShareName -eq '" + name + "'}); "
        "@{count=$c.Count; encrypted=($c.Count -gt 0 -and @($c | Where-Object {-not $_.Encrypted}).Count -eq 0)} | ConvertTo-Json")
    if not result.get("count") or result.get("encrypted") is not True:
        raise ValueError("Remote custody requires an observed encrypted SMB connection")


def medium_identity(path: Path) -> dict:
    """Conservative physical disk / remote host identity, not drive letters.

    Ambiguous virtual disks, mounted POSIX filesystems and unresolvable network
    hosts are refused: different folder/device numbers alone are not proof of
    independent physical custody.
    """
    path = _private_directory(path)
    if os.name != "nt":
        raise ValueError("Physical custody requires Windows disk identity or an audited remote adapter")
    value = str(path)
    if value.startswith("\\\\"):
        parts = value.lstrip("\\").split("\\")
        if len(parts) < 2 or not parts[0] or not parts[1]:
            raise ValueError("Invalid network custody destination")
        host = parts[0].lower()
        addresses = _addresses(host)
        local = _addresses(socket.gethostname()) | {"127.0.0.1", "::1"}
        if host in {"localhost", socket.gethostname().lower(), socket.getfqdn().lower()} or not addresses or addresses & local:
            raise ValueError("A local network alias is not off-host custody")
        _require_encrypted_smb(host, parts[1])
        return {"kind": "remote-host", "identity": ",".join(sorted(addresses)), "transport_encrypted": True}
    mount = ctypes.create_unicode_buffer(32768)
    get_volume = ctypes.windll.kernel32.GetVolumePathNameW
    get_volume.argtypes = [ctypes.c_wchar_p, ctypes.c_wchar_p, ctypes.c_uint32]
    get_volume.restype = ctypes.c_int
    if not get_volume(value, mount, len(mount)):
        raise ValueError("Cannot resolve custody volume")
    literal = mount.value.replace("'", "''")
    result = secure._powershell(
        "$p=@(Get-Partition | Where-Object {$_.AccessPaths -contains '" + literal + "'}); "
        "if($p.Count -ne 1){throw 'Unknown custody disk'}; $d=$p[0] | Get-Disk; "
        "@{id=$d.UniqueId; bus=$d.BusType.ToString()} | ConvertTo-Json")
    if not result.get("id") or result.get("bus") in {"Virtual", "File Backed Virtual", "Unknown", "Spaces"}:
        raise ValueError("Cannot establish independent physical custody")
    return {"kind": "physical-disk", "identity": result["id"]}


def _independent(source: dict, archive: dict, custody: dict, *, require_three_media: bool = False) -> dict:
    identities = [(item["kind"], item["identity"]) for item in (source, archive, custody)]
    if identities[1] in (identities[0], identities[2]):
        raise ValueError("Encrypted archive requires a medium independent from source and key custody")
    if require_three_media and len(set(identities)) != 3:
        raise ValueError("Strict mode requires three independent media")
    # Overlapping network addresses can name the same server under different DNS.
    remote = [set(item["identity"].split(",")) for item in (source, archive, custody) if item["kind"] == "remote-host"]
    if any(left & right and left != right for index, left in enumerate(remote) for right in remote[index + 1:]):
        raise ValueError("Network shares on the same host are not independent custody")
    return {"key_and_archive_separated": True, "archive_off_host_verified": archive["kind"] == "remote-host",
            "source_and_key_custody_separated": identities[0] != identities[2],
            "remote_transport_encryption_verified": all(item.get("transport_encrypted") is True for item in (source, archive, custody) if item["kind"] == "remote-host")}


def _bundle(archive: Path, key: bytes) -> tuple[dict, bytes]:
    _regular(archive)
    secure.verify_private(archive)
    if archive.stat().st_size > secure.MAX_BACKUP_BYTES + len(secure.BACKUP_HEADER) + 28:
        raise ValueError("Backup exceeds size budget")
    encrypted = archive.read_bytes()
    document = json.loads(secure.decrypt_backup_bytes(encrypted, key))
    if document.get("format") != "onjeon-state-backup-v2":
        raise ValueError("Only authenticated current backups can leave the source profile")
    database = base64.b64decode(document["database_base64"], validate=True)
    metadata = document.get("metadata")
    secure._validate_backup_metadata(metadata, database)
    if metadata.get("identity_format") != "installation-id-v1":
        raise ValueError("A stable installation identity is required")
    with closing(sqlite3.connect(":memory:")) as connection:
        connection.deserialize(database)
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("Backup SQLite integrity failed")
        installation = secure._database_installation_id(connection)
    if installation != metadata.get("installation_id") or not hmac.compare_digest(secure._backup_source_id(key, installation), metadata["source_id"]):
        raise ValueError("Backup installation does not match custody")
    limiter = base64.b64decode(document.get("rate_limit_hmac_base64") or "", validate=True)
    if len(limiter) != 32 or not document.get("issuer_keys"):
        raise ValueError("Operational backup requires rate limiter and encrypted issuer keys")
    for name, content in document["issuer_keys"].items():
        secure.issuer_key_relative(name)
        contents = base64.b64decode(content, validate=True)
        if len(contents) > 65536 or not contents.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
            raise ValueError("Backup contains invalid encrypted issuer key material")
    return document, encrypted


def export_custody(archive: Path, archive_parent: Path, custody_parent: Path,
                   profile: Path = secure.PROFILE, *, require_three_media: bool = False) -> dict:
    profile = _private_directory(profile)
    archive_parent = _private_directory(archive_parent)
    custody_parent = _private_directory(custody_parent)
    for left, right in ((profile, archive_parent), (profile, custody_parent), (archive_parent, custody_parent)):
        if left == right or left.is_relative_to(right) or right.is_relative_to(left):
            raise ValueError("Source and destination trees must not overlap")
    secure.load_profile(profile)
    before = [medium_identity(item) for item in (profile, archive_parent, custody_parent)]
    separation = _independent(*before, require_three_media=require_three_media)
    files = ["application/production.env", "key-custody/backup-key.bin",
             "key-custody/release-passphrase", "key-custody/release-private.pem", "key-custody/release-public.pem"]
    values = {}
    for name in files:
        path = _regular(profile / name)
        secure.verify_private(path)
        if path.stat().st_size > 65536:
            raise ValueError("Custody material exceeds size budget")
        values[name] = path.read_bytes()
    key = values["key-custody/backup-key.bin"]
    bundle, encrypted = _bundle(archive, key)
    metadata = bundle["metadata"]
    checkpoint_file = _regular(profile / "key-custody/backup-checkpoints.sqlite3")
    secure.verify_private(checkpoint_file)
    with secure._backup_checkpoints(profile) as checkpoints:
        if secure._read_checkpoint(checkpoints, metadata["source_id"], key) != metadata:
            raise ValueError("Archive is not the independently recorded latest backup")
        with closing(sqlite3.connect(":memory:")) as snapshot:
            # checkpoint transaction is already locked; copying via serialize
            # sees the committed current database without a second lock request.
            snapshot.deserialize(checkpoints.serialize())
            checkpoint_bytes = snapshot.serialize()
        values["key-custody/backup-checkpoints.sqlite3"] = checkpoint_bytes
        suffix = "onjeon-custody-" + secrets.token_hex(12)
        archive_target, custody_target = archive_parent / suffix, custody_parent / suffix
        for target in (archive_target, custody_target):
            target.mkdir(mode=0o700, exist_ok=False)
            secure.protect_directory(target)
        secure.private_write(archive_target / "state.onbackup", encrypted)
        if (archive_target / "state.onbackup").read_bytes() != encrypted:
            raise ValueError("Archive copy verification failed")
        for name, contents in values.items():
            target = custody_target / name
            if not target.parent.exists():
                target.parent.mkdir(mode=0o700)
                secure.protect_directory(target.parent)
            secure.private_write(target, contents)
            if target.read_bytes() != contents:
                raise ValueError("Custody copy verification failed")
        record = {"format": "onjeon-custody-v1", "backup_metadata": metadata,
                  "archive_sha256": hashlib.sha256(encrypted).hexdigest(),
                  "recovery_gate": "isolated_until_authoritative_security_state_verified"}
        secure.private_write(custody_target / "recovery-record.json", json.dumps(record, sort_keys=True).encode("ascii"))
        after = [medium_identity(item) for item in (profile, archive_target, custody_target)]
        if before != after:
            raise ValueError("Custody medium changed during export")
    return {"exported": True, "independent_media_verified": True, "output_directory_name": suffix,
            **separation, "strict_three_media_required": require_three_media,
            "off_host_backup_condition_verified": separation["archive_off_host_verified"],
            "archive_sha256": record["archive_sha256"], "backup_id": metadata["backup_id"],
            "generation": metadata["generation"], "private_recovery_file_count": len(values) + 1,
            "copy_bytes_verified": True, "service_recovery_authorized": False,
            "post_backup_security_state_verification_required": True}


SECURITY_PROJECTION = {
    "institutions": "SELECT id, name, official_domains, issuer_token_hash, disabled FROM institutions ORDER BY id",
    "signing_keys": "SELECT institution_id, version, public_key, active, revoked_at FROM signing_keys ORDER BY institution_id, version",
    "issued_qrs": "SELECT qr_id, institution_id, payload_hash, purpose, issued_at, expires_at, key_version, revoked_at FROM issued_qrs ORDER BY qr_id",
}


def _security_state_bytes(data: bytes) -> tuple[str, dict]:
    with closing(sqlite3.connect(":memory:")) as connection:
        # A complete, externally authenticated snapshot may retain WAL header
        # flags even though it has no external WAL. In-memory inspection uses
        # rollback mode; no trusted bytes or on-disk source are rewritten.
        connection.deserialize(data[:18] + b"\x01\x01" + data[20:])
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",) or connection.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("Security state database integrity failed")
        identity = secure._database_installation_id(connection)
        state = {table: connection.execute(query).fetchall() for table, query in SECURITY_PROJECTION.items()}
        return identity, state


def _security_state(path: Path) -> tuple[str, dict]:
    _regular(path)
    secure.verify_private(path)
    with closing(sqlite3.connect(path.resolve().as_uri() + "?mode=ro", uri=True)) as connection:
        connection.execute("BEGIN")
        if connection.execute("PRAGMA integrity_check").fetchone() != ("ok",) or connection.execute("PRAGMA foreign_key_check").fetchone():
            raise ValueError("Security state database integrity failed")
        identity = secure._database_installation_id(connection)
        state = {table: connection.execute(query).fetchall() for table, query in SECURITY_PROJECTION.items()}
        return identity, state


def verify_recovery_security(restored: Path, authoritative: Path, expected_sha256: str) -> dict:
    """Compare with a frozen authoritative DB whose digest came via trust channel.

    The caller must stop mutations while capturing that DB, and retain evidence
    that it covers the recovery cutover. A self supplied hash is not trust.
    """
    if not re.fullmatch(r"[0-9a-f]{64}", expected_sha256):
        raise ValueError("An independently trusted security-state digest is required")
    _regular(authoritative)
    secure.verify_private(authoritative)
    # Reject live WAL: the external digest must authenticate all state we read.
    if authoritative.with_name(authoritative.name + "-wal").exists():
        raise ValueError("Authoritative security state must be a frozen WAL-merged snapshot")
    if authoritative.stat().st_size > secure.MAX_BACKUP_BYTES // 2:
        raise ValueError("Security state exceeds size budget")
    data = authoritative.read_bytes()
    before = hashlib.sha256(data).hexdigest()
    if not hmac.compare_digest(before, expected_sha256):
        raise ValueError("Authoritative security state does not match its independent trust anchor")
    source_identity, expected = _security_state_bytes(data)
    restored_identity, actual = _security_state(restored)
    if source_identity != restored_identity or actual != expected:
        raise ValueError("Restored security state differs; keep service isolated and replay approved changes")
    if secure.digest_file(authoritative)[0] != before or authoritative.with_name(authoritative.name + "-wal").exists():
        raise ValueError("Authoritative state changed while verifying recovery")
    return {"security_state_matches_authoritative_snapshot": True, "institution_key_qr_and_credentials_state_verified": True,
            "independent_snapshot_digest_verified": True,
            "operator_cutover_freshness_and_admin_rotation_required": True,
            "service_recovery_authorized": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    export = commands.add_parser("export")
    export.add_argument("archive", type=Path)
    export.add_argument("--archive-parent", type=Path, required=True)
    export.add_argument("--custody-parent", type=Path, required=True)
    export.add_argument("--profile", type=Path, default=secure.PROFILE)
    export.add_argument("--require-three-media", action="store_true", help="Also require source and recovery key on different media")
    verify = commands.add_parser("verify-recovery")
    verify.add_argument("restored", type=Path)
    verify.add_argument("--authoritative", type=Path, required=True)
    verify.add_argument("--expected-security-sha256", required=True)
    args = parser.parse_args()
    try:
        result = export_custody(args.archive, args.archive_parent, args.custody_parent, args.profile, require_three_media=args.require_three_media) if args.command == "export" else verify_recovery_security(args.restored, args.authoritative, args.expected_security_sha256)
        print(json.dumps(result, ensure_ascii=False))
    except Exception:
        parser.exit(1, "Custody operation failed; check independent media, private permissions, latest checkpoint and external trust record. Existing source material is preserved.\n")


if __name__ == "__main__":
    main()
