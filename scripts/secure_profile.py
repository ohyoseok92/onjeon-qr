"""Create a new private local profile, authenticated backups and pinned release signatures.

Never prints credentials. Existing profiles and output files are never overwritten.
The CLI confines private writes to this project's .secrets/operation-profile.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import secrets
import shutil
import sqlite3
import stat
import subprocess
from contextlib import closing, contextmanager
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

ROOT = Path(__file__).resolve().parents[1]
PROFILE = ROOT / ".secrets" / "operation-profile"
BACKUP_HEADER = b"ONJEON_SQLITE_BACKUP_V1\x00"
SIGN_DOMAIN = b"ONJEON_RELEASE_SIGNATURE_V1\x00"
MAX_BACKUP_BYTES = 256 * 1024 * 1024


def _powershell(script: str) -> dict:
    executable = shutil.which("pwsh.exe") or shutil.which("powershell.exe")
    if not executable:
        raise RuntimeError("PowerShell is required to enforce and inspect NTFS ACLs")
    command = base64.b64encode(("$ErrorActionPreference='Stop'; " + script).encode("utf-16le")).decode("ascii")
    result = subprocess.run([executable, "-NoProfile", "-NonInteractive", "-EncodedCommand", command],
                            check=True, capture_output=True, text=True, encoding="utf-8")
    return json.loads(result.stdout)


@lru_cache(maxsize=1)
def _windows_identity() -> str:
    return _powershell("[Security.Principal.WindowsIdentity]::GetCurrent().User.Value | ConvertTo-Json")


def _windows_acl(path: Path) -> dict:
    literal = str(path.resolve()).replace("'", "''")
    return _powershell("$a = Get-Acl -LiteralPath '" + literal + "'; "
                       "@{protected=$a.AreAccessRulesProtected; owner=$a.Owner; rules=@($a.Access | ForEach-Object {"
                       "@{sid=$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value; "
                       "type=$_.AccessControlType.ToString(); inherited=$_.IsInherited; rights=$_.FileSystemRights.ToString()}"
                       "})} | ConvertTo-Json -Depth 5")


def protect_directory(path: Path) -> None:
    if path.is_symlink():
        raise ValueError("Private directory must not be a symlink")
    if os.name == "nt":
        sid = _windows_identity()
        executable = shutil.which("icacls.exe")
        if not executable:
            raise RuntimeError("icacls is required to protect the NTFS directory")
        subprocess.run([executable, str(path.resolve()), "/inheritance:r", "/grant:r",
                        f"*{sid}:(OI)(CI)F", "*S-1-5-18:(OI)(CI)F"], check=True, capture_output=True)
        # Clear any explicit pre-existing default rules on this newly created folder.
        # icacls changes only the DACL; Set-Acl may also demand SACL privileges.
        for other in {_rule["sid"] for _rule in _windows_acl(path)["rules"]} - {sid, "S-1-5-18"}:
            subprocess.run([executable, str(path.resolve()), "/remove", "*" + other], check=True, capture_output=True)
    else:
        path.chmod(0o700)
    verify_private(path)


def verify_private(path: Path) -> dict:
    if path.is_symlink():
        raise ValueError("Private path must not be a symlink")
    if os.name == "nt":
        acl = _windows_acl(path)
        allowed = {_windows_identity(), "S-1-5-18"}
        rules = acl["rules"]
        if not rules or any(rule["sid"] not in allowed or rule["type"] != "Allow" for rule in rules):
            raise ValueError("Private ACL grants access outside the current user and SYSTEM")
        if path.is_dir() and path == PROFILE and not acl["protected"]:
            raise ValueError("Operation profile must disable inherited permissions")
        return {"platform": "windows", "allowed_identities": "current user and SYSTEM only",
                "rule_count": len(rules), "other_identity_count": 0,
                "inheritance_protected": acl["protected"]}
    mode = stat.S_IMODE(path.stat().st_mode)
    expected = 0o700 if path.is_dir() else 0o600
    if mode != expected:
        raise ValueError("Private path has unsafe POSIX permissions")
    return {"platform": "posix", "mode": oct(mode), "owner_uid": path.stat().st_uid}


def private_write(path: Path, value: bytes) -> None:
    verify_private(path.parent)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(value)
    verify_private(path)


def create_profile(path: Path = PROFILE) -> dict:
    # API callers/tests may supply a fresh directory; CLI uses the fixed project path.
    path.parent.mkdir(parents=True, exist_ok=True)
    path.mkdir(mode=0o700, exist_ok=False)
    protect_directory(path)
    for name in ["application", "key-custody", "backups"]:
        directory = path / name
        directory.mkdir(mode=0o700)
        protect_directory(directory)
    admin, key_password, release_password = (secrets.token_urlsafe(48) for _ in range(3))
    private_write(path / "application/production.env", (
        "ONJEON_ENV=production\nONJEON_ADMIN_TOKEN=" + admin + "\nONJEON_KEY_PASSWORD=" + key_password + "\n"
    ).encode("ascii"))
    private_write(path / "key-custody/release-passphrase", release_password.encode("ascii"))
    private_write(path / "key-custody/backup-key.bin", AESGCM.generate_key(bit_length=256))
    private_key = Ed25519PrivateKey.generate()
    encrypted = private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                         serialization.BestAvailableEncryption(release_password.encode("ascii")))
    private_write(path / "key-custody/release-private.pem", encrypted)
    public_pem = private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)
    private_write(path / "key-custody/release-public.pem", public_pem)
    return {"created": True, "profile": str(path), "random_input_bytes": 48,
            "release_key_encrypted": encrypted.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"),
            "public_key_fingerprint_sha256": fingerprint(private_key.public_key()), "acl": verify_private(path)}


def load_profile(path: Path = PROFILE) -> None:
    verify_private(path)
    for name in ["application/production.env", "key-custody/release-passphrase", "key-custody/release-private.pem", "key-custody/backup-key.bin"]:
        verify_private(path / name)


def fingerprint(public: Ed25519PublicKey) -> str:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()


def digest_file(path: Path) -> tuple[str, int]:
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
            size += len(block)
    return digest.hexdigest(), size


def canonical(payload: dict) -> bytes:
    return SIGN_DOMAIN + json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def sign_release(artifact: Path, output: Path, profile: Path = PROFILE) -> dict:
    load_profile(profile)
    private = serialization.load_pem_private_key((profile / "key-custody/release-private.pem").read_bytes(),
                                                (profile / "key-custody/release-passphrase").read_bytes())
    if not isinstance(private, Ed25519PrivateKey):
        raise ValueError("Expected Ed25519 release key")
    digest, size = digest_file(artifact)
    payload = {"format": "onjeon-release-v1", "artifact_name": artifact.name, "sha256": digest, "bytes": size}
    public = private.public_key()
    document = {"algorithm": "Ed25519", "payload": payload,
                "public_key_pem": public.public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode("ascii"),
                "public_key_fingerprint_sha256": fingerprint(public),
                "signature_base64": base64.b64encode(private.sign(canonical(payload))).decode("ascii")}
    with output.open("x", encoding="utf-8") as target:
        target.write(json.dumps(document, ensure_ascii=False, indent=2) + "\n")
    return {"signed": True, "artifact_sha256": digest, "public_key_fingerprint_sha256": fingerprint(public)}


def verify_release(artifact: Path, signature_file: Path, expected_fingerprint: str) -> dict:
    if not re.fullmatch(r"[0-9a-f]{64}", expected_fingerprint):
        raise ValueError("An externally trusted 64-character SHA-256 fingerprint is required")
    if signature_file.stat().st_size > 65536:
        raise ValueError("Signature file too large")
    document = json.loads(signature_file.read_text(encoding="utf-8"))
    if document.get("algorithm") != "Ed25519":
        raise ValueError("Unsupported signature algorithm")
    public = serialization.load_pem_public_key(document["public_key_pem"].encode("ascii"))
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("Expected Ed25519 public key")
    actual_fingerprint = fingerprint(public)
    if not hmac.compare_digest(actual_fingerprint, expected_fingerprint) or document.get("public_key_fingerprint_sha256") != actual_fingerprint:
        raise ValueError("Publisher public key does not match the external trust anchor")
    payload = document["payload"]
    if payload.get("format") != "onjeon-release-v1":
        raise ValueError("Invalid signed payload format")
    public.verify(base64.b64decode(document["signature_base64"], validate=True), canonical(payload))
    digest, size = digest_file(artifact)
    if payload.get("artifact_name") != artifact.name or payload.get("bytes") != size or payload.get("sha256") != digest:
        raise ValueError("Artifact content does not match the signed digest")
    return {"verified": True, "artifact_sha256": digest, "public_key_fingerprint_sha256": actual_fingerprint}


def encrypt_backup_bytes(data: bytes, key: bytes) -> bytes:
    if len(data) > MAX_BACKUP_BYTES or len(key) != 32:
        raise ValueError("Backup size or AES-256 key length is invalid")
    nonce = secrets.token_bytes(12)
    return BACKUP_HEADER + nonce + AESGCM(key).encrypt(nonce, data, BACKUP_HEADER)


def decrypt_backup_bytes(data: bytes, key: bytes) -> bytes:
    if len(key) != 32 or len(data) > MAX_BACKUP_BYTES + len(BACKUP_HEADER) + 28 or not data.startswith(BACKUP_HEADER) or len(data) < len(BACKUP_HEADER) + 28:
        raise ValueError("Invalid authenticated backup envelope")
    offset = len(BACKUP_HEADER)
    return AESGCM(key).decrypt(data[offset:offset + 12], data[offset + 12:], BACKUP_HEADER)


def issuer_key_relative(value: str) -> PurePosixPath:
    relative = PurePosixPath(value)
    if len(relative.parts) != 2 or not re.fullmatch(r"[a-z0-9][a-z0-9-]{1,39}", relative.parts[0]) or not re.fullmatch(r"[a-zA-Z0-9_-]{1,32}\.pem", relative.parts[1]):
        raise ValueError("Expected issuer key path institution/version.pem")
    return relative


def _checkpoint_mac(metadata: dict, key: bytes) -> str:
    encoded = json.dumps(metadata, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hmac.new(key, b"ONJEON_BACKUP_CHECKPOINT_V1\x00" + encoded, hashlib.sha256).hexdigest()


@contextmanager
def _backup_checkpoints(profile: Path, *, create: bool = False):
    # This trust state belongs to key custody, not the replaceable backup store.
    # Keep it on an independently protected medium in production. Losing it
    # requires an externally trusted backup ID; silently starting over is unsafe.
    path = profile / "key-custody/backup-checkpoints.sqlite3"
    if create and not path.exists():
        try:
            private_write(path, b"")
        except FileExistsError:
            pass
    verify_private(path)
    with closing(sqlite3.connect(path, timeout=10)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        if create:
            connection.execute("CREATE TABLE IF NOT EXISTS checkpoints (source_id TEXT PRIMARY KEY, metadata TEXT NOT NULL, mac TEXT NOT NULL)")
        try:
            yield connection
            connection.commit()
        except Exception:
            connection.rollback()
            raise


def _read_checkpoint(connection: sqlite3.Connection, source_id: str, key: bytes) -> dict | None:
    row = connection.execute("SELECT metadata, mac FROM checkpoints WHERE source_id = ?", (source_id,)).fetchone()
    if row is None:
        return None
    metadata = json.loads(row[0])
    if not hmac.compare_digest(_checkpoint_mac(metadata, key), row[1]) or metadata.get("source_id") != source_id:
        raise ValueError("Backup checkpoint authentication failed")
    return metadata


def _validate_backup_metadata(metadata: dict, data: bytes) -> None:
    if not isinstance(metadata, dict) or any(not isinstance(metadata.get(name), str) or not re.fullmatch(r"[0-9a-f]{64}", metadata[name])
                                           for name in ("backup_id", "source_id", "database_sha256")):
        raise ValueError("Invalid authenticated backup metadata")
    if type(metadata.get("generation")) is not int or metadata["generation"] < 1:
        raise ValueError("Invalid backup generation")
    if metadata.get("audit_event_max_id") is not None and (type(metadata["audit_event_max_id"]) is not int or metadata["audit_event_max_id"] < 0):
        raise ValueError("Invalid audit checkpoint")
    created = datetime.fromisoformat(metadata["created_at_utc"])
    if created.tzinfo is None or created.utcoffset().total_seconds() != 0:
        raise ValueError("Backup timestamp must be UTC")
    if not hmac.compare_digest(hashlib.sha256(data).hexdigest(), metadata["database_sha256"]):
        raise ValueError("Backup database does not match its authenticated digest")


def _database_installation_id(connection: sqlite3.Connection) -> str:
    try:
        rows = connection.execute("SELECT singleton, installation_id FROM backup_identity").fetchall()
    except sqlite3.Error:
        raise ValueError("Backup requires an initialized database installation identity") from None
    if len(rows) != 1 or rows[0][0] != 1 or not isinstance(rows[0][1], str) or not re.fullmatch(r"[0-9a-f]{64}", rows[0][1]):
        raise ValueError("Invalid database installation identity")
    return rows[0][1]


def _backup_source_id(key: bytes, installation_id: str) -> str:
    return hmac.new(key, b"ONJEON_BACKUP_INSTALLATION_V1\x00" + installation_id.encode("ascii"), hashlib.sha256).hexdigest()


def backup_database(source: Path, output: Path, profile: Path = PROFILE, *, issuer_key_directory: Path | None = None,
                    approve_new_installation: bool = False) -> dict:
    load_profile(profile)
    if output.resolve().parent != (profile / "backups").resolve():
        raise ValueError("Encrypted backup output must be in the profile backups directory")
    key = (profile / "key-custody/backup-key.bin").read_bytes()
    with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)) as origin:
        installation_id = _database_installation_id(origin)
    source_id = _backup_source_id(key, installation_id)
    # Serialize snapshots and generation assignment for all paths of the same
    # installation. A staging/export path must never create a new trust chain.
    with _backup_checkpoints(profile, create=True) as checkpoints:
        previous = _read_checkpoint(checkpoints, source_id, key)
        if previous is None and not approve_new_installation:
            raise ValueError("First backup requires explicit new-installation approval from a trusted baseline")
        with closing(sqlite3.connect(source.resolve().as_uri() + "?mode=ro", uri=True)) as origin, closing(sqlite3.connect(":memory:")) as snapshot:
            page_size = origin.execute("PRAGMA page_size").fetchone()[0]
            def check_size(status, remaining, total):
                if total * page_size > MAX_BACKUP_BYTES // 2:
                    raise ValueError("SQLite snapshot exceeds backup size budget")
            origin.backup(snapshot, pages=512, progress=check_size)
            if _database_installation_id(snapshot) != installation_id:
                raise ValueError("Database installation changed during snapshot")
            snapshot_time = datetime.now(timezone.utc).isoformat()
            try:
                audit_max = snapshot.execute("SELECT COALESCE(MAX(id), 0) FROM audit_events").fetchone()[0]
            except sqlite3.Error:
                raise ValueError("Backup requires its security audit checkpoint") from None
            data = snapshot.serialize()
        if previous and previous.get("audit_event_max_id") is not None and audit_max < previous["audit_event_max_id"]:
            raise ValueError("Snapshot is older than the trusted audit checkpoint")
        # The snapshot API merges committed WAL; deserialize needs rollback mode.
        data = data[:18] + b"\x01\x01" + data[20:]
        limiter = source.parent / ".rate-limit-hmac"
        limiter_bytes = limiter.read_bytes() if limiter.is_file() else None
        if limiter_bytes is not None and len(limiter_bytes) != 32:
            raise ValueError("Rate-limit HMAC key must be exactly 32 bytes")
        issuer_keys = {}
        if issuer_key_directory is not None:
            for path in sorted(issuer_key_directory.rglob("*.pem")):
                relative = issuer_key_relative(path.relative_to(issuer_key_directory).as_posix())
                if path.is_symlink() or not path.resolve().is_relative_to(issuer_key_directory.resolve()) or path.stat().st_size > 65536:
                    raise ValueError("Invalid issuer key filename or size")
                contents = path.read_bytes()
                if not contents.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----"):
                    raise ValueError("Issuer backup requires encrypted PKCS8 keys")
                issuer_keys[relative.as_posix()] = base64.b64encode(contents).decode("ascii")
        metadata = {"identity_format": "installation-id-v1", "installation_id": installation_id,
                    "backup_id": secrets.token_hex(32), "source_id": source_id,
                    "generation": previous["generation"] + 1 if previous else 1,
                    "created_at_utc": snapshot_time, "audit_event_max_id": audit_max,
                    "database_sha256": hashlib.sha256(data).hexdigest()}
        bundle = {"format": "onjeon-state-backup-v2", "metadata": metadata,
                  "database_base64": base64.b64encode(data).decode("ascii"),
                  "rate_limit_hmac_base64": base64.b64encode(limiter_bytes).decode("ascii") if limiter_bytes is not None else None,
                  "issuer_keys": issuer_keys}
        encrypted = encrypt_backup_bytes(json.dumps(bundle, sort_keys=True, separators=(",", ":")).encode("ascii"), key)
        private_write(output, encrypted)
        checkpoints.execute("INSERT INTO checkpoints VALUES (?, ?, ?) ON CONFLICT(source_id) DO UPDATE SET metadata=excluded.metadata, mac=excluded.mac",
                            (source_id, json.dumps(metadata, sort_keys=True, separators=(",", ":")), _checkpoint_mac(metadata, key)))
    return {"backed_up": True, "algorithm": "AES-256-GCM", "bytes": len(encrypted), "database_bytes": len(data),
            "rate_limit_hmac_included": limiter_bytes is not None, "encrypted_issuer_key_count": len(issuer_keys),
            "metadata": metadata, "checkpoint_recorded": True,
            "new_installation_explicitly_approved": previous is None and approve_new_installation}


def restore_database(source: Path, output: Path, profile: Path = PROFILE, *,
                     expected_backup_id: str | None = None, allow_rollback: bool = False) -> dict:
    load_profile(profile)
    if output.resolve().parent != (profile / "backups").resolve():
        raise ValueError("Restore output must be in the private profile backups directory")
    if source.stat().st_size > MAX_BACKUP_BYTES + len(BACKUP_HEADER) + 28:
        raise ValueError("Encrypted backup exceeds size limit")
    key = (profile / "key-custody/backup-key.bin").read_bytes()
    plaintext = decrypt_backup_bytes(source.read_bytes(), key)
    bundle = json.loads(plaintext)
    if bundle.get("format") not in ("onjeon-state-backup-v1", "onjeon-state-backup-v2"):
        raise ValueError("Invalid authenticated state format")
    data = base64.b64decode(bundle["database_base64"], validate=True)
    metadata = bundle.get("metadata") if bundle["format"] == "onjeon-state-backup-v2" else None
    if bundle["format"] == "onjeon-state-backup-v2" and metadata is None:
        raise ValueError("Backup v2 requires authenticated metadata")
    if metadata is not None:
        _validate_backup_metadata(metadata, data)
        if metadata.get("identity_format") != "installation-id-v1" and not allow_rollback:
            raise ValueError("Path-based legacy checkpoint requires explicit rollback approval")
    elif not allow_rollback:
        raise ValueError("Legacy backup lacks authenticated recovery metadata; explicit rollback approval required")
    if expected_backup_id is not None:
        if not re.fullmatch(r"[0-9a-f]{64}", expected_backup_id) or metadata is None or not hmac.compare_digest(metadata["backup_id"], expected_backup_id):
            raise ValueError("Backup ID does not match the external recovery trust anchor")
    hmac_key = base64.b64decode(bundle["rate_limit_hmac_base64"], validate=True) if bundle.get("rate_limit_hmac_base64") else None
    if hmac_key is not None and len(hmac_key) != 32:
        raise ValueError("Invalid restored rate-limit key")
    keys = {}
    for name, encoded in bundle["issuer_keys"].items():
        relative = issuer_key_relative(name)
        key_bytes = base64.b64decode(encoded, validate=True)
        if not key_bytes.startswith(b"-----BEGIN ENCRYPTED PRIVATE KEY-----") or len(key_bytes) > 65536:
            raise ValueError("Invalid restored encrypted PKCS8 key")
        keys[relative] = key_bytes
    with closing(sqlite3.connect(":memory:")) as restored:
        restored.deserialize(data)
        if restored.execute("PRAGMA integrity_check").fetchone() != ("ok",):
            raise ValueError("Restored SQLite integrity check failed")
        if metadata is not None and metadata.get("identity_format") == "installation-id-v1":
            installation_id = _database_installation_id(restored)
            if installation_id != metadata.get("installation_id") or not hmac.compare_digest(_backup_source_id(key, installation_id), metadata["source_id"]):
                raise ValueError("Backup installation identity does not match its authenticated checkpoint")
    key_directory = output.with_name(output.name + ".keys")
    limiter_output = output.parent / ".rate-limit-hmac"
    if output.exists() or (keys and key_directory.exists()) or (hmac_key is not None and limiter_output.exists()):
        raise FileExistsError("Refusing to overwrite restored state")
    def write_restored_state():
        if keys:
            key_directory.mkdir(mode=0o700)
            protect_directory(key_directory)
            for name, value in keys.items():
                if not (key_directory / name.parent).exists():
                    (key_directory / name.parent).mkdir(mode=0o700)
                    protect_directory(key_directory / name.parent)
                private_write(key_directory / name, value)
        if hmac_key is not None:
            private_write(limiter_output, hmac_key)
        private_write(output, data)
    checkpoint_file = profile / "key-custody/backup-checkpoints.sqlite3"
    checkpoint_reanchored = False
    if metadata is not None and (checkpoint_file.exists() or expected_backup_id is not None):
        with _backup_checkpoints(profile, create=expected_backup_id is not None) as checkpoints:
            latest = _read_checkpoint(checkpoints, metadata["source_id"], key)
            if not allow_rollback:
                if latest is None and expected_backup_id is not None:
                    checkpoint_reanchored = True
                elif latest != metadata:
                    raise ValueError("Backup is older than or absent from the trusted recovery checkpoint")
            if checkpoint_reanchored:
                checkpoints.execute("INSERT INTO checkpoints VALUES (?, ?, ?)", (metadata["source_id"], json.dumps(metadata, sort_keys=True, separators=(",", ":")), _checkpoint_mac(metadata, key)))
            write_restored_state()
    else:
        if not allow_rollback and expected_backup_id is None:
            raise ValueError("Recovery checkpoint missing; an externally trusted backup ID is required")
        write_restored_state()
    return {"restored": True, "integrity_check": "ok", "bytes": len(data),
            "rate_limit_hmac_restored": hmac_key is not None, "encrypted_issuer_key_count": len(keys),
            "metadata": metadata, "rollback_explicitly_allowed": allow_rollback,
            "checkpoint_reanchored_from_external_id": checkpoint_reanchored,
            "post_backup_security_changes_must_be_replayed": True}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("create")
    commands.add_parser("inspect")
    sign = commands.add_parser("sign")
    sign.add_argument("artifact", type=Path)
    sign.add_argument("signature", type=Path)
    verify = commands.add_parser("verify")
    verify.add_argument("artifact", type=Path)
    verify.add_argument("signature", type=Path)
    verify.add_argument("--expected-fingerprint", required=True)
    for command in ["backup", "restore"]:
        subparser = commands.add_parser(command)
        subparser.add_argument("source", type=Path)
        subparser.add_argument("--name", required=True, help="New output filename in the private backups directory")
        if command == "backup":
            subparser.add_argument("--issuer-key-directory", type=Path)
            subparser.add_argument("--new-installation", action="store_true", help="Explicitly approve the first backup of a verified new installation; never use to silently replace a lost trust chain")
        else:
            subparser.add_argument("--expected-backup-id", help="Backup ID obtained from an independently trusted recovery record")
            subparser.add_argument("--allow-rollback", action="store_true", help="Explicitly approve stale/legacy recovery; replay later revocations before serving")
    args = parser.parse_args()
    try:
        if PROFILE.resolve() != ROOT.resolve() / ".secrets" / "operation-profile":
            raise ValueError("Private operation profile must stay inside this project")
        if args.command == "create":
            result = create_profile()
        elif args.command == "inspect":
            load_profile()
            result = {"profile_acl": verify_private(PROFILE), "private_files": [{"path": str(path.relative_to(PROFILE)), "acl": verify_private(path)} for path in sorted(PROFILE.rglob("*")) if path.is_file()]}
        elif args.command == "sign":
            result = sign_release(args.artifact, args.signature)
        elif args.command == "verify":
            result = verify_release(args.artifact, args.signature, args.expected_fingerprint)
        else:
            if not re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9_.-]{0,79}", args.name):
                raise ValueError("Output must be a simple filename")
            output = PROFILE / "backups" / args.name
            result = backup_database(args.source, output, issuer_key_directory=args.issuer_key_directory, approve_new_installation=args.new_installation) if args.command == "backup" else restore_database(args.source, output, expected_backup_id=args.expected_backup_id, allow_rollback=args.allow_rollback)
        print(json.dumps(result, ensure_ascii=False))
    except Exception:
        # Never expose credential-bearing paths, JSON bodies or crypto exceptions.
        parser.exit(1, "Operation failed; check inputs, private permissions and the external trust anchor. Existing files are never overwritten.\n")


if __name__ == "__main__":
    main()
