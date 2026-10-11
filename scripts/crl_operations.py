"""Pinned, offline CRL publication with authenticated rollback protection.

No network or certificate CDP access. Trust pins must come from an independent
operator source. OpenSSL still checks the peer chain during the actual handshake.
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
import sqlite3
import sys
from contextlib import closing
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.exceptions import InvalidSignature, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, rsa, ed25519, ed448
from cryptography.x509.oid import ExtensionOID, CRLEntryExtensionOID

if __package__:
    from .secure_profile import private_write, protect_directory, verify_private
else:
    from secure_profile import private_write, protect_directory, verify_private

MAX_BYTES = 4 * 1024 * 1024
CRL_RE = re.compile(rb"-----BEGIN X509 CRL-----[A-Za-z0-9+/=\s]+-----END X509 CRL-----")
CERT_RE = re.compile(rb"-----BEGIN CERTIFICATE-----[A-Za-z0-9+/=\s]+-----END CERTIFICATE-----")
DOMAIN = b"ONJEON_CRL_CHECKPOINT_V1\x00"


def _read(path: Path) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Expected a regular, non-symlink file")
    with path.open("rb") as source:
        value = source.read(MAX_BYTES + 1)
    if len(value) > MAX_BYTES:
        raise ValueError("CRL input exceeds size limit")
    return value


def _blocks(value: bytes, pattern: re.Pattern) -> list[bytes]:
    blocks = pattern.findall(value)
    if not blocks or pattern.sub(b"", value).strip():
        raise ValueError("Unexpected content in PEM bundle")
    return blocks


def _utc(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _approved_scopes(scopes: list[str] | None) -> list[str]:
    scopes = scopes or []
    if len(set(scopes)) != len(scopes):
        raise ValueError("Duplicate approved distribution point")
    for scope in scopes:
        if len(scope) > 2048 or not scope.isascii() or any(character.isspace() for character in scope):
            raise ValueError("Invalid approved distribution point")
        parsed = urlsplit(scope)
        if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
            raise ValueError("Approved distribution point must be an explicit HTTP(S) URI")
    return sorted(scopes)


def _scope(crl: x509.CertificateRevocationList, approved: list[str], approve_ca_only_crls: bool) -> tuple[str | None, str]:
    try:
        extension = crl.extensions.get_extension_for_class(x509.IssuingDistributionPoint)
    except x509.ExtensionNotFound:
        return None, "all"
    value = extension.value
    if (extension.critical and approve_ca_only_crls and value.full_name is None and value.relative_name is None
            and value.only_contains_ca_certs and not value.only_contains_user_certs
            and not value.only_contains_attribute_certs and not value.indirect_crl
            and value.only_some_reasons is None):
        return None, "ca"
    if (not extension.critical or value.relative_name is not None or value.indirect_crl
            or value.only_some_reasons is not None or value.only_contains_ca_certs
            or value.only_contains_attribute_certs or not value.only_contains_user_certs
            or value.full_name is None or len(value.full_name) != 1
            or not isinstance(value.full_name[0], x509.UniformResourceIdentifier)):
        raise ValueError("Only explicitly approved, direct user-certificate CRL shards are supported")
    scope = value.full_name[0].value
    if scope not in approved:
        raise ValueError("CRL distribution point has not been independently approved")
    return scope, "user"


def _record_key(pin: str, scope: str | None, certificate_kind: str) -> str:
    if certificate_kind == "ca":
        return pin + ":ca-only"
    return pin if scope is None else pin + ":" + hashlib.sha256(scope.encode("ascii")).hexdigest()


def validate_issued_certificates(certificates: list[bytes], ca_bundle: bytes, records: dict, *,
                                 now: datetime | None = None) -> None:
    """Check local issued certificates against the exact approved issuer/shard.

    This is a publication coverage check, not a replacement for the peer's full
    chain, hostname and revocation checks in OpenSSL.
    """
    now = now or datetime.now(timezone.utc)
    issuers = {certificate.fingerprint(hashes.SHA256()).hex(): certificate
               for certificate in (x509.load_pem_x509_certificate(block) for block in _blocks(ca_bundle, CERT_RE))}
    for data in certificates:
        blocks = _blocks(data, CERT_RE)
        if len(blocks) != 1:
            raise ValueError("Issued-certificate input must contain exactly one leaf certificate")
        certificate = x509.load_pem_x509_certificate(blocks[0])
        if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
            raise ValueError("Issued certificate is outside its validity window")
        if certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Issued-certificate coverage is for leaf certificates only")
        matching = []
        for pin, issuer in issuers.items():
            try:
                if not issuer.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign:
                    continue
                certificate.verify_directly_issued_by(issuer)
                matching.append(pin)
            except (InvalidSignature, ValueError):
                pass
        if len(matching) != 1:
            raise ValueError("Issued certificate does not match exactly one approved issuer")
        pin = matching[0]
        available = {record.get("distribution_point") for record in records.values()
                     if record["issuer_pin"] == pin and record.get("certificate_kind", "all") != "ca"}
        if None in available:
            continue
        distribution_points = certificate.extensions.get_extension_for_class(x509.CRLDistributionPoints).value
        covered = False
        for point in distribution_points:
            if (point.relative_name is not None or point.crl_issuer is not None or point.reasons is not None
                    or point.full_name is None or len(point.full_name) != 1
                    or not isinstance(point.full_name[0], x509.UniformResourceIdentifier)):
                raise ValueError("Unsupported issued-certificate distribution point scope")
            if point.full_name[0].value in available:
                covered = True
        if not covered:
            raise ValueError("Issued certificate is not covered by an approved CRL shard")


def validate_bundle(bundle: bytes, ca_bundle: bytes, pins: list[str], *,
                    now: datetime | None = None, require_current: bool = True,
                    approved_distribution_points: list[str] | None = None,
                    approve_ca_only_crls: bool = False,
                    issued_certificates: list[bytes] | None = None) -> dict:
    """Validate full CRLs and explicitly approved direct leaf CRL shards."""
    now = now or datetime.now(timezone.utc)
    if now.tzinfo is None:
        raise ValueError("Timezone-aware UTC time is required")
    if max(len(bundle), len(ca_bundle)) > MAX_BYTES:
        raise ValueError("CRL input exceeds size limit")
    if not pins or any(not re.fullmatch(r"[0-9a-f]{64}", pin) for pin in pins):
        raise ValueError("Independent SHA256 issuer pins are required")
    approved = _approved_scopes(approved_distribution_points)
    certificates = [x509.load_pem_x509_certificate(block) for block in _blocks(ca_bundle, CERT_RE)]
    issuers = {cert.fingerprint(hashes.SHA256()).hex(): cert for cert in certificates}
    if len(issuers) != len(certificates) or set(issuers) != set(pins) or len(set(pins)) != len(pins):
        raise ValueError("Issuer certificate set does not match the trusted pins")
    for certificate in certificates:
        if not certificate.not_valid_before_utc <= now < certificate.not_valid_after_utc:
            raise ValueError("Issuer certificate is outside its validity window")
        if not certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ValueError("Issuer is not a CA")
        if not certificate.extensions.get_extension_for_class(x509.KeyUsage).value.crl_sign:
            raise ValueError("Issuer cannot sign CRLs")
        public_key = certificate.public_key()
        if not isinstance(public_key, (rsa.RSAPublicKey, ec.EllipticCurvePublicKey,
                                       ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
            raise ValueError("Unsupported issuer key")
        if ((isinstance(public_key, rsa.RSAPublicKey) and public_key.key_size < 2048)
                or (isinstance(public_key, ec.EllipticCurvePublicKey) and public_key.key_size < 256)):
            raise ValueError("Weak issuer key")
    records = {}
    for block in _blocks(bundle, CRL_RE):
        crl = x509.load_pem_x509_crl(block)
        scope, certificate_kind = _scope(crl, approved, approve_ca_only_crls)
        for extension in crl.extensions:
            if extension.oid == ExtensionOID.DELTA_CRL_INDICATOR:
                raise ValueError("Only direct, complete CRLs are supported")
            if extension.critical and extension.oid not in (ExtensionOID.CRL_NUMBER, ExtensionOID.AUTHORITY_KEY_IDENTIFIER,
                                                           ExtensionOID.ISSUING_DISTRIBUTION_POINT):
                raise ValueError("Unsupported critical CRL extension")
        number = crl.extensions.get_extension_for_class(x509.CRLNumber).value.crl_number
        aki = crl.extensions.get_extension_for_class(x509.AuthorityKeyIdentifier).value.key_identifier
        if number < 0 or aki is None:
            raise ValueError("CRL number and authority key identifier are required")
        matching = []
        for pin, certificate in issuers.items():
            ski = certificate.extensions.get_extension_for_class(x509.SubjectKeyIdentifier).value.digest
            if crl.issuer == certificate.subject and aki == ski and crl.is_signature_valid(certificate.public_key()):
                matching.append(pin)
        if len(matching) != 1:
            raise ValueError("CRL issuer or signature does not match a pinned CA")
        algorithm = crl.signature_hash_algorithm
        if algorithm is not None and algorithm.name not in {"sha256", "sha384", "sha512", "sha3-256", "sha3-384", "sha3-512"}:
            raise ValueError("Weak CRL signature algorithm")
        start, end = crl.last_update_utc, crl.next_update_utc
        if end is None or end <= start:
            raise ValueError("Invalid CRL validity window")
        if require_current and not start <= now < end:
            raise ValueError("CRL is expired or not yet valid")
        serials = []
        for revoked in crl:
            if revoked.revocation_date_utc > start:
                raise ValueError("Revocation date is after CRL publication")
            for extension in revoked.extensions:
                if extension.oid == CRLEntryExtensionOID.CERTIFICATE_ISSUER or extension.critical:
                    raise ValueError("Indirect or critical entry extension is unsupported")
                if extension.oid == CRLEntryExtensionOID.CRL_REASON and extension.value.reason == x509.ReasonFlags.remove_from_crl:
                    raise ValueError("Removal from CRL is unsupported")
            serials.append(str(revoked.serial_number))
        if len(set(serials)) != len(serials):
            raise ValueError("Duplicate revoked serial number")
        pin = matching[0]
        identity = _record_key(pin, scope, certificate_kind)
        if identity in records:
            raise ValueError("Duplicate issuer and scope CRL")
        records[identity] = {"number": number, "last_update": _utc(start), "next_update": _utc(end),
                             "crl_sha256": crl.fingerprint(hashes.SHA256()).hex(), "revoked_serials": sorted(serials),
                             "issuer_pin": pin, "distribution_point": scope, "certificate_kind": certificate_kind}
    if {record["issuer_pin"] for record in records.values()} != set(issuers):
        raise ValueError("A CRL is required for every pinned issuer")
    if {record["distribution_point"] for record in records.values() if record["distribution_point"] is not None} != set(approved):
        raise ValueError("A CRL is required for every approved distribution point")
    validate_issued_certificates(issued_certificates or [], ca_bundle, records, now=now)
    return {"records": records, "pins": sorted(pins), "approved_distribution_points": approved,
            "approve_ca_only_crls": approve_ca_only_crls,
            "bundle_sha256": hashlib.sha256(bundle).hexdigest()}


def _encode(value: dict) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _connect(custody: Path):
    verify_private(custody)
    for name in ("checkpoint-key.bin", "checkpoint.sqlite3"):
        verify_private(custody / name)
    key = _read(custody / "checkpoint-key.bin")
    if len(key) != 32:
        raise ValueError("Invalid checkpoint key")
    connection = sqlite3.connect((custody / "checkpoint.sqlite3").resolve().as_uri() + "?mode=rw", uri=True, timeout=30)
    connection.execute("PRAGMA synchronous=FULL")
    connection.execute("BEGIN IMMEDIATE")
    return connection, key


def _load(connection: sqlite3.Connection, key: bytes) -> dict:
    rows = connection.execute("SELECT body, mac FROM state").fetchall()
    if len(rows) != 1:
        raise ValueError("Missing or invalid CRL checkpoint")
    body, mac = rows[0]
    if not isinstance(body, bytes) or not isinstance(mac, bytes) or not hmac.compare_digest(mac, hmac.digest(key, DOMAIN + body, "sha256")):
        raise ValueError("CRL checkpoint authentication failed")
    state = json.loads(body)
    # Preserve the authenticated v1 full-issuer history while adding explicit
    # scope metadata. A subsequent successful update records the v2 format.
    if state.get("version") == 1:
        state["approved_distribution_points"] = []
        for pin, record in state["records"].items():
            record["issuer_pin"] = pin
            record["distribution_point"] = None
    state.setdefault("approve_ca_only_crls", False)
    for record in state["records"].values():
        record.setdefault("certificate_kind", "all" if record["distribution_point"] is None else "user")
    return state


def _save(connection: sqlite3.Connection, key: bytes, state: dict) -> None:
    body = _encode(state)
    connection.execute("UPDATE state SET body=?, mac=?", (body, hmac.digest(key, DOMAIN + body, "sha256")))


def _destination(bundle_path: Path, custody: Path) -> None:
    verify_private(bundle_path.parent)
    if bundle_path.is_symlink() or bundle_path.resolve().is_relative_to(custody.resolve()):
        raise ValueError("Bundle must be outside the checkpoint custody directory")
    if bundle_path.exists():
        verify_private(bundle_path)


def _publish(bundle_path: Path, data: bytes) -> None:
    staging = bundle_path.with_name(".crl-stage-" + secrets.token_hex(16))
    try:
        private_write(staging, data)
        with staging.open("r+b") as source:
            os.fsync(source.fileno())
        os.replace(staging, bundle_path)
        # Durably persist the directory entry on POSIX. Windows replacement is
        # completed before the SQLite active checkpoint is committed.
        if os.name != "nt":
            descriptor = os.open(bundle_path.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
    finally:
        if staging.exists():
            staging.unlink()


def initialize(custody: Path, bundle_path: Path, candidate: Path, issuers: Path, pins: list[str], *,
               approve_initial_installation: bool = False, now: datetime | None = None,
               approved_distribution_points: list[str] | None = None,
               approve_ca_only_crls: bool = False,
               issued_certificates: list[Path] | None = None) -> dict:
    if not approve_initial_installation:
        raise ValueError("Explicit initial installation approval is required")
    data = _read(candidate)
    validated = validate_bundle(data, _read(issuers), pins, now=now,
                                approved_distribution_points=approved_distribution_points,
                                approve_ca_only_crls=approve_ca_only_crls,
                                issued_certificates=[_read(path) for path in (issued_certificates or [])])
    if custody.exists():
        raise ValueError("Checkpoint custody already exists")
    _destination(bundle_path, custody)
    if bundle_path.exists() and _read(bundle_path) != data:
        raise ValueError("Initial installation cannot overwrite an existing different bundle")
    custody.mkdir(mode=0o700, parents=False)
    protect_directory(custody)
    key = secrets.token_bytes(32)
    private_write(custody / "checkpoint-key.bin", key)
    private_write(custody / "checkpoint.sqlite3", b"")
    state = {"version": 2, "phase": "pending", "destination": str(bundle_path.resolve()),
             "generation": 1, "previous_sha256": None,
             "candidate": base64.b64encode(data).decode("ascii"), **validated}
    with closing(sqlite3.connect(custody / "checkpoint.sqlite3")) as connection:
        connection.execute("PRAGMA synchronous=FULL")
        connection.execute("CREATE TABLE state (body BLOB NOT NULL, mac BLOB NOT NULL)")
        body = _encode(state)
        connection.execute("INSERT INTO state VALUES (?,?)", (body, hmac.digest(key, DOMAIN + body, "sha256")))
        connection.commit()
    return recover(custody, bundle_path, issuers, now=now, issued_certificates=issued_certificates)


def update(custody: Path, bundle_path: Path, candidate: Path, issuers: Path, *, now: datetime | None = None,
           issued_certificates: list[Path] | None = None) -> dict:
    _destination(bundle_path, custody)
    data = _read(candidate)
    connection, key = _connect(custody)
    with closing(connection):
        state = _load(connection, key)
        _bound(state, bundle_path)
        if state["phase"] != "active":
            raise ValueError("Pending publication must be recovered before updating")
        if hashlib.sha256(_read(bundle_path)).hexdigest() != state["bundle_sha256"]:
            raise ValueError("Published bundle differs from the authenticated checkpoint")
        validated = validate_bundle(data, _read(issuers), state["pins"], now=now,
                                    approved_distribution_points=state["approved_distribution_points"],
                                    approve_ca_only_crls=state["approve_ca_only_crls"],
                                    issued_certificates=[_read(path) for path in (issued_certificates or [])])
        if set(validated["records"]) != set(state["records"]):
            raise ValueError("The approved issuer and distribution point identity set cannot change")
        if validated["bundle_sha256"] == state["bundle_sha256"]:
            connection.rollback()
            return {"status": "unchanged", "generation": state["generation"]}
        for pin, current in validated["records"].items():
            old = state["records"][pin]
            if current["crl_sha256"] == old["crl_sha256"]:
                continue
            if current["number"] <= old["number"] or current["last_update"] < old["last_update"]:
                raise ValueError("CRL number or publication time rollback detected")
            # A newly numbered, correctly signed complete CRL is the issuer's
            # authoritative current set. Expired certificate entries may be
            # pruned by the issuer; do not require unbounded serial retention.
            # Delta/removeFromCRL, scope changes and equivocation remain denied.
        state = {**state, **validated, "version": 2, "phase": "pending", "generation": state["generation"] + 1,
                 "previous_sha256": state["bundle_sha256"], "candidate": base64.b64encode(data).decode("ascii")}
        _save(connection, key, state)
        connection.commit()
    return recover(custody, bundle_path, issuers, now=now, issued_certificates=issued_certificates)


def _bound(state: dict, bundle_path: Path) -> None:
    if state.get("version") not in (1, 2) or state.get("destination") != str(bundle_path.resolve()):
        raise ValueError("Checkpoint is bound to a different destination")


def recover(custody: Path, bundle_path: Path, issuers: Path, *, now: datetime | None = None,
            issued_certificates: list[Path] | None = None) -> dict:
    _destination(bundle_path, custody)
    connection, key = _connect(custody)
    with closing(connection):
        state = _load(connection, key)
        _bound(state, bundle_path)
        data = base64.b64decode(state["candidate"], validate=True)
        validated = validate_bundle(data, _read(issuers), state["pins"], now=now,
                                    approved_distribution_points=state["approved_distribution_points"],
                                    approve_ca_only_crls=state["approve_ca_only_crls"],
                                    issued_certificates=[_read(path) for path in (issued_certificates or [])])
        if any(validated[name] != state[name] for name in validated):
            raise ValueError("Checkpoint candidate does not match its authenticated metadata")
        if state["phase"] == "active":
            if hashlib.sha256(_read(bundle_path)).hexdigest() != state["bundle_sha256"]:
                raise ValueError("Active bundle differs from authenticated checkpoint")
            connection.rollback()
            return {"status": "unchanged", "generation": state["generation"]}
        if state["phase"] != "pending":
            raise ValueError("Invalid publication phase")
        existing = hashlib.sha256(_read(bundle_path)).hexdigest() if bundle_path.exists() else None
        if existing not in {state["previous_sha256"], state["bundle_sha256"]}:
            raise ValueError("Existing bundle is unrelated to pending publication")
        if existing != state["bundle_sha256"]:
            _publish(bundle_path, data)
        state["phase"] = "active"
        _save(connection, key, state)
        connection.commit()
        return {"status": "published", "generation": state["generation"],
                "bundle_sha256": state["bundle_sha256"], "issuer_count": len(state["pins"])}


def check(custody: Path, bundle_path: Path, issuers: Path, *, minimum_remaining_seconds: int = 86400,
          now: datetime | None = None, issued_certificates: list[Path] | None = None) -> dict:
    now = now or datetime.now(timezone.utc)
    if minimum_remaining_seconds < 0:
        raise ValueError("Expiry margin must not be negative")
    _destination(bundle_path, custody)
    connection, key = _connect(custody)
    with closing(connection):
        state = _load(connection, key)
        _bound(state, bundle_path)
        if state["phase"] != "active":
            raise ValueError("Publication is pending recovery")
        validated = validate_bundle(_read(bundle_path), _read(issuers), state["pins"], now=now, require_current=False,
                                    approved_distribution_points=state["approved_distribution_points"],
                                    approve_ca_only_crls=state["approve_ca_only_crls"],
                                    issued_certificates=[_read(path) for path in (issued_certificates or [])])
        if any(validated[name] != state[name] for name in validated):
            raise ValueError("Published CRL rollback or replacement detected")
        remaining = min((datetime.fromisoformat(record["next_update"]) - now).total_seconds()
                        for record in state["records"].values())
        future = any(datetime.fromisoformat(record["last_update"]) > now for record in state["records"].values())
        reason = "not_yet_valid" if future else "expired" if remaining <= 0 else "refresh_required" if remaining < minimum_remaining_seconds else "ready"
        connection.rollback()
        return {"ready": reason == "ready", "reason": reason, "generation": state["generation"],
                "issuer_count": len(state["pins"]), "minimum_remaining_seconds": int(remaining),
                "bundle_sha256": state["bundle_sha256"]}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("initialize", "update", "recover", "check"))
    parser.add_argument("--custody", type=Path, required=True)
    parser.add_argument("--bundle", type=Path, required=True)
    parser.add_argument("--issuers", type=Path, required=True)
    parser.add_argument("--candidate", type=Path)
    parser.add_argument("--issuer-pin", action="append", default=[])
    parser.add_argument("--approved-distribution-point", action="append", default=[])
    parser.add_argument("--approve-ca-only-crls", action="store_true")
    parser.add_argument("--issued-certificate", type=Path, action="append", default=[])
    parser.add_argument("--approve-initial-installation", action="store_true")
    parser.add_argument("--minimum-remaining-seconds", type=int, default=86400)
    args = parser.parse_args()
    try:
        if args.command != "initialize" and (args.approved_distribution_point or args.approve_ca_only_crls):
            raise ValueError("Approved scopes are fixed by the initial authenticated checkpoint")
        if args.command in ("initialize", "update") and args.candidate is None:
            raise ValueError("Candidate CRL file is required")
        if args.command == "initialize":
            result = initialize(args.custody, args.bundle, args.candidate, args.issuers, args.issuer_pin,
                                approve_initial_installation=args.approve_initial_installation,
                                approved_distribution_points=args.approved_distribution_point,
                                approve_ca_only_crls=args.approve_ca_only_crls,
                                issued_certificates=args.issued_certificate)
        elif args.command == "update":
            result = update(args.custody, args.bundle, args.candidate, args.issuers, issued_certificates=args.issued_certificate)
        elif args.command == "recover":
            result = recover(args.custody, args.bundle, args.issuers, issued_certificates=args.issued_certificate)
        else:
            result = check(args.custody, args.bundle, args.issuers, minimum_remaining_seconds=args.minimum_remaining_seconds,
                           issued_certificates=args.issued_certificate)
        print(json.dumps(result, sort_keys=True))
        if result.get("ready") is False:
            sys.exit(2)
    except (OSError, ValueError, KeyError, TypeError, sqlite3.Error, UnsupportedAlgorithm,
            x509.ExtensionNotFound, x509.DuplicateExtension):
        print(json.dumps({"ready": False, "reason": "crl_operation_failed"}))
        sys.exit(1)


if __name__ == "__main__":
    main()
