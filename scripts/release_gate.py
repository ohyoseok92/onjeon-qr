"""Read-only release gate. Trust inputs must come from outside the release bundle.

This verifies bytes and a pinned key; it cannot establish the publisher's legal
identity or decide whether the operator's independently supplied digest is current.
No trust anchor is learned from the signature JSON or written by this tool.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import io
import json
import re
import stat
import zipfile
from pathlib import Path, PurePosixPath

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

if __package__:
    from .secure_profile import canonical, fingerprint
else:
    from secure_profile import canonical, fingerprint

MAX_ZIP_BYTES = 64 * 1024 * 1024
MAX_UNPACKED_BYTES = 256 * 1024 * 1024
MAX_MEMBER_BYTES = 32 * 1024 * 1024
FORBIDDEN_PARTS = {".secrets", ".env", "data", "node_modules", ".venv", "demo-output", ".git"}
FORBIDDEN_SUFFIXES = {".pem", ".key", ".onbackup", ".bin", ".sqlite3", ".pdf", ".docx"}


def _unique_object(pairs: list[tuple[str, object]]) -> dict:
    result = {}
    for name, value in pairs:
        if name in result:
            raise ValueError("Duplicate signature JSON property")
        result[name] = value
    return result


def _bounded_read(path: Path, maximum: int) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise ValueError("Release input must be a regular file")
    with path.open("rb") as source:
        value = source.read(maximum + 1)
    if len(value) > maximum:
        raise ValueError("Release input exceeds the size limit")
    return value


def _archive_name(name: str) -> None:
    path = PurePosixPath(name)
    if (not name or name.startswith("/") or "\\" in name or ":" in name
            or path.as_posix() != name or any(part in {".", ".."} for part in path.parts)
            or any(ord(char) < 32 or ord(char) == 127 for char in name)
            or FORBIDDEN_PARTS.intersection(part.lower() for part in path.parts)
            or path.suffix.lower() in FORBIDDEN_SUFFIXES):
        raise ValueError("Unsafe or forbidden archive path")


def verify_bundle(artifact: Path, signature: Path, expected_fingerprint: str,
                  expected_sha256: str, source_root: Path | None = None) -> dict:
    """Verify a single bounded snapshot against explicitly supplied trust inputs."""
    for value, label in [(expected_fingerprint, "fingerprint"), (expected_sha256, "digest")]:
        if not re.fullmatch(r"[0-9a-f]{64}", value):
            raise ValueError(f"An externally trusted SHA-256 {label} is required")
    bundle = _bounded_read(artifact, MAX_ZIP_BYTES)
    digest = hashlib.sha256(bundle).hexdigest()
    if not hmac.compare_digest(digest, expected_sha256):
        raise ValueError("Release digest differs from the independently approved release")
    document = json.loads(_bounded_read(signature, 65536), object_pairs_hook=_unique_object)
    if not isinstance(document, dict) or document.get("algorithm") != "Ed25519":
        raise ValueError("Unsupported release signature")
    public = serialization.load_pem_public_key(document["public_key_pem"].encode("ascii"))
    if not isinstance(public, Ed25519PublicKey):
        raise ValueError("Expected an Ed25519 release key")
    actual = fingerprint(public)
    if (not hmac.compare_digest(actual, expected_fingerprint)
            or document.get("public_key_fingerprint_sha256") != actual):
        raise ValueError("Release key differs from the external trust anchor")
    expected_payload = {"format": "onjeon-release-v1", "artifact_name": artifact.name,
                        "sha256": digest, "bytes": len(bundle)}
    if document.get("payload") != expected_payload:
        raise ValueError("Signed release metadata does not match the artifact")
    public.verify(base64.b64decode(document["signature_base64"], validate=True), canonical(expected_payload))

    source = source_root.resolve(strict=True) if source_root is not None else None
    with zipfile.ZipFile(io.BytesIO(bundle)) as archive:
        entries = archive.infolist()
        names = [entry.filename for entry in entries]
        if not entries or len(entries) > 10000 or len(names) != len(set(names)) or "MANIFEST.sha256" not in names:
            raise ValueError("Duplicate archive files, excessive entries or missing manifest")
        if sum(entry.file_size for entry in entries) > MAX_UNPACKED_BYTES:
            raise ValueError("Expanded archive exceeds the size limit")
        for entry in entries:
            _archive_name(entry.filename)
            mode = entry.external_attr >> 16
            if (entry.is_dir() or entry.flag_bits & 1 or stat.S_ISLNK(mode)
                    or entry.file_size > MAX_MEMBER_BYTES):
                raise ValueError("Archive contains a directory, encrypted, linked or oversized member")
        manifest = archive.read("MANIFEST.sha256").decode("utf-8")
        expected_hashes = {}
        for line in manifest.splitlines():
            match = re.fullmatch(r"([0-9a-f]{64})  (.+)", line)
            if match is None:
                raise ValueError("Malformed release manifest")
            expected, name = match.groups()
            if name in expected_hashes or name == "MANIFEST.sha256":
                raise ValueError("Duplicate or self-referential manifest entry")
            _archive_name(name)
            expected_hashes[name] = expected
        if set(expected_hashes) != set(names) - {"MANIFEST.sha256"}:
            raise ValueError("Manifest does not cover every archive file exactly once")
        for name, expected in expected_hashes.items():
            value = archive.read(name)
            if hashlib.sha256(value).hexdigest() != expected:
                raise ValueError("Archive member differs from its manifest digest")
            if source is not None:
                local = (source / name).resolve(strict=True)
                if not local.is_relative_to(source) or not local.is_file() or local.read_bytes() != value:
                    raise ValueError("Archive differs from the current source tree")
    return {"verified": True, "artifact_sha256": digest, "public_key_fingerprint_sha256": actual,
            "manifest_files": len(expected_hashes), "matches_current_source": source is not None,
            "trust_input": "explicit_external_fingerprint_and_release_digest",
            "publisher_identity_verified": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("artifact", type=Path)
    parser.add_argument("signature", type=Path)
    parser.add_argument("--expected-fingerprint", required=True)
    parser.add_argument("--expected-sha256", required=True)
    parser.add_argument("--source-root", type=Path)
    args = parser.parse_args()
    try:
        result = verify_bundle(args.artifact, args.signature, args.expected_fingerprint,
                               args.expected_sha256, args.source_root)
    except Exception:
        # A bad input's filename, JSON and certificate content are not echoed.
        raise SystemExit("Release gate rejected the bundle or its external trust inputs") from None
    print(json.dumps(result, ensure_ascii=True, sort_keys=True))


if __name__ == "__main__":
    main()
