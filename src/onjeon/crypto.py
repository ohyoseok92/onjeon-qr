"""Canonical signed QR format and local key provisioning."""

import base64
import binascii
import json
import os
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


PREFIX = "onqr:v1:"


def canonical_bytes(value: dict) -> bytes:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("utf-8")


def b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def b64url_decode(value: str) -> bytes:
    if not value or any(char not in "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_" for char in value):
        raise ValueError("invalid base64url")
    try:
        result = base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))
    except binascii.Error as exc:
        raise ValueError("invalid base64url") from exc
    if b64url_encode(result) != value:
        raise ValueError("noncanonical base64url")
    return result


def make_qr(payload: dict, private_key: Ed25519PrivateKey) -> str:
    raw = canonical_bytes(payload)
    return PREFIX + b64url_encode(raw) + "." + b64url_encode(private_key.sign(raw))


def parse_qr(value: str) -> tuple[dict, bytes, bytes]:
    if len(value) > 4096 or not value.startswith(PREFIX):
        raise ValueError("unsupported QR format")
    parts = value[len(PREFIX):].split(".")
    if len(parts) != 2:
        raise ValueError("invalid signed QR")
    raw, signature = (b64url_decode(part) for part in parts)
    if len(raw) > 3000 or len(signature) != 64:
        raise ValueError("invalid signed QR size")
    payload = json.loads(raw)
    if not isinstance(payload, dict) or raw != canonical_bytes(payload):
        raise ValueError("noncanonical payload")
    expected = {"destination", "expires_at", "institution_id", "issued_at", "key_version", "purpose", "qr_id", "version"}
    if set(payload) != expected or payload["version"] != 1:
        raise ValueError("invalid payload fields")
    if any(type(payload[field]) is not str for field in ("destination", "institution_id", "key_version", "purpose", "qr_id")):
        raise ValueError("invalid payload field type")
    if any(type(payload[field]) is not int for field in ("issued_at", "expires_at")):
        raise ValueError("invalid timestamp type")
    return payload, raw, signature


def load_private_key(path: Path) -> Ed25519PrivateKey:
    key = serialization.load_pem_private_key(path.read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        raise ValueError("signing key must be Ed25519")
    return key


def create_private_key(path: Path) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    private_key = Ed25519PrivateKey.generate()
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    with os.fdopen(os.open(path, flags, 0o600), "wb") as stream:
        stream.write(pem)
    public = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64url_encode(public)
