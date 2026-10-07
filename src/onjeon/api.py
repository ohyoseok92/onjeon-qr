"""Protected issuer API and read-only citizen verification API."""

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import sqlite3
import threading
import time
import unicodedata
from io import BytesIO
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
import qrcode

from .crypto import b64url_decode, b64url_encode, canonical_bytes, load_private_key, make_qr, parse_qr
from .analyzer import analyze_url
from .storage import database, initialize


DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
ID_RE = r"^[a-z0-9][a-z0-9-]{1,39}$"
KEY_RE = r"^[a-zA-Z0-9_-]{1,32}$"
bearer = HTTPBearer(auto_error=False)


@dataclass(frozen=True)
class Settings:
    database_path: Path
    key_directory: Path
    admin_token: str

    @classmethod
    def from_environment(cls) -> "Settings":
        token = os.getenv("ONJEON_ADMIN_TOKEN", "")
        if len(token) < 32:
            raise RuntimeError("ONJEON_ADMIN_TOKEN must contain at least 32 characters")
        return cls(
            database_path=Path(os.getenv("ONJEON_DATABASE_PATH", "data/onjeon.sqlite3")),
            key_directory=Path(os.getenv("ONJEON_KEY_DIRECTORY", ".secrets")),
            admin_token=token,
        )


class InstitutionInput(BaseModel):
    institution_id: str = Field(pattern=ID_RE)
    name: str = Field(min_length=2, max_length=100)
    official_domains: list[str] = Field(min_length=1, max_length=20)
    key_version: str = Field(pattern=KEY_RE)
    public_key: str

    @field_validator("name")
    @classmethod
    def safe_name(cls, value: str) -> str:
        return _safe_display_text(value)


class KeyInput(BaseModel):
    key_version: str = Field(pattern=KEY_RE)
    public_key: str


class IssueInput(BaseModel):
    destination: str = Field(min_length=1, max_length=2048)
    purpose: str = Field(min_length=2, max_length=160)
    expires_at: datetime
    include_png: bool = False

    @field_validator("purpose")
    @classmethod
    def safe_purpose(cls, value: str) -> str:
        return _safe_display_text(value)


class VerifyInput(BaseModel):
    qr_text: str = Field(min_length=1, max_length=4096)


class AnalyzeInput(BaseModel):
    qr_text: str = Field(min_length=1, max_length=2048)


def _token(credentials: HTTPAuthorizationCredentials | None) -> str:
    if credentials is None or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=401, detail="Bearer token required")
    return credentials.credentials


def _safe_display_text(value: str) -> str:
    if any(unicodedata.category(char) in ("Cc", "Cf", "Cs") for char in value):
        raise ValueError("Control and format characters are not allowed")
    return value


def _public_key_bytes(value: str) -> bytes:
    try:
        public_key = b64url_decode(value)
        if len(public_key) != 32:
            raise ValueError("invalid Ed25519 public key")
        Ed25519PublicKey.from_public_bytes(public_key)
        return public_key
    except ValueError as exc:
        raise HTTPException(status_code=422, detail="Invalid Ed25519 public key") from exc


def _domains(values: list[str]) -> list[str]:
    domains = sorted(set(value.strip().lower() for value in values))
    if len(domains) != len(values) or any(not DOMAIN_RE.fullmatch(domain) for domain in domains):
        raise HTTPException(status_code=422, detail="Use unique ASCII domain names without scheme or wildcard")
    return domains


def _destination_host(value: str, domains: list[str]) -> str | None:
    try:
        if any(char.isspace() or unicodedata.category(char) in ("Cc", "Cf", "Cs") for char in value) or "\\" in value:
            return None
        parts = urlsplit(value)
        host = parts.hostname
        if (
            parts.scheme.lower() != "https"
            or not host
            or parts.username is not None
            or parts.password is not None
            or parts.port not in (None, 443)
            or any(ord(char) > 127 for char in host)
            or not DOMAIN_RE.fullmatch(host.lower())
            or host.lower() not in domains
        ):
            return None
        return host.lower()
    except ValueError:
        return None


def _hash_token(value: str) -> str:
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def _key_path(settings: Settings, institution_id: str, key_version: str) -> Path:
    nested = settings.key_directory / institution_id / f"{key_version}.pem"
    if nested.is_file():
        return nested
    return settings.key_directory / f"{institution_id}-{key_version}.pem"  # legacy local keys


def _result(status: str, reason: str, **data) -> dict:
    return {"status": status, "reason": reason, **data}


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_environment()
    if len(settings.admin_token) < 32:
        raise RuntimeError("Admin token must contain at least 32 characters")
    initialize(settings.database_path)
    production = os.getenv("ONJEON_ENV") == "production"
    app = FastAPI(
        title="온전 QR", version="0.1.0",
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
    )
    request_counts: dict[tuple[str, str], tuple[float, int]] = {}
    rate_lock = threading.Lock()

    @app.middleware("http")
    async def disable_cache(request: Request, call_next):
        path = request.url.path
        if path in ("/verify", "/analyze") or path.startswith(("/admin/", "/institutions/")):
            if request.headers.get("transfer-encoding"):
                response = JSONResponse({"detail": "Chunked request bodies are not accepted"}, status_code=400)
                response.headers["Cache-Control"] = "no-store"
                return response
            if request.method in ("POST", "PUT", "PATCH") and "content-length" not in request.headers:
                response = JSONResponse({"detail": "Content-Length required"}, status_code=411)
                response.headers["Cache-Control"] = "no-store"
                return response
            try:
                content_length = int(request.headers.get("content-length", "0") or "0")
            except ValueError:
                content_length = 16385
            if content_length < 0 or content_length > 16384:
                response = JSONResponse({"detail": "Request too large"}, status_code=413)
                response.headers["Cache-Control"] = "no-store"
                return response
            group = "analyze" if path == "/analyze" else ("verify" if path == "/verify" else ("admin" if path.startswith("/admin/") else "issuer"))
            address = request.client.host if request.client else "unknown"
            try:
                parsed_address = ipaddress.ip_address(address)
                if parsed_address.version == 6:
                    address = str(ipaddress.ip_network(f"{parsed_address}/64", strict=False))
            except ValueError:
                pass
            now = time.monotonic()
            with rate_lock:
                key = (group, address)
                if key not in request_counts and len(request_counts) >= 10000:
                    expired = [old_key for old_key, (start, _) in request_counts.items() if now - start >= 60]
                    for old_key in expired:
                        del request_counts[old_key]
                    if len(request_counts) >= 10000:
                        response = JSONResponse({"detail": "Rate limiter busy"}, status_code=429)
                        response.headers["Cache-Control"] = "no-store"
                        return response
                start, count = request_counts.get(key, (now, 0))
                if now - start >= 60:
                    start, count = now, 0
                count += 1
                request_counts[key] = (start, count)
                limit = {"analyze": 10, "verify": 60, "issuer": 30, "admin": 30}[group]
                if count > limit:
                    response = JSONResponse({"detail": "Too many requests"}, status_code=429)
                    response.headers["Cache-Control"] = "no-store"
                    return response
        response = await call_next(request)
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(self)"
        if production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.url.path not in ("/docs", "/redoc"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data:; connect-src 'self'; "
                "media-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
            )
        return response

    def require_admin(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
        if not secrets.compare_digest(_token(credentials), settings.admin_token):
            raise HTTPException(status_code=403, detail="Not authorized")

    def require_issuer(institution_id: str, credentials: HTTPAuthorizationCredentials | None) -> None:
        with database(settings.database_path) as db:
            institution = db.execute("SELECT issuer_token_hash, disabled FROM institutions WHERE id = ?", (institution_id,)).fetchone()
        if institution is None or institution["disabled"] or not secrets.compare_digest(_hash_token(_token(credentials)), institution["issuer_token_hash"]):
            raise HTTPException(status_code=403, detail="Not authorized for institution")

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    @app.post("/admin/institutions", status_code=201, dependencies=[Depends(require_admin)])
    def register_institution(request: InstitutionInput) -> dict:
        domains = _domains(request.official_domains)
        public_key = b64url_encode(_public_key_bytes(request.public_key))
        issuer_token = secrets.token_urlsafe(32)
        with database(settings.database_path) as db:
            if db.execute("SELECT 1 FROM institutions WHERE id = ?", (request.institution_id,)).fetchone():
                raise HTTPException(status_code=409, detail="Institution already exists")
            try:
                db.execute(
                    "INSERT INTO institutions (id, name, official_domains, issuer_token_hash) VALUES (?, ?, ?, ?)",
                    (request.institution_id, request.name, json.dumps(domains), _hash_token(issuer_token)),
                )
            except sqlite3.IntegrityError as exc:
                raise HTTPException(status_code=409, detail="Institution already exists") from exc
            db.execute(
                "INSERT INTO signing_keys (institution_id, version, public_key, active) VALUES (?, ?, ?, 1)",
                (request.institution_id, request.key_version, public_key),
            )
        return {"institution_id": request.institution_id, "issuer_token": issuer_token}

    @app.post("/admin/institutions/{institution_id}/keys", status_code=201, dependencies=[Depends(require_admin)])
    def rotate_key(institution_id: str, request: KeyInput) -> dict:
        if not re.fullmatch(ID_RE, institution_id):
            raise HTTPException(status_code=422, detail="Invalid institution ID")
        public_key = b64url_encode(_public_key_bytes(request.public_key))
        key_path = _key_path(settings, institution_id, request.key_version)
        try:
            private_key = load_private_key(key_path)
            if not secrets.compare_digest(private_key.public_key().public_bytes_raw(), b64url_decode(public_key)):
                raise ValueError("Public key mismatch")
        except (OSError, ValueError) as exc:
            raise HTTPException(status_code=422, detail="Matching signing key must be provisioned before activation") from exc
        with database(settings.database_path) as db:
            if not db.execute("SELECT 1 FROM institutions WHERE id = ?", (institution_id,)).fetchone():
                raise HTTPException(status_code=404, detail="Institution not found")
            if db.execute("SELECT 1 FROM signing_keys WHERE institution_id = ? AND version = ?", (institution_id, request.key_version)).fetchone():
                raise HTTPException(status_code=409, detail="Key version already exists")
            db.execute("UPDATE signing_keys SET active = 0 WHERE institution_id = ?", (institution_id,))
            try:
                db.execute(
                    "INSERT INTO signing_keys (institution_id, version, public_key, active) VALUES (?, ?, ?, 1)",
                    (institution_id, request.key_version, public_key),
                )
            except sqlite3.IntegrityError as exc:
                raise HTTPException(status_code=409, detail="Key version already exists") from exc
        return {"institution_id": institution_id, "active_key_version": request.key_version}

    @app.post("/admin/institutions/{institution_id}/token", dependencies=[Depends(require_admin)])
    def rotate_issuer_token(institution_id: str) -> dict:
        token = secrets.token_urlsafe(32)
        with database(settings.database_path) as db:
            cursor = db.execute("UPDATE institutions SET issuer_token_hash = ? WHERE id = ?", (_hash_token(token), institution_id))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Institution not found")
        return {"institution_id": institution_id, "issuer_token": token}

    @app.post("/admin/institutions/{institution_id}/keys/{key_version}/activate", dependencies=[Depends(require_admin)])
    def activate_key(institution_id: str, key_version: str) -> dict:
        if not re.fullmatch(ID_RE, institution_id) or not re.fullmatch(KEY_RE, key_version):
            raise HTTPException(status_code=422, detail="Invalid institution or key version")
        with database(settings.database_path) as db:
            row = db.execute(
                "SELECT public_key, revoked_at FROM signing_keys WHERE institution_id = ? AND version = ?",
                (institution_id, key_version),
            ).fetchone()
            if row is None or row["revoked_at"] is not None:
                raise HTTPException(status_code=404, detail="Usable key not found")
            try:
                private_key = load_private_key(_key_path(settings, institution_id, key_version))
                if not secrets.compare_digest(private_key.public_key().public_bytes_raw(), b64url_decode(row["public_key"])):
                    raise ValueError("Public key mismatch")
            except (OSError, ValueError) as exc:
                raise HTTPException(status_code=422, detail="Matching signing key unavailable") from exc
            db.execute("UPDATE signing_keys SET active = 0 WHERE institution_id = ?", (institution_id,))
            db.execute(
                "UPDATE signing_keys SET active = 1 WHERE institution_id = ? AND version = ?",
                (institution_id, key_version),
            )
        return {"institution_id": institution_id, "active_key_version": key_version}

    @app.post("/admin/institutions/{institution_id}/disable", dependencies=[Depends(require_admin)])
    def disable_institution(institution_id: str) -> dict:
        with database(settings.database_path) as db:
            cursor = db.execute("UPDATE institutions SET disabled = 1 WHERE id = ?", (institution_id,))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Institution not found")
        return {"institution_id": institution_id, "disabled": True}

    @app.post("/admin/institutions/{institution_id}/enable", dependencies=[Depends(require_admin)])
    def enable_institution(institution_id: str) -> dict:
        with database(settings.database_path) as db:
            cursor = db.execute("UPDATE institutions SET disabled = 0 WHERE id = ?", (institution_id,))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Institution not found")
        return {"institution_id": institution_id, "disabled": False}

    @app.post("/admin/institutions/{institution_id}/keys/{key_version}/revoke", dependencies=[Depends(require_admin)])
    def revoke_key(institution_id: str, key_version: str) -> dict:
        now = int(datetime.now(timezone.utc).timestamp())
        with database(settings.database_path) as db:
            cursor = db.execute(
                "UPDATE signing_keys SET active = 0, revoked_at = ? WHERE institution_id = ? AND version = ? AND revoked_at IS NULL",
                (now, institution_id, key_version),
            )
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Active key not found")
        return {"institution_id": institution_id, "key_version": key_version, "revoked": True}

    @app.post("/institutions/{institution_id}/qrs", status_code=201)
    def issue_qr(
        institution_id: str,
        request: IssueInput,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> dict:
        require_issuer(institution_id, credentials)
        now = int(datetime.now(timezone.utc).timestamp())
        if request.expires_at.tzinfo is None:
            raise HTTPException(status_code=422, detail="expires_at must include a timezone")
        expires_at = int(request.expires_at.timestamp())
        if not now < expires_at <= now + 30 * 86400:
            raise HTTPException(status_code=422, detail="Expiry must be within the next 30 days")
        with database(settings.database_path) as db:
            institution = db.execute("SELECT official_domains FROM institutions WHERE id = ?", (institution_id,)).fetchone()
            key_row = db.execute(
                "SELECT version, public_key FROM signing_keys WHERE institution_id = ? AND active = 1 AND revoked_at IS NULL",
                (institution_id,),
            ).fetchone()
            if institution is None or key_row is None:
                raise HTTPException(status_code=404, detail="Institution or signing key not found")
            if _destination_host(request.destination, json.loads(institution["official_domains"])) is None:
                raise HTTPException(status_code=422, detail="Destination must be HTTPS on an official domain")
            key_path = _key_path(settings, institution_id, key_row["version"])
            try:
                private_key = load_private_key(key_path)
            except (OSError, ValueError) as exc:
                raise HTTPException(status_code=503, detail="Signing key unavailable") from exc
            public_key = private_key.public_key().public_bytes_raw()
            if not secrets.compare_digest(public_key, b64url_decode(key_row["public_key"])):
                raise HTTPException(status_code=503, detail="Signing key does not match registered public key")
            qr_id = str(uuid4())
            payload = {
                "version": 1,
                "qr_id": qr_id,
                "institution_id": institution_id,
                "key_version": key_row["version"],
                "destination": request.destination,
                "purpose": request.purpose,
                "issued_at": now,
                "expires_at": expires_at,
            }
            raw = canonical_bytes(payload)
            qr_text = make_qr(payload, private_key)
            if len(qr_text) > 1200:
                raise HTTPException(status_code=422, detail="Signed QR is too long; shorten destination or purpose")
            result = {"qr_id": qr_id, "qr_text": qr_text, "expires_at": expires_at}
            if request.include_png:
                image = qrcode.make(qr_text, error_correction=qrcode.constants.ERROR_CORRECT_M)
                buffer = BytesIO()
                image.save(buffer, format="PNG")
                result["qr_png_base64"] = base64.b64encode(buffer.getvalue()).decode("ascii")
            db.execute(
                "INSERT INTO issued_qrs (qr_id, institution_id, payload_hash) VALUES (?, ?, ?)",
                (qr_id, institution_id, hashlib.sha256(raw).hexdigest()),
            )
            db.execute(
                "INSERT INTO audit_events (institution_id, qr_id, action, occurred_at) VALUES (?, ?, 'issued', ?)",
                (institution_id, qr_id, now),
            )
        return result

    @app.post("/institutions/{institution_id}/qrs/{qr_id}/revoke")
    def revoke_qr(
        institution_id: str,
        qr_id: str,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> dict:
        require_issuer(institution_id, credentials)
        now = int(datetime.now(timezone.utc).timestamp())
        with database(settings.database_path) as db:
            row = db.execute("SELECT revoked_at FROM issued_qrs WHERE qr_id = ? AND institution_id = ?", (qr_id, institution_id)).fetchone()
            if row is None:
                raise HTTPException(status_code=404, detail="QR not found")
            if row["revoked_at"] is None:
                db.execute("UPDATE issued_qrs SET revoked_at = ? WHERE qr_id = ?", (now, qr_id))
                db.execute(
                    "INSERT INTO audit_events (institution_id, qr_id, action, occurred_at) VALUES (?, ?, 'revoked', ?)",
                    (institution_id, qr_id, now),
                )
        return {"qr_id": qr_id, "revoked": True}

    @app.post("/verify")
    def verify_qr(request: VerifyInput) -> dict:
        try:
            payload, raw, signature = parse_qr(request.qr_text)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            return _result("blocked", "invalid_format")
        with database(settings.database_path) as db:
            row = db.execute(
                "SELECT i.name, i.official_domains, i.disabled, k.public_key, k.revoked_at FROM institutions i "
                "JOIN signing_keys k ON k.institution_id = i.id "
                "WHERE i.id = ? AND k.version = ?",
                (payload["institution_id"], payload["key_version"]),
            ).fetchone()
            if row is None:
                return _result("blocked", "unknown_issuer")
            if row["disabled"]:
                return _result("blocked", "issuer_disabled")
            if row["revoked_at"] is not None:
                return _result("blocked", "key_revoked")
            try:
                Ed25519PublicKey.from_public_bytes(b64url_decode(row["public_key"])).verify(signature, raw)
            except (InvalidSignature, ValueError):
                return _result("blocked", "invalid_signature")
            if _destination_host(payload["destination"], json.loads(row["official_domains"])) is None:
                return _result("blocked", "destination_policy")
            issued = db.execute(
                "SELECT payload_hash, revoked_at FROM issued_qrs WHERE qr_id = ? AND institution_id = ?",
                (payload["qr_id"], payload["institution_id"]),
            ).fetchone()
            if issued is None or not secrets.compare_digest(issued["payload_hash"], hashlib.sha256(raw).hexdigest()):
                return _result("blocked", "unknown_qr")
            if issued["revoked_at"] is not None:
                return _result("blocked", "revoked")
        now = int(datetime.now(timezone.utc).timestamp())
        if payload["issued_at"] > now + 60 or payload["expires_at"] <= now or payload["expires_at"] <= payload["issued_at"]:
            return _result("blocked", "expired_or_invalid_time")
        return _result(
            "trusted", "valid_signature", institution_name=row["name"],
            destination=payload["destination"], purpose=payload["purpose"],
            expires_at=payload["expires_at"], qr_id=payload["qr_id"],
        )

    @app.post("/analyze")
    def analyze_qr(request: AnalyzeInput) -> dict:
        with database(settings.database_path) as db:
            rows = db.execute("SELECT official_domains FROM institutions WHERE disabled = 0").fetchall()
        domains = sorted({domain for row in rows for domain in json.loads(row["official_domains"])})
        return analyze_url(request.qr_text, domains)

    frontend_dist = Path(os.getenv("ONJEON_FRONTEND_DIST", str(Path(__file__).resolve().parents[2] / "frontend" / "dist")))
    if frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="web")
    return app


def create_default_app() -> FastAPI:
    return create_app()
