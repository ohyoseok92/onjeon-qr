"""Protected issuer API and read-only citizen verification API."""

import asyncio
import base64
import hashlib
import hmac
import ipaddress
import json
import logging
import os
import re
import secrets
import sqlite3
import ssl
import threading
import time
import unicodedata
from io import BytesIO
from contextlib import asynccontextmanager, suppress
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit
from uuid import uuid4

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from fastapi import Depends, FastAPI, HTTPException, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from starlette.concurrency import run_in_threadpool
import qrcode

from .crypto import b64url_decode, b64url_encode, canonical_bytes, load_private_key, make_qr, parse_qr
from .analyzer import analyze_url, tls_configuration_status
from .storage import consume_rate_limit, database, initialize, load_rate_key, maintenance, record_security_event, security_event_summary


DOMAIN_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")
ID_RE = r"^[a-z0-9][a-z0-9-]{1,39}$"
KEY_RE = r"^[a-zA-Z0-9_-]{1,32}$"
bearer = HTTPBearer(auto_error=False)
logger = logging.getLogger("onjeon.security")
MAINTENANCE_INTERVAL_SECONDS = 60
TLS_HEALTH_CACHE_SECONDS = 5


def _production_secret_is_valid(value: str) -> bool:
    if len(value) < 32 or len(set(value)) < 8:
        return False
    lowered = value.lower()
    if any(marker in lowered for marker in ("demo", "test", "changeme", "default", "password")):
        return False
    return not any(value == (value[:width] * ((len(value) + width - 1) // width))[:len(value)]
                   for width in range(1, 17))


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
    # Issuer credentials are random 256-bit tokens, not human-chosen passwords.
    salt = secrets.token_hex(32)
    digest = hashlib.sha256(bytes.fromhex(salt) + value.encode("utf-8")).hexdigest()
    return f"sha256${salt}${digest}"


def _verify_token(value: str, stored_hash: str, *, allow_legacy: bool = True) -> bool:
    if not isinstance(stored_hash, str):
        return False
    try:
        if re.fullmatch(r"[0-9a-f]{64}", stored_hash):
            if not allow_legacy:
                return False
            # Preserve existing issued credentials until their next rotation.
            digest = hashlib.sha256(value.encode("utf-8")).hexdigest()
            return secrets.compare_digest(digest, stored_hash)
        match = re.fullmatch(r"sha256\$([0-9a-f]{32}|[0-9a-f]{64})\$([0-9a-f]{64})", stored_hash)
        if match is None:
            return False
        salt, expected = match.groups()
        if not allow_legacy and len(salt) != 64:
            return False
        digest = hashlib.sha256(bytes.fromhex(salt) + value.encode("utf-8")).hexdigest()
        return secrets.compare_digest(digest, expected)
    except UnicodeEncodeError:
        return False


def _key_path(settings: Settings, institution_id: str, key_version: str, *, allow_legacy: bool = True) -> Path:
    nested = settings.key_directory / institution_id / f"{key_version}.pem"
    if nested.is_file() or not allow_legacy:
        return nested
    return settings.key_directory / f"{institution_id}-{key_version}.pem"  # legacy local keys


def _result(status: str, reason: str, **data) -> dict:
    return {"status": status, "reason": reason, **data}


def _audit_admin(db: sqlite3.Connection, institution_id: str, action: str) -> None:
    # Record the operation in the state-changing transaction, without secret material.
    db.execute(
        "INSERT INTO audit_events (institution_id, qr_id, action, occurred_at) VALUES (?, NULL, ?, ?)",
        (institution_id, action, int(datetime.now(timezone.utc).timestamp())),
    )


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or Settings.from_environment()
    if len(settings.admin_token) < 32:
        raise RuntimeError("Admin token must contain at least 32 characters")
    initialize(settings.database_path)
    production = os.getenv("ONJEON_ENV") == "production"
    if production and len(os.getenv("ONJEON_KEY_PASSWORD", "")) < 32:
        raise RuntimeError("Production requires ONJEON_KEY_PASSWORD with at least 32 characters")
    if production and (not _production_secret_is_valid(settings.admin_token)
                       or not _production_secret_is_valid(os.getenv("ONJEON_KEY_PASSWORD", ""))):
        raise RuntimeError("Production requires randomly generated secrets without placeholder or repeated patterns")
    if production:
        tls_state = tls_configuration_status()  # Malformed configuration still prevents startup.
        if not tls_state["available"]:
            logger.error("TLS_ANALYSIS_UNAVAILABLE")
    rate_key = load_rate_key(settings.database_path)
    @asynccontextmanager
    async def lifespan(application: FastAPI):
        async def cleanup():
            while True:
                await asyncio.sleep(MAINTENANCE_INTERVAL_SECONDS)
                try:
                    await run_in_threadpool(maintenance, settings.database_path, int(time.time()))
                except (sqlite3.Error, OSError):
                    logger.error("SECURITY_MAINTENANCE_FAILED")
        task = asyncio.create_task(cleanup())
        try:
            yield
        finally:
            task.cancel()
            with suppress(asyncio.CancelledError):
                await task
    app = FastAPI(
        title="온전 QR", version="0.1.0",
        lifespan=lifespan,
        docs_url=None if production else "/docs",
        redoc_url=None if production else "/redoc",
        openapi_url=None if production else "/openapi.json",
    )
    rate_lock = threading.Lock()
    body_slots = threading.BoundedSemaphore(32)
    authentication_slots = {role: threading.BoundedSemaphore(8) for role in ("admin", "issuer")}
    tls_health_lock = threading.Lock()
    tls_health_state = tls_state if production else {"available": True, "reason": "ready"}
    tls_health_checked_at = time.monotonic()
    audit_source_key = secrets.token_bytes(32)
    audit_failure_last_logged = [float("-inf")]

    @app.exception_handler(RequestValidationError)
    async def validation_error(request: Request, exc: RequestValidationError):
        # Validation errors must not echo a scanned URL, QR payload, or supplied credentials.
        return JSONResponse({"detail": [{"loc": error["loc"], "type": error["type"], "msg": "Invalid value"} for error in exc.errors()]}, status_code=422)

    async def protected_request(request: Request, call_next):
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
            authentication_failure = None
            if group in ("admin", "issuer"):
                admission = authentication_slots[group]
                if not admission.acquire(blocking=False):
                    return JSONResponse({"detail": "Authentication checks busy"}, status_code=429)
                # Unauthenticated traffic has its own bounded lane and cannot
                # consume a legitimate operator's quota behind a shared proxy.
                scheme, _, supplied = request.headers.get("authorization", "").partition(" ")
                credentials = HTTPAuthorizationCredentials(scheme=scheme, credentials=supplied) if scheme.lower() == "bearer" and supplied else None
                try:
                    if group == "admin":
                        require_admin(credentials)
                    else:
                        match = re.match(r"/institutions/([a-z0-9][a-z0-9-]{1,39})(?:/|$)", path)
                        def check_issuer():
                            with database(settings.database_path, write=False) as db:
                                require_issuer(db, match[1] if match else "", credentials)
                        await run_in_threadpool(check_issuer)
                except HTTPException as exc:
                    authentication_failure = JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
                    group += "_auth"
                finally:
                    admission.release()
            address = request.client.host if request.client else "unknown"
            try:
                parsed_address = ipaddress.ip_address(address)
                if parsed_address.version == 6:
                    address = str(ipaddress.ip_network(f"{parsed_address}/64", strict=False))
            except ValueError:
                pass
            limit = {"analyze": 10, "verify": 60, "issuer": 30, "admin": 30,
                     "admin_auth": 30, "issuer_auth": 30}[group]
            try:
                allowed = await run_in_threadpool(consume_rate_limit, settings.database_path, rate_key,
                                                group, address, int(time.time()), limit)
            except (sqlite3.Error, OSError):
                logger.error("RATE_LIMIT_STORAGE_UNAVAILABLE")
                return JSONResponse({"detail": "Rate limiter unavailable"}, status_code=429)
            if not allowed:
                return JSONResponse({"detail": "Too many requests"}, status_code=429)
            if authentication_failure is not None:
                return authentication_failure
            # Limit slow uploads before allocating a reader; never block an event loop on a slot.
            if not body_slots.acquire(blocking=False):
                return JSONResponse({"detail": "Request readers busy"}, status_code=429)
            try:
                chunks = []
                body_size = 0
                try:
                    async with asyncio.timeout(5):
                        async for chunk in request.stream():
                            body_size += len(chunk)
                            if body_size > 16384:
                                return JSONResponse({"detail": "Request too large"}, status_code=413)
                            chunks.append(chunk)
                except TimeoutError:
                    return JSONResponse({"detail": "Request body timeout"}, status_code=408)
                if body_size != content_length:
                    return JSONResponse({"detail": "Content-Length does not match request body"}, status_code=400)
                request._body = b"".join(chunks)
            finally:
                body_slots.release()
        return await call_next(request)

    @app.middleware("http")
    async def disable_cache(request: Request, call_next):
        try:
            response = await protected_request(request, call_next)
        except Exception:
            # The HTTP response must never contain database paths or exception details.
            logger.error("REQUEST_INTERNAL_ERROR")
            response = JSONResponse({"detail": "Internal server error"}, status_code=500)
        path = request.url.path
        actor_role = "admin" if path.startswith("/admin/") else ("issuer" if path.startswith("/institutions/") else None)
        if actor_role and response.status_code in (401, 403, 429):
            now = int(time.time())
            address = request.client.host if request.client else "unknown"
            try:
                parsed = ipaddress.ip_address(address)
                address = str(ipaddress.ip_network(f"{parsed}/64", strict=False)) if parsed.version == 6 else str(parsed)
            except ValueError:
                address = "unknown"
            # Different days and application processes cannot correlate this identifier.
            source = hmac.new(audit_source_key, f"{now // 86400}:{address}".encode("ascii"), hashlib.sha256).hexdigest()[:32]
            match = re.match(r"/(?:admin/)?institutions/([a-z0-9][a-z0-9-]{1,39})(?:/|$)", path)
            try:
                await run_in_threadpool(
                    record_security_event, settings.database_path, actor_role=actor_role,
                    institution_id=match[1] if match else None,
                    event_type="rate_limited" if response.status_code == 429 else "authentication_failed",
                    status_code=response.status_code, anonymous_source=source, now=now,
                )
            except (sqlite3.Error, OSError):
                # Denial remains effective; a fixed, throttled signal alerts the operator.
                with rate_lock:
                    monotonic_now = time.monotonic()
                    if monotonic_now - audit_failure_last_logged[0] >= 60:
                        logger.error("SECURITY_AUDIT_WRITE_FAILED")
                        audit_failure_last_logged[0] = monotonic_now
        response.headers["Cache-Control"] = "no-store"
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = "camera=(self)"
        if production:
            response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if request.url.path not in ("/docs", "/redoc"):
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; img-src 'self' data:; connect-src 'self'; "
                "media-src 'self' blob:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'"
            )
        return response

    def require_admin(credentials: HTTPAuthorizationCredentials | None = Depends(bearer)) -> None:
        if not secrets.compare_digest(_token(credentials).encode("utf-8"), settings.admin_token.encode("utf-8")):
            raise HTTPException(status_code=403, detail="Not authorized")

    def require_issuer(db: sqlite3.Connection, institution_id: str, credentials: HTTPAuthorizationCredentials | None):
        supplied_token = _token(credentials)
        institution = db.execute("SELECT * FROM institutions WHERE id = ?", (institution_id,)).fetchone()
        if institution is None or institution["disabled"] or not _verify_token(supplied_token, institution["issuer_token_hash"], allow_legacy=not production):
            raise HTTPException(status_code=403, detail="Not authorized for institution")
        return institution

    @app.get("/health")
    def health() -> dict:
        nonlocal tls_health_state, tls_health_checked_at
        if not production:
            return {"status": "ok"}
        with tls_health_lock:
            now = time.monotonic()
            if now < tls_health_checked_at or now - tls_health_checked_at >= TLS_HEALTH_CACHE_SECONDS:
                try:
                    tls_health_state = tls_configuration_status()
                except (ssl.SSLError, OSError):
                    tls_health_state = {"available": False, "reason": "crl_configuration_invalid"}
                tls_health_checked_at = now
            state = dict(tls_health_state)
        return {"status": "ok" if state["available"] else "degraded", "url_analysis": state}

    @app.get("/admin/security-events", dependencies=[Depends(require_admin)])
    def get_security_events() -> dict:
        return {"events": security_event_summary(settings.database_path, int(time.time())),
                "retention_days": 7, "maximum_rows": 10000}

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
            _audit_admin(db, request.institution_id, "registered")
        return {"institution_id": request.institution_id, "issuer_token": issuer_token}

    @app.post("/admin/institutions/{institution_id}/keys", status_code=201, dependencies=[Depends(require_admin)])
    def rotate_key(institution_id: str, request: KeyInput) -> dict:
        if not re.fullmatch(ID_RE, institution_id):
            raise HTTPException(status_code=422, detail="Invalid institution ID")
        public_key = b64url_encode(_public_key_bytes(request.public_key))
        key_path = _key_path(settings, institution_id, request.key_version, allow_legacy=not production)
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
            _audit_admin(db, institution_id, "key_rotated")
        return {"institution_id": institution_id, "active_key_version": request.key_version}

    @app.post("/admin/institutions/{institution_id}/token", dependencies=[Depends(require_admin)])
    def rotate_issuer_token(institution_id: str) -> dict:
        token = secrets.token_urlsafe(32)
        with database(settings.database_path) as db:
            cursor = db.execute("UPDATE institutions SET issuer_token_hash = ? WHERE id = ?", (_hash_token(token), institution_id))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Institution not found")
            _audit_admin(db, institution_id, "token_rotated")
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
                private_key = load_private_key(_key_path(settings, institution_id, key_version, allow_legacy=not production))
                if not secrets.compare_digest(private_key.public_key().public_bytes_raw(), b64url_decode(row["public_key"])):
                    raise ValueError("Public key mismatch")
            except (OSError, ValueError) as exc:
                raise HTTPException(status_code=422, detail="Matching signing key unavailable") from exc
            db.execute("UPDATE signing_keys SET active = 0 WHERE institution_id = ?", (institution_id,))
            db.execute(
                "UPDATE signing_keys SET active = 1 WHERE institution_id = ? AND version = ?",
                (institution_id, key_version),
            )
            _audit_admin(db, institution_id, "key_activated")
        return {"institution_id": institution_id, "active_key_version": key_version}

    @app.post("/admin/institutions/{institution_id}/disable", dependencies=[Depends(require_admin)])
    def disable_institution(institution_id: str) -> dict:
        with database(settings.database_path) as db:
            cursor = db.execute("UPDATE institutions SET disabled = 1 WHERE id = ?", (institution_id,))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Institution not found")
            _audit_admin(db, institution_id, "institution_disabled")
        return {"institution_id": institution_id, "disabled": True}

    @app.post("/admin/institutions/{institution_id}/enable", dependencies=[Depends(require_admin)])
    def enable_institution(institution_id: str) -> dict:
        with database(settings.database_path) as db:
            cursor = db.execute("UPDATE institutions SET disabled = 0 WHERE id = ?", (institution_id,))
            if cursor.rowcount == 0:
                raise HTTPException(status_code=404, detail="Institution not found")
            _audit_admin(db, institution_id, "institution_enabled")
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
            _audit_admin(db, institution_id, "key_revoked")
        return {"institution_id": institution_id, "key_version": key_version, "revoked": True}

    @app.post("/institutions/{institution_id}/qrs", status_code=201)
    def issue_qr(
        institution_id: str,
        request: IssueInput,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> dict:
        now = int(datetime.now(timezone.utc).timestamp())
        if request.expires_at.tzinfo is None:
            raise HTTPException(status_code=422, detail="expires_at must include a timezone")
        expires_at = int(request.expires_at.timestamp())
        if not now < expires_at <= now + 30 * 86400:
            raise HTTPException(status_code=422, detail="Expiry must be within the next 30 days")
        with database(settings.database_path) as db:
            institution = require_issuer(db, institution_id, credentials)
            key_row = db.execute(
                "SELECT version, public_key FROM signing_keys WHERE institution_id = ? AND active = 1 AND revoked_at IS NULL",
                (institution_id,),
            ).fetchone()
            if institution is None or key_row is None:
                raise HTTPException(status_code=404, detail="Institution or signing key not found")
            if _destination_host(request.destination, json.loads(institution["official_domains"])) is None:
                raise HTTPException(status_code=422, detail="Destination must be HTTPS on an official domain")
            key_path = _key_path(settings, institution_id, key_row["version"], allow_legacy=not production)
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
                "INSERT INTO issued_qrs (qr_id, institution_id, payload_hash, purpose, issued_at, expires_at, key_version) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (qr_id, institution_id, hashlib.sha256(raw).hexdigest(), request.purpose, now, expires_at, key_row["version"]),
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
        now = int(datetime.now(timezone.utc).timestamp())
        with database(settings.database_path) as db:
            require_issuer(db, institution_id, credentials)
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

    @app.get("/institutions/{institution_id}/dashboard")
    def institution_dashboard(
        institution_id: str,
        credentials: HTTPAuthorizationCredentials | None = Depends(bearer),
    ) -> dict:
        now = int(datetime.now(timezone.utc).timestamp())
        # Authorization, counts, and displayed rows all use the same database snapshot.
        with database(settings.database_path, write=False) as db:
            institution = require_issuer(db, institution_id, credentials)
            active_key = db.execute(
                "SELECT version FROM signing_keys WHERE institution_id = ? AND active = 1 AND revoked_at IS NULL",
                (institution_id,),
            ).fetchone()
            qr_rows = db.execute(
                "SELECT q.qr_id, q.purpose, q.issued_at, q.expires_at, q.key_version, q.revoked_at, "
                "CASE WHEN q.revoked_at IS NOT NULL OR k.revoked_at IS NOT NULL THEN 'revoked' "
                "WHEN q.expires_at IS NOT NULL AND q.expires_at <= ? THEN 'expired' "
                "WHEN q.issued_at IS NULL OR q.expires_at IS NULL OR q.key_version IS NULL THEN 'legacy' "
                "ELSE 'active' END AS status FROM issued_qrs q LEFT JOIN signing_keys k "
                "ON k.institution_id = q.institution_id AND k.version = q.key_version "
                "WHERE q.institution_id = ? ORDER BY q.issued_at DESC, q.qr_id DESC LIMIT 100",
                (now, institution_id),
            ).fetchall()
            count_rows = db.execute(
                "SELECT CASE WHEN q.revoked_at IS NOT NULL OR k.revoked_at IS NOT NULL THEN 'revoked' "
                "WHEN q.expires_at IS NOT NULL AND q.expires_at <= ? THEN 'expired' "
                "WHEN q.issued_at IS NULL OR q.expires_at IS NULL OR q.key_version IS NULL THEN 'legacy' "
                "ELSE 'active' END AS status, COUNT(*) AS count FROM issued_qrs q LEFT JOIN signing_keys k "
                "ON k.institution_id = q.institution_id AND k.version = q.key_version "
                "WHERE q.institution_id = ? GROUP BY status",
                (now, institution_id),
            ).fetchall()
            audit_rows = db.execute(
                "SELECT id, qr_id, action, occurred_at FROM audit_events WHERE institution_id = ? "
                "ORDER BY id DESC LIMIT 100",
                (institution_id,),
            ).fetchall()
        counts = {"active": 0, "revoked": 0, "expired": 0, "total": 0}
        for row in count_rows:
            counts["total"] += row["count"]
            if row["status"] in counts:
                counts[row["status"]] = row["count"]
        return {
            "institution": {
                "id": institution["id"], "name": institution["name"],
                "official_domains": json.loads(institution["official_domains"]),
                "active_key_version": active_key["version"] if active_key else None,
            },
            "qrs": [dict(row) for row in qr_rows],
            "audit": [dict(row) for row in audit_rows],
            "counts": counts,
        }

    @app.post("/verify")
    def verify_qr(request: VerifyInput) -> dict:
        try:
            payload, raw, signature = parse_qr(request.qr_text)
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError, RecursionError):
            return _result("blocked", "invalid_format")
        with database(settings.database_path, write=False) as db:
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
        with database(settings.database_path, write=False) as db:
            rows = db.execute("SELECT official_domains FROM institutions WHERE disabled = 0").fetchall()
        domains = sorted({domain for row in rows for domain in json.loads(row["official_domains"])})
        return analyze_url(request.qr_text, domains)

    frontend_dist = Path(os.getenv("ONJEON_FRONTEND_DIST", str(Path(__file__).resolve().parents[2] / "frontend" / "dist")))
    if frontend_dist.is_dir():
        app.mount("/", StaticFiles(directory=frontend_dist, html=True), name="web")
    return app


def create_default_app() -> FastAPI:
    return create_app()
