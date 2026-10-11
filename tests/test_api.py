import asyncio
import base64
import hashlib
import json
import secrets
import sqlite3
import ssl
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from onjeon.api import Settings, _hash_token, _verify_token, create_app
from onjeon.crypto import b64url_encode, canonical_bytes, create_private_key, load_private_key, make_qr, parse_qr


def configure_production_crl(tmp_path, monkeypatch):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    now = datetime.now(timezone.utc)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Synthetic API CRL issuer")])
    crl = (x509.CertificateRevocationListBuilder().issuer_name(name).last_update(now - timedelta(minutes=1))
           .next_update(now + timedelta(days=1)).sign(key, hashes.SHA256()))
    path = tmp_path / "synthetic-crl.pem"
    path.write_bytes(crl.public_bytes(serialization.Encoding.PEM))
    monkeypatch.setenv("ONJEON_TLS_CRL_BUNDLE", str(path))


@pytest.fixture
def setup(tmp_path):
    settings = Settings(tmp_path / "data.sqlite3", tmp_path / "keys", "a" * 40)
    public_key = create_private_key(settings.key_directory / "city-v1.pem")
    client = TestClient(create_app(settings))
    response = client.post(
        "/admin/institutions",
        headers={"Authorization": "Bearer " + settings.admin_token},
        json={
            "institution_id": "city",
            "name": "시험 시청",
            "official_domains": ["city.example.org"],
            "key_version": "v1",
            "public_key": public_key,
        },
    )
    assert response.status_code == 201, response.text
    token = response.json()["issuer_token"]
    return client, settings, token


def issue(client, token, destination="https://city.example.org/pay", days=1):
    return client.post(
        "/institutions/city/qrs",
        headers={"Authorization": "Bearer " + token},
        json={
            "destination": destination,
            "purpose": "주차요금 안내",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=days)).isoformat(),
        },
    )


def test_security_failure_audit_is_private_bounded_and_admin_only(setup, monkeypatch):
    client, settings, token = setup
    secret = "secret-bearer-that-must-not-be-logged"
    assert client.get("/institutions/city/dashboard").status_code == 401
    assert client.get("/institutions/city/dashboard", headers={"Authorization": "Bearer " + secret}).status_code == 403
    assert client.get("/institutions/other-city/dashboard", headers={"Authorization": "Bearer " + token}).status_code == 403
    assert client.get("/admin/security-events", headers={"Authorization": "Bearer " + token}).status_code == 403
    # Unicode credentials must produce an ordinary denial, not a compare_digest TypeError.
    assert client.get("/admin/security-events", headers={"Authorization": b"Bearer " + "틀린토큰".encode()}).status_code == 403
    admin_headers = {"Authorization": "Bearer " + settings.admin_token}
    result = client.get("/admin/security-events", headers=admin_headers)
    assert result.status_code == 200
    events = result.json()["events"]
    assert {row["status_code"] for row in events} == {401, 403}
    assert any(row["institution_id"] == "city" for row in events)
    assert any(row["institution_id"] is None for row in events)
    assert all(len(row["anonymous_source"]) == 32 for row in events)
    with sqlite3.connect(settings.database_path) as db:
        stored = str(db.execute("SELECT * FROM security_events").fetchall())
    for value in (secret, token, settings.admin_token, "other-city", "testclient"):
        assert value not in stored
    assert "security_events" not in client.get("/institutions/city/dashboard", headers={"Authorization": "Bearer " + token}).text
    # Public citizen checks create no persistent security event.
    before = len(events)
    client.post("/verify", json={"qr_text": "https://private.example.test/scan"})
    assert len(client.get("/admin/security-events", headers=admin_headers).json()["events"]) == before


def test_failure_audit_aggregates_and_changes_source_each_day(setup, monkeypatch):
    client, settings, _ = setup
    current = [1800000000]
    monkeypatch.setattr("onjeon.api.time.time", lambda: current[0])
    for _ in range(3):
        assert client.get("/institutions/city/dashboard").status_code == 401
    with sqlite3.connect(settings.database_path) as db:
        first = db.execute("SELECT anonymous_source, attempt_count FROM security_events").fetchone()
    assert first[1] == 3
    current[0] += 86400
    assert client.get("/institutions/city/dashboard").status_code == 401
    with sqlite3.connect(settings.database_path) as db:
        rows = db.execute("SELECT anonymous_source FROM security_events").fetchall()
    assert len(rows) == 2 and rows[0] != rows[1]


def test_issuer_rate_limit_is_audited_and_audit_failure_preserves_denial(setup, monkeypatch, caplog):
    client, settings, _ = setup
    for _ in range(30):
        assert client.get("/institutions/city/dashboard").status_code == 401
    assert client.get("/institutions/city/dashboard").status_code == 429
    with sqlite3.connect(settings.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM security_events WHERE event_type = 'rate_limited'").fetchone()[0] == 1
    def unavailable(*args, **kwargs):
        raise sqlite3.OperationalError("secret-connection-path")
    monkeypatch.setattr("onjeon.api.record_security_event", unavailable)
    denied = client.get("/institutions/city/dashboard")
    assert denied.status_code == 429
    assert denied.headers["Cache-Control"] == "no-store"
    assert "SECURITY_AUDIT_WRITE_FAILED" in caplog.text
    assert "secret-connection-path" not in caplog.text + denied.text


async def asgi_request(app, receive, *, address="192.0.2.200", body_length=1):
    messages = []
    async def send(message):
        messages.append(message)
    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"},
             "http_version": "1.1", "method": "POST", "scheme": "http", "path": "/verify",
             "raw_path": b"/verify", "query_string": b"", "root_path": "",
             "headers": [(b"content-length", str(body_length).encode()), (b"content-type", b"application/json")],
             "client": (address, 1234), "server": ("testserver", 80)}
    await app(scope, receive, send)
    return next(message for message in messages if message["type"] == "http.response.start")


def test_slow_asgi_body_times_out_with_security_headers_and_cancels_receive(setup):
    client, _, _ = setup
    async def scenario():
        cancelled = [False]
        calls = [0]
        async def receive():
            calls[0] += 1
            if calls[0] == 1:
                return {"type": "http.request", "body": b"x", "more_body": True}
            try:
                await asyncio.sleep(6)
            finally:
                cancelled[0] = True
            return {"type": "http.request", "body": b"x", "more_body": False}
        started = asyncio.get_running_loop().time()
        response = await asgi_request(client.app, receive, body_length=2)
        elapsed = asyncio.get_running_loop().time() - started
        assert response["status"] == 408
        assert 4.5 <= elapsed < 6
        assert cancelled[0]
        headers = dict(response["headers"])
        assert headers[b"cache-control"] == b"no-store"
        assert b"form-action 'self'" in headers[b"content-security-policy"]
    asyncio.run(scenario())


def test_asgi_body_readers_are_bounded_and_slots_released(setup):
    client, _, _ = setup
    body = b'{"qr_text":"invalid"}'
    async def scenario():
        gate, ready = asyncio.Event(), asyncio.Event()
        waiting = [0]
        def reader():
            async def receive():
                waiting[0] += 1
                if waiting[0] == 32:
                    ready.set()
                await gate.wait()
                return {"type": "http.request", "body": body, "more_body": False}
            return receive
        tasks = [asyncio.create_task(asgi_request(client.app, reader(), address=f"192.0.2.{index + 1}",
                                                body_length=len(body))) for index in range(32)]
        async def forbidden_receive():
            raise AssertionError("An exhausted reader pool must reject before reading the body")
        try:
            await asyncio.wait_for(ready.wait(), 2)
            overloaded = await asgi_request(client.app, forbidden_receive, address="192.0.2.100", body_length=len(body))
            assert overloaded["status"] == 429
            assert dict(overloaded["headers"])[b"cache-control"] == b"no-store"
        finally:
            gate.set()
            results = await asyncio.gather(*tasks)
        assert all(result["status"] == 200 for result in results)
        async def valid_receive():
            return {"type": "http.request", "body": body, "more_body": False}
        assert (await asgi_request(client.app, valid_receive, body_length=len(body)))["status"] == 200
    asyncio.run(scenario())


def test_rate_limit_rejects_before_asgi_body_read(setup):
    client, _, _ = setup
    for _ in range(60):
        assert client.post("/verify", json={"qr_text": "invalid"}).status_code == 200
    async def forbidden_receive():
        raise AssertionError("A rate-limited request must not read its body")
    response = asyncio.run(asgi_request(client.app, forbidden_receive, address="testclient"))
    assert response["status"] == 429


def test_issue_verify_revoke_and_no_citizen_history(setup):
    client, settings, token = setup
    issued = issue(client, token)
    assert issued.status_code == 201, issued.text
    qr = issued.json()["qr_text"]
    result = client.post("/verify", json={"qr_text": qr}).json()
    assert result["status"] == "trusted"
    assert result["institution_name"] == "시험 시청"
    assert result["destination"] == "https://city.example.org/pay"
    with sqlite3.connect(settings.database_path) as db:
        assert db.execute("SELECT action FROM audit_events ORDER BY id").fetchall() == [("registered",), ("issued",)]
        assert "city.example.org/pay" not in str(db.execute("SELECT * FROM audit_events").fetchall())
    revoked = client.post(
        "/institutions/city/qrs/" + issued.json()["qr_id"] + "/revoke",
        headers={"Authorization": "Bearer " + token},
    )
    assert revoked.status_code == 200
    assert client.post("/verify", json={"qr_text": qr}).json() == {"status": "blocked", "reason": "revoked"}


def test_tampering_and_unknown_format_are_blocked(setup):
    client, _, token = setup
    qr = issue(client, token).json()["qr_text"]
    payload, _, signature = parse_qr(qr)
    payload["destination"] = "https://evil.example.org/pay"
    tampered = "onqr:v1:" + b64url_encode(canonical_bytes(payload)) + "." + b64url_encode(signature)
    assert client.post("/verify", json={"qr_text": tampered}).json()["reason"] == "invalid_signature"
    assert client.post("/verify", json={"qr_text": "https://city.example.org/pay"}).json()["status"] == "blocked"
    assert client.post("/verify", json={"qr_text": "onqr:v1:A.A"}).json()["status"] == "blocked"


@pytest.mark.parametrize("destination", [
    "http://city.example.org/pay",
    "https://city.example.org.evil.test/pay",
    "https://127.0.0.1/pay",
    "https://city.example.org:8443/pay",
    "https://user@city.example.org/pay",
])
def test_unofficial_destinations_rejected(setup, destination):
    client, _, token = setup
    assert issue(client, token, destination=destination).status_code == 422


def test_issuer_authorization_and_expiry_bounds(setup):
    client, _, token = setup
    assert issue(client, "wrong-token").status_code == 403
    assert issue(client, token, days=31).status_code == 422
    assert issue(client, token, days=-1).status_code == 422


def test_expired_signed_qr_is_blocked(setup):
    client, settings, _ = setup
    now = int(datetime.now(timezone.utc).timestamp())
    payload = {
        "version": 1,
        "qr_id": "expired-test",
        "institution_id": "city",
        "key_version": "v1",
        "destination": "https://city.example.org/pay",
        "purpose": "시험",
        "issued_at": now - 200,
        "expires_at": now - 100,
    }
    qr = make_qr(payload, load_private_key(settings.key_directory / "city-v1.pem"))
    with sqlite3.connect(settings.database_path) as db:
        db.execute(
            "INSERT INTO issued_qrs(qr_id,institution_id,payload_hash) VALUES(?,?,?)",
            (payload["qr_id"], "city", hashlib.sha256(canonical_bytes(payload)).hexdigest()),
        )
    assert client.post("/verify", json={"qr_text": qr}).json() == {
        "status": "blocked", "reason": "expired_or_invalid_time"
    }


def test_key_rotation_keeps_old_qr_verifiable(setup):
    client, settings, token = setup
    old_qr = issue(client, token).json()["qr_text"]
    public_key = create_private_key(settings.key_directory / "city-v2.pem")
    changed = client.post(
        "/admin/institutions/city/keys",
        headers={"Authorization": "Bearer " + settings.admin_token},
        json={"key_version": "v2", "public_key": public_key},
    )
    assert changed.status_code == 201
    new_qr = issue(client, token).json()["qr_text"]
    assert parse_qr(new_qr)[0]["key_version"] == "v2"
    assert client.post("/verify", json={"qr_text": old_qr}).json()["status"] == "trusted"
    assert client.post("/verify", json={"qr_text": new_qr}).json()["status"] == "trusted"


def test_signing_key_mismatch_fails_closed(setup):
    client, settings, token = setup
    replacement = settings.key_directory / "replacement.pem"
    create_private_key(replacement)
    (settings.key_directory / "city-v1.pem").write_bytes(replacement.read_bytes())
    assert issue(client, token).status_code == 503


def test_png_generation_and_url_parser_edge_cases(setup):
    client, _, token = setup
    response = client.post(
        "/institutions/city/qrs",
        headers={"Authorization": "Bearer " + token},
        json={
            "destination": "https://city.example.org/pay",
            "purpose": "주차요금 안내",
            "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
            "include_png": True,
        },
    )
    assert response.status_code == 201, response.text
    assert base64.b64decode(response.json()["qr_png_base64"]).startswith(b"\x89PNG\r\n\x1a\n")
    assert response.headers["Cache-Control"] == "no-store"
    for destination in ("https://city.example.org\\@evil.test", "https://city.example.org/pay\n"):
        assert issue(client, token, destination=destination).status_code == 422
    assert issue(client, token, destination="https://city.example.org/" + "a" * 1800).status_code == 422


def test_api_and_docs_headers(setup):
    client, _, _ = setup
    health = client.get("/health")
    assert health.status_code == 200
    assert "frame-ancestors 'none'" in health.headers["Content-Security-Policy"]
    assert "form-action 'self'" in health.headers["Content-Security-Policy"]
    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "Content-Security-Policy" not in docs.headers


def test_unsigned_analysis_and_public_rate_limit(setup, monkeypatch):
    from onjeon import analyzer, api
    from types import SimpleNamespace

    # Test quota exhaustion within one fixed window, not a wall-clock rollover.
    monkeypatch.setattr(api, "time", SimpleNamespace(time=lambda: 1800000000, monotonic=api.time.monotonic))

    client, settings, _ = setup
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host, **kwargs: "93.184.215.14")
    monkeypatch.setattr(analyzer, "_head", lambda url, host, address, **kwargs: (200, None))
    response = client.post("/analyze", json={"qr_text": "https://city.example.org/pay"})
    assert response.status_code == 200
    assert response.json()["status"] == "warning"
    assert response.json()["host"] == "city.example.org"
    with sqlite3.connect(settings.database_path) as db:
        assert "city.example.org/pay" not in str(db.execute("SELECT * FROM audit_events").fetchall())
    for _ in range(60):
        assert client.post("/verify", json={"qr_text": "invalid"}).status_code == 200
    limited = client.post("/verify", json={"qr_text": "invalid"})
    assert limited.status_code == 429
    assert limited.headers["Cache-Control"] == "no-store"


def test_admin_recovery_controls(setup):
    client, settings, old_token = setup
    admin = {"Authorization": "Bearer " + settings.admin_token}
    qr = issue(client, old_token).json()["qr_text"]
    rotated = client.post("/admin/institutions/city/token", headers=admin)
    assert rotated.status_code == 200
    new_token = rotated.json()["issuer_token"]
    assert issue(client, old_token).status_code == 403
    assert issue(client, new_token).status_code == 201
    public_key = create_private_key(settings.key_directory / "city-v2.pem")
    assert client.post("/admin/institutions/city/keys", headers=admin, json={"key_version": "v2", "public_key": public_key}).status_code == 201
    assert client.post("/admin/institutions/city/keys/v1/activate", headers=admin).status_code == 200
    assert parse_qr(issue(client, new_token).json()["qr_text"])[0]["key_version"] == "v1"
    assert client.post("/admin/institutions/city/keys/v1/revoke", headers=admin).status_code == 200
    assert client.post("/verify", json={"qr_text": qr}).json()["reason"] == "key_revoked"
    assert client.post("/admin/institutions/city/keys/v2/activate", headers=admin).status_code == 200
    assert client.post("/admin/institutions/city/disable", headers=admin).status_code == 200
    assert issue(client, new_token).status_code == 403
    assert client.post("/admin/institutions/city/enable", headers=admin).status_code == 200
    assert issue(client, new_token).status_code == 201


def test_unsafe_display_text_and_missing_key_rejected(setup):
    client, settings, token = setup
    response = client.post(
        "/institutions/city/qrs",
        headers={"Authorization": "Bearer " + token},
        json={"destination": "https://city.example.org/pay", "purpose": "bad\u202etext", "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()},
    )
    assert response.status_code == 422
    missing = client.post(
        "/admin/institutions/city/keys",
        headers={"Authorization": "Bearer " + settings.admin_token},
        json={"key_version": "v2", "public_key": b64url_encode(load_private_key(settings.key_directory / "city-v1.pem").public_key().public_bytes_raw())},
    )
    assert missing.status_code == 422


def test_exact_host_policy_and_request_size(setup):
    client, _, token = setup
    assert issue(client, token, destination="https://sub.city.example.org/pay").status_code == 422
    oversized = client.post("/verify", content=b"x" * 17000, headers={"Content-Type": "application/json"})
    assert oversized.status_code == 413


def test_production_mode_disables_api_docs(tmp_path, monkeypatch):
    configure_production_crl(tmp_path, monkeypatch)
    monkeypatch.setenv("ONJEON_ENV", "production")
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", secrets.token_urlsafe(48))
    client = TestClient(create_app(Settings(tmp_path / "db.sqlite3", tmp_path / "keys", secrets.token_urlsafe(48))))
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/health").headers["Strict-Transport-Security"].startswith("max-age=")


def test_production_requires_key_password(tmp_path, monkeypatch):
    monkeypatch.setenv("ONJEON_ENV", "production")
    monkeypatch.delenv("ONJEON_KEY_PASSWORD", raising=False)
    with pytest.raises(RuntimeError, match="ONJEON_KEY_PASSWORD"):
        create_app(Settings(tmp_path / "db.sqlite3", tmp_path / "keys", "a" * 40))


def test_production_requires_crl_before_serving_requests(tmp_path, monkeypatch):
    monkeypatch.setenv("ONJEON_ENV", "production")
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", secrets.token_urlsafe(48))
    monkeypatch.delenv("ONJEON_TLS_CRL_BUNDLE", raising=False)
    with pytest.raises(ssl.SSLCertVerificationError):
        create_app(Settings(tmp_path / "db.sqlite3", tmp_path / "keys", secrets.token_urlsafe(48)))


@pytest.mark.parametrize("weak", ["a" * 64, "abcd1234" * 8, "changeme-admin-token-" * 4,
                                  "demo-production-token-" * 3, "test-admin-token-" * 4,
                                  "default-admin-token-" * 3, "password-for-production-" * 3])
def test_production_rejects_placeholder_or_repeated_secrets(tmp_path, monkeypatch, weak):
    monkeypatch.setenv("ONJEON_ENV", "production")
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", secrets.token_urlsafe(48))
    with pytest.raises(RuntimeError, match="randomly generated"):
        create_app(Settings(tmp_path / "db.sqlite3", tmp_path / "keys", weak))
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", weak)
    with pytest.raises(RuntimeError, match="randomly generated"):
        create_app(Settings(tmp_path / "db.sqlite3", tmp_path / "keys", secrets.token_urlsafe(48)))


@pytest.mark.parametrize("old_salt", [None, "a" * 32])
def test_production_rejects_legacy_issuer_hash_without_replacing_credentials(setup, monkeypatch, old_salt):
    client, settings, token = setup
    stored = hashlib.sha256(token.encode()).hexdigest() if old_salt is None else (
        "sha256$" + old_salt + "$" + hashlib.sha256(bytes.fromhex(old_salt) + token.encode()).hexdigest())
    with sqlite3.connect(settings.database_path) as db:
        db.execute("UPDATE institutions SET issuer_token_hash = ? WHERE id = 'city'", (stored,))
    assert dashboard(client, token).status_code == 200  # Development compatibility remains explicit.
    monkeypatch.setenv("ONJEON_ENV", "production")
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", secrets.token_urlsafe(48))
    configure_production_crl(settings.database_path.parent, monkeypatch)
    admin = secrets.token_urlsafe(48)
    production = TestClient(create_app(Settings(settings.database_path, settings.key_directory, admin)))
    assert dashboard(production, token).status_code == 403
    with sqlite3.connect(settings.database_path) as db:
        assert db.execute("SELECT issuer_token_hash FROM institutions WHERE id = 'city'").fetchone()[0] == stored
    replacement = production.post("/admin/institutions/city/token", headers={"Authorization": "Bearer " + admin})
    assert replacement.status_code == 200
    assert dashboard(production, replacement.json()["issuer_token"]).status_code == 200
    assert dashboard(production, token).status_code == 403


def test_rate_storage_failure_is_closed_and_no_forwarded_header_bypass(setup, monkeypatch, caplog):
    client, _, _ = setup
    for index in range(60):
        assert client.post("/verify", json={"qr_text": "invalid"}, headers={"X-Forwarded-For": f"192.0.2.{index}"}).status_code == 200
    assert client.post("/verify", json={"qr_text": "invalid"}, headers={"X-Forwarded-For": "198.51.100.88"}).status_code == 429
    def broken(*args, **kwargs):
        raise sqlite3.OperationalError("secret-rate-path")
    monkeypatch.setattr("onjeon.api.consume_rate_limit", broken)
    response = client.post("/verify", json={"qr_text": "invalid"})
    assert response.status_code == 429 and response.headers["Cache-Control"] == "no-store"
    assert "secret-rate-path" not in response.text + caplog.text


def test_idle_lifespan_maintenance_removes_expired_rows(setup, monkeypatch):
    import time
    client, settings, _ = setup
    now = int(time.time())
    with sqlite3.connect(settings.database_path) as db:
        db.execute("INSERT INTO security_events (actor_role,event_type,status_code,anonymous_source,window_started_at,occurred_at) "
                   "VALUES ('admin','authentication_failed',403,'expired',?,?)", (now - 604801, now - 604801))
        db.execute("INSERT INTO rate_counters VALUES ('verify','expired',?,1)", (now - 301,))
    monkeypatch.setattr("onjeon.api.MAINTENANCE_INTERVAL_SECONDS", 0.01)
    async def scenario():
        async with client.app.router.lifespan_context(client.app):
            await asyncio.sleep(0.1)  # No API calls trigger cleanup.
        with sqlite3.connect(settings.database_path) as db:
            assert db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0
            assert db.execute("SELECT COUNT(*) FROM rate_counters WHERE anonymous_source = 'expired'").fetchone()[0] == 0
    asyncio.run(scenario())


def test_configured_frontend_is_served(tmp_path, monkeypatch):
    frontend_dist = tmp_path / "dist"
    frontend_dist.mkdir()
    (frontend_dist / "index.html").write_text("<title>온전 QR</title>", encoding="utf-8")
    monkeypatch.setenv("ONJEON_FRONTEND_DIST", str(frontend_dist))
    client = TestClient(create_app(Settings(tmp_path / "db.sqlite3", tmp_path / "keys", "a" * 40)))
    response = client.get("/")
    assert response.status_code == 200
    assert "온전 QR" in response.text
    assert response.headers["Cache-Control"] == "no-store"


def test_issuer_flood_does_not_exhaust_admin_bucket(setup):
    client, settings, _ = setup
    for _ in range(31):
        client.post("/institutions/city/qrs", headers={"Authorization": "Bearer invalid"}, json={})
    assert client.post("/institutions/city/qrs", headers={"Authorization": "Bearer invalid"}, json={}).status_code == 429
    admin = client.post("/admin/institutions/city/enable", headers={"Authorization": "Bearer " + settings.admin_token})
    assert admin.status_code == 200


def dashboard(client, token, institution_id="city"):
    return client.get(f"/institutions/{institution_id}/dashboard", headers={"Authorization": "Bearer " + token})


def test_dashboard_tracks_issue_revoke_and_preserves_scan_privacy(setup):
    client, settings, token = setup
    issued = issue(client, token).json()
    client.post("/verify", json={"qr_text": issued["qr_text"]})
    response = dashboard(client, token)
    assert response.status_code == 200
    data = response.json()
    assert data["institution"] == {
        "id": "city", "name": "시험 시청", "official_domains": ["city.example.org"], "active_key_version": "v1",
    }
    assert data["counts"] == {"active": 1, "revoked": 0, "expired": 0, "total": 1}
    qr = data["qrs"][0]
    assert qr["qr_id"] == issued["qr_id"]
    assert qr["purpose"] == "주차요금 안내"
    assert qr["key_version"] == "v1" and qr["status"] == "active"
    assert qr["issued_at"] < qr["expires_at"] == issued["expires_at"]
    assert qr["revoked_at"] is None
    assert [entry["action"] for entry in data["audit"]] == ["issued", "registered"]
    assert "/pay" not in response.text and "qr_text" not in response.text
    client.post(f"/institutions/city/qrs/{issued['qr_id']}/revoke", headers={"Authorization": "Bearer " + token})
    updated = dashboard(client, token).json()
    assert updated["qrs"][0]["status"] == "revoked"
    assert updated["counts"] == {"active": 0, "revoked": 1, "expired": 0, "total": 1}
    assert [entry["action"] for entry in updated["audit"]] == ["revoked", "issued", "registered"]
    with sqlite3.connect(settings.database_path) as db:
        assert "/pay" not in str(db.execute("SELECT * FROM issued_qrs").fetchall())


def test_dashboard_and_revoke_enforce_institution_token_isolation(setup):
    client, settings, token = setup
    public_key = create_private_key(settings.key_directory / "other-v1.pem")
    other_token = client.post("/admin/institutions", headers={"Authorization": "Bearer " + settings.admin_token}, json={
        "institution_id": "other", "name": "다른 기관", "official_domains": ["other.example.org"],
        "key_version": "v1", "public_key": public_key,
    }).json()["issuer_token"]
    issued = issue(client, token).json()
    assert client.get("/institutions/city/dashboard").status_code == 401
    assert dashboard(client, other_token).status_code == 403
    assert dashboard(client, token, "other").status_code == 403
    assert dashboard(client, settings.admin_token).status_code == 403
    assert dashboard(client, other_token, "other").json()["counts"]["total"] == 0
    assert client.post(f"/institutions/city/qrs/{issued['qr_id']}/revoke", headers={"Authorization": "Bearer " + other_token}).status_code == 403
    assert client.post(f"/institutions/other/qrs/{issued['qr_id']}/revoke", headers={"Authorization": "Bearer " + other_token}).status_code == 404
    new_token = client.post("/admin/institutions/city/token", headers={"Authorization": "Bearer " + settings.admin_token}).json()["issuer_token"]
    assert dashboard(client, token).status_code == 403
    assert dashboard(client, new_token).status_code == 200
    client.post("/admin/institutions/city/disable", headers={"Authorization": "Bearer " + settings.admin_token})
    assert dashboard(client, new_token).status_code == 403


def test_dashboard_legacy_expired_and_page_bounds(setup):
    client, settings, token = setup
    now = int(datetime.now(timezone.utc).timestamp())
    with sqlite3.connect(settings.database_path) as db:
        db.execute("INSERT INTO issued_qrs(qr_id,institution_id,payload_hash) VALUES('legacy','city','hash')")
        for number in range(105):
            db.execute(
                "INSERT INTO issued_qrs(qr_id,institution_id,payload_hash,purpose,issued_at,expires_at,key_version) VALUES(?,?,?,?,?,?,?)",
                (f"expired-{number}", "city", "hash", "종료된 안내", now - 200, now - 100, "v1"),
            )
            db.execute("INSERT INTO audit_events(institution_id,qr_id,action,occurred_at) VALUES('city',?,'issued',?)", (f"expired-{number}", now - 200))
    data = dashboard(client, token).json()
    assert len(data["qrs"]) == len(data["audit"]) == 100
    assert data["counts"] == {"active": 0, "revoked": 0, "expired": 105, "total": 106}
    with sqlite3.connect(settings.database_path) as db:
        db.execute("DELETE FROM issued_qrs WHERE qr_id <> 'legacy'")
    legacy = dashboard(client, token).json()["qrs"][0]
    assert legacy["status"] == "legacy" and legacy["purpose"] is None and legacy["key_version"] is None


def test_dashboard_key_revocation_changes_effective_qr_status(setup):
    client, settings, token = setup
    issue(client, token)
    client.post("/admin/institutions/city/keys/v1/revoke", headers={"Authorization": "Bearer " + settings.admin_token})
    data = dashboard(client, token).json()
    assert data["institution"]["active_key_version"] is None
    assert data["qrs"][0]["status"] == "revoked"
    assert data["counts"]["revoked"] == 1


@pytest.mark.parametrize("status,headers,body", [
    (413, {"Content-Length": "1"}, b"x" * 17000),
    (400, {"Content-Length": "1"}, b'{"qr_text":"bad"}'),
    (400, {"Transfer-Encoding": "chunked"}, b"{}"),
    (413, {"Content-Length": "not-a-number"}, b"{}"),
])
def test_actual_body_limit_and_error_security_headers(setup, status, headers, body):
    client, _, _ = setup
    response = client.post("/verify", headers=headers, content=body)
    assert response.status_code == status
    assert response.headers["Cache-Control"] == "no-store"
    assert response.headers["X-Content-Type-Options"] == "nosniff"
    assert response.headers["Referrer-Policy"] == "no-referrer"
    assert "frame-ancestors 'none'" in response.headers["Content-Security-Policy"]
    assert "form-action 'self'" in response.headers["Content-Security-Policy"]


def test_validation_and_unexpected_errors_do_not_echo_private_input(setup, monkeypatch):
    from onjeon import api

    client, _, _ = setup
    secret = "sensitive-scanned-url-" * 300
    response = client.post("/verify", json={"qr_text": secret})
    assert response.status_code == 422 and "sensitive-scanned-url" not in response.text

    def fail_analysis(*args):
        raise RuntimeError("Private path C:/secret/database.sqlite3 and scanned URL")

    monkeypatch.setattr(api, "analyze_url", fail_analysis)
    response = client.post("/analyze", json={"qr_text": "https://city.example.org/pay"})
    assert response.status_code == 500 and response.json() == {"detail": "Internal server error"}
    assert response.headers["X-Content-Type-Options"] == "nosniff"


def test_issuance_holds_write_transaction_during_signing(setup, monkeypatch):
    from onjeon import api

    client, settings, token = setup
    original_make_qr = api.make_qr
    attempted = []

    def check_atomic_issue(payload, private_key):
        with sqlite3.connect(settings.database_path, timeout=0) as concurrent_db:
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                concurrent_db.execute("UPDATE institutions SET disabled = 1 WHERE id = 'city'")
            with pytest.raises(sqlite3.OperationalError, match="locked"):
                concurrent_db.execute("UPDATE signing_keys SET active = 0, revoked_at = 1 WHERE institution_id = 'city'")
        attempted.append(True)
        return original_make_qr(payload, private_key)

    monkeypatch.setattr(api, "make_qr", check_atomic_issue)
    assert issue(client, token).status_code == 201
    assert attempted == [True]


def test_verification_reads_a_coherent_snapshot_during_revocation(setup, monkeypatch):
    from onjeon import api

    client, settings, token = setup
    qr = issue(client, token).json()["qr_text"]
    public_key_type = api.Ed25519PublicKey

    class RevokingPublicKey:
        @staticmethod
        def from_public_bytes(value):
            public_key = public_key_type.from_public_bytes(value)

            class Key:
                def verify(self, signature, raw):
                    with sqlite3.connect(settings.database_path) as db:
                        db.execute("UPDATE issued_qrs SET revoked_at = 1 WHERE institution_id = 'city'")
                    public_key.verify(signature, raw)

            return Key()

    monkeypatch.setattr(api, "Ed25519PublicKey", RevokingPublicKey)
    # A request that started before the committed revocation sees its original snapshot.
    assert client.post("/verify", json={"qr_text": qr}).json()["status"] == "trusted"
    assert client.post("/verify", json={"qr_text": qr}).json()["reason"] == "revoked"


def test_salted_random_token_hashes_and_legacy_compatibility():
    token = "random-token-with-256-bit-entropy-in-production"
    first = _hash_token(token)
    second = _hash_token(token)
    assert first.startswith("sha256$") and len(first.split("$")[1]) == 64
    assert first != second
    assert _verify_token(token, first) and _verify_token(token, second)
    assert not _verify_token("wrong-token", first)
    legacy = hashlib.sha256(token.encode("utf-8")).hexdigest()
    old_salt = "a" * 32
    old_salted = "sha256$" + old_salt + "$" + hashlib.sha256(bytes.fromhex(old_salt) + token.encode()).hexdigest()
    assert _verify_token(token, old_salted)
    assert _verify_token(token, legacy)
    assert not _verify_token("wrong-token", legacy)


@pytest.mark.parametrize("stored", [
    "", "short", "a" * 63, "x" * 64, "sha256$$", "sha256$" + "a" * 32 + "$" + "b" * 63,
    "sha256$" + "x" * 32 + "$" + "a" * 64, "sha256$" + "a" * 32 + "$" + "b" * 64 + "$extra",
])
def test_malformed_stored_token_hash_fails_closed(setup, stored):
    client, settings, token = setup
    with sqlite3.connect(settings.database_path) as db:
        db.execute("UPDATE institutions SET issuer_token_hash = ? WHERE id = 'city'", (stored,))
    response = dashboard(client, token)
    assert response.status_code == 403
    assert response.json() == {"detail": "Not authorized for institution"}
    assert token not in response.text
    assert not _verify_token(token, stored)


def test_legacy_issuer_hash_survives_then_rotates_to_salted_format(setup):
    client, settings, token = setup
    with sqlite3.connect(settings.database_path) as db:
        stored = db.execute("SELECT issuer_token_hash FROM institutions WHERE id = 'city'").fetchone()[0]
        assert stored.startswith("sha256$")
        db.execute("UPDATE institutions SET issuer_token_hash = ? WHERE id = 'city'", (hashlib.sha256(token.encode("utf-8")).hexdigest(),))
    assert dashboard(client, token).status_code == 200
    response = client.post("/admin/institutions/city/token", headers={"Authorization": "Bearer " + settings.admin_token})
    new_token = response.json()["issuer_token"]
    assert dashboard(client, token).status_code == 403
    assert dashboard(client, new_token).status_code == 200
    with sqlite3.connect(settings.database_path) as db:
        new_hash = db.execute("SELECT issuer_token_hash FROM institutions WHERE id = 'city'").fetchone()[0]
    assert new_hash.startswith("sha256$") and token not in new_hash and new_token not in new_hash
    assert _verify_token(new_token, new_hash)


def test_admin_audit_tracks_controls_with_isolation_and_no_secrets(setup):
    client, settings, old_token = setup
    admin = {"Authorization": "Bearer " + settings.admin_token}
    other_public = create_private_key(settings.key_directory / "other-v1.pem")
    other_token = client.post("/admin/institutions", headers=admin, json={
        "institution_id": "other", "name": "다른 기관", "official_domains": ["other.example.org"],
        "key_version": "v1", "public_key": other_public,
    }).json()["issuer_token"]
    assert [entry["action"] for entry in dashboard(client, old_token).json()["audit"]] == ["registered"]
    public = create_private_key(settings.key_directory / "city-v2.pem")
    assert client.post("/admin/institutions/city/keys", headers=admin, json={"key_version": "v2", "public_key": public}).status_code == 201
    rotated = client.post("/admin/institutions/city/token", headers=admin)
    new_token = rotated.json()["issuer_token"]
    assert dashboard(client, old_token).status_code == 403
    assert client.post("/admin/institutions/city/keys/v1/activate", headers=admin).status_code == 200
    assert client.post("/admin/institutions/city/keys/v1/revoke", headers=admin).status_code == 200
    assert client.post("/admin/institutions/city/disable", headers=admin).status_code == 200
    assert dashboard(client, new_token).status_code == 403
    assert client.post("/admin/institutions/city/enable", headers=admin).status_code == 200
    response = dashboard(client, new_token)
    audit = response.json()["audit"]
    assert [entry["action"] for entry in audit] == [
        "institution_enabled", "institution_disabled", "key_revoked", "key_activated", "token_rotated", "key_rotated", "registered",
    ]
    assert all(entry["qr_id"] is None and entry["occurred_at"] > 0 for entry in audit)
    assert all(set(entry) == {"id", "qr_id", "action", "occurred_at"} for entry in audit)
    assert old_token not in response.text and new_token not in response.text and public not in response.text
    other_audit = dashboard(client, other_token, "other").json()["audit"]
    assert [entry["action"] for entry in other_audit] == ["registered"]
    assert not {entry["id"] for entry in other_audit} & {entry["id"] for entry in audit}


def test_failed_admin_change_cannot_commit_without_its_audit_record(setup):
    client, settings, token = setup
    admin = {"Authorization": "Bearer " + settings.admin_token}
    with sqlite3.connect(settings.database_path) as db:
        original = db.execute("SELECT issuer_token_hash FROM institutions WHERE id = 'city'").fetchone()[0]
        db.execute(
            "CREATE TRIGGER reject_token_audit BEFORE INSERT ON audit_events WHEN NEW.action = 'token_rotated' "
            "BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END"
        )
    response = client.post("/admin/institutions/city/token", headers=admin)
    assert response.status_code == 500 and response.json() == {"detail": "Internal server error"}
    assert dashboard(client, token).status_code == 200
    with sqlite3.connect(settings.database_path) as db:
        assert db.execute("SELECT issuer_token_hash FROM institutions WHERE id = 'city'").fetchone()[0] == original
        assert db.execute("SELECT action FROM audit_events").fetchall() == [("registered",)]


def test_unsuccessful_admin_actions_do_not_claim_success_in_audit(setup):
    client, settings, token = setup
    admin = {"Authorization": "Bearer " + settings.admin_token}
    assert client.post("/admin/institutions/city/token", headers={"Authorization": "Bearer " + token}).status_code == 403
    assert client.post("/admin/institutions/city/keys/missing/revoke", headers=admin).status_code == 404
    assert client.post("/admin/institutions/missing/disable", headers=admin).status_code == 404
    assert [entry["action"] for entry in dashboard(client, token).json()["audit"]] == ["registered"]


def test_l3_colliding_legacy_key_names_use_distinct_nested_paths(tmp_path):
    from onjeon.api import _key_path

    settings = Settings(tmp_path / "db.sqlite3", tmp_path / "keys", secrets.token_urlsafe(48))
    legacy = settings.key_directory / "aa-b-c.pem"
    create_private_key(legacy)
    first = settings.key_directory / "aa-b" / "c.pem"
    second = settings.key_directory / "aa" / "b-c.pem"
    assert first != second
    # Both IDs and versions are valid, but their legacy flat encoding collides.
    assert _key_path(settings, "aa-b", "c", allow_legacy=True) == legacy
    assert _key_path(settings, "aa", "b-c", allow_legacy=True) == legacy
    assert _key_path(settings, "aa-b", "c", allow_legacy=False) == first
    assert _key_path(settings, "aa", "b-c", allow_legacy=False) == second
    assert not first.exists() and not second.exists()
    first_public = create_private_key(first)
    second_public = create_private_key(second)
    assert first_public != second_public
    for allow_legacy in (False, True):
        assert _key_path(settings, "aa-b", "c", allow_legacy=allow_legacy) == first
        assert _key_path(settings, "aa", "b-c", allow_legacy=allow_legacy) == second


def test_l3_production_rejects_colliding_flat_keys_but_local_demo_and_nested_keys_work(tmp_path, monkeypatch):
    monkeypatch.setenv("ONJEON_ENV", "development")
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", secrets.token_urlsafe(48))
    settings = Settings(tmp_path / "db.sqlite3", tmp_path / "keys", secrets.token_urlsafe(48))
    legacy = settings.key_directory / "aa-b-c.pem"
    public = create_private_key(legacy)
    local = TestClient(create_app(settings))
    identities = [("aa-b", "c"), ("aa", "b-c")]
    tokens = {}
    for institution, version in identities:
        registered = local.post(
            "/admin/institutions",
            headers={"Authorization": "Bearer " + settings.admin_token},
            json={"institution_id": institution, "name": "Legacy collision fixture",
                  "official_domains": ["city.example.org"], "key_version": version, "public_key": public},
        )
        assert registered.status_code == 201, registered.text
        tokens[institution] = registered.json()["issuer_token"]

    def issue_for(client, institution):
        return client.post(
            f"/institutions/{institution}/qrs",
            headers={"Authorization": "Bearer " + tokens[institution]},
            json={"destination": "https://city.example.org/pay", "purpose": "Collision regression",
                  "expires_at": (datetime.now(timezone.utc) + timedelta(days=1)).isoformat()},
        )

    assert all(issue_for(local, institution).status_code == 201 for institution, _ in identities)
    configure_production_crl(tmp_path, monkeypatch)
    monkeypatch.setenv("ONJEON_ENV", "production")
    production = TestClient(create_app(settings))
    with sqlite3.connect(settings.database_path) as db:
        before = db.execute("SELECT COUNT(*) FROM issued_qrs").fetchone()[0]
    for institution, version in identities:
        denied = issue_for(production, institution)
        assert denied.status_code == 503
        assert denied.json() == {"detail": "Signing key unavailable"}
        assert str(legacy) not in denied.text
        admin = {"Authorization": "Bearer " + settings.admin_token}
        assert production.post(
            f"/admin/institutions/{institution}/keys/{version}/activate", headers=admin,
        ).status_code == 422
        assert production.post(
            f"/admin/institutions/{institution}/keys", headers=admin,
            json={"key_version": version, "public_key": public},
        ).status_code == 422
    with sqlite3.connect(settings.database_path) as db:
        assert db.execute("SELECT COUNT(*) FROM issued_qrs").fetchone()[0] == before

    for institution, version in identities:
        nested = settings.key_directory / institution / f"{version}.pem"
        nested.parent.mkdir(parents=True, exist_ok=True)
        nested.write_bytes(legacy.read_bytes())
    legacy.unlink()
    for institution, version in identities:
        issued = issue_for(production, institution)
        assert issued.status_code == 201, issued.text
        payload, _, _ = parse_qr(issued.json()["qr_text"])
        assert payload["institution_id"] == institution and payload["key_version"] == version
