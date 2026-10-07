import base64
import hashlib
import json
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient

from onjeon.api import Settings, create_app
from onjeon.crypto import b64url_encode, canonical_bytes, create_private_key, load_private_key, make_qr, parse_qr


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
        assert db.execute("SELECT action FROM audit_events").fetchall() == [("issued",)]
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
    docs = client.get("/docs")
    assert docs.status_code == 200
    assert "Content-Security-Policy" not in docs.headers


def test_unsigned_analysis_and_public_rate_limit(setup, monkeypatch):
    from onjeon import analyzer

    client, settings, _ = setup
    monkeypatch.setattr(analyzer, "_resolve_public", lambda host: "93.184.215.14")
    monkeypatch.setattr(analyzer, "_head", lambda url, host, address: (200, None))
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
    monkeypatch.setenv("ONJEON_ENV", "production")
    client = TestClient(create_app(Settings(tmp_path / "db.sqlite3", tmp_path / "keys", "a" * 40)))
    assert client.get("/docs").status_code == 404
    assert client.get("/openapi.json").status_code == 404
    assert client.get("/health").headers["Strict-Transport-Security"].startswith("max-age=")


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
