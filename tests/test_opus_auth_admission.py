"""Real ASGI requests exercise admission before issuer DB/token evaluation."""

import asyncio
from contextlib import contextmanager
import secrets
import sqlite3
import threading

import httpx
import pytest
from fastapi.testclient import TestClient

from onjeon import api
from onjeon.crypto import create_private_key


@pytest.fixture
def issuer_app(tmp_path, monkeypatch):
    monkeypatch.setenv("ONJEON_ENV", "development")
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", secrets.token_urlsafe(48))
    settings = api.Settings(tmp_path / "db.sqlite3", tmp_path / "keys", secrets.token_urlsafe(48))
    public = create_private_key(settings.key_directory / "city" / "v1.pem")
    app = api.create_app(settings)
    registered = TestClient(app).post(
        "/admin/institutions",
        headers={"Authorization": "Bearer " + settings.admin_token},
        json={"institution_id": "city", "name": "Admission fixture",
              "official_domains": ["city.example.org"], "key_version": "v1", "public_key": public},
    )
    assert registered.status_code == 201
    return app, settings, registered.json()["issuer_token"]


@pytest.mark.parametrize("fail_first_wave", [False, True])
def test_auth_admission_rejects_ninth_before_classification_and_recovers(
    issuer_app, monkeypatch, fail_first_wave,
):
    app, settings, token = issuer_app
    original_database = api.database
    original_verify = api._verify_token
    original_compare = api.secrets.compare_digest
    stats = {"database_reads": 0, "token_checks": 0, "admin_checks": 0}
    stats_lock = threading.Lock()

    def verify_token(*args, **kwargs):
        with stats_lock:
            stats["token_checks"] += 1
        return original_verify(*args, **kwargs)

    def compare_digest(first, second):
        # Count the administrator credential comparison separately from issuer hashes.
        if isinstance(second, bytes) and second == settings.admin_token.encode("utf-8"):
            with stats_lock:
                stats["admin_checks"] += 1
        return original_compare(first, second)

    monkeypatch.setattr(api, "_verify_token", verify_token)
    monkeypatch.setattr(api.secrets, "compare_digest", compare_digest)

    async def wave(client, *, fail):
        release = threading.Event()
        all_entered = threading.Event()
        entered = [0]

        @contextmanager
        def delayed_database(path, *, write=True):
            if not write:
                with stats_lock:
                    stats["database_reads"] += 1
                    entered[0] += 1
                    if entered[0] == 8:
                        all_entered.set()
                if not release.wait(10):
                    raise AssertionError("Authentication admission fixture was not released")
                if fail:
                    raise sqlite3.OperationalError("synthetic-private-auth-database-error")
            with original_database(path, write=write) as db:
                yield db

        monkeypatch.setattr(api, "database", delayed_database)
        tasks = [asyncio.create_task(client.get(
            "/institutions/city/dashboard", headers={"Authorization": "Bearer " + token},
        )) for _ in range(8)]
        try:
            assert await asyncio.to_thread(all_entered.wait, 4), "Eight authentication checks must reach the gate"
            with stats_lock:
                before = dict(stats)
            with sqlite3.connect(settings.database_path) as db:
                counters_before = db.execute("SELECT * FROM rate_counters ORDER BY request_group, anonymous_source").fetchall()
            overloaded = await asyncio.wait_for(client.get(
                "/institutions/city/dashboard", headers={"Authorization": "Bearer " + token},
            ), 3)
            assert overloaded.status_code == 429
            assert overloaded.json() == {"detail": "Authentication checks busy"}
            assert overloaded.headers["Cache-Control"] == "no-store"
            assert overloaded.headers["X-Content-Type-Options"] == "nosniff"
            assert token not in overloaded.text and settings.admin_token not in overloaded.text
            with stats_lock:
                assert stats == before  # No ninth pre-auth DB read or credential evaluation.
            with sqlite3.connect(settings.database_path) as db:
                assert db.execute("SELECT * FROM rate_counters ORDER BY request_group, anonymous_source").fetchall() == counters_before
            # The issuer admission lane must not occupy the administrator lane.
            independent_admin = await asyncio.wait_for(client.get(
                "/admin/security-events", headers={"Authorization": "Bearer " + settings.admin_token},
            ), 3)
            assert independent_admin.status_code == 200
            with stats_lock:
                assert stats["admin_checks"] > before["admin_checks"]
        finally:
            release.set()
            responses = await asyncio.gather(*tasks)
            monkeypatch.setattr(api, "database", original_database)
        expected = 500 if fail else 200
        assert all(response.status_code == expected for response in responses)
        if fail:
            assert all(response.json() == {"detail": "Internal server error"} for response in responses)
            assert all("synthetic-private-auth-database-error" not in response.text for response in responses)

    async def scenario():
        transport = httpx.ASGITransport(app=app, raise_app_exceptions=False)
        async with httpx.AsyncClient(transport=transport, base_url="http://testserver") as client:
            await wave(client, fail=fail_first_wave)
            # Reoccupying all eight slots proves every finally path returned its slot.
            await wave(client, fail=False)
            assert (await client.get(
                "/institutions/city/dashboard", headers={"Authorization": "Bearer " + token},
            )).status_code == 200

    asyncio.run(scenario())
