"""Health polling must amortize CRL parsing without sharing application state."""

import secrets
import ssl
import time
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from onjeon import api


@pytest.fixture
def health_probe(tmp_path, monkeypatch):
    probe = SimpleNamespace(now=100.0, calls=0, result={"available": True, "reason": "ready"})

    def read_status():
        probe.calls += 1
        if isinstance(probe.result, Exception):
            raise probe.result
        return dict(probe.result)

    def make_app(name="state"):
        return api.create_app(api.Settings(
            tmp_path / f"{name}.sqlite3", tmp_path / f"{name}-keys", secrets.token_urlsafe(48),
        ))

    monkeypatch.setenv("ONJEON_ENV", "production")
    monkeypatch.setenv("ONJEON_KEY_PASSWORD", secrets.token_urlsafe(48))
    monkeypatch.setattr(api, "tls_configuration_status", read_status)
    # Replace only the API's time reference. Freezing the shared time module's
    # monotonic clock would interfere with AnyIO's real request timeouts.
    monkeypatch.setattr(api, "time", SimpleNamespace(time=time.time, monotonic=lambda: probe.now))
    probe.make_app = make_app
    return probe


def test_health_reuses_startup_status_for_100_polls_and_refreshes_once_after_ttl(health_probe):
    probe = health_probe
    with TestClient(probe.make_app()) as client:
        assert probe.calls == 1
        for _ in range(100):
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json() == {"status": "ok", "url_analysis": {"available": True, "reason": "ready"}}
        assert probe.calls == 1

        probe.result = {"available": False, "reason": "crl_expired"}
        probe.now += 4.9
        assert client.get("/health").json()["status"] == "ok"
        assert probe.calls == 1
        probe.now += 0.2
        for _ in range(10):
            assert client.get("/health").json() == {
                "status": "degraded", "url_analysis": {"available": False, "reason": "crl_expired"},
            }
        assert probe.calls == 2


def test_invalid_refresh_is_sanitized_cached_and_recovers_after_next_ttl(health_probe):
    probe = health_probe
    with TestClient(probe.make_app()) as client:
        probe.result = ssl.SSLCertVerificationError("fixture operator path and private error detail")
        probe.now += 5.1
        for _ in range(100):
            response = client.get("/health")
            assert response.status_code == 200
            assert response.json() == {
                "status": "degraded", "url_analysis": {"available": False, "reason": "crl_configuration_invalid"},
            }
            assert "private error detail" not in response.text
        assert probe.calls == 2

        probe.result = {"available": True, "reason": "ready"}
        assert client.get("/health").json()["status"] == "degraded"
        assert probe.calls == 2
        probe.now += 5.1
        assert client.get("/health").json() == {
            "status": "ok", "url_analysis": {"available": True, "reason": "ready"},
        }
        assert probe.calls == 3


def test_health_cache_is_local_to_each_application(health_probe):
    probe = health_probe
    ready_app = probe.make_app("ready")
    probe.result = {"available": False, "reason": "crl_not_yet_valid"}
    future_app = probe.make_app("future")
    assert probe.calls == 2
    with TestClient(ready_app) as ready, TestClient(future_app) as future:
        assert ready.get("/health").json()["status"] == "ok"
        assert future.get("/health").json() == {
            "status": "degraded", "url_analysis": {"available": False, "reason": "crl_not_yet_valid"},
        }
        assert probe.calls == 2
