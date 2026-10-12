import os
import multiprocessing
import sqlite3
import stat

import pytest

from onjeon.storage import initialize, record_security_event, security_event_summary


def _api_rate_worker(database_path, key_directory, count, queue, start_gate=None):
    phase = "imports"
    try:
        from pathlib import Path
        from unittest.mock import patch
        from fastapi.testclient import TestClient
        from onjeon.api import Settings, create_app
        phase = "startup"
        if start_gate is not None:
            start_gate.wait(timeout=20)
        with patch.dict(os.environ, {"ONJEON_ENV": "development"}), patch("onjeon.api.time.time", return_value=1800000000):
            with TestClient(create_app(Settings(Path(database_path), Path(key_directory), "a" * 40))) as client:
                phase = "requests"
                statuses = [client.post("/verify", json={"qr_text": "invalid"}).status_code for _ in range(count)]
                with sqlite3.connect(database_path) as db:
                    identity = db.execute("SELECT installation_id FROM backup_identity WHERE singleton=1").fetchone()[0]
                queue.put({"accepted": statuses.count(200), "limited": statuses.count(429), "pid": os.getpid(),
                           "identity_digest": __import__("hashlib").sha256(identity.encode()).hexdigest()})
    except Exception as error:
        # Never serialize exception messages, paths, credentials or request bodies.
        queue.put({"failed": True, "phase": phase, "exception_type": type(error).__name__,
                   "sqlite_code": getattr(error, "sqlite_errorcode", None)})


@pytest.mark.parametrize("startup_round", range(2))
@pytest.mark.parametrize("database_state", ("fresh", "legacy"))
def test_two_real_processes_and_restart_share_atomic_rate_limit(tmp_path, startup_round, database_state):
    path = tmp_path / "shared.sqlite3"
    if database_state == "legacy":
        with sqlite3.connect(path) as db:
            db.execute("CREATE TABLE institutions (id TEXT PRIMARY KEY, name TEXT NOT NULL, official_domains TEXT NOT NULL, issuer_token_hash TEXT NOT NULL)")
            db.execute("CREATE TABLE signing_keys (institution_id TEXT NOT NULL, version TEXT NOT NULL, public_key TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (institution_id, version))")
            db.execute("CREATE TABLE issued_qrs(qr_id TEXT PRIMARY KEY, institution_id TEXT NOT NULL, payload_hash TEXT NOT NULL, revoked_at INTEGER)")
            db.execute("INSERT INTO institutions VALUES('legacy-city', 'City', '[]', 'hash')")
            db.execute("CREATE TABLE rate_counters (request_group TEXT NOT NULL CHECK(request_group IN ('admin','issuer','verify','analyze')), "
                       "anonymous_source TEXT NOT NULL,window_started_at INTEGER NOT NULL,request_count INTEGER NOT NULL,"
                       "PRIMARY KEY(request_group,anonymous_source,window_started_at))")
    context = multiprocessing.get_context("spawn")
    queue = context.Queue()
    start_gate = context.Barrier(2)
    processes = [context.Process(target=_api_rate_worker, args=(str(path), str(tmp_path / "keys"), 40, queue, start_gate)) for _ in range(2)]
    for process in processes:
        process.start()
    results = [queue.get(timeout=30) for _ in processes]
    for process in processes:
        process.join(timeout=30)
        assert process.exitcode == 0
    assert not any(result.get("failed") for result in results), results
    assert len({result["pid"] for result in results}) == 2
    assert len({result["identity_digest"] for result in results}) == 1
    assert sum(result["accepted"] for result in results) == 60
    assert sum(result["limited"] for result in results) == 20
    restarted = context.Process(target=_api_rate_worker, args=(str(path), str(tmp_path / "keys"), 1, queue))
    restarted.start()
    after = queue.get(timeout=30)
    restarted.join(timeout=30)
    assert restarted.exitcode == 0 and not after.get("failed"), after
    assert after["accepted"] == 0 and after["limited"] == 1
    assert after["identity_digest"] == results[0]["identity_digest"]
    print({"database_state": database_state, "startup_round": startup_round,
           "two_process_ids": [result["pid"] for result in results], "requests": 80,
           "accepted": sum(result["accepted"] for result in results), "limited": sum(result["limited"] for result in results),
           "restart_process_id": after["pid"], "restart_limited": after["limited"]})
    with sqlite3.connect(path) as db:
        rows = db.execute("SELECT * FROM rate_counters").fetchall()
        assert len(rows) == 1 and rows[0][-1] == 60
        assert "testclient" not in str(rows)
        identity_rows = db.execute("SELECT singleton,installation_id FROM backup_identity").fetchall()
        assert len(identity_rows) == 1 and identity_rows[0][0] == 1 and len(identity_rows[0][1]) == 64
        if database_state == "legacy":
            assert db.execute("SELECT id,disabled FROM institutions").fetchall() == [("legacy-city", 0)]
            assert {"purpose", "issued_at", "expires_at", "key_version"} <= {row[1] for row in db.execute("PRAGMA table_info(issued_qrs)")}
    queue.close()


def test_backup_identity_survives_restart_and_sqlite_backup_to_another_path(tmp_path, monkeypatch):
    from contextlib import closing
    import re
    import onjeon.storage as storage
    source = tmp_path / "original.sqlite3"
    initialize(source)
    with closing(sqlite3.connect(source)) as db:
        identity = db.execute("SELECT installation_id FROM backup_identity WHERE singleton=1").fetchone()[0]
    assert re.fullmatch(r"[0-9a-f]{64}", identity)
    staging = tmp_path / "other-staging-directory" / "restored.sqlite3"
    staging.parent.mkdir()
    with closing(sqlite3.connect(source)) as original, closing(sqlite3.connect(staging)) as restored:
        original.backup(restored)
    def forbidden_replacement(_):
        pytest.fail("Existing installation identity must never be regenerated")
    monkeypatch.setattr(storage.secrets, "token_hex", forbidden_replacement)
    initialize(source)
    initialize(staging)
    with closing(sqlite3.connect(staging)) as db:
        assert db.execute("SELECT singleton,installation_id FROM backup_identity").fetchall() == [(1, identity)]


@pytest.mark.parametrize("invalid", ("", "a" * 63, "a" * 65, "A" * 64, "g" * 64, "a" * 63 + "한", b"a" * 64))
def test_invalid_existing_backup_identity_fails_closed_without_replacement(tmp_path, invalid):
    path = tmp_path / "invalid-identity.sqlite3"
    initialize(path)
    with sqlite3.connect(path) as db:
        db.execute("UPDATE backup_identity SET installation_id=? WHERE singleton=1", (invalid,))
    with pytest.raises(RuntimeError, match="^Invalid backup installation identity; operator recovery required$"):
        initialize(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT installation_id FROM backup_identity WHERE singleton=1").fetchone()[0] == invalid


def test_existing_empty_backup_identity_table_is_not_silently_recreated(tmp_path):
    path = tmp_path / "missing-identity.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE backup_identity(singleton INTEGER PRIMARY KEY CHECK(singleton=1),installation_id TEXT NOT NULL)")
    with pytest.raises(RuntimeError, match="^Invalid backup installation identity; operator recovery required$"):
        initialize(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM backup_identity").fetchone()[0] == 0
        # Identity validation and other schema creation belong to the same transaction.
        assert db.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [("backup_identity",)]


def test_shared_rate_counter_privacy_expiry_and_capacity_fail_closed(tmp_path, monkeypatch):
    import onjeon.storage as storage
    path = tmp_path / "rate.sqlite3"
    initialize(path)
    key = storage.load_rate_key(path)
    assert storage.load_rate_key(path) == key
    monkeypatch.setitem(storage.RATE_COUNTER_GROUP_MAX_ROWS, "issuer", 3)
    now = 1800000000
    for address in ("192.0.2.1", "192.0.2.2", "192.0.2.3"):
        assert storage.consume_rate_limit(path, key, "issuer", address, now, 2)
    assert not storage.consume_rate_limit(path, key, "issuer", "192.0.2.4", now, 2)
    assert storage.consume_rate_limit(path, key, "issuer", "192.0.2.1", now, 2)
    assert not storage.consume_rate_limit(path, key, "issuer", "192.0.2.1", now, 2)
    with sqlite3.connect(path) as db:
        rows = db.execute("SELECT * FROM rate_counters").fetchall()
        assert "192.0.2." not in str(rows) and all(len(row[1]) == 64 for row in rows)
        first_source = rows[0][1]
    assert storage.consume_rate_limit(path, key, "issuer", "192.0.2.1", now + 360, 2)
    with sqlite3.connect(path) as db:
        rows = db.execute("SELECT * FROM rate_counters").fetchall()
        assert len(rows) == 1 and rows[0][1] != first_source


def test_public_rate_capacity_does_not_block_other_groups_and_next_window_is_fresh(tmp_path, monkeypatch):
    import onjeon.storage as storage
    path = tmp_path / "group-capacity.sqlite3"
    initialize(path)
    key = storage.load_rate_key(path)
    now = 1800000000
    monkeypatch.setitem(storage.RATE_COUNTER_GROUP_MAX_ROWS, "verify", 3)
    for index in range(3):
        assert storage.consume_rate_limit(path, key, "verify", f"192.0.2.{index + 1}", now, 2)
    assert not storage.consume_rate_limit(path, key, "verify", "192.0.2.4", now, 2)
    for group in ("admin", "issuer", "analyze", "admin_auth", "issuer_auth"):
        assert storage.consume_rate_limit(path, key, group, "192.0.2.4", now, 2)
    # A full group retains live quotas rather than evicting the earliest counter.
    assert storage.consume_rate_limit(path, key, "verify", "192.0.2.1", now + 59, 2)
    assert not storage.consume_rate_limit(path, key, "verify", "192.0.2.1", now + 59, 2)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT request_group,COUNT(*) FROM rate_counters GROUP BY request_group").fetchall() == [
            ("admin", 1), ("admin_auth", 1), ("analyze", 1), ("issuer", 1), ("issuer_auth", 1), ("verify", 3),
        ]
    # The previous window must not occupy capacity in the immediately following one.
    for index in range(3):
        assert storage.consume_rate_limit(path, key, "verify", f"198.51.100.{index + 1}", now + 60, 2)
    assert not storage.consume_rate_limit(path, key, "verify", "198.51.100.4", now + 60, 2)
    with sqlite3.connect(path) as db:
        rows = db.execute("SELECT request_group,window_started_at,request_count FROM rate_counters").fetchall()
        assert len(rows) == 3 and all(row == ("verify", now + 60, 1) for row in rows)


@pytest.mark.parametrize("auth_group,authenticated_group", (("admin_auth", "admin"), ("issuer_auth", "issuer")))
def test_failed_auth_capacity_and_quota_are_separate_from_authenticated_group(tmp_path, monkeypatch, auth_group, authenticated_group):
    import onjeon.storage as storage
    path = tmp_path / "auth-groups.sqlite3"
    initialize(path)
    key = storage.load_rate_key(path)
    now = 1800000000
    monkeypatch.setitem(storage.RATE_COUNTER_GROUP_MAX_ROWS, auth_group, 3)
    for index in range(3):
        assert storage.consume_rate_limit(path, key, auth_group, f"192.0.2.{index + 1}", now, 1)
    assert not storage.consume_rate_limit(path, key, auth_group, "192.0.2.1", now, 1)
    assert not storage.consume_rate_limit(path, key, auth_group, "192.0.2.4", now, 1)
    # Both an exhausted source and a new source still get their authenticated quota.
    assert storage.consume_rate_limit(path, key, authenticated_group, "192.0.2.1", now, 1)
    assert storage.consume_rate_limit(path, key, authenticated_group, "192.0.2.4", now, 1)
    assert not storage.consume_rate_limit(path, key, authenticated_group, "192.0.2.1", now, 1)


def test_old_rate_group_constraint_is_migrated_without_resetting_live_quota(tmp_path, monkeypatch):
    import hashlib
    import hmac
    import onjeon.storage as storage
    path = tmp_path / "legacy-rate-groups.sqlite3"
    now = 1800000000
    key = storage.load_rate_key(path)
    source = hmac.new(key, f"{now}:verify:192.0.2.1".encode(), hashlib.sha256).hexdigest()
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE rate_counters (request_group TEXT NOT NULL CHECK(request_group IN ('admin','issuer','verify','analyze')), "
                   "anonymous_source TEXT NOT NULL,window_started_at INTEGER NOT NULL,request_count INTEGER NOT NULL,"
                   "PRIMARY KEY(request_group,anonymous_source,window_started_at))")
        db.execute("INSERT INTO rate_counters VALUES ('verify',?,?,60)", (source, now))
        db.execute("INSERT INTO rate_counters VALUES ('admin','expired',?,30)", (now - 60,))
        db.execute("CREATE INDEX rate_counters_window ON rate_counters(window_started_at)")
    monkeypatch.setattr(storage.time, "time", lambda: now)
    initialize(path)
    initialize(path)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT * FROM rate_counters").fetchall() == [("verify", source, now, 60)]
        assert db.execute("SELECT name FROM sqlite_master WHERE type='index' AND name='rate_counters_window'").fetchone()
    assert not storage.consume_rate_limit(path, key, "verify", "192.0.2.1", now, 60)
    for group in ("admin_auth", "issuer_auth"):
        assert storage.consume_rate_limit(path, key, group, "192.0.2.1", now, 30)


@pytest.mark.parametrize("group", ("unknown", "", "admin-authenticated", "verify/../admin"))
def test_rate_counter_rejects_unrecognized_groups_without_writing(tmp_path, group):
    import onjeon.storage as storage
    path = tmp_path / "known-groups.sqlite3"
    initialize(path)
    assert not storage.consume_rate_limit(path, storage.load_rate_key(path), group, "192.0.2.1", 1800000000, 2)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM rate_counters").fetchone()[0] == 0


def test_old_database_schema_is_migrated(tmp_path):
    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE institutions (id TEXT PRIMARY KEY, name TEXT NOT NULL, official_domains TEXT NOT NULL, issuer_token_hash TEXT NOT NULL)")
        db.execute("CREATE TABLE signing_keys (institution_id TEXT NOT NULL, version TEXT NOT NULL, public_key TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (institution_id, version))")
        db.execute("CREATE TABLE issued_qrs(qr_id TEXT PRIMARY KEY, institution_id TEXT NOT NULL, payload_hash TEXT NOT NULL, revoked_at INTEGER)")
        db.execute("INSERT INTO institutions VALUES('city', 'City', '[\"city.example.org\"]', 'hash')")
        db.execute("INSERT INTO issued_qrs VALUES('old-qr', 'city', 'payload-hash', NULL)")
    initialize(path)
    initialize(path)
    with sqlite3.connect(path) as db:
        assert "disabled" in {row[1] for row in db.execute("PRAGMA table_info(institutions)")}
        assert "revoked_at" in {row[1] for row in db.execute("PRAGMA table_info(signing_keys)")}
        assert {"purpose", "issued_at", "expires_at", "key_version"} <= {row[1] for row in db.execute("PRAGMA table_info(issued_qrs)")}
        assert db.execute("SELECT qr_id,payload_hash,purpose,issued_at,expires_at,key_version FROM issued_qrs").fetchall() == [
            ("old-qr", "payload-hash", None, None, None, None),
        ]


def test_security_event_retention_maximum_and_aggregation(tmp_path, monkeypatch):
    import onjeon.storage as storage
    path = tmp_path / "private.sqlite3"
    initialize(path)
    monkeypatch.setattr(storage, "SECURITY_EVENT_MAX_ROWS", 3)
    now = 1800000000
    def record(at, source):
        record_security_event(path, actor_role="admin", institution_id=None,
                              event_type="authentication_failed", status_code=403,
                              anonymous_source=source, now=at)
    record(now - 7 * 86400, "expired")
    for index in range(5):
        record(now + index, f"source-{index}")
    record(now + 5, "source-4")
    rows = security_event_summary(path, now + 5)
    assert len(rows) == 3
    assert rows[0]["anonymous_source"] == "source-4" and rows[0]["attempt_count"] == 2
    assert {row["anonymous_source"] for row in rows} == {"source-2", "source-3", "source-4"}
    assert security_event_summary(path, now + 5 + 7 * 86400) == []
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 0


def test_security_event_cap_is_enforced_on_insert_without_recounting_aggregates(tmp_path, monkeypatch):
    import onjeon.storage as storage
    path = tmp_path / "private.sqlite3"
    initialize(path)
    monkeypatch.setattr(storage, "SECURITY_EVENT_MAX_ROWS", 3)
    cap_checks = 0
    original = storage._prune_security_event_excess

    def count_cap_checks(connection):
        nonlocal cap_checks
        cap_checks += 1
        original(connection)

    monkeypatch.setattr(storage, "_prune_security_event_excess", count_cap_checks)
    now = 1800000000

    def record(source, at=now):
        record_security_event(path, actor_role="admin", institution_id=None,
                              event_type="authentication_failed", status_code=403,
                              anonymous_source=source, now=at)

    for index in range(3):
        record(f"source-{index}", now + index)
    for _ in range(20):
        record("source-2", now + 3)
    assert cap_checks == 3
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 3
        assert db.execute("SELECT attempt_count FROM security_events WHERE anonymous_source = 'source-2'").fetchone() == (21,)

    record("source-3", now + 4)
    assert cap_checks == 4
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] == 3
        assert {row[0] for row in db.execute("SELECT anonymous_source FROM security_events")} == {
            "source-1", "source-2", "source-3",
        }


def test_security_event_retention_is_enforced_on_write(tmp_path):
    path = tmp_path / "private.sqlite3"
    initialize(path)
    now = 1800000000
    for source, at in (("expired", now), ("current", now + 7 * 86400)):
        record_security_event(path, actor_role="issuer", institution_id=None,
                              event_type="authentication_failed", status_code=401,
                              anonymous_source=source, now=at)
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT anonymous_source FROM security_events").fetchall() == [("current",)]


@pytest.mark.skipif(os.name != "posix", reason="Windows uses deployment ACLs instead of POSIX mode")
def test_database_permissions_are_owner_only(tmp_path):
    path = tmp_path / "state" / "private.sqlite3"
    initialize(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
    from onjeon.storage import load_rate_key
    load_rate_key(path)
    assert stat.S_IMODE((path.parent / ".rate-limit-hmac").stat().st_mode) == 0o600
