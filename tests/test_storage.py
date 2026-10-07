import sqlite3

from onjeon.storage import initialize


def test_old_database_schema_is_migrated(tmp_path):
    path = tmp_path / "old.sqlite3"
    with sqlite3.connect(path) as db:
        db.execute("CREATE TABLE institutions (id TEXT PRIMARY KEY, name TEXT NOT NULL, official_domains TEXT NOT NULL, issuer_token_hash TEXT NOT NULL)")
        db.execute("CREATE TABLE signing_keys (institution_id TEXT NOT NULL, version TEXT NOT NULL, public_key TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 0, PRIMARY KEY (institution_id, version))")
    initialize(path)
    with sqlite3.connect(path) as db:
        assert "disabled" in {row[1] for row in db.execute("PRAGMA table_info(institutions)")}
        assert "revoked_at" in {row[1] for row in db.execute("PRAGMA table_info(signing_keys)")}
