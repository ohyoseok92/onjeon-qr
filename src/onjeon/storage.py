"""SQLite state. Raw scan URLs and citizen scan history are not persisted."""

import sqlite3
from contextlib import closing, contextmanager
from pathlib import Path


SCHEMA = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS institutions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    official_domains TEXT NOT NULL,
    issuer_token_hash TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS signing_keys (
    institution_id TEXT NOT NULL REFERENCES institutions(id),
    version TEXT NOT NULL,
    public_key TEXT NOT NULL,
    active INTEGER NOT NULL DEFAULT 0,
    revoked_at INTEGER,
    PRIMARY KEY (institution_id, version)
);
CREATE TABLE IF NOT EXISTS issued_qrs (
    qr_id TEXT PRIMARY KEY,
    institution_id TEXT NOT NULL REFERENCES institutions(id),
    payload_hash TEXT NOT NULL,
    revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    institution_id TEXT NOT NULL,
    qr_id TEXT,
    action TEXT NOT NULL,
    occurred_at INTEGER NOT NULL
);
"""


def initialize(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with closing(sqlite3.connect(path)) as connection:
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        connection.executescript(SCHEMA)
        if "disabled" not in {row[1] for row in connection.execute("PRAGMA table_info(institutions)")}:
            connection.execute("ALTER TABLE institutions ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0")
        if "revoked_at" not in {row[1] for row in connection.execute("PRAGMA table_info(signing_keys)")}:
            connection.execute("ALTER TABLE signing_keys ADD COLUMN revoked_at INTEGER")
        connection.commit()


@contextmanager
def database(path: Path):
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout=5000")
    try:
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
