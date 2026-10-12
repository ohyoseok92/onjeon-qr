"""SQLite state. Raw scan URLs and citizen scan history are not persisted."""

import os
import hashlib
import hmac
import re
import secrets
import sqlite3
import tempfile
import threading
import time
from contextlib import closing, contextmanager
from pathlib import Path


_RATE_COUNTER_COLUMNS = """
    request_group TEXT NOT NULL CHECK(request_group IN ('admin', 'issuer', 'verify', 'analyze', 'admin_auth', 'issuer_auth')),
    anonymous_source TEXT NOT NULL,
    window_started_at INTEGER NOT NULL,
    request_count INTEGER NOT NULL,
    PRIMARY KEY(request_group, anonymous_source, window_started_at)
"""

SCHEMA = f"""
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS institutions (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    official_domains TEXT NOT NULL,
    issuer_token_hash TEXT NOT NULL,
    disabled INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS backup_identity (
    singleton INTEGER PRIMARY KEY CHECK(singleton = 1),
    installation_id TEXT NOT NULL
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
    purpose TEXT,
    issued_at INTEGER,
    expires_at INTEGER,
    key_version TEXT,
    revoked_at INTEGER
);
CREATE TABLE IF NOT EXISTS audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    institution_id TEXT NOT NULL,
    qr_id TEXT,
    action TEXT NOT NULL,
    occurred_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS security_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    actor_role TEXT NOT NULL CHECK(actor_role IN ('admin', 'issuer')),
    institution_id TEXT NOT NULL DEFAULT '',
    event_type TEXT NOT NULL CHECK(event_type IN ('authentication_failed', 'rate_limited')),
    status_code INTEGER NOT NULL CHECK(status_code IN (401, 403, 429)),
    anonymous_source TEXT NOT NULL,
    window_started_at INTEGER NOT NULL,
    occurred_at INTEGER NOT NULL,
    attempt_count INTEGER NOT NULL DEFAULT 1,
    UNIQUE(actor_role, institution_id, event_type, status_code, anonymous_source, window_started_at)
);
CREATE TABLE IF NOT EXISTS rate_counters (
{_RATE_COUNTER_COLUMNS}
);
"""

SECURITY_EVENT_RETENTION_SECONDS = 7 * 86400
SECURITY_EVENT_MAX_ROWS = 10000
RATE_COUNTER_RETENTION_SECONDS = 60
_RATE_GROUPS = frozenset(("admin", "issuer", "verify", "analyze", "admin_auth", "issuer_auth"))
RATE_COUNTER_GROUP_MAX_ROWS = {group: 10000 for group in _RATE_GROUPS}
_rate_write_lock = threading.Lock()


def load_rate_key(path: Path) -> bytes:
    """Provision a separate owner-only key atomically across local processes."""
    key_path = path.parent / ".rate-limit-hmac"
    if not key_path.exists():
        descriptor, temporary = tempfile.mkstemp(prefix=".rate-key-", dir=path.parent)
        try:
            with os.fdopen(descriptor, "wb") as stream:
                stream.write(secrets.token_bytes(32))
                stream.flush()
                os.fsync(stream.fileno())
            try:
                # A complete file becomes visible at once; an existing key is never replaced.
                os.link(temporary, key_path)
            except FileExistsError:
                pass
        finally:
            os.unlink(temporary)
    if os.name == "posix":
        key_path.chmod(0o600)
    with key_path.open("rb") as stream:
        key = stream.read(33)
    if len(key) != 32:
        raise RuntimeError("Invalid rate limiter key; operator recovery required")
    return key


def _prune_rate_counters(connection: sqlite3.Connection, now: int) -> None:
    window = now // RATE_COUNTER_RETENTION_SECONDS * RATE_COUNTER_RETENTION_SECONDS
    connection.execute("DELETE FROM rate_counters WHERE window_started_at < ?", (window,))


def consume_rate_limit(path: Path, key: bytes, group: str, address: str, now: int, limit: int) -> bool:
    if group not in _RATE_GROUPS or limit <= 0:
        return False
    window = now // 60 * 60
    source = hmac.new(key, f"{window}:{group}:{address}".encode("utf-8"), hashlib.sha256).hexdigest()
    with _rate_write_lock, closing(sqlite3.connect(path, timeout=1)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _prune_rate_counters(connection, now)
        row = connection.execute(
            "SELECT request_count FROM rate_counters WHERE request_group = ? AND anonymous_source = ? AND window_started_at = ?",
            (group, source, window),
        ).fetchone()
        if row is not None:
            allowed = row[0] < limit
            if allowed:
                connection.execute(
                    "UPDATE rate_counters SET request_count = request_count + 1 "
                    "WHERE request_group = ? AND anonymous_source = ? AND window_started_at = ?", (group, source, window),
                )
        elif connection.execute(
            "SELECT COUNT(*) FROM rate_counters WHERE request_group = ?", (group,),
        ).fetchone()[0] >= RATE_COUNTER_GROUP_MAX_ROWS[group]:
            # Never evict a live counter: doing so would allow a quota bypass.
            allowed = False
        else:
            connection.execute("INSERT INTO rate_counters VALUES (?, ?, ?, 1)", (group, source, window))
            allowed = True
        connection.commit()
        return allowed


def maintenance(path: Path, now: int) -> None:
    with database(path) as connection:
        _prune_security_events(connection, now)
        _prune_rate_counters(connection, now)


def _prune_security_events(connection: sqlite3.Connection, now: int) -> None:
    _prune_security_event_age(connection, now)
    _prune_security_event_excess(connection)


def _prune_security_event_age(connection: sqlite3.Connection, now: int) -> None:
    connection.execute("DELETE FROM security_events WHERE occurred_at <= ?", (now - SECURITY_EVENT_RETENTION_SECONDS,))


def _prune_security_event_excess(connection: sqlite3.Connection) -> None:
    excess = connection.execute("SELECT COUNT(*) FROM security_events").fetchone()[0] - SECURITY_EVENT_MAX_ROWS
    if excess > 0:
        # The (occurred_at, id) index finds only the oldest rows to evict.
        connection.execute(
            "DELETE FROM security_events WHERE id IN (SELECT id FROM security_events "
            "ORDER BY occurred_at, id LIMIT ?)", (excess,),
        )


def record_security_event(path: Path, *, actor_role: str, institution_id: str | None,
                          event_type: str, status_code: int, anonymous_source: str, now: int) -> None:
    # A short busy timeout keeps denial responses available if audit storage is unavailable.
    with closing(sqlite3.connect(path, timeout=0.2)) as connection:
        connection.execute("BEGIN IMMEDIATE")
        _prune_security_event_age(connection, now)
        institution = connection.execute("SELECT id FROM institutions WHERE id = ?", (institution_id,)).fetchone()
        recognized_id = institution[0] if institution else ""
        attempt_count = connection.execute(
            "INSERT INTO security_events (actor_role, institution_id, event_type, status_code, "
            "anonymous_source, window_started_at, occurred_at) VALUES (?, ?, ?, ?, ?, ?, ?) "
            "ON CONFLICT(actor_role, institution_id, event_type, status_code, anonymous_source, window_started_at) "
            "DO UPDATE SET occurred_at = excluded.occurred_at, attempt_count = MIN(attempt_count + 1, 2147483647) "
            "RETURNING attempt_count",
            (actor_role, recognized_id, event_type, status_code, anonymous_source, now // 60 * 60, now),
        ).fetchone()[0]
        if attempt_count == 1:
            # An aggregation update cannot increase the row count. Keep the
            # bounded full-table count out of the repeated failure hot path.
            _prune_security_event_excess(connection)
        connection.commit()


def security_event_summary(path: Path, now: int) -> list[dict]:
    with database(path) as connection:
        _prune_security_events(connection, now)
        rows = connection.execute(
            "SELECT id, actor_role, NULLIF(institution_id, '') AS institution_id, event_type, status_code, "
            "anonymous_source, window_started_at, occurred_at, attempt_count FROM security_events "
            "ORDER BY occurred_at DESC, id DESC LIMIT 100"
        ).fetchall()
        return [dict(row) for row in rows]


def _startup_statement(connection: sqlite3.Connection, statement: str, deadline: float) -> None:
    """Retry only SQLite startup lock contention, with a finite total wait."""
    while True:
        try:
            connection.execute(statement)
            return
        except sqlite3.OperationalError as error:
            code = getattr(error, "sqlite_errorcode", 0) & 0xFF
            if code not in (sqlite3.SQLITE_BUSY, sqlite3.SQLITE_LOCKED) or time.monotonic() >= deadline:
                raise
            time.sleep(min(0.025, max(0, deadline - time.monotonic())))


def _migrate_rate_counter_groups(connection: sqlite3.Connection) -> None:
    schema = connection.execute("SELECT sql FROM sqlite_master WHERE type = 'table' AND name = 'rate_counters'").fetchone()[0]
    if "admin_auth" in schema and "issuer_auth" in schema:
        return
    # SQLite cannot alter a CHECK constraint. Preserve live counts while changing
    # the fixed group allowlist, inside the enclosing startup write transaction.
    connection.execute(f"CREATE TABLE rate_counters_updated ({_RATE_COUNTER_COLUMNS})")
    connection.execute(
        "INSERT INTO rate_counters_updated SELECT request_group,anonymous_source,window_started_at,request_count FROM rate_counters"
    )
    connection.execute("DROP TABLE rate_counters")
    connection.execute("ALTER TABLE rate_counters_updated RENAME TO rate_counters")


def _initialize_backup_identity(connection: sqlite3.Connection, *, table_existed: bool) -> None:
    if not table_existed:
        connection.execute(
            "INSERT OR IGNORE INTO backup_identity(singleton, installation_id) VALUES(1, ?)",
            (secrets.token_hex(32),),
        )
    rows = connection.execute("SELECT singleton,installation_id FROM backup_identity").fetchall()
    if (len(rows) != 1 or rows[0][0] != 1 or not isinstance(rows[0][1], str)
            or re.fullmatch(r"[0-9a-f]{64}", rows[0][1]) is None):
        raise RuntimeError("Invalid backup installation identity; operator recovery required")


def initialize(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    except FileExistsError:
        pass
    else:
        os.close(descriptor)
    if os.name == "posix":
        path.chmod(0o600)
    with closing(sqlite3.connect(path, timeout=0.2)) as connection:
        deadline = time.monotonic() + 5
        connection.execute("PRAGMA foreign_keys=ON")
        # Concurrent first starts can fail the journal-mode transition immediately,
        # even when a busy timeout is configured. Retry only that lock condition.
        _startup_statement(connection, "PRAGMA journal_mode=WAL", deadline)
        _startup_statement(connection, "BEGIN IMMEDIATE", deadline)
        identity_table_existed = connection.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' AND name='backup_identity'"
        ).fetchone() is not None
        # executescript implicitly commits; execute fixed schema statements directly
        # so schema checks, ALTERs and indexes remain serialized in one transaction.
        for statement in SCHEMA.split(";"):
            if statement.strip():
                connection.execute(statement)
        _initialize_backup_identity(connection, table_existed=identity_table_existed)
        _migrate_rate_counter_groups(connection)
        if "disabled" not in {row[1] for row in connection.execute("PRAGMA table_info(institutions)")}:
            connection.execute("ALTER TABLE institutions ADD COLUMN disabled INTEGER NOT NULL DEFAULT 0")
        if "revoked_at" not in {row[1] for row in connection.execute("PRAGMA table_info(signing_keys)")}:
            connection.execute("ALTER TABLE signing_keys ADD COLUMN revoked_at INTEGER")
        qr_columns = {row[1] for row in connection.execute("PRAGMA table_info(issued_qrs)")}
        for name, column_type in (("purpose", "TEXT"), ("issued_at", "INTEGER"), ("expires_at", "INTEGER"), ("key_version", "TEXT")):
            if name not in qr_columns:
                connection.execute(f"ALTER TABLE issued_qrs ADD COLUMN {name} {column_type}")
        connection.execute("CREATE INDEX IF NOT EXISTS issued_qrs_institution ON issued_qrs(institution_id, issued_at)")
        connection.execute("CREATE INDEX IF NOT EXISTS audit_events_institution ON audit_events(institution_id, id)")
        connection.execute("CREATE INDEX IF NOT EXISTS security_events_occurred ON security_events(occurred_at, id)")
        connection.execute("CREATE INDEX IF NOT EXISTS rate_counters_window ON rate_counters(window_started_at)")
        _prune_security_events(connection, int(time.time()))
        _prune_rate_counters(connection, int(time.time()))
        connection.commit()


@contextmanager
def database(path: Path, *, write: bool = True):
    connection = sqlite3.connect(path, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA busy_timeout=5000")
    try:
        # Writers authenticate and change state atomically; readers see one coherent snapshot.
        connection.execute("BEGIN IMMEDIATE" if write else "BEGIN")
        yield connection
        connection.commit()
    except Exception:
        connection.rollback()
        raise
    finally:
        connection.close()
