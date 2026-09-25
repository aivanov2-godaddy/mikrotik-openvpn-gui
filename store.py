from __future__ import annotations

import json
import hashlib
import os
import sqlite3
import threading
import time
import uuid
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Callable, Iterator


class MetadataStore:
    """Stores audit/device metadata only. Password columns intentionally do not exist."""

    def __init__(self, path: str) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.RLock()
        self._readiness_valid_until = 0.0
        self._audit_hook: Callable[[dict[str, Any]], None] | None = None
        self._initialize()
        try:
            os.chmod(self.path, 0o600)
        except OSError:
            pass

    def set_audit_hook(self, hook: Callable[[dict[str, Any]], None] | None) -> None:
        self._audit_hook = hook

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path, timeout=5)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("PRAGMA journal_mode=WAL")
        connection.execute("PRAGMA busy_timeout=5000")
        return connection

    @contextmanager
    def _connection(self) -> Iterator[sqlite3.Connection]:
        connection = self._connect()
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def _initialize(self) -> None:
        with self._connection() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS devices (
                    id TEXT PRIMARY KEY,
                    vpn_user TEXT NOT NULL,
                    device_name TEXT NOT NULL,
                    certificate_name TEXT NOT NULL UNIQUE,
                    certificate_id TEXT,
                    fingerprint TEXT,
                    created_at INTEGER NOT NULL,
                    revoked_at INTEGER
                );

                CREATE TABLE IF NOT EXISTS audit (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    actor TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    status TEXT NOT NULL,
                    details TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS user_metadata (
                    vpn_user TEXT PRIMARY KEY,
                    email TEXT NOT NULL COLLATE NOCASE,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS connection_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id TEXT NOT NULL,
                    vpn_user TEXT NOT NULL,
                    source_address TEXT NOT NULL,
                    vpn_address TEXT NOT NULL,
                    encoding TEXT NOT NULL,
                    connected_at INTEGER NOT NULL,
                    last_seen_at INTEGER NOT NULL,
                    disconnected_at INTEGER,
                    rx_bytes INTEGER NOT NULL DEFAULT 0,
                    tx_bytes INTEGER NOT NULL DEFAULT 0,
                    rx_packets INTEGER NOT NULL DEFAULT 0,
                    tx_packets INTEGER NOT NULL DEFAULT 0
                );

                CREATE TABLE IF NOT EXISTS user_controls (
                    vpn_user TEXT PRIMARY KEY,
                    policy TEXT NOT NULL DEFAULT 'full-tunnel',
                    expires_at INTEGER,
                    max_sessions INTEGER NOT NULL DEFAULT 5,
                    rate_limit_kbps INTEGER NOT NULL DEFAULT 0,
                    dns_mode TEXT NOT NULL DEFAULT 'router',
                    notifications INTEGER NOT NULL DEFAULT 1,
                    quota_mb INTEGER NOT NULL DEFAULT 0,
                    schedule TEXT NOT NULL DEFAULT 'always',
                    enforcement_state TEXT NOT NULL DEFAULT '',
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS alerts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    severity TEXT NOT NULL,
                    action TEXT NOT NULL,
                    target TEXT NOT NULL,
                    title TEXT NOT NULL,
                    details TEXT NOT NULL,
                    acknowledged INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS policy_templates (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    description TEXT NOT NULL,
                    group_name TEXT NOT NULL,
                    controls TEXT NOT NULL,
                    protected INTEGER NOT NULL DEFAULT 0,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS user_policy_templates (
                    vpn_user TEXT PRIMARY KEY,
                    template_id TEXT NOT NULL REFERENCES policy_templates(id),
                    overrides TEXT NOT NULL DEFAULT '[]',
                    assigned_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS profile_migrations (
                    legacy_certificate_name TEXT PRIMARY KEY,
                    vpn_user TEXT NOT NULL,
                    replacement_certificate_name TEXT NOT NULL,
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS deployment_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    version TEXT NOT NULL,
                    revision TEXT NOT NULL,
                    status TEXT NOT NULL,
                    channel TEXT NOT NULL DEFAULT 'runtime',
                    details TEXT NOT NULL DEFAULT '{}',
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS health_snapshots (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    overall TEXT NOT NULL,
                    healthy_count INTEGER NOT NULL DEFAULT 0,
                    warning_count INTEGER NOT NULL DEFAULT 0,
                    unavailable_count INTEGER NOT NULL DEFAULT 0,
                    checks TEXT NOT NULL DEFAULT '[]',
                    created_at INTEGER NOT NULL
                );

                CREATE TABLE IF NOT EXISTS api_tokens (
                    id TEXT PRIMARY KEY,
                    token_hash TEXT NOT NULL UNIQUE,
                    label TEXT NOT NULL,
                    actor TEXT NOT NULL,
                    capabilities TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    expires_at INTEGER,
                    last_used_at INTEGER,
                    revoked_at INTEGER
                );

                CREATE TABLE IF NOT EXISTS user_tags (
                    vpn_user TEXT NOT NULL,
                    tag TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    PRIMARY KEY(vpn_user, tag)
                );

                CREATE TABLE IF NOT EXISTS saved_views (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
                    filters TEXT NOT NULL,
                    created_at INTEGER NOT NULL,
                    updated_at INTEGER NOT NULL
                );

                CREATE INDEX IF NOT EXISTS idx_devices_vpn_user ON devices(vpn_user);
                CREATE INDEX IF NOT EXISTS idx_audit_created_at ON audit(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_connection_history_connected ON connection_history(connected_at DESC);
                CREATE INDEX IF NOT EXISTS idx_connection_history_open ON connection_history(session_id, disconnected_at);
                CREATE INDEX IF NOT EXISTS idx_alerts_created_at ON alerts(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_profile_migrations_user ON profile_migrations(vpn_user);
                CREATE INDEX IF NOT EXISTS idx_deployment_events_created_at ON deployment_events(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_health_snapshots_created_at ON health_snapshots(created_at DESC);
                CREATE INDEX IF NOT EXISTS idx_api_tokens_hash ON api_tokens(token_hash);
                CREATE INDEX IF NOT EXISTS idx_user_tags_tag ON user_tags(tag);
                CREATE INDEX IF NOT EXISTS idx_saved_views_updated_at ON saved_views(updated_at DESC);
                """
            )
            # Existing RouterOS dashboard databases predate quota/schedule
            # controls. Apply additive migrations without touching credentials
            # or historical connection records.
            migrations = {
                "quota_mb": "INTEGER NOT NULL DEFAULT 0",
                "schedule": "TEXT NOT NULL DEFAULT 'always'",
                "enforcement_state": "TEXT NOT NULL DEFAULT ''",
            }
            for column, definition in migrations.items():
                try:
                    connection.execute(
                        f"ALTER TABLE user_controls ADD COLUMN {column} {definition}"
                    )
                except sqlite3.OperationalError as error:
                    if "duplicate column name" not in str(error).lower():
                        raise
            # Older releases used 0 for an unlimited device cap. The product
            # now keeps the simple, bounded 1–5 device model and defaults
            # existing accounts to five concurrent sessions.
            connection.execute("UPDATE user_controls SET max_sessions=5 WHERE max_sessions=0")
            now = int(time.time())
            for template in self._built_in_templates():
                connection.execute(
                    """
                    INSERT OR IGNORE INTO policy_templates(
                        id, name, description, group_name, controls, protected, created_at, updated_at
                    ) VALUES (?, ?, ?, ?, ?, 1, ?, ?)
                    """,
                    (
                        template["id"], template["name"], template["description"], template["group_name"],
                        json.dumps(template["controls"], separators=(",", ":"), sort_keys=True), now, now,
                    ),
                )

    @staticmethod
    def _built_in_templates() -> tuple[dict[str, Any], ...]:
        """Small, conservative defaults that administrators may copy but not overwrite."""
        return (
            {
                "id": "standard", "name": "Standard", "group_name": "Employees",
                "description": "Full VPN access with the normal five-device allowance.",
                "controls": {"policy": "full-tunnel", "expires_at": None, "max_sessions": 5,
                             "rate_limit_kbps": 0, "dns_mode": "router", "notifications": True,
                             "quota_mb": 0, "schedule": "always"},
            },
            {
                "id": "contractor", "name": "Contractor", "group_name": "Contractors",
                "description": "Time-limited-style LAN access with a controlled device and speed allowance.",
                "controls": {"policy": "lan-only", "expires_at": None, "max_sessions": 2,
                             "rate_limit_kbps": 10240, "dns_mode": "router", "notifications": True,
                             "quota_mb": 10240, "schedule": "weekdays"},
            },
            {
                "id": "admin", "name": "Administrator", "group_name": "Administrators",
                "description": "Unrestricted route and device policy for trusted administrators.",
                "controls": {"policy": "full-tunnel", "expires_at": None, "max_sessions": 5,
                             "rate_limit_kbps": 0, "dns_mode": "router", "notifications": True,
                             "quota_mb": 0, "schedule": "always"},
            },
        )

    def verify_readiness(self) -> None:
        """Raise unless SQLite passes a quick check and a rolled-back write."""
        with self._lock:
            if time.monotonic() < self._readiness_valid_until:
                return
            connection = self._connect()
            transaction_started = False
            try:
                integrity = connection.execute("PRAGMA quick_check").fetchall()
                if len(integrity) != 1 or str(integrity[0][0]).lower() != "ok":
                    raise sqlite3.DatabaseError("SQLite quick check failed")

                connection.execute("BEGIN IMMEDIATE")
                transaction_started = True
                connection.execute(
                    """
                    INSERT INTO audit(actor, action, target, status, details, created_at)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    ("readiness", "database.probe", "local", "success", "{}", 0),
                )
            finally:
                if transaction_started:
                    connection.rollback()
                connection.close()
            self._readiness_valid_until = time.monotonic() + 10.0

    @staticmethod
    def _control_defaults(username: str) -> dict[str, Any]:
        return {
            "vpn_user": username,
            "policy": "full-tunnel",
            "expires_at": None,
            "max_sessions": 5,
            "rate_limit_kbps": 0,
            "dns_mode": "router",
            "notifications": True,
            "quota_mb": 0,
            "schedule": "always",
            "enforcement_state": "",
            "updated_at": 0,
        }

    def user_controls(self, vpn_user: str) -> dict[str, Any]:
        username = str(vpn_user)
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM user_controls WHERE vpn_user=?", (username,)
            ).fetchone()
        if not row:
            return self._control_defaults(username)
        value = dict(row)
        value["notifications"] = bool(value.get("notifications"))
        return value

    def all_user_controls(self) -> dict[str, dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM user_controls")
            values = {}
            for row in rows:
                value = dict(row)
                value["notifications"] = bool(value.get("notifications"))
                values[str(value["vpn_user"])] = value
            return values

    def set_user_controls(
        self,
        vpn_user: str,
        *,
        policy: str,
        expires_at: int | None,
        max_sessions: int,
        rate_limit_kbps: int,
        dns_mode: str,
        notifications: bool,
        quota_mb: int = 0,
        schedule: str = "always",
    ) -> dict[str, Any]:
        now = int(time.time())
        values = (
            str(vpn_user), policy, expires_at, max(1, min(5, int(max_sessions))),
            max(0, int(rate_limit_kbps)), dns_mode, 1 if notifications else 0,
            max(0, int(quota_mb)), str(schedule), now,
        )
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO user_controls(
                    vpn_user, policy, expires_at, max_sessions, rate_limit_kbps,
                    dns_mode, notifications, quota_mb, schedule, updated_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(vpn_user) DO UPDATE SET
                    policy=excluded.policy, expires_at=excluded.expires_at,
                    max_sessions=excluded.max_sessions,
                    rate_limit_kbps=excluded.rate_limit_kbps,
                    dns_mode=excluded.dns_mode,
                    notifications=excluded.notifications,
                    quota_mb=excluded.quota_mb,
                    schedule=excluded.schedule,
                    updated_at=excluded.updated_at
                """,
                values,
            )
        return self.user_controls(str(vpn_user))

    def set_enforcement_state(self, vpn_user: str, state: str) -> None:
        with self._lock, self._connection() as connection:
            connection.execute(
                "UPDATE user_controls SET enforcement_state=?, updated_at=? WHERE vpn_user=?",
                (str(state), int(time.time()), str(vpn_user)),
            )

    def quota_usage(self, vpn_user: str, since: int) -> int:
        with self._connection() as connection:
            row = connection.execute(
                """
                SELECT COALESCE(SUM(rx_bytes + tx_bytes), 0) AS total
                FROM connection_history
                WHERE vpn_user=? AND connected_at>=?
                """,
                (str(vpn_user), int(since)),
            ).fetchone()
        return int(row["total"] if row else 0)

    def usage_summary(self, since: int) -> dict[str, dict[str, Any]]:
        """Return observed traffic totals for each user since ``since``.

        This is an operational report built from the connection ledger, not a
        billing meter. It stores no packet payloads or VPN credentials.
        """
        with self._connection() as connection:
            rows = connection.execute(
                """
                SELECT
                    vpn_user,
                    COUNT(*) AS connection_count,
                    COALESCE(SUM(rx_bytes), 0) AS rx_bytes,
                    COALESCE(SUM(tx_bytes), 0) AS tx_bytes,
                    COALESCE(SUM(rx_packets), 0) AS rx_packets,
                    COALESCE(SUM(tx_packets), 0) AS tx_packets,
                    MAX(last_seen_at) AS last_seen_at
                FROM connection_history
                WHERE connected_at >= ?
                GROUP BY vpn_user
                ORDER BY (COALESCE(SUM(rx_bytes), 0) + COALESCE(SUM(tx_bytes), 0)) DESC, vpn_user
                """,
                (int(since),),
            )
            return {str(row["vpn_user"]): dict(row) for row in rows}

    @staticmethod
    def _template_row(row: sqlite3.Row | None) -> dict[str, Any] | None:
        if not row:
            return None
        value = dict(row)
        try:
            value["controls"] = json.loads(str(value["controls"]))
        except (TypeError, ValueError, json.JSONDecodeError):
            value["controls"] = {}
        value["protected"] = bool(value.get("protected"))
        return value

    def list_policy_templates(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM policy_templates ORDER BY protected DESC, name COLLATE NOCASE"
            ).fetchall()
        return [value for row in rows if (value := self._template_row(row)) is not None]

    def policy_template(self, template_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM policy_templates WHERE id=?", (str(template_id),)
            ).fetchone()
        return self._template_row(row)

    def save_policy_template(
        self,
        *,
        template_id: str,
        name: str,
        description: str,
        group_name: str,
        controls: dict[str, Any],
    ) -> dict[str, Any]:
        now = int(time.time())
        with self._lock, self._connection() as connection:
            existing = connection.execute(
                "SELECT protected FROM policy_templates WHERE id=?", (str(template_id),)
            ).fetchone()
            if existing and bool(existing["protected"]):
                raise ValueError("Built-in templates cannot be changed; create a custom copy instead")
            connection.execute(
                """
                INSERT INTO policy_templates(id, name, description, group_name, controls, protected, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?, 0, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, description=excluded.description, group_name=excluded.group_name,
                    controls=excluded.controls, updated_at=excluded.updated_at
                """,
                (
                    str(template_id), str(name), str(description), str(group_name),
                    json.dumps(controls, separators=(",", ":"), sort_keys=True), now, now,
                ),
            )
        template = self.policy_template(str(template_id))
        if template is None:
            raise RuntimeError("Policy template could not be saved")
        return template

    def user_template_assignments(self) -> dict[str, dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute("SELECT * FROM user_policy_templates").fetchall()
        values: dict[str, dict[str, Any]] = {}
        for row in rows:
            value = dict(row)
            try:
                value["overrides"] = json.loads(str(value.get("overrides", "[]")))
            except (TypeError, ValueError, json.JSONDecodeError):
                value["overrides"] = []
            values[str(value["vpn_user"])] = value
        return values

    def assign_policy_template(self, vpn_user: str, template_id: str, *, overrides: list[str] | None = None) -> None:
        now = int(time.time())
        safe_overrides = [str(item) for item in (overrides or []) if str(item)]
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO user_policy_templates(vpn_user, template_id, overrides, assigned_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(vpn_user) DO UPDATE SET
                    template_id=excluded.template_id, overrides=excluded.overrides, updated_at=excluded.updated_at
                """,
                (str(vpn_user), str(template_id), json.dumps(safe_overrides), now, now),
            )

    def clear_policy_template_assignment(self, vpn_user: str) -> None:
        with self._lock, self._connection() as connection:
            connection.execute("DELETE FROM user_policy_templates WHERE vpn_user=?", (str(vpn_user),))

    def delete_user_controls(self, vpn_user: str) -> None:
        with self._lock, self._connection() as connection:
            connection.execute("DELETE FROM user_controls WHERE vpn_user=?", (str(vpn_user),))

    def user_tags(self, vpn_user: str) -> list[str]:
        """Return dashboard-only tags for a VPN user.

        Tags are intentionally kept in the metadata store. They are operator
        labels, not RouterOS comments, credentials, certificates, or profile
        contents.
        """
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT tag FROM user_tags WHERE vpn_user=? ORDER BY tag COLLATE NOCASE",
                (str(vpn_user),),
            ).fetchall()
            return [str(row["tag"]) for row in rows]

    def all_user_tags(self) -> dict[str, list[str]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT vpn_user, tag FROM user_tags ORDER BY vpn_user COLLATE NOCASE, tag COLLATE NOCASE"
            )
            values: dict[str, list[str]] = {}
            for row in rows:
                values.setdefault(str(row["vpn_user"]), []).append(str(row["tag"]))
            return values

    def add_user_tag(self, vpn_user: str, tag: str) -> bool:
        """Add a tag and report whether it changed state."""
        with self._lock, self._connection() as connection:
            cursor = connection.execute(
                "INSERT OR IGNORE INTO user_tags(vpn_user, tag, created_at) VALUES (?, ?, ?)",
                (str(vpn_user), str(tag), int(time.time())),
            )
            return cursor.rowcount > 0

    def remove_user_tags(self, vpn_user: str) -> None:
        with self._lock, self._connection() as connection:
            connection.execute("DELETE FROM user_tags WHERE vpn_user=?", (str(vpn_user),))

    def saved_views(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT id, name, filters, created_at, updated_at FROM saved_views ORDER BY updated_at DESC, name COLLATE NOCASE"
            )
            values = []
            for row in rows:
                try:
                    filters = json.loads(str(row["filters"]))
                except (TypeError, json.JSONDecodeError):
                    filters = {}
                values.append({
                    "id": str(row["id"]),
                    "name": str(row["name"]),
                    "filters": filters if isinstance(filters, dict) else {},
                    "created_at": int(row["created_at"]),
                    "updated_at": int(row["updated_at"]),
                })
            return values

    def save_view(self, *, name: str, filters: dict[str, Any], view_id: str | None = None) -> dict[str, Any]:
        safe_name = str(name).strip()
        if not 2 <= len(safe_name) <= 64:
            raise ValueError("Saved view names must be between 2 and 64 characters")
        view_id = str(view_id or f"view-{uuid.uuid4().hex[:16]}")
        now = int(time.time())
        serialized = json.dumps(filters, separators=(",", ":"), sort_keys=True)
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO saved_views(id, name, filters, created_at, updated_at)
                VALUES (?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    name=excluded.name, filters=excluded.filters, updated_at=excluded.updated_at
                """,
                (view_id, safe_name, serialized, now, now),
            )
            row = connection.execute(
                "SELECT id, name, filters, created_at, updated_at FROM saved_views WHERE id=?",
                (view_id,),
            ).fetchone()
        if not row:
            raise RuntimeError("Saved view could not be stored")
        return {
            "id": str(row["id"]), "name": str(row["name"]),
            "filters": json.loads(str(row["filters"])),
            "created_at": int(row["created_at"]), "updated_at": int(row["updated_at"]),
        }

    def delete_view(self, view_id: str) -> bool:
        with self._lock, self._connection() as connection:
            cursor = connection.execute("DELETE FROM saved_views WHERE id=?", (str(view_id),))
            return cursor.rowcount > 0

    def add_alert(
        self,
        *,
        severity: str,
        action: str,
        target: str,
        title: str,
        details: str,
        now: int | None = None,
    ) -> bool:
        created = int(time.time() if now is None else now)
        with self._lock, self._connection() as connection:
            duplicate = connection.execute(
                """
                SELECT 1 FROM alerts
                WHERE action=? AND target=? AND acknowledged=0 AND created_at>?
                LIMIT 1
                """,
                (action, target, created - 3600),
            ).fetchone()
            if duplicate:
                return False
            connection.execute(
                """
                INSERT INTO alerts(severity, action, target, title, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (severity, action, target, title, details, created),
            )
            return True

    def recent_alerts(self, limit: int = 20, *, include_acknowledged: bool = False) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 100))
        with self._connection() as connection:
            where = "" if include_acknowledged else "WHERE acknowledged=0"
            rows = connection.execute(
                f"SELECT * FROM alerts {where} ORDER BY id DESC LIMIT ?", (safe_limit,)
            )
            return [dict(row) for row in rows]

    def acknowledge_alert(self, alert_id: int) -> None:
        with self._lock, self._connection() as connection:
            connection.execute("UPDATE alerts SET acknowledged=1 WHERE id=?", (int(alert_id),))

    def set_user_email(self, vpn_user: str, email: str) -> None:
        now = int(time.time())
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO user_metadata(vpn_user, email, created_at, updated_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(vpn_user) DO UPDATE SET
                    email=excluded.email,
                    updated_at=excluded.updated_at
                """,
                (vpn_user, email, now, now),
            )

    def user_emails(self) -> dict[str, str]:
        with self._connection() as connection:
            rows = connection.execute("SELECT vpn_user, email FROM user_metadata")
            return {str(row["vpn_user"]): str(row["email"]) for row in rows}

    def backup_snapshot(self) -> dict[str, Any]:
        """Return portable dashboard metadata, never RouterOS credentials or profiles.

        The database intentionally has no password or private-key columns.  This
        explicit allow-list also prevents future operational tables from being
        silently included in a recovery archive.
        """
        tables = (
            "devices", "profile_migrations", "user_metadata", "user_controls", "alerts",
            "policy_templates", "user_policy_templates", "audit", "connection_history",
            "deployment_events", "health_snapshots",
        )
        with self._connection() as connection:
            snapshot = {
                table: [dict(row) for row in connection.execute(f"SELECT * FROM {table} ORDER BY rowid")]
                for table in tables
            }
        return {"format": "mikrotik-openvpn-gui-metadata", "version": 1, "tables": snapshot}

    def record_deployment_event(
        self,
        *,
        version: str,
        revision: str,
        status: str = "running",
        channel: str = "runtime",
        details: dict[str, Any] | None = None,
        now: int | None = None,
    ) -> None:
        """Record non-secret runtime release identity for local observability.

        This is deliberately a metadata-only ledger.  It never stores image
        credentials, RouterOS configuration, certificates, or application data.
        Duplicate startup observations for the same revision are coalesced for a
        short window so health polling cannot create noisy deployment history.
        """
        created = int(time.time() if now is None else now)
        safe_version = str(version or "unknown")[:64]
        safe_revision = str(revision or "unknown")[:128]
        safe_status = str(status or "unknown")[:32]
        safe_channel = str(channel or "runtime")[:32]
        forbidden = {"password", "passphrase", "private_key", "authorization", "secret", "token"}
        safe_details = {
            str(key): value for key, value in (details or {}).items()
            if str(key).lower() not in forbidden
        }
        with self._lock, self._connection() as connection:
            duplicate = connection.execute(
                """
                SELECT 1 FROM deployment_events
                WHERE version=? AND revision=? AND status=? AND channel=? AND created_at>?
                LIMIT 1
                """,
                (safe_version, safe_revision, safe_status, safe_channel, created - 300),
            ).fetchone()
            if duplicate:
                return
            connection.execute(
                """
                INSERT INTO deployment_events(version, revision, status, channel, details, created_at)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    safe_version,
                    safe_revision,
                    safe_status,
                    safe_channel,
                    json.dumps(safe_details, separators=(",", ":"), sort_keys=True),
                    created,
                ),
            )

    def recent_deployment_events(self, limit: int = 20) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 100))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM deployment_events ORDER BY id DESC LIMIT ?", (safe_limit,)
            )
            values = []
            for row in rows:
                value = dict(row)
                try:
                    value["details"] = json.loads(str(value.get("details", "{}")))
                except (TypeError, ValueError, json.JSONDecodeError):
                    value["details"] = {}
                values.append(value)
            return values

    def record_health_snapshot(self, health: dict[str, Any], *, now: int | None = None) -> None:
        """Persist a compact, non-secret health observation for the timeline."""
        checks = list(health.get("checks") or [])
        counts = {
            state: sum(1 for item in checks if str(item.get("status", "")) == state)
            for state in ("healthy", "warning", "unavailable")
        }
        created = int(time.time() if now is None else now)
        # Keep check labels and outcomes, not remediation strings that may grow
        # over time. This makes the timeline cheap and stable to render.
        safe_checks = [
            {"id": str(item.get("id", ""))[:64], "status": str(item.get("status", "unavailable"))[:24]}
            for item in checks
        ]
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO health_snapshots(
                    overall, healthy_count, warning_count, unavailable_count, checks, created_at
                ) VALUES (?, ?, ?, ?, ?, ?)
                """,
                (
                    str(health.get("overall", "unavailable"))[:24],
                    counts["healthy"],
                    counts["warning"],
                    counts["unavailable"],
                    json.dumps(safe_checks, separators=(",", ":"), sort_keys=True),
                    created,
                ),
            )

    def recent_health_snapshots(self, limit: int = 30) -> list[dict[str, Any]]:
        safe_limit = max(1, min(int(limit), 100))
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM health_snapshots ORDER BY id DESC LIMIT ?", (safe_limit,)
            )
            values = []
            for row in rows:
                value = dict(row)
                try:
                    value["checks"] = json.loads(str(value.get("checks", "[]")))
                except (TypeError, ValueError, json.JSONDecodeError):
                    value["checks"] = []
                values.append(value)
            return values

    def delete_user_email(self, vpn_user: str) -> None:
        with self._lock, self._connection() as connection:
            connection.execute("DELETE FROM user_metadata WHERE vpn_user=?", (vpn_user,))

    def add_device(
        self,
        *,
        device_id: str,
        vpn_user: str,
        device_name: str,
        certificate_name: str,
        certificate_id: str | None,
        fingerprint: str | None,
    ) -> None:
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO devices(
                    id, vpn_user, device_name, certificate_name,
                    certificate_id, fingerprint, created_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    device_id,
                    vpn_user,
                    device_name,
                    certificate_name,
                    certificate_id,
                    fingerprint,
                    int(time.time()),
                ),
            )

    def devices_for_user(self, vpn_user: str, include_revoked: bool = False) -> list[dict[str, Any]]:
        query = "SELECT * FROM devices WHERE vpn_user=?"
        if not include_revoked:
            query += " AND revoked_at IS NULL"
        query += " ORDER BY created_at DESC"
        with self._connection() as connection:
            return [dict(row) for row in connection.execute(query, (vpn_user,))]

    def active_devices(self) -> list[dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM devices WHERE revoked_at IS NULL ORDER BY created_at DESC"
            )
            return [dict(row) for row in rows]

    def device_by_id(self, device_id: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute("SELECT * FROM devices WHERE id=?", (device_id,)).fetchone()
            return dict(row) if row else None

    def device_by_certificate(self, certificate_name: str) -> dict[str, Any] | None:
        with self._connection() as connection:
            row = connection.execute(
                "SELECT * FROM devices WHERE certificate_name=?", (certificate_name,)
            ).fetchone()
            return dict(row) if row else None

    def mark_revoked(self, device_id: str) -> None:
        with self._lock, self._connection() as connection:
            connection.execute(
                "UPDATE devices SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                (int(time.time()), device_id),
            )

    def record_profile_migration(
        self, *, legacy_certificate_name: str, vpn_user: str, replacement_certificate_name: str
    ) -> None:
        """Record a replacement without storing any profile material or secrets."""
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO profile_migrations(
                    legacy_certificate_name, vpn_user, replacement_certificate_name, created_at
                ) VALUES (?, ?, ?, ?)
                ON CONFLICT(legacy_certificate_name) DO UPDATE SET
                    vpn_user=excluded.vpn_user,
                    replacement_certificate_name=excluded.replacement_certificate_name,
                    created_at=excluded.created_at
                """,
                (legacy_certificate_name, vpn_user, replacement_certificate_name, int(time.time())),
            )

    def profile_migrations(self) -> dict[str, dict[str, Any]]:
        with self._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM profile_migrations ORDER BY created_at DESC"
            )
            return {str(row["legacy_certificate_name"]): dict(row) for row in rows}

    def audit(
        self,
        *,
        actor: str,
        action: str,
        target: str,
        status: str,
        details: dict[str, Any] | None = None,
    ) -> None:
        safe_details = details or {}
        forbidden = {
            "password", "passphrase", "private_key", "authorization", "secret",
            "token", "cookie", "credential", "private-key", "api_key", "api-key",
        }
        sanitized = {key: value for key, value in safe_details.items() if key.lower() not in forbidden}
        with self._lock, self._connection() as connection:
            connection.execute(
                "INSERT INTO audit(actor, action, target, status, details, created_at) VALUES (?, ?, ?, ?, ?, ?)",
                (
                    actor,
                    action,
                    target,
                    status,
                    json.dumps(sanitized, separators=(",", ":"), sort_keys=True),
                    int(time.time()),
                ),
            )
        if self._audit_hook:
            try:
                self._audit_hook({"event": "audit", "actor": actor, "action": action, "target": target, "status": status, "details": sanitized, "created_at": int(time.time())})
            except Exception:
                pass

    def recent_audit(
        self, limit: int = 25, *, start_at: int | None = None, end_at: int | None = None
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 100))
        clauses: list[str] = []
        values: list[int] = []
        if start_at is not None:
            clauses.append("created_at >= ?")
            values.append(int(start_at))
        if end_at is not None:
            clauses.append("created_at < ?")
            values.append(int(end_at))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT actor, action, target, status, details, created_at FROM audit{where} ORDER BY id DESC LIMIT ?",
                [*values, safe_limit],
            )
            return [dict(row) for row in rows]

    def create_api_token(
        self,
        *,
        token_id: str,
        token_hash: str,
        label: str,
        actor: str,
        capabilities: list[str],
        expires_at: int | None,
        now: int | None = None,
    ) -> dict[str, Any]:
        """Persist only a one-way token hash and its bounded metadata."""
        created = int(time.time() if now is None else now)
        safe_label = str(label).strip()[:80]
        safe_actor = str(actor).strip()[:64]
        safe_capabilities = sorted({str(item).strip() for item in capabilities if str(item).strip()})
        if not safe_label or not safe_actor or not token_id or not token_hash:
            raise ValueError("Token metadata is incomplete")
        with self._lock, self._connection() as connection:
            connection.execute(
                """
                INSERT INTO api_tokens(id, token_hash, label, actor, capabilities, created_at, expires_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (token_id, token_hash, safe_label, safe_actor, json.dumps(safe_capabilities), created, expires_at),
            )
        return {
            "id": token_id,
            "label": safe_label,
            "actor": safe_actor,
            "capabilities": safe_capabilities,
            "created_at": created,
            "expires_at": expires_at,
            "last_used_at": None,
            "revoked_at": None,
        }

    def list_api_tokens(self, *, include_revoked: bool = False) -> list[dict[str, Any]]:
        where = "" if include_revoked else " WHERE revoked_at IS NULL"
        with self._connection() as connection:
            rows = connection.execute(f"SELECT id, label, actor, capabilities, created_at, expires_at, last_used_at, revoked_at FROM api_tokens{where} ORDER BY created_at DESC")
            values = []
            for row in rows:
                item = dict(row)
                try:
                    item["capabilities"] = json.loads(item.get("capabilities") or "[]")
                except (TypeError, json.JSONDecodeError):
                    item["capabilities"] = []
                values.append(item)
            return values

    def authenticate_api_token(self, token: str, *, now: int | None = None) -> dict[str, Any] | None:
        """Resolve a bearer token without ever persisting or returning plaintext."""
        candidate = str(token or "").strip()
        if not candidate or len(candidate) > 256:
            return None
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        current = int(time.time() if now is None else now)
        with self._lock, self._connection() as connection:
            row = connection.execute(
                "SELECT id, label, actor, capabilities, expires_at FROM api_tokens WHERE token_hash=? AND revoked_at IS NULL",
                (digest,),
            ).fetchone()
            if row is None or (row["expires_at"] is not None and int(row["expires_at"]) <= current):
                return None
            connection.execute("UPDATE api_tokens SET last_used_at=? WHERE id=?", (current, row["id"]))
            try:
                capabilities = json.loads(row["capabilities"] or "[]")
            except (TypeError, json.JSONDecodeError):
                capabilities = []
            return {
                "id": str(row["id"]),
                "label": str(row["label"]),
                "actor": str(row["actor"]),
                "capabilities": sorted({str(item) for item in capabilities}),
                "expires_at": row["expires_at"],
            }

    def revoke_api_token(self, token_id: str, *, now: int | None = None) -> bool:
        current = int(time.time() if now is None else now)
        with self._lock, self._connection() as connection:
            changed = connection.execute(
                "UPDATE api_tokens SET revoked_at=? WHERE id=? AND revoked_at IS NULL",
                (current, str(token_id)),
            ).rowcount
            return bool(changed)

    @staticmethod
    def _uptime_seconds(value: str) -> int:
        units = {"w": 604800, "d": 86400, "h": 3600, "m": 60, "s": 1}
        amount = 0
        digits = ""
        for character in str(value):
            if character.isdigit():
                digits += character
            elif character in units and digits:
                amount += int(digits) * units[character]
                digits = ""
        return amount

    def observe_sessions(self, sessions: list[dict[str, Any]], now: int | None = None) -> None:
        observed_at = int(time.time() if now is None else now)
        incoming = {str(item.get("id", "")): item for item in sessions if item.get("id")}
        with self._lock, self._connection() as connection:
            open_rows = {
                str(row["session_id"]): dict(row)
                for row in connection.execute(
                    "SELECT * FROM connection_history WHERE disconnected_at IS NULL"
                )
            }
            for session_id, item in incoming.items():
                values = (
                    str(item.get("source_address", "")),
                    str(item.get("vpn_address", "")),
                    str(item.get("encoding", "")),
                    observed_at,
                    int(item.get("rx_bytes", 0) or 0),
                    int(item.get("tx_bytes", 0) or 0),
                    int(item.get("rx_packets", 0) or 0),
                    int(item.get("tx_packets", 0) or 0),
                )
                if session_id in open_rows:
                    connection.execute(
                        """
                        UPDATE connection_history SET
                            source_address=?, vpn_address=?, encoding=?, last_seen_at=?,
                            rx_bytes=?, tx_bytes=?, rx_packets=?, tx_packets=?
                        WHERE id=?
                        """,
                        (*values, int(open_rows[session_id]["id"])),
                    )
                else:
                    connected_at = max(
                        0, observed_at - self._uptime_seconds(str(item.get("uptime", "")))
                    )
                    connection.execute(
                        """
                        INSERT INTO connection_history(
                            session_id, vpn_user, source_address, vpn_address, encoding,
                            connected_at, last_seen_at, rx_bytes, tx_bytes, rx_packets, tx_packets
                        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                        """,
                        (
                            session_id,
                            str(item.get("name", "")),
                            values[0], values[1], values[2], connected_at,
                            values[3], values[4], values[5], values[6], values[7],
                        ),
                    )
            for session_id, row in open_rows.items():
                if session_id not in incoming:
                    connection.execute(
                        "UPDATE connection_history SET disconnected_at=? WHERE id=?",
                        (observed_at, int(row["id"])),
                    )

    def recent_connections(
        self, limit: int = 50, *, start_at: int | None = None, end_at: int | None = None
    ) -> list[dict[str, Any]]:
        safe_limit = max(1, min(limit, 250))
        clauses: list[str] = []
        values: list[int] = []
        if start_at is not None:
            clauses.append("connected_at >= ?")
            values.append(int(start_at))
        if end_at is not None:
            clauses.append("connected_at < ?")
            values.append(int(end_at))
        where = f" WHERE {' AND '.join(clauses)}" if clauses else ""
        with self._connection() as connection:
            rows = connection.execute(
                f"SELECT * FROM connection_history{where} ORDER BY connected_at DESC, id DESC LIMIT ?",
                [*values, safe_limit],
            )
            return [dict(row) for row in rows]

    def prune_history(self, *, before: int) -> dict[str, int]:
        """Prune dashboard metadata only; RouterOS users and certificates are untouched."""
        with self._lock, self._connection() as connection:
            audit = connection.execute("DELETE FROM audit WHERE created_at < ?", (int(before),)).rowcount
            connections = connection.execute(
                "DELETE FROM connection_history WHERE disconnected_at IS NOT NULL AND disconnected_at < ?",
                (int(before),),
            ).rowcount
            deployments = connection.execute(
                "DELETE FROM deployment_events WHERE created_at < ?", (int(before),)
            ).rowcount
            health = connection.execute(
                "DELETE FROM health_snapshots WHERE created_at < ?", (int(before),)
            ).rowcount
        return {
            "audit": max(0, audit),
            "connections": max(0, connections),
            "deployments": max(0, deployments),
            "health": max(0, health),
        }

    def connection_summaries(self) -> dict[str, dict[str, Any]]:
        with self._connection() as connection:
            summaries = {
                str(row["vpn_user"]): dict(row)
                for row in connection.execute(
                    """
                    SELECT
                        vpn_user,
                        COUNT(*) AS connection_count,
                        MAX(last_seen_at) AS last_seen_at,
                        SUM(rx_bytes + tx_bytes) AS total_bytes,
                        SUM(rx_packets + tx_packets) AS total_packets,
                        SUM(CASE WHEN disconnected_at IS NULL THEN 1 ELSE 0 END) AS active_connections
                    FROM connection_history
                    GROUP BY vpn_user
                    """
                )
            }
            latest_rows = connection.execute(
                """
                SELECT history.*
                FROM connection_history AS history
                INNER JOIN (
                    SELECT vpn_user, MAX(id) AS latest_id
                    FROM connection_history
                    GROUP BY vpn_user
                ) AS latest ON latest.latest_id = history.id
                """
            )
            for row in latest_rows:
                username = str(row["vpn_user"])
                if username not in summaries:
                    continue
                summaries[username].update(
                    {
                        "last_source_address": row["source_address"],
                        "last_vpn_address": row["vpn_address"],
                        "last_connected_at": row["connected_at"],
                        "last_disconnected_at": row["disconnected_at"],
                        "last_encoding": row["encoding"],
                    }
                )
            return summaries
