from __future__ import annotations

import tempfile
import time
import hashlib
import unittest
from pathlib import Path
from unittest import mock

from security import (
    LoginRateLimiter,
    SessionStore,
    csrf_matches,
    has_capability,
    normalize_role,
    role_label,
)
from store import MetadataStore
from templates import _certificate_expiry, _router_uptime
from app import simultaneous_session_sources


class SecurityTests(unittest.TestCase):
    def test_dashboard_role_capability_matrix_fails_closed(self) -> None:
        self.assertEqual(normalize_role("operator"), "administrator")
        self.assertEqual(normalize_role("viewer"), "read_only")
        self.assertEqual(normalize_role("unrecognised-group"), "read_only")
        self.assertEqual(role_label("security-operator"), "Security operator")
        self.assertTrue(has_capability("owner", "anything.new"))
        self.assertTrue(has_capability("security_operator", "device.manage"))
        self.assertFalse(has_capability("security_operator", "users.manage"))
        self.assertTrue(has_capability("administrator", "users.manage"))
        self.assertFalse(has_capability("administrator", "device.manage"))
        self.assertTrue(has_capability("auditor", "audit.read"))
        self.assertFalse(has_capability("auditor", "users.manage"))
        self.assertFalse(has_capability("read_only", "audit.read"))

    def test_session_store_normalizes_legacy_roles(self) -> None:
        session = SessionStore().create("admin", "secret", role="operator")
        self.assertEqual(session.role, "administrator")

    def test_router_uptime_display(self) -> None:
        self.assertEqual(_router_uptime("1d22h44m45s"), "1d 22:44:45s")
        self.assertEqual(_router_uptime("1w2d3h4m5s"), "9d 03:04:05s")
        self.assertEqual(_router_uptime("8m12s"), "00:08:12s")
        self.assertEqual(_router_uptime("unknown"), "unknown")

    def test_certificate_lifecycle_display(self) -> None:
        expiry = int(time.mktime(time.strptime("2030-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")))
        self.assertEqual(_certificate_expiry("2030-01-01 00:00:00", expiry - 10 * 86400), ("Expires in 10 days", "warning"))
        self.assertEqual(_certificate_expiry("2030-01-01 00:00:00", expiry + 86400), ("Expired", "expired"))
        self.assertEqual(_certificate_expiry("not-a-date", expiry), ("Expiry unknown", "warning"))

    def test_simultaneous_source_detection_is_grouped_and_non_destructive(self) -> None:
        sessions = [
            {"name": "user-one", "source_address": "198.51.100.8"},
            {"name": "user-one", "source_address": "203.0.113.9"},
            {"name": "user-two", "source_address": "198.51.100.10"},
            {"name": "missing-source"},
        ]
        self.assertEqual(
            simultaneous_session_sources(sessions),
            {"user-one": ("198.51.100.8", "203.0.113.9")},
        )

    def test_session_idle_and_absolute_expiry(self) -> None:
        store = SessionStore(idle_seconds=10, absolute_seconds=30)
        session = store.create("admin", "secret", now=100)
        self.assertIsNotNone(store.get(session.session_id, now=109))
        self.assertIsNone(store.get(session.session_id, now=120))

        session = store.create("admin", "secret", now=200)
        self.assertIsNone(store.get(session.session_id, now=231))

    def test_session_snapshot_is_safe_and_revoke_is_scoped(self) -> None:
        store = SessionStore(idle_seconds=60, absolute_seconds=600)
        first = store.create("admin", "router-secret", now=100, source_address="192.0.2.10", user_agent="Test browser")
        second = store.create("auditor", "another-secret", now=110, role="auditor")
        snapshot = store.snapshot(current_session_id=first.session_id, now=120)
        self.assertEqual(len(snapshot), 2)
        first_view = next(item for item in snapshot if item["id_hash"] == hashlib.sha256(first.session_id.encode()).hexdigest()[:16])
        self.assertTrue(first_view["current"])
        self.assertEqual(first_view["id"], "")
        self.assertNotIn(first.session_id, str(snapshot))
        identified = store.snapshot(current_session_id=first.session_id, now=120, include_identifiers=True)
        self.assertEqual(next(item for item in identified if item["id"] == first.session_id)["id"], first.session_id)
        self.assertNotIn("password", str(snapshot).lower())
        self.assertTrue(store.revoke(second.session_id))
        self.assertFalse(store.revoke(second.session_id))

    def test_csrf_comparison(self) -> None:
        self.assertTrue(csrf_matches("token", "token"))
        self.assertFalse(csrf_matches("token", "wrong"))
        self.assertFalse(csrf_matches("", ""))

    def test_rate_limit(self) -> None:
        limiter = LoginRateLimiter(limit=2, window_seconds=10)
        self.assertTrue(limiter.allow("ip", now=1))
        limiter.fail("ip", now=1)
        limiter.fail("ip", now=2)
        self.assertFalse(limiter.allow("ip", now=3))
        self.assertTrue(limiter.allow("ip", now=12.1))

    def test_api_token_storage_never_returns_plaintext(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            plaintext = "vpt_test-secret"
            token = store.create_api_token(
                token_id="token-1",
                token_hash=hashlib.sha256(plaintext.encode()).hexdigest(),
                label="metrics",
                actor="admin",
                capabilities=["health.read"],
                expires_at=500,
                now=100,
            )
            self.assertNotIn(plaintext, str(token))
            self.assertEqual(store.authenticate_api_token(plaintext, now=200)["actor"], "admin")
            self.assertIsNone(store.authenticate_api_token(plaintext, now=600))
            self.assertNotIn(plaintext, Path(temporary, "dashboard.sqlite").read_bytes().decode("latin-1", errors="ignore"))

    def test_metadata_schema_and_audit_strip_secrets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "dashboard.sqlite"
            store = MetadataStore(str(database))
            self.assertEqual(store.user_emails(), {})
            self.assertEqual(store.all_user_controls(), {})
            store.set_user_email("maria", "maria@example.com")
            self.assertEqual(store.user_emails()["maria"], "maria@example.com")
            store.delete_user_email("maria")
            self.assertNotIn("maria", store.user_emails())
            store.audit(
                actor="admin",
                action="test",
                target="user-one",
                status="success",
                details={"password": "forbidden", "device": "phone"},
            )
            row = store.recent_audit(1)[0]
            self.assertNotIn("forbidden", row["details"])
            self.assertNotIn("password", database.read_bytes().decode("latin-1", errors="ignore"))

    def test_observability_ledgers_are_local_and_secret_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "dashboard.sqlite"
            store = MetadataStore(str(database))
            store.record_deployment_event(
                version="1.2.3",
                revision="a" * 40,
                details={"source": "container-start", "authorization": "must-not-persist"},
                now=100,
            )
            store.record_health_snapshot(
                {"overall": "warning", "checks": [{"id": "router-capacity", "status": "warning", "remediation": "safe"}]},
                now=100,
            )
            deployments = store.recent_deployment_events()
            health = store.recent_health_snapshots()
            self.assertEqual(deployments[0]["revision"], "a" * 40)
            self.assertNotIn("authorization", deployments[0]["details"])
            self.assertEqual(health[0]["warning_count"], 1)
            self.assertNotIn("must-not-persist", database.read_bytes().decode("latin-1", errors="ignore"))

    def test_existing_metadata_is_preserved_during_initialization(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "dashboard.sqlite"
            store = MetadataStore(str(database))
            store.set_user_email("existing-user", "owner@example.com")
            store.set_user_controls(
                "existing-user",
                policy="full-tunnel",
                expires_at=None,
                max_sessions=3,
                rate_limit_kbps=0,
                dns_mode="router",
                notifications=True,
            )

            reopened = MetadataStore(str(database))

            self.assertEqual(reopened.user_emails(), {"existing-user": "owner@example.com"})
            self.assertEqual(reopened.user_controls("existing-user")["max_sessions"], 3)

    def test_database_readiness_write_is_rolled_back(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            audit_before = store.recent_audit(100)

            store.verify_readiness()

            self.assertEqual(store.recent_audit(100), audit_before)

    def test_database_readiness_success_is_cached_briefly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            with (
                mock.patch.object(store, "_connect", wraps=store._connect) as connect,
                mock.patch("store.time.monotonic", side_effect=(100.0, 100.0, 109.9)),
            ):
                store.verify_readiness()
                store.verify_readiness()

            self.assertEqual(connect.call_count, 1)

    def test_database_readiness_cache_expires_and_failures_are_not_cached(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            real_connect = store._connect
            attempts = 0

            def fail_once():
                nonlocal attempts
                attempts += 1
                if attempts == 1:
                    raise RuntimeError("database unavailable")
                return real_connect()

            with (
                mock.patch.object(store, "_connect", side_effect=fail_once),
                mock.patch("store.time.monotonic", side_effect=(100.0, 100.0, 100.0)),
            ):
                with self.assertRaises(RuntimeError):
                    store.verify_readiness()
                store.verify_readiness()

            self.assertEqual(attempts, 2)

            with (
                mock.patch.object(store, "_connect", wraps=real_connect) as connect,
                mock.patch("store.time.monotonic", side_effect=(110.1, 110.1)),
            ):
                store.verify_readiness()

            self.assertEqual(connect.call_count, 1)

    def test_connection_history_opens_updates_and_closes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            session = {
                "id": "*A1", "name": "user-two", "source_address": "198.51.100.8",
                "vpn_address": "10.8.0.48", "encoding": "AES-256-GCM",
                "uptime": "1m30s", "rx_bytes": 100, "tx_bytes": 200,
                "rx_packets": 3, "tx_packets": 4,
            }
            store.observe_sessions([session], now=1000)
            row = store.recent_connections(1)[0]
            self.assertEqual(row["connected_at"], 910)
            self.assertIsNone(row["disconnected_at"])

            store.observe_sessions([{**session, "rx_bytes": 450, "tx_bytes": 900}], now=1010)
            row = store.recent_connections(1)[0]
            self.assertEqual(row["rx_bytes"], 450)
            self.assertEqual(row["last_seen_at"], 1010)
            summary = store.connection_summaries()["user-two"]
            self.assertEqual(summary["connection_count"], 1)
            self.assertEqual(summary["total_bytes"], 1350)
            self.assertEqual(summary["last_source_address"], "198.51.100.8")
            self.assertEqual(summary["active_connections"], 1)
            self.assertEqual(store.quota_usage("user-two", 900), 1350)

            store.observe_sessions([], now=1020)
            row = store.recent_connections(1)[0]
            self.assertEqual(row["disconnected_at"], 1020)
            self.assertEqual(store.connection_summaries()["user-two"]["active_connections"], 0)

    def test_controls_and_alerts_are_persistent_and_secret_free(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            controls = store.set_user_controls(
                "user-one", policy="lan-only", expires_at=1234, max_sessions=2,
                rate_limit_kbps=1024, dns_mode="cloudflare", notifications=False,
                quota_mb=1024, schedule="weekdays",
            )
            self.assertEqual(controls["policy"], "lan-only")
            self.assertEqual(controls["max_sessions"], 2)
            self.assertFalse(controls["notifications"])
            self.assertEqual(controls["quota_mb"], 1024)
            self.assertEqual(controls["schedule"], "weekdays")
            store.set_enforcement_state("user-one", "quota")
            self.assertEqual(store.user_controls("user-one")["enforcement_state"], "quota")
            self.assertTrue(store.add_alert(
                severity="warning", action="user.expire", target="user-one",
                title="Access expired", details="safe details",
            ))
            self.assertFalse(store.add_alert(
                severity="warning", action="user.expire", target="user-one",
                title="Access expired", details="duplicate",
            ))
            alerts = store.recent_alerts()
            self.assertEqual(len(alerts), 1)
            store.acknowledge_alert(int(alerts[0]["id"]))
            self.assertEqual(store.recent_alerts(), [])


if __name__ == "__main__":
    unittest.main()
