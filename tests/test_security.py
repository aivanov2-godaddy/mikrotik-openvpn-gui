from __future__ import annotations

import tempfile
import time
import hashlib
import sqlite3
import shutil
import threading
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest import mock

from security import (
    ConcurrentSessionLimitReached,
    LoginRateLimiter,
    SessionStore,
    csrf_matches,
    has_capability,
    normalize_role,
    role_label,
    role_capabilities,
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
        self.assertTrue(has_capability("read_only", "policies.read"))
        self.assertFalse(has_capability("read_only", "policies.manage"))
        self.assertFalse(has_capability("auditor", "users.manage"))
        self.assertFalse(has_capability("read_only", "audit.read"))

    def test_every_role_matches_the_complete_declared_capability_set(self) -> None:
        """Require explicit review when a role gains or loses any capability."""
        capabilities = {
            "health.read", "users.read", "profiles.read", "sessions.read",
            "audit.read", "policies.read", "security.manage", "device.manage",
            "profiles.manage", "session.manage", "users.manage", "policies.manage",
            "backup.manage", "alert.manage",
        }
        expected = {
            "owner": capabilities,
            "security_operator": {
                "health.read", "users.read", "profiles.read", "sessions.read",
                "audit.read", "policies.read", "security.manage", "device.manage",
                "profiles.manage", "session.manage",
            },
            "administrator": {
                "health.read", "users.read", "profiles.read", "sessions.read",
                "audit.read", "policies.read", "users.manage", "profiles.manage",
                "policies.manage", "backup.manage", "session.manage", "alert.manage",
            },
            "auditor": {
                "health.read", "users.read", "profiles.read", "sessions.read",
                "audit.read", "policies.read",
            },
            "read_only": {
                "health.read", "users.read", "profiles.read", "sessions.read",
                "policies.read",
            },
        }

        for role, granted in expected.items():
            self.assertEqual(
                role_capabilities(role), {"*"} if role == "owner" else granted,
            )
            for capability in capabilities | {"security.new-unreviewed"}:
                with self.subTest(role=role, capability=capability):
                    self.assertEqual(
                        has_capability(role, capability),
                        role == "owner" or capability in granted,
                    )

    def test_session_store_normalizes_legacy_roles(self) -> None:
        session = SessionStore().create("admin", "secret", role="operator")
        self.assertEqual(session.role, "administrator")

    def test_session_repr_never_contains_routeros_password_or_csrf_token(self) -> None:
        session = SessionStore().create(
            "admin", "router-password-marker", now=100,
        )
        session.csrf_token = "csrf-token-marker"

        rendered = repr(session)

        self.assertNotIn("router-password-marker", rendered)
        self.assertNotIn("csrf-token-marker", rendered)
        self.assertIn(session.username, rendered)
        self.assertEqual(session.password, "router-password-marker")
        self.assertEqual(session.csrf_token, "csrf-token-marker")

    def test_session_tokens_are_fresh_csprng_reference_values(self) -> None:
        store = SessionStore()
        with mock.patch("security.secrets.token_urlsafe", side_effect=("session-one", "csrf-one", "session-two", "csrf-two")) as token:
            first = store.create("admin", "secret")
            second = store.create("admin", "secret")

        self.assertEqual(first.session_id, "session-one")
        self.assertEqual(second.session_id, "session-two")
        self.assertNotEqual(first.session_id, second.session_id)
        self.assertEqual(token.call_args_list, [mock.call(32), mock.call(32), mock.call(32), mock.call(32)])

    def test_session_reauthentication_rotates_tokens_atomically_at_account_limit(self) -> None:
        store = SessionStore(max_sessions_per_account=1)
        original = store.create(
            "admin", "old-password", role="owner", source_address="192.0.2.5",
            user_agent="dashboard-test", now=100,
        )

        rotated = store.rotate(original.session_id, "new-password", role="read_only", now=110)

        self.assertIsNotNone(rotated)
        assert rotated is not None
        self.assertNotEqual(rotated.session_id, original.session_id)
        self.assertNotEqual(rotated.csrf_token, original.csrf_token)
        self.assertEqual(rotated.password, "new-password")
        self.assertEqual(rotated.role, "read_only")
        self.assertEqual((rotated.created_at, rotated.last_seen), (110, 110))
        self.assertEqual((rotated.source_address, rotated.user_agent), ("192.0.2.5", "dashboard-test"))
        self.assertIsNone(store.get(original.session_id, now=110, touch=False))
        self.assertIs(store.get(rotated.session_id, now=110, touch=False), rotated)
        self.assertEqual(len(store.active(now=110)), 1)

    def test_session_rotation_fails_closed_for_expired_or_non_routeros_sessions(self) -> None:
        store = SessionStore(idle_seconds=10, absolute_seconds=30)
        expired = store.create("admin", "secret", now=100)
        self.assertIsNone(store.rotate(expired.session_id, "new-secret", role="owner", now=111))
        self.assertIsNone(store.get(expired.session_id, now=111, touch=False))

        token_session = store.create("api-actor", "", now=200)
        token_session.auth_method = "api_token"
        self.assertIsNone(store.rotate(token_session.session_id, "new-secret", role="owner", now=201))
        self.assertIs(store.get(token_session.session_id, now=201, touch=False), token_session)

    def test_session_rotation_fails_closed_at_idle_and_absolute_expiry_boundaries(self) -> None:
        idle_store = SessionStore(idle_seconds=10, absolute_seconds=100)
        idle_expiring = idle_store.create("idle-admin", "secret", now=100)
        self.assertIsNone(
            idle_store.rotate(idle_expiring.session_id, "new-secret", role="owner", now=110)
        )
        self.assertIsNone(idle_store.get(idle_expiring.session_id, now=110, touch=False))

        absolute_store = SessionStore(idle_seconds=100, absolute_seconds=30)
        absolute_expiring = absolute_store.create("absolute-admin", "secret", now=200)
        self.assertIsNone(
            absolute_store.rotate(
                absolute_expiring.session_id, "new-secret", role="owner", now=230
            )
        )
        self.assertIsNone(absolute_store.get(absolute_expiring.session_id, now=230, touch=False))

    def test_session_limit_is_per_account_and_expired_sessions_free_a_slot(self) -> None:
        store = SessionStore(
            idle_seconds=10,
            absolute_seconds=30,
            max_sessions_per_account=2,
        )
        store.create("Admin", "secret", now=100)
        store.create("other", "secret", now=100)
        store.create("admin", "secret", now=105)

        with self.assertRaises(ConcurrentSessionLimitReached):
            store.create("ADMIN", "secret", now=109)

        admitted = store.create("admin", "secret", now=111)
        self.assertEqual(admitted.username, "admin")
        self.assertEqual(
            sum(session.username.casefold() == "admin" for session in store.active(now=111)),
            2,
        )

    def test_session_limit_must_be_positive(self) -> None:
        with self.assertRaisesRegex(ValueError, "must be positive"):
            SessionStore(max_sessions_per_account=0)

    def test_router_uptime_display(self) -> None:
        self.assertEqual(_router_uptime("1d22h44m45s"), "1d 22:44:45s")
        self.assertEqual(_router_uptime("1w2d3h4m5s"), "9d 03:04:05s")
        self.assertEqual(_router_uptime("8m12s"), "00:08:12s")
        self.assertEqual(_router_uptime("unknown"), "unknown")

    def test_certificate_lifecycle_display(self) -> None:
        self.assertEqual(_certificate_expiry("2w"), ("Expires in 14 days", "warning"))
        self.assertEqual(_certificate_expiry("-1s"), ("Expired", "expired"))
        self.assertEqual(_certificate_expiry("40w"), ("Valid · 280 days remaining", ""))
        self.assertEqual(_certificate_expiry("not-a-date"), ("Expiry unknown", "warning"))

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
        idle_store = SessionStore(idle_seconds=10, absolute_seconds=100)
        idle_session = idle_store.create("idle-admin", "secret", now=100)
        self.assertIs(idle_store.get(idle_session.session_id, now=109, touch=False), idle_session)
        self.assertIsNone(idle_store.get(idle_session.session_id, now=110, touch=False))

        absolute_store = SessionStore(idle_seconds=100, absolute_seconds=30)
        absolute_session = absolute_store.create("absolute-admin", "secret", now=200)
        self.assertIs(
            absolute_store.get(absolute_session.session_id, now=229, touch=False),
            absolute_session,
        )
        self.assertIsNone(absolute_store.get(absolute_session.session_id, now=230, touch=False))

    def test_session_timeouts_use_monotonic_time_when_wall_clock_moves_backward(self) -> None:
        idle_store = SessionStore(idle_seconds=10, absolute_seconds=100)
        with mock.patch("security.time.monotonic", return_value=100.0):
            idle_session = idle_store.create("idle-admin", "secret", now=100)
        with mock.patch("security.time.monotonic", return_value=110.0):
            self.assertIsNone(
                idle_store.get(idle_session.session_id, now=99, touch=False)
            )

        absolute_store = SessionStore(idle_seconds=100, absolute_seconds=30)
        with mock.patch("security.time.monotonic", return_value=200.0):
            absolute_session = absolute_store.create(
                "absolute-admin", "secret", now=200
            )
        with mock.patch("security.time.monotonic", return_value=230.0):
            self.assertIsNone(
                absolute_store.get(absolute_session.session_id, now=199, touch=False)
            )

    def test_session_activity_resets_monotonic_idle_deadline(self) -> None:
        store = SessionStore(idle_seconds=10, absolute_seconds=100)
        with mock.patch("security.time.monotonic", return_value=10.0):
            session = store.create("admin", "secret", now=100)
        with mock.patch("security.time.monotonic", return_value=15.0):
            self.assertIs(store.get(session.session_id, now=105), session)
        self.assertEqual(session.last_seen_monotonic, 15.0)

        with mock.patch("security.time.monotonic", return_value=24.9):
            self.assertIs(store.get(session.session_id, now=99, touch=False), session)
        with mock.patch("security.time.monotonic", return_value=25.0):
            self.assertIsNone(store.get(session.session_id, now=99, touch=False))

    def test_session_snapshot_countdowns_use_monotonic_time(self) -> None:
        store = SessionStore(idle_seconds=10, absolute_seconds=100)
        with mock.patch("security.time.monotonic", return_value=10.0):
            session = store.create("admin", "secret", now=100)
        with (
            mock.patch("security.time.monotonic", return_value=15.0),
            mock.patch("security.time.time", return_value=105.0),
        ):
            store.get(session.session_id)
        with (
            mock.patch("security.time.monotonic", return_value=24.0),
            mock.patch("security.time.time", return_value=99.0),
        ):
            snapshot = store.snapshot()

        self.assertEqual(snapshot[0]["idle_seconds"], 9)
        self.assertEqual(snapshot[0]["idle_remaining"], 1)
        self.assertEqual(snapshot[0]["absolute_remaining"], 86)

    def test_session_snapshot_preserves_explicit_wall_clock_injection(self) -> None:
        store = SessionStore(idle_seconds=60, absolute_seconds=300)
        with mock.patch("security.time.monotonic", return_value=10.0):
            store.create("admin", "secret", now=100)

        with mock.patch("security.time.monotonic", return_value=10.0):
            snapshot = store.snapshot(now=120)

        self.assertEqual(snapshot[0]["idle_seconds"], 20)
        self.assertEqual(snapshot[0]["idle_remaining"], 40)
        self.assertEqual(snapshot[0]["absolute_remaining"], 280)

    def test_session_purge_expires_at_idle_and_absolute_boundaries(self) -> None:
        idle_store = SessionStore(idle_seconds=10, absolute_seconds=100)
        idle_session = idle_store.create("idle-admin", "secret", now=100)
        self.assertEqual(idle_store.purge(now=110), 1)
        self.assertIsNone(idle_store.get(idle_session.session_id, now=110, touch=False))

        absolute_store = SessionStore(idle_seconds=100, absolute_seconds=30)
        absolute_session = absolute_store.create("absolute-admin", "secret", now=200)
        self.assertEqual(absolute_store.purge(now=230), 1)
        self.assertIsNone(absolute_store.get(absolute_session.session_id, now=230, touch=False))

    def test_read_only_session_revalidation_does_not_extend_idle_timeout(self) -> None:
        store = SessionStore(idle_seconds=10, absolute_seconds=30)
        session = store.create("admin", "secret", now=100)

        self.assertIs(store.get(session.session_id, now=109, touch=False), session)
        self.assertEqual(session.last_seen, 100)
        self.assertIsNone(store.get(session.session_id, now=111, touch=False))

    def test_cached_role_session_only_authorizes_a_fresh_routeros_role(self) -> None:
        store = SessionStore()
        session = store.create("admin", "router-secret", role="owner", now=100)

        fresh, cached = store.cached_role_session(session.session_id, now=114)
        self.assertTrue(fresh)
        self.assertIs(cached, session)
        self.assertEqual(session.last_seen, 100)

        stale, cached = store.cached_role_session(session.session_id, now=115)
        self.assertFalse(stale)
        self.assertIsNone(cached)

        store._role_checked_at[session.session_id] = 200
        rolled_back, cached = store.cached_role_session(session.session_id, now=101)
        self.assertFalse(rolled_back)
        self.assertIsNone(cached)

    def test_role_revalidation_does_not_return_a_session_expired_during_lookup(self) -> None:
        store = SessionStore(idle_seconds=10, absolute_seconds=100)
        monotonic_now = [10.0]
        with mock.patch("security.time.monotonic", side_effect=lambda: monotonic_now[0]):
            session = store.create("admin", "secret", now=100)

            def slow_role_lookup(_session):
                monotonic_now[0] = 20.0
                return "owner"

            self.assertIsNone(
                store.revalidate_role(
                    session.session_id,
                    slow_role_lookup,
                    now=101,
                    interval_seconds=0,
                )
            )
            self.assertIsNone(store.get(session.session_id, now=101, touch=False))

    def test_cached_role_session_is_unavailable_during_forced_revalidation(self) -> None:
        store = SessionStore()
        session = store.create("admin", "router-secret", role="owner", now=100)
        self.assertIs(
            store.revalidate_role(
                session.session_id, lambda _session: "owner", now=101, interval_seconds=0
            ),
            session,
        )
        resolver_started = threading.Event()
        release_resolver = threading.Event()

        def delayed_resolver(_session) -> str:
            resolver_started.set()
            release_resolver.wait(timeout=2)
            return "owner"

        with ThreadPoolExecutor(max_workers=1) as executor:
            refresh = executor.submit(
                store.revalidate_role,
                session.session_id,
                delayed_resolver,
                now=102,
                interval_seconds=0,
            )
            try:
                self.assertTrue(resolver_started.wait(timeout=1))
                authoritative, cached = store.cached_role_session(
                    session.session_id, now=103
                )
                self.assertFalse(authoritative)
                self.assertIsNone(cached)
            finally:
                release_resolver.set()
            self.assertIs(refresh.result(timeout=1), session)

        authoritative, cached = store.cached_role_session(session.session_id, now=103)
        self.assertTrue(authoritative)
        self.assertIs(cached, session)

    def test_routeros_role_revalidation_downgrades_without_extending_idle_lifetime(self) -> None:
        store = SessionStore()
        session = store.create("admin", "router-secret", role="owner", now=100)
        checked = store.revalidate_role(
            session.session_id, lambda _session: "read_only", now=116,
        )

        self.assertIs(checked, session)
        self.assertEqual(session.role, "read_only")
        self.assertEqual(session.last_seen, 100)
        self.assertIs(
            store.revalidate_role(
                session.session_id,
                lambda _session: self.fail("cached role validation should not call RouterOS again"),
                now=117,
            ),
            session,
        )

    def test_routeros_role_revalidation_never_elevates_an_existing_session(self) -> None:
        store = SessionStore()
        session = store.create("admin", "router-secret", role="read_only", now=100)

        self.assertIs(
            store.revalidate_role(session.session_id, lambda _session: "owner", now=116),
            session,
        )
        self.assertEqual(session.role, "read_only")

    def test_routeros_role_revalidation_treats_clock_rollback_as_stale(self) -> None:
        for interval_seconds in (0, 15):
            with self.subTest(interval_seconds=interval_seconds):
                store = SessionStore()
                session = store.create("admin", "router-secret", role="owner", now=100)
                # The check timestamp is ahead of the current wall clock, as
                # after a system-clock rollback. It must not authorize from a
                # cache whose age cannot be established.
                store._role_checked_at[session.session_id] = 200
                calls = 0

                def account_is_disabled(_session) -> None:
                    nonlocal calls
                    calls += 1
                    return None

                self.assertIsNone(
                    store.revalidate_role(
                        session.session_id,
                        account_is_disabled,
                        now=101,
                        interval_seconds=interval_seconds,
                    )
                )
                self.assertEqual(calls, 1)
                self.assertIsNone(store.get(session.session_id, now=101, touch=False))

    def test_routeros_role_revalidation_revokes_missing_or_incomparable_identity(self) -> None:
        missing_store = SessionStore()
        missing = missing_store.create("admin", "router-secret", role="owner", now=100)
        self.assertIsNone(missing_store.revalidate_role(missing.session_id, lambda _session: None, now=116))
        self.assertIsNone(missing_store.get(missing.session_id, now=116, touch=False))

        changed_store = SessionStore()
        changed = changed_store.create("admin", "router-secret", role="administrator", now=100)
        self.assertIsNone(
            changed_store.revalidate_role(changed.session_id, lambda _session: "security_operator", now=116)
        )
        self.assertIsNone(changed_store.get(changed.session_id, now=116, touch=False))

    def test_routeros_role_lookup_error_revokes_session(self) -> None:
        for role in ("owner", "read_only"):
            with self.subTest(role=role):
                store = SessionStore()
                session = store.create("admin", "router-secret", role=role, now=100)

                checked = store.revalidate_role(
                    session.session_id,
                    lambda _session: (_ for _ in ()).throw(RuntimeError("private RouterOS failure")),
                    now=116,
                )

                self.assertIsNone(checked)
                self.assertIsNone(store.get(session.session_id, now=116, touch=False))
                self.assertNotIn("private RouterOS failure", repr(checked))

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
        first = limiter.reserve("ip", now=1)
        second = limiter.reserve("ip", now=1)
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertIsNone(limiter.reserve("ip", now=1))
        limiter.finish(first, failed=True, now=1)
        limiter.finish(second, failed=True, now=2)
        self.assertIsNone(limiter.reserve("ip", now=3))
        self.assertIsNotNone(limiter.reserve("ip", now=12.1))

    def test_rate_limiter_bounds_distinct_identity_history_and_prunes_expired_entries(self) -> None:
        limiter = LoginRateLimiter(
            limit=2, window_seconds=10, max_tracked_identities=3,
        )
        for index in range(3):
            reservation = limiter.reserve(f"identity-{index}", now=1)
            self.assertIsNotNone(reservation)
            limiter.finish(reservation, failed=True, now=1)

        self.assertEqual(len(limiter._attempts), 3)
        self.assertIsNone(limiter.reserve("identity-overflow", now=2))

        # A request after the failure window expires prunes old identities and
        # releases capacity for a new client without growing retained state.
        replacement = limiter.reserve("identity-replacement", now=12)
        self.assertIsNotNone(replacement)
        self.assertEqual(set(limiter._attempts), set())
        limiter.finish(replacement, failed=True, now=12)
        self.assertEqual(len(limiter._attempts), 1)

    def test_rate_limiter_bounds_global_in_flight_reservations(self) -> None:
        limiter = LoginRateLimiter(
            limit=2, window_seconds=10, max_tracked_identities=4, max_in_flight=2,
        )
        first = limiter.reserve("identity-1", now=1)
        second = limiter.reserve("identity-2", now=1)
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertIsNone(limiter.reserve("identity-3", now=1))

        limiter.finish(first, failed=None, now=1)
        self.assertIsNotNone(limiter.reserve("identity-3", now=1))

    def _assert_concurrent_auth_attempts_are_limited(self, operation: str) -> None:
        limit = 3
        concurrent_attempts = 12
        limiter = LoginRateLimiter(limit=limit, window_seconds=60)
        start = threading.Barrier(concurrent_attempts)
        admitted = threading.Barrier(concurrent_attempts)

        def attempt() -> bool:
            start.wait(timeout=5)
            reservation = limiter.reserve("shared-client", now=100)
            # Keep admitted attempts in flight until every worker has tried to
            # reserve, making this a deterministic check-then-record regression.
            admitted.wait(timeout=5)
            if reservation is not None:
                limiter.finish(reservation, failed=True, now=100)
            return reservation is not None

        with ThreadPoolExecutor(max_workers=concurrent_attempts) as executor:
            outcomes = list(executor.map(lambda _index: attempt(), range(concurrent_attempts)))

        self.assertEqual(sum(outcomes), limit, operation)
        self.assertIsNone(limiter.reserve("shared-client", now=101))

    def test_concurrent_failed_login_admissions_are_limited_atomically(self) -> None:
        self._assert_concurrent_auth_attempts_are_limited("login")

    def test_concurrent_failed_admin_reauth_admissions_are_limited_atomically(self) -> None:
        self._assert_concurrent_auth_attempts_are_limited("admin reauthentication")

    def test_unavailable_completion_releases_reservation_and_preserves_failure_history(self) -> None:
        limiter = LoginRateLimiter(limit=2, window_seconds=60)
        failed = limiter.reserve("ip", now=1)
        self.assertIsNotNone(failed)
        limiter.finish(failed, failed=True, now=1)

        unavailable = limiter.reserve("ip", now=2)
        self.assertIsNotNone(unavailable)
        limiter.finish(unavailable, failed=None, now=3)

        next_reservation = limiter.reserve("ip", now=4)
        self.assertIsNotNone(next_reservation)
        limiter.finish(next_reservation, failed=True, now=4)
        self.assertIsNone(limiter.reserve("ip", now=5))

    def test_successful_completion_clears_failure_history(self) -> None:
        limiter = LoginRateLimiter(limit=2, window_seconds=60)
        failed = limiter.reserve("ip", now=1)
        self.assertIsNotNone(failed)
        limiter.finish(failed, failed=True, now=1)

        successful = limiter.reserve("ip", now=2)
        self.assertIsNotNone(successful)
        limiter.finish(successful, failed=False, now=2)
        first = limiter.reserve("ip", now=3)
        second = limiter.reserve("ip", now=3)
        self.assertIsNotNone(first)
        self.assertIsNotNone(second)
        self.assertIsNone(limiter.reserve("ip", now=3))

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

    def test_sqlite_wal_checkpoint_and_backup_are_consistent(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "dashboard.sqlite"
            backup = Path(temporary) / "backups" / "dashboard.sqlite"
            store = MetadataStore(str(database))
            store.set_audit_hook(lambda _event: None)
            store.audit(actor="admin", action="backup.test", target="local", status="success", details={"nested": {"password": "secret", "safe": True}})

            connection = sqlite3.connect(database)
            try:
                self.assertEqual(connection.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
                self.assertEqual(connection.execute("PRAGMA busy_timeout").fetchone()[0], 5000)
            finally:
                connection.close()
            checkpoint = store.checkpoint_wal()
            self.assertEqual(checkpoint["mode"], "PASSIVE")
            result = store.backup_database(str(backup))
            self.assertGreater(result["bytes"], 0)
            connection = sqlite3.connect(backup)
            try:
                self.assertEqual(connection.execute("PRAGMA integrity_check").fetchone()[0].lower(), "ok")
                payload = connection.execute("SELECT payload FROM integration_outbox").fetchone()[0]
                self.assertNotIn("password", payload)
            finally:
                connection.close()

            restored = Path(temporary) / "restore-rehearsal.sqlite"
            shutil.copy2(backup, restored)
            restored_store = MetadataStore(str(restored))
            restored_store.verify_readiness()
            self.assertEqual(restored_store.recent_audit(10)[0]["action"], "backup.test")
            self.assertEqual(restored_store.integration_outbox_metrics()["pending"], 1)

    def test_outbox_metrics_are_aggregate_and_reflect_retry_and_delivery(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            store.set_audit_hook(lambda _event: None)
            store.audit(actor="admin", action="metrics.test", target="local", status="success", details={})
            pending = store.integration_outbox_metrics(now=int(time.time()) + 5)
            self.assertEqual(pending["pending"], 1)
            self.assertEqual(pending["due"], 1)
            self.assertEqual(pending["dead_lettered"], 0)
            self.assertNotIn("event_id", pending)
            event_id = store.pending_integration_events(1)[0]["event_id"]
            store.mark_integration_failed(event_id, "ConnectionError", retry_at=int(time.time()) + 30)
            retried = store.integration_outbox_metrics(now=int(time.time()))
            self.assertEqual(retried["retried"], 1)
            self.assertEqual(retried["due"], 0)
            store.mark_integration_delivered(event_id)
            delivered = store.integration_outbox_metrics()
            self.assertEqual(delivered["pending"], 0)
            self.assertEqual(delivered["dead_lettered"], 0)
            self.assertGreater(delivered["last_delivered"], 0)

    def test_recent_integration_delivery_state_omits_payload_and_event_id(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            store.set_audit_hook(lambda _event: None)
            store.audit(actor="private-actor", action="private.action", target="private-target", status="success", details={"secret": "no"})
            rows = store.recent_integration_delivery_events()
            self.assertEqual(len(rows), 1)
            self.assertEqual(rows[0]["event_type"], "audit")
            self.assertIn("source_id", rows[0])
            self.assertNotIn("event_id", rows[0])
            self.assertNotIn("payload", rows[0])
            self.assertNotIn("last_error", rows[0])

    def test_database_readiness_success_is_cached_briefly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            with (
                mock.patch.object(store, "_connect", wraps=store._connect) as connect,
                mock.patch("store._monotonic", side_effect=(100.0, 100.0, 109.9)),
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
                mock.patch("store._monotonic", return_value=100.0),
            ):
                with self.assertRaises(RuntimeError):
                    store.verify_readiness()
                store.verify_readiness()

            self.assertEqual(attempts, 2)

            with (
                mock.patch.object(store, "_connect", wraps=real_connect) as connect,
                mock.patch("store._monotonic", return_value=110.1),
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
            timeline = store.recent_connection_timeline(500, start_at=1015, end_at=1025)
            self.assertEqual(len(timeline), 1)
            self.assertEqual(set(timeline[0]), {"id", "vpn_user", "connected_at", "disconnected_at"})
            self.assertEqual(store.recent_connection_timeline(10, start_at=1021, end_at=1030), [])

    def test_connection_history_preserves_counters_when_observation_is_incomplete(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            session = {
                "id": "*A1", "name": "user-two", "source_address": "198.51.100.8",
                "vpn_address": "10.8.0.48", "encoding": "AES-256-GCM", "uptime": "1m30s",
                "rx_bytes": 100, "tx_bytes": 200, "rx_packets": 3, "tx_packets": 4,
                "counter_complete": True,
            }
            store.observe_sessions([session], now=1000)

            store.observe_sessions(
                [{**session, "rx_bytes": "unavailable", "tx_bytes": "unavailable",
                  "rx_packets": "unavailable", "tx_packets": "unavailable",
                  "counter_complete": False}],
                now=1010,
            )
            row = store.recent_connections(1)[0]
            self.assertEqual(
                (row["rx_bytes"], row["tx_bytes"], row["rx_packets"], row["tx_packets"]),
                (100, 200, 3, 4),
            )
            self.assertEqual(row["last_seen_at"], 1010)

            store.observe_sessions(
                [{**session, "rx_bytes": 150, "tx_bytes": 250, "rx_packets": 5, "tx_packets": 6}],
                now=1020,
            )
            row = store.recent_connections(1)[0]
            self.assertEqual(
                (row["rx_bytes"], row["tx_bytes"], row["rx_packets"], row["tx_packets"]),
                (150, 250, 5, 6),
            )

    def test_connection_history_starts_incomplete_observation_with_zero_counters(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            session = {
                "id": "*A2", "name": "user-three", "source_address": "198.51.100.9",
                "vpn_address": "10.8.0.49", "encoding": "AES-256-GCM", "uptime": "5s",
                "rx_bytes": "unavailable", "tx_bytes": "unavailable",
                "rx_packets": "unavailable", "tx_packets": "unavailable",
                "counter_complete": False,
            }

            store.observe_sessions([session], now=2000)
            row = store.recent_connections(1)[0]
            self.assertEqual(
                (row["rx_bytes"], row["tx_bytes"], row["rx_packets"], row["tx_packets"]),
                (0, 0, 0, 0),
            )
            self.assertEqual(row["last_seen_at"], 2000)
            self.assertIsNone(row["disconnected_at"])

            store.observe_sessions(
                [{**session, "rx_bytes": 25, "tx_bytes": 35, "rx_packets": 2, "tx_packets": 3,
                  "counter_complete": True}],
                now=2010,
            )
            row = store.recent_connections(1)[0]
            self.assertEqual(
                (row["rx_bytes"], row["tx_bytes"], row["rx_packets"], row["tx_packets"]),
                (25, 35, 2, 3),
            )

    def test_alert_recurrence_migrates_existing_rows(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "legacy.sqlite"
            connection = sqlite3.connect(path)
            try:
                connection.execute(
                    """CREATE TABLE alerts (
                       id INTEGER PRIMARY KEY AUTOINCREMENT, severity TEXT NOT NULL,
                       action TEXT NOT NULL, target TEXT NOT NULL, title TEXT NOT NULL,
                       details TEXT NOT NULL, acknowledged INTEGER NOT NULL DEFAULT 0,
                       created_at INTEGER NOT NULL)"""
                )
                connection.execute(
                    """INSERT INTO alerts(severity, action, target, title, details, created_at)
                       VALUES ('warning', 'user.expire', 'user-one', 'Expired', 'safe', 1000)"""
                )
                connection.commit()
            finally:
                connection.close()
            store = MetadataStore(str(path))
            alert = store.recent_alerts()[0]
            self.assertEqual(alert["created_at"], 1000)
            self.assertEqual(alert["last_seen_at"], 1000)
            self.assertEqual(alert["occurrence_count"], 1)

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
                title="Access expired", details="safe details", now=1000,
            ))
            self.assertFalse(store.add_alert(
                severity="critical", action="user.expire", target="user-one",
                title="Access expiry requires urgent review", details="latest safe details", now=1015,
            ))
            grouped = next(item for item in store.recent_alerts() if item["target"] == "user-one")
            self.assertEqual(grouped["created_at"], 1000)
            self.assertEqual(grouped["last_seen_at"], 1015)
            self.assertEqual(grouped["occurrence_count"], 2)
            self.assertEqual(grouped["severity"], "critical")
            self.assertEqual(grouped["title"], "Access expiry requires urgent review")
            self.assertEqual(grouped["details"], "latest safe details")
            self.assertFalse(store.add_alert(
                severity="warning", action="user.expire", target="user-one",
                title="Out-of-order stale alert", details="stale details", now=1010,
            ))
            grouped = next(item for item in store.recent_alerts() if item["target"] == "user-one")
            self.assertEqual(grouped["last_seen_at"], 1015)
            self.assertEqual(grouped["occurrence_count"], 3)
            self.assertEqual(grouped["title"], "Access expiry requires urgent review")
            self.assertEqual(grouped["details"], "latest safe details")
            for index in range(1, 10):
                self.assertTrue(store.add_alert(
                    severity="warning", action="user.expire", target=f"user-{index}",
                    title="Access expired", details="safe details", now=1000,
                ))
            self.assertFalse(store.add_alert(
                severity="warning", action="user.expire", target="user-over-limit",
                title="Access expired", details="safe details", now=1000,
            ))
            # Notification throttling must not suppress durable audit writes.
            store.audit(actor="admin", action="alert.observed", target="local", status="success")
            store.audit(actor="admin", action="alert.observed", target="local", status="success")
            self.assertEqual(
                len([row for row in store.recent_audit(10) if row["action"] == "alert.observed"]), 2,
            )
            alerts = store.recent_alerts()
            self.assertEqual(len(alerts), 10)
            for alert in alerts:
                store.acknowledge_alert(int(alert["id"]))
            self.assertEqual(store.recent_alerts(), [])
            self.assertTrue(store.add_alert(
                severity="warning", action="user.expire", target="user-one",
                title="Access expired again", details="new incident after acknowledgement", now=1061,
            ))
            reopened = next(item for item in store.recent_alerts() if item["target"] == "user-one")
            self.assertEqual(reopened["occurrence_count"], 1)
            self.assertEqual(reopened["created_at"], 1061)


if __name__ == "__main__":
    unittest.main()
