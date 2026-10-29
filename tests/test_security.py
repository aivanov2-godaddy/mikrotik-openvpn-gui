from __future__ import annotations

import asyncio
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
    SessionAuthorizationChanged,
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

    def test_session_create_does_not_commit_when_before_commit_fails(self) -> None:
        store = SessionStore()

        def fail_commit(_session) -> None:
            raise RuntimeError("audit unavailable")

        with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
            store.create("admin", "secret", before_commit=fail_commit)

        self.assertEqual(store.active(), [])

    def test_session_rotation_preserves_old_session_when_before_commit_fails(self) -> None:
        store = SessionStore(max_sessions_per_account=1)
        original = store.create("admin", "old-password", role="owner")

        def fail_commit(_session) -> None:
            raise RuntimeError("audit unavailable")

        with self.assertRaisesRegex(RuntimeError, "audit unavailable"):
            store.rotate(
                original.session_id,
                "new-password",
                role="read_only",
                before_commit=fail_commit,
            )

        self.assertIs(store.get(original.session_id, touch=False), original)
        self.assertEqual(original.password, "old-password")
        self.assertEqual(len(store.active()), 1)

    def test_audit_transition_does_not_block_unrelated_session_reads(self) -> None:
        store = SessionStore()
        original = store.create("admin", "old-password")
        unrelated = store.create("other", "other-password")
        callback_started = threading.Event()
        finish_callback = threading.Event()
        result: list[object] = []

        def before_commit(_replacement) -> None:
            callback_started.set()
            if not finish_callback.wait(timeout=2):
                raise TimeoutError("test callback timed out")

        def rotate() -> None:
            result.append(
                store.rotate(
                    original.session_id,
                    "new-password",
                    role="owner",
                    before_commit=before_commit,
                )
            )

        worker = threading.Thread(target=rotate)
        worker.start()
        self.assertTrue(callback_started.wait(timeout=1))
        self.assertIs(store.get(unrelated.session_id, touch=False), unrelated)
        finish_callback.set()
        worker.join(timeout=2)

        self.assertFalse(worker.is_alive())
        self.assertEqual(len(result), 1)
        self.assertIsNotNone(result[0])

    def test_individual_revocation_during_reauthentication_prevents_replacement(self) -> None:
        store = SessionStore()
        original = store.create("admin", "old-password")
        transition_started = threading.Event()
        finish_transition = threading.Event()
        rotation_result: list[object] = []

        def audit_before_rotation(_replacement) -> None:
            transition_started.set()
            if not finish_transition.wait(timeout=2):
                raise TimeoutError("test transition timed out")

        def rotate() -> None:
            rotation_result.append(
                store.rotate(
                    original.session_id,
                    "new-password",
                    role="owner",
                    before_commit=audit_before_rotation,
                )
            )

        rotation_worker = threading.Thread(target=rotate)
        rotation_worker.start()
        self.assertTrue(transition_started.wait(timeout=1))
        revoke_worker = threading.Thread(
            target=store.destroy, args=(original.session_id,)
        )
        revoke_worker.start()
        deadline = time.monotonic() + 1
        while store._invalidating.get(original.session_id, 0) < 2:
            if time.monotonic() >= deadline:
                self.fail("individual revoke did not publish invalidation")
            time.sleep(0.005)
        finish_transition.set()
        rotation_worker.join(timeout=2)
        revoke_worker.join(timeout=2)

        self.assertFalse(rotation_worker.is_alive())
        self.assertFalse(revoke_worker.is_alive())
        self.assertEqual(rotation_result, [None])
        self.assertIsNone(store.get(original.session_id, touch=False))
        self.assertEqual(store.active(), [])
        self.assertEqual(store._invalidating, {})

    def test_account_revocation_keeps_deny_marker_until_busy_set_lock_is_swept(self) -> None:
        store = SessionStore()
        session = store.create("admin", "secret")
        store._session_set_lock.acquire()
        original_start = threading.Thread.start
        start_attempts = 0

        def start_after_transient_failure(worker: threading.Thread) -> None:
            nonlocal start_attempts
            if worker.name == "session-revocation-retry":
                start_attempts += 1
                if start_attempts == 1:
                    raise RuntimeError("injected transient thread-start failure")
            original_start(worker)

        async def revoke_in_event_loop() -> None:
            with mock.patch.object(
                threading.Thread,
                "start",
                autospec=True,
                side_effect=start_after_transient_failure,
            ):
                self.assertIsNone(store.revoke_account_sessions("admin"))
                self.assertIsNone(store.get(session.session_id, touch=False))
                self.assertGreater(store._invalidating_usernames.get("admin", 0), 0)
                store._session_set_lock.release()
                await self._wait_for_account_revocation(
                    store, "admin", session.session_id
                )
                self.assertEqual(start_attempts, 2)
                self.assertIsNone(store.get(session.session_id, touch=False))
                self.assertEqual(store._invalidating_usernames, {})
                self.assertEqual(store.active(), [])

        asyncio.run(revoke_in_event_loop())

    def test_account_revocation_retries_when_role_delivery_lock_is_busy(self) -> None:
        store = SessionStore()
        session = store.create("admin", "secret")
        role_lock = store.role_check_lock(session.session_id)
        assert role_lock is not None
        role_lock.acquire()

        async def revoke_in_event_loop() -> None:
            self.assertIsNone(store.revoke_account_sessions("admin"))
            self.assertIsNone(store.get(session.session_id, touch=False))
            self.assertGreater(store._invalidating_usernames.get("admin", 0), 0)
            role_lock.release()
            await self._wait_for_account_revocation(store, "admin", session.session_id)
            self.assertIsNone(store.get(session.session_id, touch=False))
            self.assertEqual(store._invalidating_usernames, {})
            self.assertEqual(store.active(), [])

        asyncio.run(revoke_in_event_loop())

    async def _wait_for_account_revocation(
        self, store: SessionStore, username: str, session_id: str
    ) -> None:
        for _ in range(500):
            with store._lock:
                completed = (
                    session_id not in store._sessions
                    and username not in store._invalidating_usernames
                    and username not in store._pending_account_revocation_retries
                )
            if completed:
                return
            await asyncio.sleep(0.01)
        self.fail("background account revocation did not finish")

    def test_account_revocation_denies_immediately_and_cancels_inflight_rotation(self) -> None:
        store = SessionStore()
        rotating = store.create("admin", "old-password")
        revalidating = store.create("admin", "second-password")
        transition_started = threading.Event()
        finish_transition = threading.Event()
        invalidation_published = threading.Event()
        rotation_result: list[object] = []
        revalidation_result: list[object] = []
        original_mark = store._mark_account_invalidating_locked

        def mark_and_signal(username_key: str) -> None:
            original_mark(username_key)
            invalidation_published.set()

        def audit_before_rotation(_replacement) -> None:
            transition_started.set()
            if not finish_transition.wait(timeout=2):
                raise TimeoutError("test transition timed out")

        def rotate() -> None:
            rotation_result.append(
                store.rotate(
                    rotating.session_id,
                    "new-password",
                    role="owner",
                    before_commit=audit_before_rotation,
                )
            )

        def revalidate() -> None:
            revalidation_result.append(
                store.revalidate_role(
                    revalidating.session_id,
                    lambda _session: None,
                    interval_seconds=0,
                )
            )

        with mock.patch.object(
            store, "_mark_account_invalidating_locked", side_effect=mark_and_signal
        ):
            rotation_worker = threading.Thread(target=rotate)
            rotation_worker.start()
            self.assertTrue(transition_started.wait(timeout=1))
            revalidation_worker = threading.Thread(target=revalidate)
            revalidation_worker.start()
            self.assertTrue(invalidation_published.wait(timeout=1))
            self.assertIsNone(store.get(rotating.session_id, touch=False))
            self.assertIsNone(store.get(revalidating.session_id, touch=False))
            finish_transition.set()
            rotation_worker.join(timeout=2)
            revalidation_worker.join(timeout=2)

        self.assertFalse(rotation_worker.is_alive())
        self.assertFalse(revalidation_worker.is_alive())
        self.assertEqual(len(rotation_result), 1)
        self.assertIsNone(rotation_result[0])
        self.assertEqual(revalidation_result, [None])
        self.assertEqual(store.active(), [])
        self.assertEqual(store._invalidating_usernames, {})

    def test_session_repr_never_contains_routeros_password_or_csrf_token(self) -> None:
        session = SessionStore().create(
            "admin", "router-password-marker", now=100,
            source_address="192.0.2.77", user_agent="sensitive-browser-marker",
        )
        session.csrf_token = "csrf-token-marker"

        rendered = repr(session)

        for marker in (
            "router-password-marker", "csrf-token-marker", session.session_id,
            "192.0.2.77", "sensitive-browser-marker",
        ):
            self.assertNotIn(marker, rendered)
        self.assertIn(session.username, rendered)
        self.assertEqual(session.password, "router-password-marker")
        self.assertEqual(session.csrf_token, "csrf-token-marker")

    def test_session_tokens_are_fresh_csprng_reference_values(self) -> None:
        store = SessionStore()
        with mock.patch(
            "security.secrets.token_urlsafe",
            side_effect=(
                "session-one", "csrf-one", "revoke-one", "auth-ref-one",
                "session-two", "csrf-two", "revoke-two", "auth-ref-two",
            ),
        ) as token:
            first = store.create("admin", "secret")
            second = store.create("admin", "secret")

        self.assertEqual(first.session_id, "session-one")
        self.assertEqual(second.session_id, "session-two")
        self.assertNotEqual(first.session_id, second.session_id)
        self.assertEqual((first.revocation_ref, second.revocation_ref), ("revoke-one", "revoke-two"))
        self.assertNotEqual(first.authorization_ref, second.authorization_ref)
        self.assertEqual(
            token.call_args_list,
            [
                mock.call(32), mock.call(32), mock.call(24), mock.call(24),
                mock.call(32), mock.call(32), mock.call(24), mock.call(24),
            ],
        )

    def test_session_reauthentication_rotates_tokens_atomically_at_account_limit(self) -> None:
        store = SessionStore(max_sessions_per_account=1)
        original = store.create(
            "admin", "old-password", role="owner", source_address="192.0.2.5",
            user_agent="dashboard-test", now=100,
        )
        original_revocation_ref = original.revocation_ref

        rotated = store.rotate(original.session_id, "new-password", role="read_only", now=110)

        self.assertIsNotNone(rotated)
        assert rotated is not None
        self.assertNotEqual(rotated.session_id, original.session_id)
        self.assertNotEqual(rotated.revocation_ref, original_revocation_ref)
        self.assertNotEqual(rotated.csrf_token, original.csrf_token)
        self.assertEqual(rotated.password, "new-password")
        self.assertEqual(rotated.role, "read_only")
        self.assertEqual((rotated.created_at, rotated.last_seen), (110, 110))
        self.assertEqual((rotated.source_address, rotated.user_agent), ("192.0.2.5", "dashboard-test"))
        self.assertEqual((original.password, original.csrf_token), ("", ""))
        self.assertEqual(original.authorization_ref, "")
        self.assertEqual(original.revocation_ref, "")
        self.assertIsNone(store.get(original.session_id, now=110, touch=False))
        self.assertIs(store.get(rotated.session_id, now=110, touch=False), rotated)
        self.assertFalse(store.revoke_by_reference(original_revocation_ref))
        self.assertEqual(
            store.snapshot(include_revocation_refs=True, now=110)[0]["id"],
            rotated.revocation_ref,
        )
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
        self.assertEqual((idle_session.password, idle_session.csrf_token), ("", ""))
        self.assertEqual(idle_session.authorization_ref, "")

        absolute_store = SessionStore(idle_seconds=100, absolute_seconds=30)
        absolute_session = absolute_store.create("absolute-admin", "secret", now=200)
        self.assertIs(
            absolute_store.get(absolute_session.session_id, now=229, touch=False),
            absolute_session,
        )
        self.assertIsNone(absolute_store.get(absolute_session.session_id, now=230, touch=False))
        self.assertEqual((absolute_session.password, absolute_session.csrf_token), ("", ""))
        self.assertEqual(absolute_session.authorization_ref, "")

    def test_nonblocking_active_session_check_does_not_touch_idle_deadline(self) -> None:
        store = SessionStore(idle_seconds=10, absolute_seconds=30)
        session = store.create("operator", "secret")
        last_seen = session.last_seen
        last_seen_monotonic = session.last_seen_monotonic

        self.assertTrue(store.is_active_nonblocking(session.session_id))
        self.assertFalse(store.is_active_nonblocking("unknown-session"))
        self.assertEqual(session.last_seen, last_seen)
        self.assertEqual(session.last_seen_monotonic, last_seen_monotonic)

        session.last_seen = time.time() - 11
        session.last_seen_monotonic = time.monotonic() - 11
        self.assertFalse(store.is_active_nonblocking(session.session_id))

    def test_nonblocking_active_session_check_fails_closed_on_store_lock_contention(self) -> None:
        store = SessionStore()
        session = store.create("operator", "secret")
        lock_held = threading.Event()
        release_lock = threading.Event()

        def hold_store_lock() -> None:
            with store._lock:
                lock_held.set()
                release_lock.wait(timeout=2)

        worker = threading.Thread(target=hold_store_lock, daemon=True)
        worker.start()
        self.assertTrue(lock_held.wait(timeout=1))
        started = time.monotonic()
        try:
            self.assertFalse(store.is_active_nonblocking(session.session_id))
            self.assertLess(time.monotonic() - started, 0.1)
        finally:
            release_lock.set()
            worker.join(timeout=1)
        self.assertFalse(worker.is_alive())

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
        idle_reference = idle_session.revocation_ref
        self.assertEqual(idle_store.purge(now=110), 1)
        self.assertEqual((idle_session.password, idle_session.csrf_token), ("", ""))
        self.assertEqual(idle_session.authorization_ref, "")
        self.assertEqual(idle_session.revocation_ref, "")
        self.assertFalse(idle_store.revoke_by_reference(idle_reference))
        self.assertIsNone(idle_store.get(idle_session.session_id, now=110, touch=False))

        absolute_store = SessionStore(idle_seconds=100, absolute_seconds=30)
        absolute_session = absolute_store.create("absolute-admin", "secret", now=200)
        absolute_reference = absolute_session.revocation_ref
        self.assertEqual(absolute_store.purge(now=230), 1)
        self.assertEqual((absolute_session.password, absolute_session.csrf_token), ("", ""))
        self.assertEqual(absolute_session.authorization_ref, "")
        self.assertEqual(absolute_session.revocation_ref, "")
        self.assertFalse(absolute_store.revoke_by_reference(absolute_reference))
        self.assertIsNone(absolute_store.get(absolute_session.session_id, now=230, touch=False))

    def test_read_only_session_revalidation_does_not_extend_idle_timeout(self) -> None:
        store = SessionStore(idle_seconds=10, absolute_seconds=30)
        session = store.create("admin", "secret", now=100)

        self.assertIs(store.get(session.session_id, now=109, touch=False), session)
        self.assertEqual(session.last_seen, 100)
        self.assertIsNone(store.get(session.session_id, now=111, touch=False))

    def test_cached_role_session_only_authorizes_a_fresh_routeros_role(self) -> None:
        store = SessionStore()
        monotonic_now = [10.0]
        with mock.patch("security.time.monotonic", side_effect=lambda: monotonic_now[0]):
            session = store.create("admin", "router-secret", role="owner", now=100)

            monotonic_now[0] = 24.0
            fresh, cached = store.cached_role_session(session.session_id, now=114)
            self.assertTrue(fresh)
            self.assertIs(cached, session)
            self.assertEqual(session.last_seen, 100)

            monotonic_now[0] = 25.0
            stale, cached = store.cached_role_session(session.session_id, now=115)
            self.assertFalse(stale)
            self.assertIsNone(cached)

            store._role_checked_monotonic[session.session_id] = 26.0
            future, cached = store.cached_role_session(session.session_id, now=101)
            self.assertFalse(future)
            self.assertIsNone(cached)

    def test_role_cache_expires_when_wall_clock_stalls(self) -> None:
        store = SessionStore()
        monotonic_now = [10.0]
        calls = 0

        def resolve_role(_session) -> str:
            nonlocal calls
            calls += 1
            return "owner"

        with mock.patch("security.time.monotonic", side_effect=lambda: monotonic_now[0]):
            session = store.create("admin", "router-secret", role="owner", now=100)
            fresh, cached = store.cached_role_session(session.session_id, now=100)
            self.assertTrue(fresh)
            self.assertIs(cached, session)

            # Wall time stays fixed at 100 while 16 seconds of monotonic time
            # pass, beyond the 15-second RouterOS-role revalidation interval.
            monotonic_now[0] = 26.0
            fresh, cached = store.cached_role_session(session.session_id, now=100)
            self.assertFalse(fresh)
            self.assertIsNone(cached)
            self.assertIs(
                store.revalidate_role(
                    session.session_id,
                    resolve_role,
                    now=100,
                    interval_seconds=15,
                ),
                session,
            )
            self.assertEqual(calls, 1)

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
        monotonic_now = [100.0]
        with mock.patch("security.time.monotonic", side_effect=lambda: monotonic_now[0]):
            session = store.create("admin", "router-secret", role="owner", now=100)
            monotonic_now[0] = 116.0
            checked = store.revalidate_role(
                session.session_id, lambda _session: "read_only", now=116,
            )

            self.assertIs(checked, session)
            self.assertEqual(session.role, "read_only")
            self.assertEqual(session.last_seen, 100)
            monotonic_now[0] = 117.0
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
        monotonic_now = [100.0]
        with mock.patch("security.time.monotonic", side_effect=lambda: monotonic_now[0]):
            session = store.create("admin", "router-secret", role="read_only", now=100)
            monotonic_now[0] = 116.0
            self.assertIs(
                store.revalidate_role(session.session_id, lambda _session: "owner", now=116),
                session,
            )
            self.assertEqual(session.role, "read_only")

    def test_routeros_role_revalidation_treats_clock_rollback_as_stale(self) -> None:
        for interval_seconds in (0, 15):
            with self.subTest(interval_seconds=interval_seconds):
                store = SessionStore()
                monotonic_now = [10.0]
                with mock.patch("security.time.monotonic", side_effect=lambda: monotonic_now[0]):
                    session = store.create("admin", "router-secret", role="owner", now=100)
                    calls = 0

                    def account_is_disabled(_session) -> None:
                        nonlocal calls
                        calls += 1
                        return None

                    # Wall time rolls back while monotonic time advances past
                    # the cache interval; the RouterOS role must be refreshed.
                    monotonic_now[0] = 26.0
                    self.assertIsNone(
                        store.revalidate_role(
                            session.session_id,
                            account_is_disabled,
                            now=90,
                            interval_seconds=interval_seconds,
                        )
                    )
                    self.assertEqual(calls, 1)
                    self.assertIsNone(store.get(session.session_id, now=90, touch=False))

    def test_routeros_role_revalidation_revokes_missing_or_incomparable_identity(self) -> None:
        monotonic_now = [100.0]
        with mock.patch("security.time.monotonic", side_effect=lambda: monotonic_now[0]):
            missing_store = SessionStore()
            missing = missing_store.create("admin", "router-secret", role="owner", now=100)
            monotonic_now[0] = 116.0
            self.assertIsNone(
                missing_store.revalidate_role(missing.session_id, lambda _session: None, now=116)
            )
            self.assertIsNone(missing_store.get(missing.session_id, now=116, touch=False))

            monotonic_now[0] = 100.0
            changed_store = SessionStore()
            changed = changed_store.create("admin", "router-secret", role="administrator", now=100)
            monotonic_now[0] = 116.0
            self.assertIsNone(
                changed_store.revalidate_role(
                    changed.session_id, lambda _session: "security_operator", now=116
                )
            )
            self.assertIsNone(changed_store.get(changed.session_id, now=116, touch=False))

    def test_disabled_routeros_account_revokes_all_casefold_matching_sessions(self) -> None:
        store = SessionStore()
        disabled_account = store.create("admin", "first-secret", role="owner")
        second_session = store.create("ADMIN", "second-secret", role="read_only")
        unrelated = store.create("auditor", "other-secret", role="auditor")

        self.assertIsNone(
            store.revalidate_role(
                disabled_account.session_id,
                lambda _session: None,
                interval_seconds=0,
            )
        )

        self.assertIsNone(store.get(disabled_account.session_id, touch=False))
        self.assertIsNone(store.get(second_session.session_id, touch=False))
        self.assertEqual(disabled_account.password, "")
        self.assertEqual(second_session.password, "")
        self.assertIs(store.get(unrelated.session_id, touch=False), unrelated)
        self.assertEqual(store.active(), [unrelated])
        self.assertEqual(store._invalidating_usernames, {})

    def test_disabled_account_generation_blocks_stale_authenticated_session_insert(self) -> None:
        store = SessionStore()
        existing = store.create("admin", "existing-secret", role="owner")
        generation = store.account_revocation_generation("ADMIN")

        self.assertIsNone(
            store.revalidate_role(
                existing.session_id,
                lambda _session: None,
                interval_seconds=0,
            )
        )
        self.assertEqual(store.account_revocation_generation("admin"), generation + 1)
        with self.assertRaises(SessionAuthorizationChanged):
            store.create(
                "admin",
                "stale-login-secret",
                expected_account_revocation_generation=generation,
            )

        # A later login may proceed only after it observes the new generation
        # and independently completes fresh RouterOS authentication.
        fresh = store.create(
            "ADMIN",
            "fresh-login-secret",
            expected_account_revocation_generation=(
                store.account_revocation_generation("admin")
            ),
        )
        self.assertIs(store.get(fresh.session_id, touch=False), fresh)

    def test_role_refresh_cache_fast_path_honors_concurrent_account_invalidation(self) -> None:
        store = SessionStore()
        session = store.create("admin", "router-secret", role="owner")
        original_get = store.get
        invalidation_started = False

        def get_then_start_invalidation(*args, **kwargs):
            nonlocal invalidation_started
            current = original_get(*args, **kwargs)
            if current is session and not invalidation_started:
                invalidation_started = True
                with store._lock:
                    store._mark_account_invalidating_locked("admin")
            return current

        with mock.patch.object(store, "get", side_effect=get_then_start_invalidation):
            refreshed = store.revalidate_role(
                session.session_id,
                lambda _session: self.fail("warm cache should not bypass invalidation"),
            )

        self.assertIsNone(refreshed)
        self.assertFalse(store.is_active_nonblocking(session.session_id))

    def test_disabled_account_blocks_peer_session_until_live_send_drains(self) -> None:
        store = SessionStore()
        disabled_account = store.create("admin", "first-secret", role="owner")
        peer = store.create("admin", "peer-secret", role="owner")
        peer_lock = store.role_check_lock(peer.session_id)
        self.assertIsNotNone(peer_lock)
        assert peer_lock is not None
        peer_lock.acquire()

        with ThreadPoolExecutor(max_workers=1) as executor:
            refresh = executor.submit(
                store.revalidate_role,
                disabled_account.session_id,
                lambda _session: None,
                interval_seconds=0,
            )
            try:
                deadline = time.monotonic() + 1
                while store.is_active_nonblocking(peer.session_id) and time.monotonic() < deadline:
                    time.sleep(0.001)
                self.assertFalse(store.is_active_nonblocking(peer.session_id))
                self.assertFalse(refresh.done())
                self.assertEqual(peer.password, "peer-secret")
            finally:
                peer_lock.release()

            self.assertIsNone(refresh.result(timeout=1))

        self.assertIsNone(store.get(peer.session_id, touch=False))
        self.assertEqual(peer.password, "")

    def test_routeros_role_lookup_error_revokes_session(self) -> None:
        for role in ("owner", "read_only"):
            with self.subTest(role=role):
                store = SessionStore()
                monotonic_now = [100.0]
                with mock.patch("security.time.monotonic", side_effect=lambda: monotonic_now[0]):
                    session = store.create("admin", "router-secret", role=role, now=100)
                    monotonic_now[0] = 116.0
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
        first_view = next(item for item in snapshot if item["id_hash"] == hashlib.sha256(first.revocation_ref.encode()).hexdigest()[:16])
        self.assertTrue(first_view["current"])
        self.assertEqual(first_view["id"], "")
        self.assertNotIn(first.session_id, str(snapshot))
        identified = store.snapshot(current_session_id=first.session_id, now=120, include_revocation_refs=True)
        first_reference = next(item["id"] for item in identified if item["username"] == "admin")
        self.assertEqual(first_reference, first.revocation_ref)
        self.assertNotEqual(first_reference, first.session_id)
        self.assertNotIn(first.session_id, str(identified))
        self.assertNotIn("password", str(snapshot).lower())
        second_reference = second.revocation_ref
        self.assertTrue(store.revoke_by_reference(second_reference))
        self.assertFalse(store.revoke_by_reference(second_reference))
        self.assertEqual((second.password, second.csrf_token), ("", ""))
        self.assertEqual(second.authorization_ref, "")
        self.assertEqual(second.revocation_ref, "")
        self.assertFalse(store.revoke_by_reference("invalid-reference"))
        self.assertFalse(store.revoke(second.session_id))

    def test_revoke_account_sessions_except_is_casefold_scoped_and_preserves_caller(self) -> None:
        store = SessionStore()
        caller = store.create("Admin", "secret", role="owner")
        same_account = store.create("admin", "secret", role="owner")
        another_same_account = store.create("ADMIN", "secret", role="administrator")
        other_account = store.create("auditor", "secret", role="auditor")

        revoked = store.revoke_account_sessions_except("admin", caller.session_id)

        self.assertEqual(revoked, 2)
        self.assertIsNotNone(store.get(caller.session_id, touch=False))
        self.assertIsNone(store.get(same_account.session_id, touch=False))
        self.assertIsNone(store.get(another_same_account.session_id, touch=False))
        self.assertIsNotNone(store.get(other_account.session_id, touch=False))
        self.assertEqual((same_account.password, another_same_account.password), ("", ""))
        self.assertEqual(store.revoke_account_sessions_except("admin", caller.session_id), 0)

        self.assertIsNone(store.revoke_account_sessions_except("admin", "stale-session-id"))
        self.assertIsNotNone(store.get(caller.session_id, touch=False))
        self.assertIsNotNone(store.get(other_account.session_id, touch=False))

    def test_telemetry_dispatch_is_atomic_with_session_revocation(self) -> None:
        store = SessionStore()
        session = store.create("admin", "secret")
        authorization_ref = session.authorization_ref
        dispatch_entered = threading.Event()
        release_dispatch = threading.Event()
        revoked = threading.Event()
        order = []
        accepted = []

        def dispatch() -> None:
            order.append("dispatch-start")
            dispatch_entered.set()
            release_dispatch.wait(1)
            order.append("dispatch-end")

        publisher = threading.Thread(
            target=lambda: accepted.append(
                store.dispatch_if_active_authorization_ref(authorization_ref, dispatch)
            )
        )
        publisher.start()
        self.assertTrue(dispatch_entered.wait(1))

        def revoke() -> None:
            store.revoke(session.session_id)
            order.append("revoke")
            revoked.set()

        revoker = threading.Thread(target=revoke)
        revoker.start()
        self.assertFalse(revoked.wait(0.02))
        release_dispatch.set()
        publisher.join(1)
        revoker.join(1)

        self.assertFalse(publisher.is_alive())
        self.assertFalse(revoker.is_alive())
        self.assertEqual(accepted, [True])
        self.assertEqual(order, ["dispatch-start", "dispatch-end", "revoke"])
        self.assertFalse(
            store.dispatch_if_active_authorization_ref(authorization_ref, lambda: None)
        )

    def test_telemetry_dispatch_rechecks_expiry_after_waiting_for_store_lock(self) -> None:
        clock = {"wall": 100.0, "monotonic": 100.0}
        store = SessionStore(idle_seconds=5, absolute_seconds=100)
        with mock.patch("security.time.monotonic", side_effect=lambda: clock["monotonic"]):
            session = store.create("admin", "secret", now=clock["wall"])

        underlying_lock = threading.RLock()
        lock_requested = threading.Event()

        class LockGate:
            def __enter__(self):
                lock_requested.set()
                underlying_lock.acquire()
                return self

            def __exit__(self, _exc_type, _exc, _traceback):
                underlying_lock.release()

        store._lock = LockGate()  # noqa: SLF001 - hold the store lock across clock advance
        result = []
        underlying_lock.acquire()
        with (
            mock.patch("security.time.time", side_effect=lambda: clock["wall"]),
            mock.patch("security.time.monotonic", side_effect=lambda: clock["monotonic"]),
        ):
            worker = threading.Thread(
                target=lambda: result.append(
                    store.dispatch_if_active_authorization_ref(
                        session.authorization_ref, lambda: result.append("dispatched")
                    )
                )
            )
            worker.start()
            self.assertTrue(lock_requested.wait(1))
            clock["wall"] = 106.0
            clock["monotonic"] = 106.0
            underlying_lock.release()
            worker.join(1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(result, [False])
        self.assertEqual(session.authorization_ref, "")

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

    def test_rate_limited_login_audit_is_globally_coalesced_under_concurrency(self) -> None:
        limiter = LoginRateLimiter(rate_limited_login_audit_interval_seconds=60)
        concurrent_attempts = 20
        start = threading.Barrier(concurrent_attempts)

        def reserve_audit_slot() -> int | None:
            start.wait(timeout=5)
            return limiter.reserve_rate_limited_login_audit(now=100)

        with ThreadPoolExecutor(max_workers=concurrent_attempts) as executor:
            results = list(executor.map(lambda _index: reserve_audit_slot(), range(concurrent_attempts)))

        self.assertEqual([value for value in results if value is not None], [0])
        limiter.complete_rate_limited_login_audit(succeeded=True)
        self.assertIsNone(limiter.reserve_rate_limited_login_audit(now=159.99))
        self.assertEqual(limiter.reserve_rate_limited_login_audit(now=160), 20)
        limiter.complete_rate_limited_login_audit(succeeded=True)
        self.assertIsNone(limiter.reserve_rate_limited_login_audit(now=160.1))

    def test_admin_account_rate_limited_audit_is_coalesced_under_concurrency(self) -> None:
        limiter = LoginRateLimiter()
        concurrent_attempts = 20
        start = threading.Barrier(concurrent_attempts)

        def reserve_audit_slot() -> bool:
            start.wait(timeout=5)
            return limiter.reserve_admin_account_rate_limited_audit(now=100)

        with ThreadPoolExecutor(max_workers=concurrent_attempts) as executor:
            outcomes = list(executor.map(lambda _index: reserve_audit_slot(), range(concurrent_attempts)))

        self.assertEqual(sum(outcomes), 1)
        limiter.complete_admin_account_rate_limited_audit(succeeded=True)
        self.assertFalse(limiter.reserve_admin_account_rate_limited_audit(now=159.99))
        self.assertTrue(limiter.reserve_admin_account_rate_limited_audit(now=160))
        limiter.complete_admin_account_rate_limited_audit(succeeded=True)

    def test_admin_account_rate_limited_audit_can_retry_after_failed_write(self) -> None:
        limiter = LoginRateLimiter()
        self.assertTrue(limiter.reserve_admin_account_rate_limited_audit(now=100))
        self.assertFalse(limiter.reserve_admin_account_rate_limited_audit(now=101))
        limiter.complete_admin_account_rate_limited_audit(succeeded=False)

        self.assertTrue(limiter.reserve_admin_account_rate_limited_audit(now=101))
        limiter.complete_admin_account_rate_limited_audit(succeeded=True)
        self.assertFalse(limiter.reserve_admin_account_rate_limited_audit(now=160.99))
        self.assertTrue(limiter.reserve_admin_account_rate_limited_audit(now=161))
        limiter.complete_admin_account_rate_limited_audit(succeeded=True)

    def test_rate_limited_login_audit_retains_count_after_failed_write(self) -> None:
        limiter = LoginRateLimiter(rate_limited_login_audit_interval_seconds=60)
        self.assertEqual(limiter.reserve_rate_limited_login_audit(now=10), 0)
        self.assertIsNone(limiter.reserve_rate_limited_login_audit(now=11))
        limiter.complete_rate_limited_login_audit(succeeded=False)

        self.assertIsNone(limiter.reserve_rate_limited_login_audit(now=69.99))
        self.assertEqual(limiter.reserve_rate_limited_login_audit(now=70), 3)
        limiter.complete_rate_limited_login_audit(succeeded=True)
        self.assertEqual(limiter.reserve_rate_limited_login_audit(now=130), 0)
        limiter.complete_rate_limited_login_audit(succeeded=True)

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
