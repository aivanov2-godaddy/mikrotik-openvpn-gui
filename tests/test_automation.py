from __future__ import annotations

import unittest
from copy import deepcopy
from types import SimpleNamespace
from typing import Any

from automation import AutomationMixin
from routeros import RouterOSError


class FakeStore:
    def __init__(self, control: dict[str, Any] | None = None) -> None:
        self.control = control or {"enforcement_state": "", "notifications": True, "max_sessions": 5}
        self.audits: list[dict[str, Any]] = []
        self.alerts: list[dict[str, Any]] = []
        self.enforcement_state = str(self.control.get("enforcement_state", ""))
        self.fail_enforcement_state_write = False

    def audit(self, **record: Any) -> None:
        self.audits.append(record)

    def add_alert(self, **record: Any) -> bool:
        self.alerts.append(record)
        return True

    def set_enforcement_state(self, _username: str, value: str) -> None:
        if self.fail_enforcement_state_write:
            raise OSError("private local database failure")
        self.enforcement_state = value
        self.control["enforcement_state"] = value

    def all_user_controls(self) -> dict[str, dict[str, Any]]:
        return {"alice": self.control}

    def user_controls(self, _username: str) -> dict[str, Any]:
        return self.control

    def quota_usage(self, _username: str, _period_start: int) -> int:
        return 0

    def observe_sessions(self, _sessions: list[dict[str, Any]]) -> None:
        pass


class FakeRouter:
    def __init__(self, *, sessions: list[dict[str, Any]] | None = None) -> None:
        self.users = [{"id": "*1", "name": "alice", "profile": "default", "comment": "", "disabled": False}]
        self.sessions = sessions or []
        self.update_error: str | None = None
        self.update_commits_before_error = False
        self.terminate_failures = 0
        self.terminate_commits_before_error = False
        self.checkpoints = 0
        self.after_checkpoint = None
        self.user_read_calls = 0
        self.fail_user_read_calls: set[int] = set()
        self.session_read_calls = 0
        self.fail_session_read_calls: set[int] = set()
        self.change_session_on_read: dict[int, dict[str, Any]] = {}

    def list_ovpn_users(self, _credentials: Any) -> list[dict[str, Any]]:
        self.user_read_calls += 1
        if self.user_read_calls in self.fail_user_read_calls:
            raise RouterOSError("private account read-back error")
        return deepcopy(self.users)

    def list_active_ovpn_sessions(self, _credentials: Any) -> list[dict[str, Any]]:
        self.session_read_calls += 1
        if self.session_read_calls in self.change_session_on_read:
            replacement = self.change_session_on_read[self.session_read_calls]
            self.sessions = [replacement if item["id"] == replacement["id"] else item for item in self.sessions]
        if self.session_read_calls in self.fail_session_read_calls:
            raise RouterOSError("private session read-back error")
        return deepcopy(self.sessions)

    def create_configuration_export(self, _credentials: Any, *, name: str) -> str:
        self.checkpoints += 1
        if self.after_checkpoint:
            self.after_checkpoint(self)
        return name

    def update_user(self, _credentials: Any, *, user_id: str, disabled: bool) -> None:
        user = next(item for item in self.users if item["id"] == user_id)
        if self.update_error and not self.update_commits_before_error:
            raise RouterOSError(self.update_error)
        user["disabled"] = disabled
        if self.update_error:
            raise RouterOSError(self.update_error)

    def terminate_session(self, _credentials: Any, *, session_id: str) -> None:
        if self.terminate_failures and not self.terminate_commits_before_error:
            self.terminate_failures -= 1
            raise RouterOSError("private router response must not be copied to audit")
        self.sessions = [item for item in self.sessions if item["id"] != session_id]
        if self.terminate_failures:
            self.terminate_failures -= 1
            raise RouterOSError("private router response must not be copied to audit")


class Worker(AutomationMixin):
    def __init__(self, router: FakeRouter, store: FakeStore) -> None:
        self.context = SimpleNamespace(router=router, store=store, sessions=None)


class OnePassStop:
    def __init__(self) -> None:
        self.calls = 0

    def wait(self, _seconds: int) -> bool:
        self.calls += 1
        return self.calls > 1


class ActiveCredentials:
    @staticmethod
    def active() -> list[Any]:
        return [SimpleNamespace(username="router-admin", password="in-memory-only")]


def session(identifier: str) -> dict[str, Any]:
    return {
        "id": identifier,
        "name": "alice",
        "session_id": f"sid-{identifier}",
        "source_address": "192.0.2.8",
        "vpn_address": "10.8.0.2",
        "uptime": "5m",
    }


class AutomationMutationTests(unittest.TestCase):
    credentials = object()

    def apply(self, router: FakeRouter, store: FakeStore, *, state: str = "quota", reason: str = "Quota reached") -> list[dict[str, Any]]:
        return Worker(router, store)._apply_automation_access(
            self.credentials,
            deepcopy(router.users[0]),
            deepcopy(router.sessions),
            store.control,
            state,
            reason,
            1_800_000_000,
        )

    def test_stale_account_snapshot_blocks_automatic_write(self) -> None:
        router = FakeRouter()
        store = FakeStore()
        observed_user = deepcopy(router.users[0])
        router.users[0]["comment"] = "operator changed after snapshot"

        Worker(router, store)._apply_automation_access(
            self.credentials, observed_user, [], store.control, "quota", "Quota reached", 1_800_000_000
        )

        self.assertFalse(router.users[0]["disabled"])
        self.assertEqual(router.checkpoints, 0)
        self.assertEqual(store.audits[-1]["status"], "stale")

    def test_account_change_during_checkpoint_blocks_automatic_write(self) -> None:
        router = FakeRouter()
        router.after_checkpoint = lambda current: current.users[0].update(comment="changed during export")
        store = FakeStore()

        self.apply(router, store)

        self.assertFalse(router.users[0]["disabled"])
        self.assertEqual(router.checkpoints, 1)
        self.assertEqual(store.enforcement_state, "")
        self.assertEqual(store.audits[-1]["status"], "stale")

    def test_session_appearing_during_disable_is_included_in_cleanup(self) -> None:
        router = FakeRouter()
        router.after_checkpoint = lambda current: current.sessions.append(session("*late"))
        store = FakeStore()

        self.apply(router, store)

        self.assertEqual(router.sessions, [])
        self.assertEqual(store.audits[-1]["status"], "success")
        self.assertEqual(store.audits[-1]["details"]["sessions_still_active"], 0)

    def test_session_identity_change_is_partial_not_success(self) -> None:
        router = FakeRouter(sessions=[session("*a")])
        changed = session("*a")
        changed["session_id"] = "different-session"
        # Read 3 is the initial cleanup snapshot; read 4 is the per-target
        # revalidation immediately before DELETE.
        router.change_session_on_read[4] = changed
        store = FakeStore()

        self.apply(router, store)

        self.assertEqual(len(router.sessions), 1)
        self.assertEqual(store.audits[-1]["status"], "partial")
        self.assertEqual(store.audits[-1]["details"]["sessions_still_active"], 1)

    def test_unavailable_final_session_readback_is_unknown_not_success(self) -> None:
        router = FakeRouter(sessions=[session("*a")])
        router.fail_session_read_calls.update({6, 7})
        store = FakeStore()

        self.apply(router, store)

        self.assertEqual(router.sessions, [])
        self.assertEqual(store.audits[-1]["status"], "partial")
        self.assertIsNone(store.audits[-1]["details"]["sessions_still_active"])
        self.assertEqual(store.audits[-1]["details"]["final_session_readback"], "unknown")

    def test_unknown_disable_readback_persists_intent_for_next_poll_reconciliation(self) -> None:
        router = FakeRouter()
        # First read checks freshness; the second is the post-write read-back.
        router.fail_user_read_calls.add(3)
        store = FakeStore()
        worker = Worker(router, store)

        worker._apply_automation_access(
            self.credentials, deepcopy(router.users[0]), [], store.control,
            "quota", "Quota reached", 1_800_000_000,
        )

        self.assertEqual(store.enforcement_state, "pending:quota")
        self.assertTrue(router.users[0]["disabled"])
        worker._apply_automation_access(
            self.credentials, deepcopy(router.users[0]), [], store.control,
            "quota", "Quota reached", 1_800_000_030,
        )
        self.assertEqual(store.enforcement_state, "quota")

    def test_pending_expiry_is_terminal_and_does_not_restore_after_policy_edit(self) -> None:
        router = FakeRouter()
        router.users[0]["disabled"] = True
        store = FakeStore({"enforcement_state": "pending:expired", "notifications": True, "max_sessions": 5})

        self.apply(router, store, state="", reason="Expiry removed by later edit")

        self.assertTrue(router.users[0]["disabled"])
        self.assertEqual(router.checkpoints, 0)
        self.assertEqual(store.enforcement_state, "expired")
        self.assertFalse(any(item["action"] == "user.auto_restore" for item in store.audits))

    def test_lost_disable_response_is_verified_by_exact_account_readback(self) -> None:
        router = FakeRouter()
        router.update_error = "response lost"
        router.update_commits_before_error = True
        store = FakeStore()

        self.apply(router, store)

        self.assertTrue(router.users[0]["disabled"])
        self.assertEqual(store.enforcement_state, "quota")
        self.assertEqual(store.audits[-1]["status"], "success")
        self.assertTrue(store.audits[-1]["details"]["account_readback"] == "verified")

    def test_unverified_disable_does_not_record_enforcement_success(self) -> None:
        router = FakeRouter()
        router.update_error = "rejected"
        store = FakeStore()

        self.apply(router, store)

        self.assertFalse(router.users[0]["disabled"])
        self.assertEqual(store.enforcement_state, "")
        self.assertEqual(store.audits[-1]["status"], "failed")
        self.assertNotIn("private router response", str(store.alerts))

    def test_disable_fails_closed_when_pending_intent_cannot_be_persisted(self) -> None:
        router = FakeRouter()
        store = FakeStore()
        store.fail_enforcement_state_write = True

        self.apply(router, store)

        self.assertFalse(router.users[0]["disabled"])
        self.assertEqual(router.checkpoints, 1)
        self.assertNotIn("private local database failure", str(store.alerts))
        self.assertIn("No RouterOS account change was applied", store.alerts[-1]["details"])

    def test_failed_session_disconnect_is_partial_and_retried_next_poll(self) -> None:
        router = FakeRouter(sessions=[session("*a")])
        router.terminate_failures = 1
        store = FakeStore()
        worker = Worker(router, store)

        worker._apply_automation_access(
            self.credentials, deepcopy(router.users[0]), deepcopy(router.sessions),
            store.control, "quota", "Quota reached", 1_800_000_000,
        )

        first = store.audits[-1]
        self.assertEqual(first["status"], "partial")
        self.assertEqual(first["details"]["sessions_failed"], 1)
        self.assertEqual(len(router.sessions), 1)
        self.assertIn("worker will retry", store.alerts[-1]["details"])

        worker._apply_automation_access(
            self.credentials, deepcopy(router.users[0]), deepcopy(router.sessions),
            store.control, "quota", "Quota reached", 1_800_000_030,
        )

        self.assertEqual(router.sessions, [])
        self.assertEqual(store.audits[-1]["status"], "success")
        self.assertEqual(store.audits[-1]["details"]["sessions_disconnected_verified"], 1)

    def test_lost_disconnect_response_is_success_only_when_readback_confirms_absence(self) -> None:
        router = FakeRouter(sessions=[session("*a")])
        router.terminate_failures = 1
        router.terminate_commits_before_error = True
        store = FakeStore()

        self.apply(router, store)

        self.assertEqual(router.sessions, [])
        self.assertEqual(store.audits[-1]["status"], "success")
        self.assertEqual(store.audits[-1]["details"]["sessions_disconnected_verified"], 1)

    def test_restoration_clears_enforcement_only_after_readback(self) -> None:
        router = FakeRouter()
        router.users[0]["disabled"] = True
        store = FakeStore({"enforcement_state": "schedule", "notifications": True, "max_sessions": 5})
        router.update_error = "response lost"
        router.update_commits_before_error = True

        self.apply(router, store, state="", reason="Schedule opened")

        self.assertFalse(router.users[0]["disabled"])
        self.assertEqual(store.enforcement_state, "")
        self.assertEqual(store.audits[-1]["status"], "success")

    def test_session_limit_failure_is_not_audited_as_success(self) -> None:
        router = FakeRouter(sessions=[session("*a"), session("*b")])
        router.terminate_failures = 1
        store = FakeStore({"enforcement_state": "", "notifications": True, "max_sessions": 1})
        worker = Worker(router, store)
        worker.context.sessions = ActiveCredentials()
        worker._telemetry_stop = OnePassStop()

        worker._telemetry_loop()

        record = next(item for item in store.audits if item["action"] == "session.limit")
        self.assertEqual(record["status"], "partial")
        self.assertEqual(record["details"]["sessions_failed"], 1)
        self.assertTrue(record["details"]["still_over_limit"])
        alert = next(item for item in store.alerts if item["action"] == "session.limit.partial")
        self.assertEqual(alert["severity"], "critical")
        self.assertNotIn("*a", str(record))
        self.assertNotIn("*b", str(record))


if __name__ == "__main__":
    unittest.main()
