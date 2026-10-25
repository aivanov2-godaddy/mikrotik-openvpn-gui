from __future__ import annotations

import sqlite3
import threading
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from integrations import RedisStreamPublisher, WebhookDispatcher
from store import MetadataStore


class FailingRedis:
    def __init__(self) -> None:
        self.calls = 0

    def xadd(self, *_args, **_kwargs):
        self.calls += 1
        raise OSError("unavailable")


class RecordingRedis:
    def __init__(self, *, failures_remaining: int = 0) -> None:
        self.entries: list[tuple[str, dict[str, str]]] = []
        self.failures_remaining = failures_remaining
        self.calls = 0

    def xadd(self, stream: str, fields: dict[str, str], **_kwargs: object) -> str:
        self.calls += 1
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise OSError("unavailable")
        self.entries.append((stream, dict(fields)))
        return str(len(self.entries))


class FailOnceSQLiteOutbox:
    """Inject a transient SQLite exception at one durable-worker boundary."""

    def __init__(self, store: MetadataStore, *, operation: str) -> None:
        self.store = store
        self.operation = operation
        self.failed = False

    def pending_integration_events(self, limit: int = 20, *, now: int | None = None):
        if self.operation == "claim" and not self.failed:
            self.failed = True
            raise sqlite3.OperationalError("database is locked")
        return self.store.pending_integration_events(limit, now=now)

    def mark_integration_delivered(self, event_id: str, *, now: int | None = None) -> None:
        if self.operation == "ack" and not self.failed:
            self.failed = True
            raise sqlite3.OperationalError("database is locked")
        self.store.mark_integration_delivered(event_id, now=now)

    def mark_integration_failed(self, event_id: str, error: str, *, retry_at: int) -> None:
        if self.operation == "mark_failed" and not self.failed:
            self.failed = True
            raise sqlite3.OperationalError("database is locked")
        self.store.mark_integration_failed(event_id, error, retry_at=retry_at)

    def mark_integration_dead_lettered(self, event_id: str, reason: str) -> None:
        if self.operation == "dead_letter" and not self.failed:
            self.failed = True
            raise sqlite3.OperationalError("database is locked")
        self.store.mark_integration_dead_lettered(event_id, reason)


class IntegrationDeadLetterTests(unittest.TestCase):
    def _wait_until(self, predicate, *, timeout: float = 5.0) -> None:
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if predicate():
                return
            time.sleep(0.01)
        self.fail("outbox worker did not recover before the deadline")

    def _run_worker_after_sqlite_failure(
        self,
        operation: str,
        *,
        redis_client: RecordingRedis | None = None,
        max_outbox_attempts: int = 10,
    ) -> tuple[MetadataStore, WebhookDispatcher, FailOnceSQLiteOutbox, RecordingRedis, str]:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        store = MetadataStore(str(Path(temporary.name) / "dashboard.sqlite"))
        store.set_audit_hook(lambda _event: None)
        store.audit(actor="test", action="worker-recovery", target="local", status="success")
        record = store.pending_integration_events()[0]
        event_id = str(record["event_id"])
        store.mark_integration_failed(event_id, "test_retry_due", retry_at=int(time.time()))

        fault_store = FailOnceSQLiteOutbox(store, operation=operation)
        redis_client = redis_client or RecordingRedis()
        publisher = RedisStreamPublisher("redis://unused", client=redis_client)
        dispatcher = WebhookDispatcher(
            None,
            None,
            store=fault_store,
            redis_publisher=publisher,
            base_backoff=0.01,
            max_backoff=0.05,
            circuit_threshold=100,
            max_outbox_attempts=max_outbox_attempts,
        )
        self.addCleanup(dispatcher.stop)
        dispatcher.publish(record["payload"])
        self._wait_until(lambda: store.integration_outbox_metrics()["pending"] == 0)
        return store, dispatcher, fault_store, redis_client, event_id

    def test_outbox_batch_wakes_for_earliest_retry_deadline(self) -> None:
        class BatchStore:
            def __init__(self) -> None:
                self.failed_retries: list[tuple[str, int]] = []

            def pending_integration_events(self, _limit: int = 20):
                return [
                    {"event_id": "early", "attempts": 1, "payload": {}},
                    {"event_id": "late", "attempts": 6, "payload": {}},
                ]

            def mark_integration_failed(self, event_id: str, _error: str, *, retry_at: int) -> None:
                self.failed_retries.append((event_id, retry_at))

        store = BatchStore()
        dispatcher = WebhookDispatcher(
            None,
            None,
            store=store,  # type: ignore[arg-type]
            base_backoff=1,
            max_backoff=60,
            circuit_threshold=100,
        )

        with patch.object(dispatcher, "_deliver_with_retries", side_effect=OSError("offline")):
            with patch("integrations.time.time", return_value=100):
                with patch("integrations.time.monotonic", return_value=200):
                    succeeded, retry_deadline = dispatcher._dispatch_outbox_batch()

        self.assertTrue(succeeded)
        self.assertEqual(store.failed_retries, [("early", 101), ("late", 132)])
        self.assertEqual(retry_deadline, 201)

    def test_outbox_batch_wakes_for_earliest_sqlite_retry_deadline(self) -> None:
        class BatchStore:
            def pending_integration_events(self, _limit: int = 20):
                return [
                    {"event_id": "early", "attempts": 1, "payload": {}},
                    {"event_id": "late", "attempts": 1, "payload": {}},
                ]

            def mark_integration_delivered(self, _event_id: str) -> None:
                raise sqlite3.OperationalError("database is locked")

            def mark_integration_failed(self, *_args, **_kwargs) -> None:
                return None

        dispatcher = WebhookDispatcher(None, None, store=BatchStore())  # type: ignore[arg-type]
        with patch.object(
            dispatcher, "_record_outbox_storage_failure", side_effect=[1.0, 2.0]
        ):
            with patch("integrations.time.monotonic", return_value=200):
                succeeded, retry_deadline = dispatcher._dispatch_outbox_batch()

        self.assertFalse(succeeded)
        self.assertEqual(retry_deadline, 201.0)

    def test_outbox_worker_does_not_repeat_elapsed_batch_retry_delay(self) -> None:
        dispatcher = WebhookDispatcher(None, None, store=object())  # type: ignore[arg-type]
        first_batch = threading.Event()
        second_batch = threading.Event()
        calls = 0

        def dispatch_batch() -> tuple[bool, float | None]:
            nonlocal calls
            calls += 1
            if calls == 1:
                first_batch.set()
                return False, 201.0
            second_batch.set()
            dispatcher._stop.set()
            return True, None

        worker = threading.Thread(target=dispatcher._run, daemon=True)
        try:
            with patch.object(dispatcher, "_dispatch_outbox_batch", side_effect=dispatch_batch):
                with patch("integrations.time.monotonic", return_value=202.0):
                    worker.start()
                    self.assertTrue(first_batch.wait(1.0), "worker did not finish its first batch")
                    self.assertTrue(
                        second_batch.wait(1.0),
                        "worker reapplied a relative retry delay after its deadline passed",
                    )
        finally:
            dispatcher.stop(timeout=1.0)
            worker.join(timeout=1.0)

        self.assertFalse(worker.is_alive())

    def test_outbox_worker_wakes_for_new_event_during_retry_backoff(self) -> None:
        dispatcher = WebhookDispatcher(None, None, store=object())  # type: ignore[arg-type]
        dispatcher._url = "https://example.invalid"
        dispatcher._secret = b"test"
        first_batch = threading.Event()
        second_batch = threading.Event()
        calls = 0

        def dispatch_batch() -> tuple[bool, float | None]:
            nonlocal calls
            calls += 1
            if calls == 1:
                first_batch.set()
                return False, time.monotonic() + 30.0
            second_batch.set()
            dispatcher._stop.set()
            return True, None

        worker = threading.Thread(target=dispatcher._run, daemon=True)
        try:
            with patch.object(dispatcher, "_dispatch_outbox_batch", side_effect=dispatch_batch):
                worker.start()
                self.assertTrue(first_batch.wait(1.0), "worker did not enter its retry backoff")
                dispatcher.publish({"event": "new_event"})
                self.assertTrue(
                    second_batch.wait(2.0),
                    "new outbox event waited behind the previous retry delay",
                )
        finally:
            dispatcher.stop(timeout=1.0)
            worker.join(timeout=1.0)

        self.assertFalse(worker.is_alive())

    def test_outbox_worker_retries_after_sqlite_claim_failure(self) -> None:
        with self.assertLogs("integrations", level="WARNING") as captured:
            store, dispatcher, fault_store, redis_client, event_id = self._run_worker_after_sqlite_failure("claim")

        self.assertTrue(fault_store.failed)
        self.assertIn("OperationalError", "\n".join(captured.output))
        self.assertNotIn("database is locked", "\n".join(captured.output))
        self.assertEqual(store.integration_outbox_metrics()["pending"], 0)
        self.assertEqual([entry[1]["event_id"] for entry in redis_client.entries], [event_id])
        self.assertEqual(dispatcher.metrics()["outbox_storage_failures"], 1)

    def test_outbox_worker_retries_after_sqlite_ack_failure_with_stable_id(self) -> None:
        store, dispatcher, fault_store, redis_client, event_id = self._run_worker_after_sqlite_failure("ack")

        self.assertTrue(fault_store.failed)
        self.assertEqual(store.integration_outbox_metrics()["pending"], 0)
        self.assertEqual([entry[1]["event_id"] for entry in redis_client.entries], [event_id, event_id])
        self.assertEqual(dispatcher.metrics()["outbox_storage_failures"], 1)
        self.assertEqual(dispatcher.metrics()["delivery_successes"], 2)

    def test_outbox_worker_continues_claimed_batch_after_sqlite_ack_failure(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            store.set_audit_hook(lambda _event: None)
            store.audit(actor="test", action="worker-recovery-first", target="local", status="success")
            store.audit(actor="test", action="worker-recovery-second", target="local", status="success")
            records = store.pending_integration_events(20)
            event_ids = [str(record["event_id"]) for record in records]
            for event_id in event_ids:
                store.mark_integration_failed(event_id, "test_retry_due", retry_at=int(time.time()))

            fault_store = FailOnceSQLiteOutbox(store, operation="ack")
            redis_client = RecordingRedis()
            dispatcher = WebhookDispatcher(
                None,
                None,
                store=fault_store,
                redis_publisher=RedisStreamPublisher("redis://unused", client=redis_client),
                base_backoff=0.01,
                max_backoff=0.05,
                circuit_threshold=100,
            )
            self.addCleanup(dispatcher.stop)
            for record in records:
                dispatcher.publish(record["payload"])

            self._wait_until(lambda: store.integration_outbox_metrics()["pending"] == 0)
            dispatcher.stop()

        self.assertEqual(
            [entry[1]["event_id"] for entry in redis_client.entries],
            [event_ids[0], event_ids[1], event_ids[0]],
        )
        self.assertEqual(dispatcher.metrics()["outbox_storage_failures"], 1)

    def test_outbox_worker_recovers_after_sqlite_retry_state_failure(self) -> None:
        redis_client = RecordingRedis(failures_remaining=3)
        store, dispatcher, fault_store, redis_client, event_id = self._run_worker_after_sqlite_failure(
            "mark_failed", redis_client=redis_client
        )

        self.assertTrue(fault_store.failed)
        self.assertEqual(store.integration_outbox_metrics()["pending"], 0)
        self.assertEqual([entry[1]["event_id"] for entry in redis_client.entries], [event_id])
        self.assertEqual(redis_client.calls, 4)
        self.assertEqual(dispatcher.metrics()["outbox_storage_failures"], 1)

    def test_outbox_worker_recovers_after_sqlite_dead_letter_failure(self) -> None:
        redis_client = RecordingRedis(failures_remaining=6)
        store, dispatcher, fault_store, redis_client, event_id = self._run_worker_after_sqlite_failure(
            "dead_letter", redis_client=redis_client, max_outbox_attempts=1
        )

        self.assertTrue(fault_store.failed)
        outbox = store.integration_outbox_metrics()
        self.assertEqual(outbox["pending"], 0)
        self.assertEqual(outbox["dead_lettered"], 1)
        self.assertEqual(redis_client.entries, [])
        self.assertEqual(redis_client.calls, 6)
        self.assertEqual(dispatcher.metrics()["outbox_storage_failures"], 1)

    def test_malformed_and_exhausted_outbox_rows_are_classified_and_retained(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = MetadataStore(str(Path(temporary) / "dashboard.sqlite"))
            store.set_audit_hook(lambda _event: None)
            store.audit(actor="test", action="malformed", target="local", status="success")
            store.audit(actor="test", action="retry-limit", target="local", status="success")
            connection = sqlite3.connect(store.path)
            try:
                malformed_id = connection.execute(
                    "SELECT event_id FROM integration_outbox WHERE event_type='audit' ORDER BY created_at,event_id LIMIT 1"
                ).fetchone()[0]
                connection.execute(
                    "UPDATE integration_outbox SET payload='not-json' WHERE event_id=?",
                    (malformed_id,),
                )
                connection.commit()
            finally:
                connection.close()

            redis = FailingRedis()
            dispatcher = WebhookDispatcher(
                None,
                None,
                store=store,
                redis_publisher=RedisStreamPublisher("redis://unused", client=redis),
                max_outbox_attempts=1,
                base_backoff=0.1,
                max_backoff=0.1,
                circuit_threshold=100,
            )
            try:
                deadline = time.monotonic() + 5
                while store.integration_outbox_metrics()["dead_lettered"] != 2:
                    if time.monotonic() >= deadline:
                        self.fail("outbox poison and retry-exhausted rows were not classified")
                    time.sleep(0.01)
            finally:
                dispatcher.stop()

            metrics = store.integration_outbox_metrics()
            self.assertEqual(metrics["pending"], 0)
            self.assertEqual(metrics["due"], 0)
            self.assertEqual(metrics["dead_lettered"], 2)
            self.assertEqual(redis.calls, 3, "only the valid event should get three bounded sends")
            self.assertNotIn("event_id", metrics)
            connection = sqlite3.connect(store.path)
            try:
                reasons = {
                    row[0]
                    for row in connection.execute(
                        "SELECT last_error FROM integration_outbox WHERE dead_lettered_at IS NOT NULL"
                    )
                }
            finally:
                connection.close()
            self.assertIn("malformed_payload_invalid_json", reasons)
            self.assertIn("retry_limit_OSError", reasons)
            self.assertEqual(store.pending_integration_events(now=int(time.time()) + 1000), [])

            pruned = store.prune_history(before=int(time.time()) + 1)
            self.assertEqual(pruned["integration_outbox"], 2)

    def test_existing_outbox_schema_gets_additive_dead_letter_migration(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            database = Path(temporary) / "dashboard.sqlite"
            connection = sqlite3.connect(database)
            try:
                connection.execute(
                    """CREATE TABLE integration_outbox (
                       event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL, payload TEXT NOT NULL,
                       created_at INTEGER NOT NULL, attempts INTEGER NOT NULL DEFAULT 0,
                       next_attempt_at INTEGER NOT NULL, last_error TEXT NOT NULL DEFAULT '',
                       delivered_at INTEGER)"""
                )
                connection.commit()
            finally:
                connection.close()

            MetadataStore(str(database))
            connection = sqlite3.connect(database)
            try:
                columns = {row[1] for row in connection.execute("PRAGMA table_info(integration_outbox)")}
                index_names = {row[1] for row in connection.execute("PRAGMA index_list(integration_outbox)")}
            finally:
                connection.close()
            self.assertIn("dead_lettered_at", columns)
            self.assertIn("idx_integration_outbox_active", index_names)


if __name__ == "__main__":
    unittest.main()
