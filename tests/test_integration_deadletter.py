from __future__ import annotations

import sqlite3
import tempfile
import time
import unittest
from pathlib import Path

from integrations import RedisStreamPublisher, WebhookDispatcher
from store import MetadataStore


class FailingRedis:
    def __init__(self) -> None:
        self.calls = 0

    def xadd(self, *_args, **_kwargs):
        self.calls += 1
        raise OSError("unavailable")


class IntegrationDeadLetterTests(unittest.TestCase):
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
