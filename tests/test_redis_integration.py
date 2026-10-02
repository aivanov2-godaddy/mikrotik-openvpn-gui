from __future__ import annotations

import os
import subprocess
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any

from integrations import RedisStreamPublisher
from store import MetadataStore


class RedisOutboxRecoveryTests(unittest.TestCase):
    """Exercise the durable outbox against a disposable real Redis container."""

    @classmethod
    def setUpClass(cls) -> None:
        cls.redis_url = os.environ.get("REDIS_TEST_URL", "")
        cls.container = os.environ.get("REDIS_TEST_CONTAINER", "")
        if not cls.redis_url or not cls.container:
            raise unittest.SkipTest("requires the isolated REDIS_TEST_URL and REDIS_TEST_CONTAINER")
        try:
            import redis
        except ImportError as error:
            raise unittest.SkipTest("optional Redis test dependency is not installed") from error
        cls.redis_errors = redis.exceptions.RedisError
        cls.client = redis.Redis.from_url(
            cls.redis_url,
            decode_responses=True,
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
        )
        cls.client.ping()

    def setUp(self) -> None:
        self.client.flushdb()
        self.tempdir = tempfile.TemporaryDirectory()
        self.addCleanup(self.tempdir.cleanup)
        self.store = MetadataStore(str(Path(self.tempdir.name) / "outbox.sqlite"))
        self.store.set_audit_hook(lambda _event: None)
        self.publisher = RedisStreamPublisher(
            self.redis_url,
            stream="vpn-dashboard.test.events",
            client=self.client,
        )

    def _enqueue_event(self) -> dict[str, Any]:
        self.store.audit(
            actor="test-operator",
            action="user.update",
            target="test-user",
            status="success",
            details={"safe": "retained", "password": "must-not-escape"},
        )
        return self.store.pending_integration_events(now=int(time.time()))[0]

    def _restart_redis(self) -> None:
        subprocess.run(
            ["docker", "restart", self.container],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            try:
                if self.client.ping():
                    return
            except Exception:
                time.sleep(0.1)
        self.fail("disposable Redis did not become ready after restart")

    def test_outbox_survives_redis_restart_and_drains_without_leaking_secrets(self) -> None:
        record = self._enqueue_event()
        event_id = str(record["event_id"])
        subprocess.run(
            ["docker", "stop", self.container],
            check=True,
            capture_output=True,
            text=True,
            timeout=30,
        )
        try:
            with self.assertRaises(self.redis_errors):
                self.publisher.publish(record["payload"])
        finally:
            self._restart_redis()

        self.store.mark_integration_failed(event_id, "ConnectionError", retry_at=int(time.time()) + 1)
        retry = self.store.pending_integration_events(now=int(time.time()) + 2)[0]
        self.publisher.publish(retry["payload"])
        self.store.mark_integration_delivered(event_id)

        entries = self.client.xrange("vpn-dashboard.test.events")
        self.assertEqual(len(entries), 1)
        fields = entries[0][1]
        self.assertEqual(fields["event_id"], event_id)
        self.assertNotIn("must-not-escape", fields["payload"])
        self.assertEqual(self.store.integration_outbox_metrics()["pending"], 0)
        self.assertEqual(self.publisher.metrics()["publish_failures"], 1)
        self.assertEqual(self.publisher.metrics()["publish_successes"], 1)

    def test_ambiguous_publish_retry_keeps_stable_id_for_consumer_deduplication(self) -> None:
        record = self._enqueue_event()
        event_id = str(record["event_id"])

        # Model XADD succeeding while its SQLite acknowledgement is lost. The
        # event remains pending and is published again with the same ID.
        self.publisher.publish(record["payload"])
        self.store.mark_integration_failed(event_id, "acknowledgement_lost", retry_at=int(time.time()) + 1)
        retry = self.store.pending_integration_events(now=int(time.time()) + 2)[0]
        self.publisher.publish(retry["payload"])
        self.store.mark_integration_delivered(event_id)

        entries = self.client.xrange("vpn-dashboard.test.events")
        self.assertEqual(len(entries), 2)
        self.assertEqual([fields["event_id"] for _, fields in entries], [event_id, event_id])
        self.assertEqual(self.store.integration_outbox_metrics()["pending"], 0)


if __name__ == "__main__":
    unittest.main()
