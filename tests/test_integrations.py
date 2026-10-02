import json
import unittest
from unittest import mock

from integrations import RedisStreamPublisher, WebhookDispatcher


class FakeRedis:
    def __init__(self):
        self.calls = []
        self.failures = 0

    def xadd(self, *args, **kwargs):
        self.calls.append((args, kwargs))
        if self.failures:
            self.failures -= 1
            raise OSError("redis unavailable")
        return "1-0"


class IntegrationTests(unittest.TestCase):
    def test_redis_stream_publisher_redacts_payload_and_sets_idempotency_key(self):
        client = FakeRedis()
        publisher = RedisStreamPublisher("redis://localhost", client=client)
        stream_id = publisher.publish(
            {
                "event": "audit",
                "event_id": "evt-1",
                "details": {"safe": "yes", "password": "never"},
            }
        )
        self.assertEqual(stream_id, "1-0")
        _, kwargs = client.calls[0]
        fields = client.calls[0][0][1]
        self.assertEqual(kwargs["maxlen"], 10_000)
        payload = json.loads(fields["payload"])
        self.assertEqual(payload["event_id"], "evt-1")
        self.assertNotIn("password", json.dumps(payload))

    def test_redis_outage_retry_preserves_event_id_and_records_aggregate_health(self):
        client = FakeRedis()
        client.failures = 1
        publisher = RedisStreamPublisher("redis://localhost", client=client)
        dispatcher = WebhookDispatcher(None, None, redis_publisher=publisher)
        with mock.patch("integrations.time.sleep"):
            dispatcher._deliver_with_retries({"event": "audit", "event_id": "evt-retry"})

        self.assertEqual(len(client.calls), 2)
        self.assertEqual([call[0][1]["event_id"] for call in client.calls], ["evt-retry", "evt-retry"])
        self.assertEqual(publisher.metrics()["publish_failures"], 1)
        self.assertEqual(publisher.metrics()["publish_successes"], 1)
        self.assertEqual(publisher.metrics()["available"], 1)
        self.assertEqual(dispatcher.metrics()["delivery_successes"], 1)
        dispatcher.stop()

    def test_signed_webhook_uses_timestamp_and_event_id_headers(self):
        dispatcher = WebhookDispatcher(
            "https://events.example.test/ingest",
            "s" * 32,
            base_backoff=0.1,
        )
        response = mock.MagicMock(status=202)
        response.__enter__.return_value = response
        with mock.patch("integrations.urllib.request.urlopen", return_value=response) as request:
            dispatcher._deliver(
                {
                    "event": "audit",
                    "event_id": "evt-2",
                    "details": {"token": "never", "safe": "yes"},
                },
                attempt=1,
            )
        sent = request.call_args.args[0]
        self.assertEqual(sent.get_header("X-vpn-dashboard-event-id"), "evt-2")
        self.assertIsNotNone(sent.get_header("X-vpn-dashboard-timestamp"))
        self.assertTrue(sent.get_header("X-vpn-dashboard-signature").startswith("sha256="))
        self.assertNotIn(b"token", sent.data)


if __name__ == "__main__":
    unittest.main()
