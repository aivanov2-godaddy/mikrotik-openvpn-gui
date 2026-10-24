import hashlib
import hmac
import json
from pathlib import Path
from tempfile import TemporaryDirectory
from typing import Any
import unittest
from unittest import mock

from event_safety import sanitize_integration_event
from integrations import RedisStreamPublisher, WebhookDispatcher
from store import MetadataStore


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
    def test_integration_event_omits_unclassified_values_and_private_fields(self):
        payload = sanitize_integration_event(
            {
                "event": "unexpected-private-value",
                "event_id": "private-user@example.test",
                "action": "user.delete.private-user",
                "status": "operator entered free text",
                "created_at": True,
                "actor": "private-operator",
                "target": "private-vpn-user",
                "details": {"source_address": "192.0.2.55"},
            }
        )

        self.assertEqual(
            payload,
            {
                "schema_version": 2,
                "event": "audit",
                "action": "user",
            },
        )
        self.assertNotIn("private-user", json.dumps(payload))
        self.assertNotIn("private-user@example.test", json.dumps(payload))

    def test_integration_event_rejects_non_random_uuid_event_ids(self):
        payload = sanitize_integration_event(
            {"event": "audit", "event_id": "11111111-1111-1111-8111-111111111111"}
        )

        self.assertNotIn("event_id", payload)

    def test_full_audit_remains_local_while_remote_stream_is_minimized(self):
        with TemporaryDirectory() as directory:
            store = MetadataStore(str(Path(directory) / "dashboard.db"))
            observed = []
            store.set_audit_hook(observed.append)
            rationale = "fake-secret-sentinel-not-a-real-credential"
            store.audit(
                actor="private-operator",
                action="user.delete",
                target="private-vpn-user",
                status="success",
                details={"rationale": rationale, "source_address": "192.0.2.55"},
            )

            local_event = store.pending_integration_events()[0]["payload"]
            self.assertEqual(local_event["actor"], "private-operator")
            self.assertEqual(observed[0]["target"], "private-vpn-user")
            self.assertTrue(local_event["details"]["rationale_recorded"])
            self.assertNotIn("rationale", local_event["details"])
            self.assertNotIn(rationale, json.dumps(local_event))
            self.assertNotIn(rationale, json.dumps(observed[0]))
            self.assertEqual(local_event["details"]["source_address"], "192.0.2.55")

            audit_details = json.loads(store.recent_audit(1)[0]["details"])
            self.assertTrue(audit_details["rationale_recorded"])
            self.assertNotIn(rationale, json.dumps(audit_details))

            client = FakeRedis()
            RedisStreamPublisher("redis://localhost", client=client).publish(local_event)

            remote_payload = json.loads(client.calls[0][0][1]["payload"])
            self.assertEqual(remote_payload["action"], "user")
            self.assertEqual(remote_payload["status"], "success")
            self.assertNotIn("private-operator", json.dumps(remote_payload))
            self.assertNotIn("private-vpn-user", json.dumps(remote_payload))
            self.assertNotIn("private operator rationale", json.dumps(remote_payload))
            self.assertNotIn("192.0.2.55", json.dumps(remote_payload))

    def test_redis_stream_publisher_redacts_payload_and_sets_idempotency_key(self):
        client = FakeRedis()
        publisher = RedisStreamPublisher("redis://localhost", client=client)
        stream_id = publisher.publish(
            {
                "event": "audit",
                "event_id": "11111111-1111-4111-8111-111111111111",
                "action": "user.delete",
                "status": "success",
                "created_at": 1234,
                "actor": "private-operator",
                "target": "private-vpn-user",
                "source_address": "192.0.2.55",
                "details": {"reason": "private operator rationale", "password": "never"},
            }
        )
        self.assertEqual(stream_id, "1-0")
        _, kwargs = client.calls[0]
        fields = client.calls[0][0][1]
        self.assertEqual(kwargs["maxlen"], 10_000)
        payload = json.loads(fields["payload"])
        self.assertEqual(payload["event_id"], "11111111-1111-4111-8111-111111111111")
        self.assertEqual(payload, {
            "schema_version": 2,
            "event": "audit",
            "event_id": "11111111-1111-4111-8111-111111111111",
            "action": "user",
            "status": "success",
            "created_at": 1234,
        })
        self.assertNotIn("private-operator", json.dumps(payload))
        self.assertNotIn("private-vpn-user", json.dumps(payload))
        self.assertNotIn("192.0.2.55", json.dumps(payload))
        self.assertNotIn("fake-secret-sentinel-not-a-real-credential", json.dumps(payload))

    def test_redis_outage_retry_preserves_event_id_and_records_aggregate_health(self):
        client = FakeRedis()
        client.failures = 1
        publisher = RedisStreamPublisher("redis://localhost", client=client)
        dispatcher = WebhookDispatcher(None, None, redis_publisher=publisher)
        with mock.patch("integrations.time.sleep"):
            dispatcher._deliver_with_retries({
                "event": "audit",
                "event_id": "22222222-2222-4222-8222-222222222222",
            })

        self.assertEqual(len(client.calls), 2)
        self.assertEqual(
            [call[0][1]["event_id"] for call in client.calls],
            ["22222222-2222-4222-8222-222222222222"] * 2,
        )
        self.assertEqual(publisher.metrics()["publish_failures"], 1)
        self.assertEqual(publisher.metrics()["publish_successes"], 1)
        self.assertEqual(publisher.metrics()["available"], 1)
        self.assertEqual(dispatcher.metrics()["delivery_successes"], 1)
        dispatcher.stop()

    def test_retry_generates_one_stable_id_when_input_id_is_invalid(self):
        dispatcher = WebhookDispatcher(None, None)
        observed: list[tuple[str, int]] = []

        def fail_once(event: dict[str, Any], *, attempt: int) -> None:
            observed.append((event["event_id"], attempt))
            if attempt == 1:
                raise OSError("temporary delivery failure")

        generated_id = "44444444-4444-4444-8444-444444444444"
        with (
            mock.patch.object(dispatcher, "_deliver", side_effect=fail_once),
            mock.patch("integrations.uuid.uuid4", return_value=generated_id) as make_uuid,
            mock.patch("integrations.time.sleep"),
        ):
            dispatcher._deliver_with_retries({"event": "audit", "event_id": "invalid"})

        self.assertEqual(make_uuid.call_count, 1)
        self.assertEqual(
            observed,
            [(generated_id, 1), (generated_id, 2)],
        )
        dispatcher.stop()

    def test_delivery_backoff_is_exponential_and_bounded(self):
        dispatcher = WebhookDispatcher(
            None,
            None,
            redis_publisher=RedisStreamPublisher("redis://localhost", client=FakeRedis()),
            base_backoff=0.2,
            max_backoff=0.5,
        )
        self.assertEqual(dispatcher._backoff_for_attempt(1), 0.2)
        self.assertEqual(dispatcher._backoff_for_attempt(2), 0.4)
        self.assertEqual(dispatcher._backoff_for_attempt(3), 0.5)
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
                    "event_id": "33333333-3333-4333-8333-333333333333",
                    "action": "admin-session.revoke",
                    "status": "success",
                    "created_at": 1234,
                    "actor": "private-operator",
                    "target": "private-session",
                    "source_address": "192.0.2.55",
                    "details": {"token": "never", "reason": "private rationale"},
                },
                attempt=1,
            )
        sent = request.call_args.args[0]
        self.assertEqual(
            sent.get_header("X-vpn-dashboard-event-id"),
            "33333333-3333-4333-8333-333333333333",
        )
        timestamp = sent.get_header("X-vpn-dashboard-timestamp")
        self.assertIsNotNone(timestamp)
        signature = hmac.new(
            ("s" * 32).encode("utf-8"),
            timestamp.encode("ascii") + b"." + sent.data,
            hashlib.sha256,
        ).hexdigest()
        self.assertEqual(sent.get_header("X-vpn-dashboard-signature"), f"sha256={signature}")
        payload = json.loads(sent.data)
        self.assertEqual(payload, {
            "schema_version": 2,
            "event": "audit",
            "event_id": "33333333-3333-4333-8333-333333333333",
            "action": "admin-session",
            "status": "success",
            "created_at": 1234,
        })
        self.assertNotIn(b"private-operator", sent.data)
        self.assertNotIn(b"private-session", sent.data)
        self.assertNotIn(b"192.0.2.55", sent.data)
        self.assertNotIn(b"private rationale", sent.data)
        self.assertNotIn(b"token", sent.data)


if __name__ == "__main__":
    unittest.main()
