import types
import unittest

from routeros_binary import RouterOSReply
from telemetry_broker import TelemetryBroker, TelemetryEvent
from telemetry_gateway import (
    SUPPORTED_EVENTS,
    TelemetryAuthorizationError,
    TelemetryGatewayContract,
    TelemetryPrincipal,
    TelemetrySubscriptionError,
)
from scripts.telemetry_stream_observer import validate_frame


class TelemetryGatewayContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.broker = TelemetryBroker(clock=lambda: 100)
        self.monotonic = [10.0]
        self.gateway = TelemetryGatewayContract(
            self.broker,
            clock=lambda: 100,
            monotonic_clock=lambda: self.monotonic[0],
            max_replay=2,
            max_clients=1,
        )
        self.principal = TelemetryPrincipal.from_session(
            types.SimpleNamespace(auth_method="routeros", role="owner", capabilities=None)
        )

    def test_requires_authenticated_routeros_session_with_read_capability(self) -> None:
        with self.assertRaises(TelemetryAuthorizationError):
            self.gateway.open(TelemetryPrincipal(False))
        with self.assertRaises(TelemetryAuthorizationError):
            self.gateway.open(TelemetryPrincipal(True, auth_method="api_token", role="owner"))
        with self.assertRaises(TelemetryAuthorizationError):
            self.gateway.open(
                TelemetryPrincipal(
                    True,
                    auth_method="routeros",
                    role="read_only",
                    capabilities=frozenset(),
                )
            )

    def test_frames_are_versioned_and_redacted(self) -> None:
        subscription = self.gateway.open(self.principal)
        events = self.broker.apply(
            RouterOSReply(
                "re",
                {
                    ".id": "*1",
                    "name": "alice",
                    "address": "10.0.0.2",
                    "password": "must-not-leak",
                    "private-key": "must-not-leak",
                    "rx-byte": "12",
                },
            ),
            now=101,
        )
        self.gateway.publish(events)
        frame = self.gateway.poll(subscription)[0]
        self.assertEqual(frame["protocol_version"], 1)
        self.assertEqual(frame["event"], "vpn.session.connected")
        self.assertEqual(frame["payload"]["rx_bytes"], 12)
        self.assertNotIn("password", str(frame))
        self.assertNotIn("private-key", str(frame))

    def test_stale_cursor_recovers_with_a_redacted_snapshot(self) -> None:
        subscription = self.gateway.open(self.principal)
        for sequence in range(1, 4):
            events = self.broker.apply(
                RouterOSReply("re", {".id": f"*{sequence}", "name": f"user-{sequence}"}),
                now=100 + sequence,
            )
            self.gateway.publish(events)
        frames = self.gateway.poll(subscription, after_sequence=0)
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["event"], "telemetry.snapshot")
        self.assertEqual(len(frames[0]["payload"]["sessions"]), 3)
        metrics = self.gateway.metrics()
        self.assertEqual(metrics["published_events"], 3)
        self.assertEqual(metrics["snapshot_recoveries"], 1)
        self.assertEqual(metrics["replayed_events"], 0)
        self.assertNotIn("subscription_id", str(metrics))

    def test_cursor_from_a_previous_process_epoch_recovers_with_current_snapshot(self) -> None:
        subscription = self.gateway.open(self.principal)
        events = self.broker.apply(
            RouterOSReply("re", {".id": "*1", "name": "current-user"}),
            now=101,
        )
        self.gateway.publish(events)

        # The current broker only knows sequence 1; sequence 50 belongs to a
        # previous process epoch and must not make the client wait forever.
        frames = self.gateway.poll(subscription, after_sequence=50)

        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["event"], "telemetry.snapshot")
        self.assertEqual(frames[0]["sequence"], self.broker.sequence)
        self.assertEqual(
            [session["name"] for session in frames[0]["payload"]["sessions"]],
            ["current-user"],
        )
        self.assertEqual(self.gateway.metrics()["snapshot_recoveries"], 1)

    def test_missing_sequence_inside_replay_window_recovers_with_snapshot(self) -> None:
        subscription = self.gateway.open(self.principal)
        first = self.broker.apply(RouterOSReply("re", {".id": "*1", "name": "first"}), now=101)
        self.broker.apply(RouterOSReply("re", {".id": "*2", "name": "second"}), now=102)
        third = self.broker.apply(RouterOSReply("re", {".id": "*3", "name": "third"}), now=103)
        # Model a lost delivery batch while later batches still reach the
        # gateway; the retained buffer has an interior gap, not a stale head.
        self.gateway.publish([*first, *third])

        frames = self.gateway.poll(subscription, after_sequence=0)

        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0]["event"], "telemetry.snapshot")
        self.assertEqual(frames[0]["sequence"], self.broker.sequence)
        self.assertEqual(
            {session["name"] for session in frames[0]["payload"]["sessions"]},
            {"first", "second", "third"},
        )
        self.assertEqual(self.gateway.metrics()["snapshot_recoveries"], 1)

    def test_out_of_order_published_batches_replay_in_sequence_order(self) -> None:
        gateway = TelemetryGatewayContract(
            self.broker,
            clock=lambda: 100,
            monotonic_clock=lambda: self.monotonic[0],
            max_replay=8,
        )
        subscription = gateway.open(self.principal)
        first = self.broker.apply(RouterOSReply("re", {".id": "*1", "name": "first"}), now=101)
        second = self.broker.apply(RouterOSReply("re", {".id": "*2", "name": "second"}), now=102)
        gateway.publish(second)
        gateway.publish(first)

        frames = gateway.poll(subscription, after_sequence=0)

        self.assertEqual([frame["sequence"] for frame in frames], [1, 2])
        self.assertEqual([frame["payload"]["name"] for frame in frames], ["first", "second"])
        self.assertEqual(gateway.metrics()["snapshot_recoveries"], 0)

    def test_every_supported_event_uses_an_exact_redacted_projection(self) -> None:
        secret_sentinel = "telemetry-secret-sentinel"
        session_fields = {
            "id": "*safe-id",
            "name": "safe-user",
            "vpn_address": "10.8.0.2",
            "source_address": "203.0.113.2",
            "uptime": "1m",
            "encoding": "AES-256-GCM",
            "service": "ovpn-in1",
            "rx_bytes": 12,
            "tx_bytes": 34,
            "rx_packets": 5,
            "tx_packets": 6,
            "counter_complete": True,
        }
        session_payload = {
            **session_fields,
            "password": secret_sentinel,
            "private_key": secret_sentinel,
            "access_token": secret_sentinel,
        }
        counter_fields = {
            "id": "*interface-id",
            "name": "ovpn-in1",
            "rx_bytes": 100,
            "tx_bytes": 200,
            "rx_packets": 10,
            "tx_packets": 20,
            "rx_bytes_per_second": 1.5,
            "tx_bytes_per_second": 2.5,
            "rx_packets_per_second": 3.5,
            "tx_packets_per_second": 4.5,
        }
        router_fields = {
            "cpu_percent": 10,
            "memory_percent": 20,
            "storage_percent": 30,
            "status": "healthy",
            "age_seconds": 0.5,
        }
        cases = {
            "telemetry.snapshot": (
                {"sessions": [session_payload], "password": secret_sentinel},
                {"sessions"},
            ),
            "vpn.session.connected": (session_payload, set(session_fields)),
            "vpn.session.updated": (session_payload, set(session_fields)),
            "vpn.session.disconnected": (session_payload, set(session_fields)),
            "vpn.interface.counters": (
                {"interface": {**counter_fields, "private_key": secret_sentinel}, "token": secret_sentinel},
                set(counter_fields),
            ),
            "telemetry.counter_reset": (
                {
                    "scope": "interface",
                    "id": "*interface-id",
                    "name": "ovpn-in1",
                    "fields": ["rx_bytes"],
                    "certificate": secret_sentinel,
                },
                {"scope", "id", "name", "fields"},
            ),
            "router.capacity.updated": ({**router_fields, "password": secret_sentinel}, set(router_fields)),
            "router.health.updated": ({**router_fields, "private_key": secret_sentinel}, set(router_fields)),
            "telemetry.reconciled": ({**router_fields, "access_token": secret_sentinel}, set(router_fields)),
        }
        self.assertEqual(set(cases), SUPPORTED_EVENTS)

        for sequence, (event_name, (payload, expected_payload_keys)) in enumerate(cases.items(), start=1):
            with self.subTest(event=event_name):
                frame = TelemetryGatewayContract._frame(TelemetryEvent(event_name, sequence, 100, payload))
                self.assertEqual(
                    set(frame),
                    {"protocol_version", "event", "sequence", "router_timestamp", "payload"},
                )
                self.assertEqual(set(frame["payload"]), expected_payload_keys)
                self.assertEqual(validate_frame(event_name, frame), (sequence, event_name))
                if event_name == "telemetry.snapshot":
                    self.assertEqual(set(frame["payload"]["sessions"][0]), set(session_fields))
                if event_name in {
                    "vpn.session.connected",
                    "vpn.session.updated",
                    "vpn.session.disconnected",
                }:
                    self.assertEqual(set(frame["payload"]), set(session_fields))
                if event_name == "vpn.interface.counters":
                    self.assertEqual(frame["payload"], counter_fields)
                self.assertNotIn(secret_sentinel, repr(frame))

        flat_interface_frame = TelemetryGatewayContract._frame(
            TelemetryEvent(
                "vpn.interface.counters",
                10,
                100,
                {**counter_fields, "password": secret_sentinel},
            )
        )
        self.assertEqual(flat_interface_frame["payload"], counter_fields)
        self.assertNotIn(secret_sentinel, repr(flat_interface_frame))
        self.assertEqual(
            validate_frame("vpn.interface.counters", flat_interface_frame),
            (10, "vpn.interface.counters"),
        )

        broker_event = self.broker.reconcile_interfaces(
            [{".id": "*broker-interface", "name": "ovpn-in1", "rx-byte": 100, "tx-byte": 200}],
            now=101,
        )[0]
        broker_frame = TelemetryGatewayContract._frame(broker_event)
        self.assertEqual(
            broker_frame["payload"],
            {
                "id": "*broker-interface",
                "name": "ovpn-in1",
                "rx_bytes": 100,
                "tx_bytes": 200,
                "rx_packets": 0,
                "tx_packets": 0,
            },
        )
        self.assertEqual(
            validate_frame(broker_event.name, broker_frame),
            (broker_event.sequence, broker_event.name),
        )
        broker_rate_event = self.broker.reconcile_interfaces(
            [
                {
                    ".id": "*broker-interface",
                    "name": "ovpn-in1",
                    "rx-byte": 300,
                    "tx-byte": 240,
                    "rx-packet": 10,
                    "tx-packet": 20,
                }
            ],
            now=103,
        )[0]
        broker_rate_frame = TelemetryGatewayContract._frame(broker_rate_event)
        self.assertEqual(
            broker_rate_frame["payload"],
            {
                "id": "*broker-interface",
                "name": "ovpn-in1",
                "rx_bytes": 300,
                "tx_bytes": 240,
                "rx_packets": 10,
                "tx_packets": 20,
                "rx_bytes_per_second": 100.0,
                "tx_bytes_per_second": 20.0,
                "rx_packets_per_second": 5.0,
                "tx_packets_per_second": 10.0,
            },
        )
        self.assertEqual(
            validate_frame(broker_rate_event.name, broker_rate_frame),
            (broker_rate_event.sequence, broker_rate_event.name),
        )

    def test_counter_reset_frames_are_supported_and_redacted(self) -> None:
        subscription = self.gateway.open(self.principal)
        self.gateway.publish(
            self.broker.apply(
                RouterOSReply("re", {".id": "*1", "name": "alice", "rx-byte": "100"}),
                now=100,
            )
        )
        self.gateway.publish(
            self.broker.apply(
                RouterOSReply(
                    "re",
                    {
                        ".id": "*1",
                        "name": "alice",
                        "rx-byte": "2",
                        "password": "must-not-leak",
                    },
                ),
                now=101,
            )
        )
        frame = self.gateway.poll(subscription, after_sequence=1)[0]
        self.assertEqual(frame["event"], "telemetry.counter_reset")
        self.assertEqual(frame["payload"]["fields"], ["rx_bytes"])
        self.assertNotIn("password", str(frame))

    def test_client_limit_and_close_are_explicit(self) -> None:
        subscription = self.gateway.open(self.principal)
        with self.assertRaises(TelemetrySubscriptionError):
            self.gateway.open(self.principal)
        self.assertTrue(self.gateway.close(subscription))
        self.assertFalse(self.gateway.close(subscription))
        self.assertEqual(self.gateway.client_count, 0)
        metrics = self.gateway.metrics()
        self.assertEqual(metrics["active_clients"], 0)
        self.assertEqual(metrics["rejected_clients"], 1)

    def test_delivery_queue_age_is_bounded_aggregate_and_identifier_free(self) -> None:
        subscription = self.gateway.open(self.principal)
        events = self.broker.apply(
            RouterOSReply("re", {".id": "*secret-id", "name": "private-user"}),
            now=100,
        )
        self.gateway.publish(events)
        self.monotonic[0] += 1.25

        frames = self.gateway.poll(subscription)
        metrics = self.gateway.metrics()

        self.assertEqual(len(frames), 1)
        self.assertEqual(metrics["delivery_observations"], 1)
        self.assertEqual(metrics["delivery_queue_age_seconds"], 1.25)
        self.assertEqual(metrics["delivery_queue_age_p95_seconds"], 1.25)
        self.assertNotIn("private-user", str(metrics))
        self.assertNotIn("secret-id", str(metrics))


if __name__ == "__main__":
    unittest.main()
