import unittest

from routeros_binary import RouterOSReply
from telemetry_broker import TelemetryBroker, normalize_session


class TelemetryBrokerTests(unittest.TestCase):
    def test_normalize_uses_allow_list_and_numeric_counters(self) -> None:
        session = normalize_session(
            {
                ".id": "*1",
                "name": "alice",
                "address": "10.8.0.2",
                "caller-id": "203.0.113.7",
                "rx-byte": "1024",
                "tx-byte": "bad",
                "password": "must-not-leak",
                "private-key": "must-not-leak",
            }
        )
        self.assertIsNotNone(session)
        assert session is not None
        self.assertEqual(session["rx_bytes"], 1024)
        self.assertEqual(session["tx_bytes"], 0)
        self.assertNotIn("password", session)
        self.assertNotIn("private-key", session)

    def test_connect_and_update_emit_versioned_redacted_events(self) -> None:
        broker = TelemetryBroker(clock=lambda: 100)
        reply = RouterOSReply(
            "re",
            {
                ".id": "*1",
                "name": "alice",
                "address": "10.8.0.2",
                "caller-id": "203.0.113.7",
                "rx-byte": "12",
                "tx-byte": "34",
                "password": "secret",
            },
        )
        connected = broker.apply(reply)
        updated = broker.apply(
            RouterOSReply("re", {**reply.attributes, "rx-byte": "99"}), now=101
        )
        self.assertEqual(connected[0].name, "vpn.session.connected")
        self.assertEqual(updated[0].name, "vpn.session.updated")
        self.assertEqual(connected[0].sequence, 1)
        self.assertEqual(updated[0].sequence, 2)
        self.assertEqual(updated[0].router_timestamp, 101)
        self.assertNotIn("password", updated[0].as_dict()["payload"])

    def test_dead_record_emits_disconnect_and_removes_session(self) -> None:
        broker = TelemetryBroker(clock=lambda: 200)
        broker.apply(RouterOSReply("re", {".id": "*1", "name": "alice"}))
        events = broker.apply(RouterOSReply("re", {".id": "*1", ".dead": "yes"}))
        self.assertEqual(events[0].name, "vpn.session.disconnected")
        self.assertEqual(broker.snapshot(), [])

    def test_reconcile_emits_transitions_and_snapshot(self) -> None:
        broker = TelemetryBroker(clock=lambda: 300)
        broker.apply(RouterOSReply("re", {".id": "*old", "name": "old"}))
        events = broker.reconcile(
            [{".id": "*new", "name": "new", "rx-byte": 7}], now=301
        )
        self.assertEqual([event.name for event in events], [
            "vpn.session.disconnected", "vpn.session.connected", "telemetry.snapshot"
        ])
        self.assertEqual(broker.snapshot()[0]["name"], "new")
        self.assertEqual(events[-1].payload["sessions"][0]["rx_bytes"], 7)

    def test_non_record_replies_do_not_change_sequence(self) -> None:
        broker = TelemetryBroker(clock=lambda: 400)
        self.assertEqual(broker.apply(RouterOSReply("done", {})), [])
        self.assertEqual(broker.sequence, 0)

    def test_counter_reset_is_explicit_and_does_not_leak_record_data(self) -> None:
        broker = TelemetryBroker(clock=lambda: 500)
        broker.apply(
            RouterOSReply(
                "re", {".id": "*1", "name": "alice", "rx-byte": "100", "tx-byte": "20"}
            )
        )
        events = broker.apply(
            RouterOSReply(
                "re", {".id": "*1", "name": "alice", "rx-byte": "2", "tx-byte": "30"}
            ),
            now=501,
        )
        self.assertEqual([event.name for event in events], ["telemetry.counter_reset", "vpn.session.updated"])
        self.assertEqual(events[0].payload["fields"], ["rx_bytes"])
        self.assertNotIn("password", events[0].payload)
        self.assertEqual(broker.counter_resets, 1)


if __name__ == "__main__":
    unittest.main()
