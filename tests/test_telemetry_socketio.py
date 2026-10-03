import unittest

from routeros_binary import RouterOSReply
from telemetry_broker import TelemetryBroker
from telemetry_gateway import TelemetryGatewayContract, TelemetryPrincipal
from telemetry_socketio import SocketIOTelemetryAdapter, SocketIOTelemetryError


class FakeSocketIO:
    def __init__(self) -> None:
        self.handlers = {}
        self.emitted = []

    def on(self, event, handler, namespace=None):
        self.handlers[(namespace, event)] = handler

    def emit(self, event, payload, **kwargs):
        self.emitted.append((event, payload, kwargs))


class SocketIOTelemetryAdapterTests(unittest.TestCase):
    def setUp(self) -> None:
        broker = TelemetryBroker(clock=lambda: 100)
        gateway = TelemetryGatewayContract(broker, clock=lambda: 100)
        principal = TelemetryPrincipal(True, auth_method="routeros", role="owner")
        self.adapter = SocketIOTelemetryAdapter(gateway, lambda _sid, _facts: principal)
        self.server = FakeSocketIO()
        self.adapter.attach(self.server)
        self.broker = broker

    def test_connect_subscribe_publish_and_disconnect_are_explicit(self) -> None:
        self.assertTrue(self.adapter.on_connect("sid-1", {}, {}))
        events = self.broker.apply(RouterOSReply("re", {".id": "*1", "name": "alice", "password": "secret"}), now=101)
        self.assertEqual(self.adapter.publish(events), 1)
        self.assertEqual(len(self.server.emitted), 1)
        self.assertNotIn("secret", str(self.server.emitted[0]))
        self.adapter.on_disconnect("sid-1")
        with self.assertRaises(SocketIOTelemetryError):
            self.adapter.on_poll("sid-1")

    def test_rejects_unauthorized_principal(self) -> None:
        adapter = SocketIOTelemetryAdapter(
            TelemetryGatewayContract(TelemetryBroker()),
            lambda _sid, _facts: TelemetryPrincipal(False),
        )
        self.assertFalse(adapter.on_connect("sid", {}, {}))

    def test_reconnect_replays_live_updates_after_client_cursor(self) -> None:
        self.assertTrue(self.adapter.on_connect("sid-before", {}, {}))
        first_events = self.broker.apply(
            RouterOSReply("re", {".id": "*1", "name": "alice", "password": "secret"}),
            now=101,
        )
        self.adapter.publish(first_events)
        self.adapter.on_disconnect("sid-before")

        second_events = self.broker.apply(
            RouterOSReply("re", {".id": "*1", "name": "alice", "rx-byte": "42", "password": "secret"}),
            now=102,
        )
        self.adapter.publish(second_events)

        self.assertTrue(self.adapter.on_connect("sid-after", {}, {}))
        response = self.adapter.on_poll("sid-after", {"after_sequence": first_events[-1].sequence})

        self.assertEqual([frame["event"] for frame in response["frames"]], ["vpn.session.updated"])
        self.assertEqual(response["frames"][0]["payload"]["rx_bytes"], 42)
        self.assertEqual(self.server.emitted[-1][0], "vpn.session.updated")
        self.assertNotIn("secret", str(response))
        self.adapter.on_disconnect("sid-after")

    def test_reconnect_with_expired_cursor_recovers_redacted_snapshot(self) -> None:
        broker = TelemetryBroker(clock=lambda: 100)
        gateway = TelemetryGatewayContract(broker, clock=lambda: 100, max_replay=1)
        principal = TelemetryPrincipal(True, auth_method="routeros", role="owner")
        adapter = SocketIOTelemetryAdapter(gateway, lambda _sid, _facts: principal)

        self.assertTrue(adapter.on_connect("sid-before", {}, {}))
        first = broker.apply(
            RouterOSReply("re", {".id": "*1", "name": "alice", "password": "secret"}), now=101
        )
        adapter.publish(first)
        adapter.on_disconnect("sid-before")
        second = broker.apply(
            RouterOSReply("re", {".id": "*2", "name": "bob", "private-key": "secret-key"}), now=102
        )
        adapter.publish(second)

        self.assertTrue(adapter.on_connect("sid-after", {}, {}))
        response = adapter.on_poll("sid-after", {"after_sequence": 0})

        self.assertEqual(len(response["frames"]), 1)
        self.assertEqual(response["frames"][0]["event"], "telemetry.snapshot")
        self.assertEqual(
            [session["name"] for session in response["frames"][0]["payload"]["sessions"]],
            ["alice", "bob"],
        )
        self.assertNotIn("secret", str(response))
        self.assertNotIn("private-key", str(response))
        self.assertEqual(gateway.metrics()["snapshot_recoveries"], 1)
        adapter.on_disconnect("sid-after")


if __name__ == "__main__":
    unittest.main()
