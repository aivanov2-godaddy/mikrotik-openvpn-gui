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


if __name__ == "__main__":
    unittest.main()
