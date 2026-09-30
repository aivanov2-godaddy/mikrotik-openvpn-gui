import json
import unittest

from routeros_binary import RouterOSReply
from telemetry_broker import TelemetryBroker
from telemetry_gateway import TelemetryGatewayContract, TelemetryPrincipal
from telemetry_socketio_polling import SocketIOPollingBridge


class SocketIOPollingBridgeTests(unittest.TestCase):
    def setUp(self) -> None:
        broker = TelemetryBroker(clock=lambda: 100)
        gateway = TelemetryGatewayContract(broker, clock=lambda: 100)
        self.principal = TelemetryPrincipal(True, auth_method="routeros", role="owner")
        self.bridge = SocketIOPollingBridge(gateway, lambda _session_id: self.principal)
        self.broker = broker

    def test_handshake_connect_and_event_poll(self) -> None:
        result = self.bridge.handshake("session-1")
        self.assertIsNotNone(result)
        sid, handshake = result
        payload = json.loads(handshake[1:])
        self.assertEqual(payload["sid"], sid)
        self.assertEqual(payload["upgrades"], [])

        self.assertTrue(self.bridge.post(sid, "session-1", b"40/telemetry,"))
        self.assertEqual(self.bridge.poll(sid, "session-1"), "40/telemetry,")

        events = self.broker.apply(
            RouterOSReply("re", {".id": "*1", "name": "alice", "password": "secret"}),
            now=101,
        )
        self.bridge.gateway.publish(events)
        packet = self.bridge.poll(sid, "session-1")
        self.assertIsNotNone(packet)
        self.assertTrue(packet.startswith("42/telemetry,"))
        self.assertNotIn("secret", packet)

    def test_unauthorized_handshake_is_rejected(self) -> None:
        bridge = SocketIOPollingBridge(
            self.bridge.gateway,
            lambda _session_id: TelemetryPrincipal(False),
        )
        self.assertIsNone(bridge.handshake("session-1"))


if __name__ == "__main__":
    unittest.main()
