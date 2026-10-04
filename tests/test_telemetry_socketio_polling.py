import json
import threading
import unittest

from routeros_binary import RouterOSReply
from telemetry_broker import TelemetryBroker, TelemetryEvent
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

    def test_polling_sid_is_bound_to_the_session_that_opened_it(self) -> None:
        result = self.bridge.handshake("session-1")
        self.assertIsNotNone(result)
        sid, _ = result

        # A second, independently authenticated session must not be able to
        # reuse a leaked SID to open or read the first session's stream.
        self.assertFalse(self.bridge.post(sid, "session-2", b"40/telemetry,"))
        self.assertIsNone(self.bridge.poll(sid, "session-2"))
        self.assertNotIn(sid, self.bridge._clients)
        self.assertEqual(self.bridge.gateway.client_count, 0)

    def test_poll_waits_for_namespace_connect_race(self) -> None:
        result = self.bridge.handshake("session-1")
        self.assertIsNotNone(result)
        sid, _ = result
        polled: list[str | None] = []

        worker = threading.Thread(
            target=lambda: polled.append(self.bridge.poll(sid, "session-1")),
        )
        worker.start()
        self.assertTrue(self.bridge.post(sid, "session-1", b"40/telemetry,"))
        worker.join(timeout=1)

        self.assertFalse(worker.is_alive())
        self.assertEqual(polled, ["40/telemetry,"])

    def test_poll_stops_batch_when_stream_authorization_is_revoked(self) -> None:
        result = self.bridge.handshake("session-1")
        self.assertIsNotNone(result)
        sid, _ = result
        self.assertTrue(self.bridge.post(sid, "session-1", b"40/telemetry,"))
        self.assertEqual(self.bridge.poll(sid, "session-1"), "40/telemetry,")
        # Keep the synthetic event sequence aligned with the broker epoch;
        # the real runtime derives these event numbers from this broker.
        self.broker.apply(
            RouterOSReply("re", {".id": "*1", "name": "first"}), now=100
        )
        self.broker.apply(
            RouterOSReply("re", {".id": "*2", "name": "second"}), now=101
        )
        self.bridge.gateway.publish([
            TelemetryEvent("telemetry.reconciled", 1, 100, {"status": "online"}),
            TelemetryEvent("telemetry.reconciled", 2, 101, {"status": "online"}),
        ])

        resolver_calls = 0

        def revoke_during_batch(_session_id: str) -> TelemetryPrincipal | None:
            nonlocal resolver_calls
            resolver_calls += 1
            return self.principal if resolver_calls <= 2 else None

        self.bridge.principal_resolver = revoke_during_batch
        packet = self.bridge.poll(sid, "session-1")

        self.assertIsNotNone(packet)
        frames = [json.loads(item.removeprefix("42/telemetry,")) for item in packet.split("\x1e")]
        self.assertEqual(len(frames), 1)
        self.assertEqual(frames[0][1]["sequence"], 1)
        self.assertNotIn(sid, self.bridge._clients)

    def test_poll_closes_when_authenticated_session_expires(self) -> None:
        result = self.bridge.handshake("session-1")
        self.assertIsNotNone(result)
        sid, _ = result
        self.assertTrue(self.bridge.post(sid, "session-1", b"40/telemetry,"))
        self.assertEqual(self.bridge.gateway.client_count, 1)

        # SessionStore returns None after idle/absolute expiry. The bridge
        # must close the subscription rather than leave a stale SID alive.
        self.bridge.principal_resolver = lambda _session_id: None
        self.assertIsNone(self.bridge.poll(sid, "session-1"))
        self.assertNotIn(sid, self.bridge._clients)
        self.assertEqual(self.bridge.gateway.client_count, 0)

    def test_idle_client_expires_and_releases_gateway_capacity(self) -> None:
        now = [100.0]
        gateway = TelemetryGatewayContract(
            self.broker, clock=lambda: 100, max_clients=1
        )
        bridge = SocketIOPollingBridge(
            gateway,
            lambda _session_id: self.principal,
            idle_timeout_seconds=10,
            clock=lambda: now[0],
        )
        first = bridge.handshake("session-1")
        self.assertIsNotNone(first)
        first_sid, _ = first
        self.assertTrue(bridge.post(first_sid, "session-1", b"40/telemetry,"))
        self.assertEqual(gateway.client_count, 1)
        self.assertTrue(bridge.post(first_sid, "session-1", b"40/telemetry,"))
        self.assertEqual(gateway.client_count, 1)

        # At the exact timeout boundary, the next handshake reaps the client
        # and closes its gateway subscription before another client connects.
        now[0] += 10
        second = bridge.handshake("session-2")
        self.assertIsNotNone(second)
        second_sid, _ = second
        self.assertNotIn(first_sid, bridge._clients)
        self.assertEqual(gateway.client_count, 0)

        self.assertTrue(bridge.post(second_sid, "session-2", b"40/telemetry,"))
        self.assertEqual(gateway.client_count, 1)

    def test_idle_timeout_boundary_and_activity_refresh(self) -> None:
        now = [0.0]
        bridge = SocketIOPollingBridge(
            self.bridge.gateway,
            lambda _session_id: self.principal,
            idle_timeout_seconds=10,
            clock=lambda: now[0],
        )
        result = bridge.handshake("session-1")
        self.assertIsNotNone(result)
        sid, _ = result
        self.assertTrue(bridge.post(sid, "session-1", b"40/telemetry,"))
        self.assertEqual(bridge.poll(sid, "session-1"), "40/telemetry,")

        now[0] = 9.999
        bridge.handshake("session-2")
        self.assertIn(sid, bridge._clients)
        self.assertEqual(self.bridge.gateway.client_count, 1)

        # A successful poll refreshes activity, so expiry is measured from
        # the most recent request rather than from namespace connection.
        self.assertEqual(bridge.poll(sid, "session-1"), "2")
        now[0] = 19.998
        bridge.handshake("session-3")
        self.assertIn(sid, bridge._clients)
        now[0] = 20.0
        bridge.handshake("session-4")
        self.assertNotIn(sid, bridge._clients)
        self.assertEqual(self.bridge.gateway.client_count, 0)


if __name__ == "__main__":
    unittest.main()
