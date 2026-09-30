import types
import unittest

from routeros_binary import RouterOSReply
from telemetry_broker import TelemetryBroker
from telemetry_gateway import (
    TelemetryAuthorizationError,
    TelemetryGatewayContract,
    TelemetryPrincipal,
    TelemetrySubscriptionError,
)


class TelemetryGatewayContractTests(unittest.TestCase):
    def setUp(self) -> None:
        self.broker = TelemetryBroker(clock=lambda: 100)
        self.gateway = TelemetryGatewayContract(self.broker, clock=lambda: 100, max_replay=2, max_clients=1)
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

    def test_client_limit_and_close_are_explicit(self) -> None:
        subscription = self.gateway.open(self.principal)
        with self.assertRaises(TelemetrySubscriptionError):
            self.gateway.open(self.principal)
        self.assertTrue(self.gateway.close(subscription))
        self.assertFalse(self.gateway.close(subscription))
        self.assertEqual(self.gateway.client_count, 0)


if __name__ == "__main__":
    unittest.main()
