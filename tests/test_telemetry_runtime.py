import unittest

from config import RuntimeConfig
from security import SessionStore
from telemetry_broker import TelemetryEvent
from telemetry_runtime import TelemetryRuntime


class TelemetryRuntimeFreshnessTests(unittest.TestCase):
    def test_publish_updates_only_aggregate_session_and_traffic_freshness(self) -> None:
        config = RuntimeConfig.from_environ({"LIVE_TRANSPORT": "binary"})
        runtime = TelemetryRuntime(
            sessions=SessionStore(),
            rest_url=config.routeros_rest_url,
            ca_file=None,
            insecure_tls=False,
            api_ssl_port=config.routeros_api_ssl_port,
            requested_transport=config.live_transport,
        )

        runtime._publish(
            [
                TelemetryEvent("vpn.session.connected", 1, 100, {"name": "private-user"}),
                TelemetryEvent("vpn.interface.counters", 2, 100, {"name": "private-interface"}),
                TelemetryEvent("vpn.interface.counters", 3, 100, {"name": "private-interface-2"}),
            ]
        )

        metrics = runtime.state.as_dict()
        self.assertEqual(metrics["session_events"], 1)
        self.assertEqual(metrics["traffic_samples"], 2)
        self.assertIsNotNone(metrics["session_event_age_seconds"])
        self.assertIsNotNone(metrics["traffic_sample_age_seconds"])
        self.assertNotIn("private-user", str(metrics))
        self.assertNotIn("private-interface", str(metrics))


if __name__ == "__main__":
    unittest.main()
