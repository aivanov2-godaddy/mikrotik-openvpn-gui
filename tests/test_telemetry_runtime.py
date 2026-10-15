import unittest
from unittest.mock import patch

from config import RuntimeConfig
from security import SessionStore
from telemetry_broker import TelemetryEvent
from telemetry_runtime import TelemetryRuntime


class TelemetryRuntimeFreshnessTests(unittest.TestCase):
    def test_live_stream_role_downgrade_is_applied_at_15_second_cache_deadline(self) -> None:
        config = RuntimeConfig.from_environ({"LIVE_TRANSPORT": "binary"})
        sessions = SessionStore()
        clock = {"now": 100.0, "monotonic": 100.0}
        routeros_state = {"role": "owner"}
        role_checks = []

        def resolve_role(_session):
            role_checks.append(clock["now"])
            return routeros_state["role"]

        with (
            patch("security.time.time", side_effect=lambda: clock["now"]),
            patch("security.time.monotonic", side_effect=lambda: clock["monotonic"]),
        ):
            session = sessions.create(
                "router-user", "router-password", role="owner", now=clock["now"]
            )
            runtime = TelemetryRuntime(
                sessions=sessions,
                rest_url=config.routeros_rest_url,
                ca_file=None,
                insecure_tls=False,
                api_ssl_port=config.routeros_api_ssl_port,
                requested_transport=config.live_transport,
                role_resolver=resolve_role,
            )
            routeros_state["role"] = "read_only"

            # A warm cache is permitted only within the documented bound.
            clock["now"] = 114.999
            clock["monotonic"] = 114.999
            self.assertIs(runtime.revalidate_session(session.session_id), session)
            self.assertEqual(role_checks, [])

            # At the 15-second boundary, the RouterOS-derived downgrade takes
            # effect before another live authorization check can pass.
            clock["now"] = 115.0
            clock["monotonic"] = 115.0
            self.assertIs(runtime.revalidate_session(session.session_id), session)
            self.assertEqual(session.role, "read_only")
            self.assertEqual(role_checks, [115.0])

    def test_binary_credentials_are_refused_after_source_session_revocation(self) -> None:
        config = RuntimeConfig.from_environ({"LIVE_TRANSPORT": "binary"})
        sessions = SessionStore()
        session = sessions.create("router-user", "router-password")
        runtime = TelemetryRuntime(
            sessions=sessions,
            rest_url=config.routeros_rest_url,
            ca_file=None,
            insecure_tls=False,
            api_ssl_port=config.routeros_api_ssl_port,
            requested_transport=config.live_transport,
        )

        self.assertEqual(runtime._credentials(), ("router-user", "router-password"))
        sessions.revoke(session.session_id)

        self.assertFalse(runtime._credentials_valid("router-user", "router-password"))
        with self.assertRaisesRegex(RuntimeError, "credentials_unavailable"):
            runtime._credentials()

    def test_authoritative_session_snapshot_updates_history_observer(self) -> None:
        config = RuntimeConfig.from_environ({"LIVE_TRANSPORT": "binary"})
        observed = []
        runtime = TelemetryRuntime(
            sessions=SessionStore(),
            rest_url=config.routeros_rest_url,
            ca_file=None,
            insecure_tls=False,
            api_ssl_port=config.routeros_api_ssl_port,
            requested_transport=config.live_transport,
            on_session_snapshot=observed.append,
        )
        active = [{"id": "*1", "name": "test-user", "rx_bytes": 12}]

        runtime._publish([
            TelemetryEvent("vpn.session.disconnected", 1, 100, {"name": "test-user"}),
            TelemetryEvent("telemetry.snapshot", 2, 101, {"sessions": active}),
        ])

        self.assertEqual(observed, [active])

    def test_event_publish_does_not_misrepresent_events_as_counter_samples(self) -> None:
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
        self.assertEqual(metrics["traffic_samples"], 0)
        self.assertIsNotNone(metrics["session_event_age_seconds"])
        self.assertIsNone(metrics["traffic_sample_age_seconds"])
        self.assertNotIn("private-user", str(metrics))
        self.assertNotIn("private-interface", str(metrics))

    def test_successful_no_change_counter_poll_advances_aggregate_freshness(self) -> None:
        config = RuntimeConfig.from_environ({"LIVE_TRANSPORT": "binary"})
        runtime = TelemetryRuntime(
            sessions=SessionStore(),
            rest_url=config.routeros_rest_url,
            ca_file=None,
            insecure_tls=False,
            api_ssl_port=config.routeros_api_ssl_port,
            requested_transport=config.live_transport,
        )

        class EmptyCounterConnection:
            def connect(self, username, password):
                return None

            def execute(self, path, *, query=()):
                return []

            def close(self):
                return None

        runtime.sampler._connection_factory = EmptyCounterConnection
        runtime.sampler._credentials_provider = lambda: ("router-user", "router-password")
        runtime.sampler._authorization_check = lambda _username, _password: True
        self.assertEqual(runtime.sampler.sample_once(), [])

        metrics = runtime.state.as_dict()

        self.assertEqual(metrics["traffic_samples"], 1)
        self.assertAlmostEqual(metrics["traffic_sample_age_seconds"], 0, places=3)


if __name__ == "__main__":
    unittest.main()
