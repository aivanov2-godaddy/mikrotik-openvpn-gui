import unittest
from unittest.mock import patch

from config import RuntimeConfig
from security import SessionStore
from telemetry_broker import TelemetryEvent
from telemetry_runtime import MAX_CONCURRENT_LIVE_ROLE_REFRESHES, TelemetryRuntime


class TelemetryRuntimeFreshnessTests(unittest.TestCase):
    def test_live_role_refresh_capacity_is_shared_across_runtime_instances(self) -> None:
        sessions = SessionStore()

        def make_runtime() -> TelemetryRuntime:
            return TelemetryRuntime(
                sessions=sessions,
                rest_url="https://127.0.0.1",
                ca_file=None,
                insecure_tls=False,
                api_ssl_port=8729,
                requested_transport="sse",
            )

        first = make_runtime()
        second = make_runtime()
        self.assertIs(first._live_role_refresh_slots, second._live_role_refresh_slots)

    def test_interface_sampler_worker_is_gated_by_requested_transport(self) -> None:
        def runtime_for(transport: str) -> TelemetryRuntime:
            return TelemetryRuntime(
                sessions=SessionStore(),
                rest_url="https://127.0.0.1",
                ca_file=None,
                insecure_tls=False,
                api_ssl_port=8729,
                requested_transport=transport,
            )

        for transport in ("binary", "auto"):
            with self.subTest(transport=transport):
                runtime = runtime_for(transport)
                self.assertIsNotNone(runtime.sampler)
                with patch("telemetry_runtime.threading.Thread") as make_thread:
                    runtime.start()

                worker_names = {call.kwargs["name"] for call in make_thread.call_args_list}
                worker_targets = {
                    call.kwargs["target"].__name__ for call in make_thread.call_args_list
                }
                self.assertEqual(
                    worker_names,
                    {"vpn-dashboard-binary", "vpn-dashboard-interface-sampler"},
                )
                self.assertIn("_run_sampler", worker_targets)

        fallback = runtime_for("sse")
        self.assertIsNone(fallback.sampler)
        with patch("telemetry_runtime.threading.Thread") as make_thread:
            fallback.start()
        make_thread.assert_not_called()

    def test_live_stream_role_downgrade_is_applied_at_one_second_cache_deadline(self) -> None:
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

            # A live stream uses a one-second app-side role freshness bound.
            clock["now"] = 100.999
            clock["monotonic"] = 100.999
            self.assertIsNotNone(runtime.principal_for_session(session.session_id))
            self.assertEqual(role_checks, [])

            # At the one-second boundary, the RouterOS-derived downgrade takes
            # effect on the first authorization check after the cache expires.
            clock["now"] = 101.0
            clock["monotonic"] = 101.0
            for _ in range(MAX_CONCURRENT_LIVE_ROLE_REFRESHES):
                self.assertTrue(runtime._live_role_refresh_slots.acquire(blocking=False))
            try:
                # Saturated live refresh capacity denies stale authorization,
                # without revoking a still-valid session or affecting ordinary
                # request checks that retain their 15-second cache.
                self.assertIsNone(runtime.principal_for_session(session.session_id))
                self.assertIs(runtime.revalidate_session(session.session_id), session)
                self.assertEqual(session.role, "owner")
                self.assertEqual(role_checks, [])
            finally:
                for _ in range(MAX_CONCURRENT_LIVE_ROLE_REFRESHES):
                    runtime._live_role_refresh_slots.release()

            self.assertIsNotNone(runtime.principal_for_session(session.session_id))
            self.assertEqual(session.role, "read_only")
            self.assertEqual(role_checks, [101.0])

            # Ordinary authenticated requests keep their separate 15-second
            # cache, avoiding a global increase in RouterOS role lookups.
            routeros_state["role"] = None
            clock["now"] = 115.999
            clock["monotonic"] = 115.999
            self.assertIs(runtime.revalidate_session(session.session_id), session)
            self.assertEqual(role_checks, [101.0])

            clock["now"] = 116.0
            clock["monotonic"] = 116.0
            self.assertIsNone(runtime.revalidate_session(session.session_id))
            self.assertEqual(role_checks, [101.0, 116.0])

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

    def test_binary_credential_lease_uses_session_ref_and_fails_after_revocation(self) -> None:
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

        lease = runtime._credential_lease()
        self.assertEqual(lease.username, "router-user")
        self.assertEqual(lease.password, "router-password")
        self.assertEqual(lease.authorization_ref, session.authorization_ref)
        self.assertTrue(runtime._authorization_ref_valid(lease.authorization_ref))
        dispatched = []
        self.assertTrue(
            runtime._dispatch_authorized_events(
                lease.authorization_ref, lambda: dispatched.append("delivered")
            )
        )
        self.assertEqual(dispatched, ["delivered"])

        sessions.revoke(session.session_id)

        self.assertFalse(runtime._authorization_ref_valid(lease.authorization_ref))
        self.assertFalse(
            runtime._dispatch_authorized_events(
                lease.authorization_ref, lambda: dispatched.append("after-revoke")
            )
        )
        self.assertEqual(dispatched, ["delivered"])
        self.assertEqual(session.authorization_ref, "")

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

        events = [
            TelemetryEvent("vpn.session.disconnected", 1, 100, {"name": "test-user"}),
            TelemetryEvent("telemetry.snapshot", 2, 101, {"sessions": active}),
        ]
        runtime._publish(events)
        runtime._persist_session_snapshot(events)

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
        sessions = SessionStore()
        sessions.create("router-user", "router-password")
        runtime = TelemetryRuntime(
            sessions=sessions,
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
        self.assertEqual(runtime.sampler.sample_once(), [])

        metrics = runtime.state.as_dict()

        self.assertEqual(metrics["traffic_samples"], 1)
        self.assertAlmostEqual(metrics["traffic_sample_age_seconds"], 0, places=3)


if __name__ == "__main__":
    unittest.main()
