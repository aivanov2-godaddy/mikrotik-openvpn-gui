import unittest

from telemetry_state import TelemetryRuntimeState


class TelemetryRuntimeStateTests(unittest.TestCase):
    def test_status_is_stale_until_first_observation(self) -> None:
        state = TelemetryRuntimeState("binary", clock=lambda: 100)
        status = state.as_dict()
        self.assertEqual(status["requested_transport"], "binary")
        self.assertEqual(status["transport"], "sse")
        self.assertEqual(status["state"], "stale")
        self.assertIsNone(status["last_event_at"])

    def test_event_and_reconciliation_age_are_bounded_and_secret_free(self) -> None:
        state = TelemetryRuntimeState("auto", clock=lambda: 200)
        state.mark_event(reconciliation=True)
        state.mark_reconnect()
        status = state.as_dict(now=204)
        self.assertEqual(status["state"], "healthy")
        self.assertEqual(status["event_age_seconds"], 4)
        self.assertEqual(status["reconciliation_age_seconds"], 4)
        self.assertEqual(status["reconnects"], 1)
        self.assertNotIn("password", status)

    def test_errors_make_state_explicit(self) -> None:
        state = TelemetryRuntimeState(clock=lambda: 300)
        state.mark_event()
        state.mark_error("router_api_timeout")
        self.assertEqual(state.as_dict()["state"], "error")
        self.assertEqual(state.as_dict()["last_error"], "router_api_timeout")

    def test_session_and_traffic_freshness_are_independent_and_secret_free(self) -> None:
        state = TelemetryRuntimeState("binary", clock=lambda: 100.25)
        state.mark_session_events(2, reconciliation=True)
        state.mark_traffic_samples(3, now=98.0)

        metrics = state.as_dict(now=101.5)
        self.assertEqual(metrics["session_event_age_seconds"], 1.25)
        self.assertEqual(metrics["traffic_sample_age_seconds"], 3.5)
        self.assertEqual(metrics["session_events"], 2)
        self.assertEqual(metrics["traffic_samples"], 3)
        self.assertEqual(metrics["last_reconciliation_at"], 100)
        self.assertNotIn("username", str(metrics).lower())
        self.assertNotIn("session_id", str(metrics).lower())

    def test_freshness_is_unknown_until_each_observation_type_arrives(self) -> None:
        state = TelemetryRuntimeState(clock=lambda: 100)
        metrics = state.as_dict()
        self.assertIsNone(metrics["session_event_age_seconds"])
        self.assertIsNone(metrics["traffic_sample_age_seconds"])
        state.mark_traffic_samples(now=99)
        metrics = state.as_dict(now=100)
        self.assertIsNone(metrics["session_event_age_seconds"])
        self.assertEqual(metrics["traffic_sample_age_seconds"], 1)


if __name__ == "__main__":
    unittest.main()
