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


if __name__ == "__main__":
    unittest.main()
