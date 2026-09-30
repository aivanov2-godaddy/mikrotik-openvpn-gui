from __future__ import annotations

import json
import unittest

from scripts.telemetry_acceptance import evaluate


LIMITS = {
    "latency_p95_ms": 1000.0,
    "event_age_seconds": 2.0,
    "router_cpu_percent": 80.0,
    "router_memory_percent": 90.0,
    "router_storage_percent": 90.0,
    "max_reconnects": 0.0,
    "recovery_seconds": 10.0,
}


def records(*values: dict[str, object]) -> list[str]:
    return [json.dumps(value) for value in values]


class TelemetryAcceptanceTests(unittest.TestCase):
    def test_complete_acceptance_window_passes(self) -> None:
        code, result = evaluate(
            records(
                {
                    "type": "sample",
                    "transport": "binary",
                    "latency_ms": 180,
                    "event_age_seconds": 0.7,
                    "router_cpu_percent": 22,
                    "router_memory_percent": 34,
                    "router_storage_percent": 12,
                    "container_healthy": True,
                    "event_sequence": 101,
                    "event_lost": False,
                    "event_duplicated": False,
                    "out_of_order": False,
                },
                {
                    "type": "reconnect",
                    "recovery_seconds": 4.2,
                    "snapshot_recovered": True,
                    "api_interruption_tested": True,
                    "rest_fallback_available": True,
                },
                {"type": "comparison", "binary_matches_rest": True},
                {
                    "type": "security",
                    "unauthenticated_denied": True,
                    "secret_bearing_payload": False,
                    "secret_free_logs": True,
                },
            ),
            limits=LIMITS,
        )
        self.assertEqual(code, 0)
        self.assertTrue(result["healthy"])
        self.assertEqual(result["failed_gates"], [])

    def test_reconnect_and_secret_failures_are_reported(self) -> None:
        code, result = evaluate(
            records(
                {
                    "type": "sample",
                    "transport": "binary",
                    "latency_ms": 180,
                    "event_age_seconds": 0.7,
                    "router_cpu_percent": 22,
                    "router_memory_percent": 34,
                    "event_sequence": 101,
                },
                {"type": "reconnect", "recovery_seconds": 12, "snapshot_recovered": False, "api_interruption_tested": True, "rest_fallback_available": True},
                {"type": "comparison", "binary_matches_rest": True},
                {"type": "security", "unauthenticated_denied": False, "secret_bearing_payload": True, "secret_free_logs": False},
            ),
            limits=LIMITS,
        )
        self.assertEqual(code, 1)
        self.assertFalse(result["healthy"])
        self.assertIn("snapshot_recovery", result["failed_gates"])
        self.assertIn("recovery_time", result["failed_gates"])
        self.assertIn("unauthenticated_access", result["failed_gates"])
        self.assertIn("secret_exposure", result["failed_gates"])

    def test_counter_reset_must_be_recovered(self) -> None:
        code, result = evaluate(
            records(
                {
                    "type": "sample",
                    "transport": "binary",
                    "latency_ms": 180,
                    "event_age_seconds": 0.7,
                    "router_cpu_percent": 22,
                    "router_memory_percent": 34,
                    "event_sequence": 101,
                    "counter_reset": True,
                    "counter_reset_recovered": False,
                },
                {"type": "reconnect", "recovery_seconds": 1, "snapshot_recovered": True, "api_interruption_tested": True, "rest_fallback_available": True},
                {"type": "comparison", "binary_matches_rest": True},
                {"type": "security", "unauthenticated_denied": True, "secret_bearing_payload": False, "secret_free_logs": True},
            ),
            limits=LIMITS,
        )
        self.assertEqual(code, 1)
        self.assertIn("counter_reset_recovery", result["failed_gates"])

    def test_cross_transport_and_restart_evidence_is_required(self) -> None:
        code, result = evaluate(
            records(
                {"type": "sample", "latency_ms": 100, "event_age_seconds": 0.5},
                {
                    "type": "reconnect",
                    "recovery_seconds": 1,
                    "snapshot_recovered": True,
                    "api_interruption_tested": False,
                    "rest_fallback_available": False,
                },
                {"type": "security", "unauthenticated_denied": True, "secret_bearing_payload": False, "secret_free_logs": True},
            ),
            limits=LIMITS,
        )
        self.assertEqual(code, 1)
        self.assertIn("binary_rest_comparison_missing", result["failed_gates"])
        self.assertIn("api_interruption_test", result["failed_gates"])
        self.assertIn("rest_fallback", result["failed_gates"])


if __name__ == "__main__":
    unittest.main()
