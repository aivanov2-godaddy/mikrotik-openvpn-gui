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


def acceptance_window(sample: dict[str, object]) -> list[str]:
    return records(
        sample,
        {
            "type": "reconnect", "recovery_seconds": 1,
            "snapshot_recovered": True, "api_interruption_tested": True,
            "rest_fallback_available": True,
        },
        {"type": "comparison", "binary_matches_rest": True},
        {
            "type": "security", "unauthenticated_denied": True,
            "secret_bearing_payload": False, "secret_free_logs": True,
        },
        {
            "type": "verification", "event_latency_measured": True,
            "traffic_freshness_measured": True, "counter_reset_tested": True,
            "event_integrity_tested": True, "binary_rest_parity_tested": True,
            "secret_scan_complete": True,
        },
    )


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
                    "counter_reset": True,
                    "counter_reset_recovered": True,
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
                {
                    "type": "verification",
                    "event_latency_measured": True,
                    "traffic_freshness_measured": True,
                    "counter_reset_tested": True,
                    "event_integrity_tested": True,
                    "binary_rest_parity_tested": True,
                    "secret_scan_complete": True,
                },
            ),
            limits=LIMITS,
        )
        self.assertEqual(code, 0)
        self.assertTrue(result["healthy"])
        self.assertEqual(result["failed_gates"], [])

    def test_router_resource_measurements_are_required_individually(self) -> None:
        sample: dict[str, object] = {
            "transport": "binary", "latency_ms": 180, "event_age_seconds": 0.7,
            "router_cpu_percent": 22, "router_memory_percent": 34,
            "router_storage_percent": 12, "container_healthy": True,
            "event_sequence": 101, "event_lost": False,
            "counter_reset": True, "counter_reset_recovered": True,
        }
        expected_gates = {
            "router_cpu_percent": "router_cpu_measurement_missing",
            "router_memory_percent": "router_memory_measurement_missing",
            "router_storage_percent": "router_storage_measurement_missing",
        }

        for field, expected_gate in expected_gates.items():
            with self.subTest(field=field):
                incomplete_sample = dict(sample)
                incomplete_sample.pop(field)
                code, result = evaluate(acceptance_window(incomplete_sample), limits=LIMITS)
                self.assertEqual(code, 1)
                self.assertFalse(result["healthy"])
                self.assertIn(expected_gate, result["failed_gates"])

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
                {
                    "type": "verification",
                    "event_latency_measured": True,
                    "traffic_freshness_measured": True,
                    "counter_reset_tested": True,
                    "event_integrity_tested": True,
                    "binary_rest_parity_tested": True,
                    "secret_scan_complete": True,
                },
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

    def test_sequence_gap_is_reported_as_event_loss(self) -> None:
        code, result = evaluate(
            records(
                {"type": "sample", "event_sequence": 101},
                {"type": "sample", "event_sequence": 103},
                {"type": "reconnect", "recovery_seconds": 1, "snapshot_recovered": True, "api_interruption_tested": True, "rest_fallback_available": True},
                {"type": "comparison", "binary_matches_rest": True},
                {"type": "security", "unauthenticated_denied": True, "secret_bearing_payload": False, "secret_free_logs": True},
            ),
            limits=LIMITS,
        )

        self.assertEqual(code, 1)
        self.assertIn("event_loss", result["failed_gates"])

    def test_repeated_sequence_is_reported_as_duplicate_not_reordering(self) -> None:
        window = acceptance_window({
            "type": "sample", "event_sequence": 101, "latency_ms": 100,
            "event_age_seconds": 0.5, "router_cpu_percent": 22,
            "router_memory_percent": 34, "router_storage_percent": 12,
        })
        window.extend(records({"type": "sample", "event_sequence": 101}))

        code, result = evaluate(window, limits=LIMITS)

        self.assertEqual(code, 1)
        self.assertIn("duplicate_events", result["failed_gates"])
        self.assertNotIn("out_of_order_events", result["failed_gates"])
        self.assertEqual(result["duplicate_events"], 1)

    def test_sequence_regression_is_reported_as_reordering(self) -> None:
        window = acceptance_window({
            "type": "sample", "event_sequence": 101, "latency_ms": 100,
            "event_age_seconds": 0.5, "router_cpu_percent": 22,
            "router_memory_percent": 34, "router_storage_percent": 12,
        })
        window.extend(records(
            {"type": "sample", "event_sequence": 102},
            {"type": "sample", "event_sequence": 100},
        ))

        code, result = evaluate(window, limits=LIMITS)

        self.assertEqual(code, 1)
        self.assertIn("out_of_order_events", result["failed_gates"])
        self.assertNotIn("duplicate_events", result["failed_gates"])
        self.assertEqual(result["out_of_order_events"], 1)

    def test_sequence_reset_requires_a_new_epoch(self) -> None:
        window = acceptance_window({
            "type": "sample", "event_sequence": 101, "latency_ms": 100,
            "event_age_seconds": 0.5, "router_cpu_percent": 22,
            "router_memory_percent": 34, "router_storage_percent": 12,
        })
        window.extend(records({"type": "sample", "event_epoch": 1, "event_sequence": 0}))

        code, result = evaluate(window, limits=LIMITS)

        self.assertIn("counter_reset_evidence_missing", result["failed_gates"])
        self.assertNotIn("event_loss", result["failed_gates"])
        self.assertNotIn("out_of_order_events", result["failed_gates"])
        self.assertNotIn("duplicate_events", result["failed_gates"])
        self.assertEqual(result["duplicate_events"], 0)
        self.assertEqual(result["out_of_order_events"], 0)

    def test_event_epoch_must_be_a_non_negative_integer(self) -> None:
        with self.assertRaisesRegex(ValueError, "event_epoch"):
            evaluate(records({"type": "sample", "event_sequence": 101, "event_epoch": "restart"}), limits=LIMITS)

    def test_event_sequence_must_be_an_integer(self) -> None:
        with self.assertRaisesRegex(ValueError, "non-negative integer"):
            evaluate(records({"type": "sample", "event_sequence": 101.5}), limits=LIMITS)


if __name__ == "__main__":
    unittest.main()
