import json
import unittest

from scripts.telemetry_baseline import summarize


class TelemetryBaselineTests(unittest.TestCase):
    def test_summary_passes_within_safe_limits(self) -> None:
        lines = [
            json.dumps({"transport": "binary", "latency_ms": 100, "event_age_seconds": 0.5, "router_cpu_percent": 20}),
            json.dumps({"transport": "binary", "latency_ms": 200, "event_age_seconds": 1, "router_cpu_percent": 30}),
        ]
        code, result = summarize(
            lines,
            limits={
                "latency_p95_ms": 500,
                "event_age_seconds": 2,
                "router_cpu_percent": 80,
                "router_memory_percent": 90,
                "reconnects": 0,
            },
        )
        self.assertEqual(code, 0)
        self.assertTrue(result["healthy"])
        self.assertEqual(result["latency_p95_ms"], 200.0)
        self.assertEqual(result["transport_counts"], {"binary": 2})

    def test_summary_fails_on_stale_or_lost_events_without_echoing_records(self) -> None:
        code, result = summarize(
            [json.dumps({"event_age_seconds": 3, "event_lost": True, "password": "do-not-echo"})],
            limits={
                "latency_p95_ms": 1000,
                "event_age_seconds": 2,
                "router_cpu_percent": 80,
                "router_memory_percent": 90,
                "reconnects": 0,
            },
        )
        self.assertEqual(code, 1)
        self.assertEqual(result["failed_gates"], ["event_age", "event_loss"])
        self.assertNotIn("password", str(result))

    def test_invalid_transport_is_rejected(self) -> None:
        with self.assertRaises(ValueError):
            summarize([json.dumps({"transport": "private"})], limits={"latency_p95_ms": 1, "event_age_seconds": 1, "router_cpu_percent": 1, "router_memory_percent": 1, "reconnects": 0})


if __name__ == "__main__":
    unittest.main()
