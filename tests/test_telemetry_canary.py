import json
import time
import unittest

from telemetry_canary import CanaryPolicy, TelemetryCanary, compare_snapshots, evaluate
from scripts.telemetry_canary import run as run_script


class TelemetryCanaryTests(unittest.TestCase):
    def test_matching_snapshots_are_healthy(self) -> None:
        result = compare_snapshots(
            [{"id": "*1"}], [{"id": "*1"}], binary_timestamp=100, clock=lambda: 102
        )
        self.assertTrue(result.healthy)
        self.assertEqual(result.reason, "ok")

    def test_stale_or_mismatched_snapshot_is_not_healthy(self) -> None:
        result = compare_snapshots(
            [{"id": "*1"}], [{"id": "*2"}], binary_timestamp=1, clock=lambda: 20,
            policy=CanaryPolicy(max_age_seconds=5),
        )
        self.assertFalse(result.healthy)
        self.assertEqual(result.reason, "binary_snapshot_stale")

    def test_missing_binary_timestamp_is_unhealthy_and_resets_window(self) -> None:
        canary = TelemetryCanary(CanaryPolicy(required_consecutive=2))
        canary.observe([{"id": "*1"}], [{"id": "*1"}], binary_timestamp=100, clock=lambda: 100)
        result = canary.observe([{"id": "*1"}], [{"id": "*1"}], clock=lambda: 100)
        self.assertFalse(result.healthy)
        self.assertEqual(result.reason, "binary_timestamp_missing")
        self.assertIsNone(result.age_seconds)
        self.assertEqual(canary.consecutive_healthy, 0)
        self.assertFalse(canary.ready_to_promote)

    def test_future_binary_timestamp_is_unhealthy_not_clamped_to_zero(self) -> None:
        result = compare_snapshots(
            [{"id": "*1"}], [{"id": "*1"}], binary_timestamp=103, clock=lambda: 102
        )
        self.assertFalse(result.healthy)
        self.assertEqual(result.reason, "binary_timestamp_in_future")
        self.assertIsNone(result.age_seconds)

    def test_epoch_zero_timestamp_is_stale_not_missing(self) -> None:
        result = compare_snapshots(
            [{"id": "*1"}], [{"id": "*1"}], binary_timestamp=0, clock=lambda: 102
        )
        self.assertFalse(result.healthy)
        self.assertEqual(result.reason, "binary_snapshot_stale")
        self.assertEqual(result.age_seconds, 102.0)

    def test_evaluators_do_not_accept_missing_or_future_timestamps(self) -> None:
        for sample, expected_reason in (
            ({"legacy": [], "binary": []}, "binary_timestamp_missing"),
            (
                {"legacy": [], "binary": [], "binary_timestamp": int(time.time()) + 60},
                "binary_timestamp_in_future",
            ),
        ):
            line = json.dumps(sample)
            code, result = evaluate([line] * 3, policy=CanaryPolicy(required_consecutive=3))
            self.assertEqual(code, 1)
            self.assertFalse(result["healthy"])
            self.assertEqual(result["reason_counts"], {expected_reason: 3})
            self.assertIsNone(result["last_result"]["age_seconds"])

            script_code, script_result = run_script(
                [line] * 3, policy=CanaryPolicy(required_consecutive=3)
            )
            self.assertEqual(script_code, 1)
            self.assertFalse(script_result["healthy"])
            self.assertEqual(script_result["reason"], expected_reason)
            self.assertIsNone(script_result["age_seconds"])

    def test_promotion_requires_consecutive_healthy_samples(self) -> None:
        canary = TelemetryCanary(CanaryPolicy(required_consecutive=2))
        self.assertFalse(canary.ready_to_promote)
        canary.observe([{"id": "*1"}], [{"id": "*1"}], binary_timestamp=100, clock=lambda: 100)
        self.assertFalse(canary.ready_to_promote)
        canary.observe([{"id": "*1"}], [{"id": "*1"}], binary_timestamp=100, clock=lambda: 100)
        self.assertTrue(canary.ready_to_promote)

    def test_evaluator_is_redacted_and_requires_consecutive_samples(self) -> None:
        lines = [
            json.dumps(
                {
                    "legacy": [{"id": "private-1"}],
                    "binary": [{"id": "private-1"}],
                    "binary_timestamp": int(time.time()),
                }
            )
            for _ in range(3)
        ]
        code, result = evaluate(lines, policy=CanaryPolicy(required_consecutive=3))
        self.assertEqual(code, 0)
        self.assertTrue(result["healthy"])
        self.assertNotIn("private-1", str(result))


if __name__ == "__main__":
    unittest.main()
