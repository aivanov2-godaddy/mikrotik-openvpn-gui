import unittest

import json

from telemetry_canary import CanaryPolicy, TelemetryCanary, compare_snapshots, evaluate


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

    def test_promotion_requires_consecutive_healthy_samples(self) -> None:
        canary = TelemetryCanary(CanaryPolicy(required_consecutive=2))
        self.assertFalse(canary.ready_to_promote)
        canary.observe([{"id": "*1"}], [{"id": "*1"}], binary_timestamp=100, clock=lambda: 100)
        self.assertFalse(canary.ready_to_promote)
        canary.observe([{"id": "*1"}], [{"id": "*1"}], binary_timestamp=100, clock=lambda: 100)
        self.assertTrue(canary.ready_to_promote)

    def test_evaluator_is_redacted_and_requires_consecutive_samples(self) -> None:
        lines = [
            json.dumps({"legacy": [{"id": "private-1"}], "binary": [{"id": "private-1"}]})
            for _ in range(3)
        ]
        code, result = evaluate(lines, policy=CanaryPolicy(required_consecutive=3))
        self.assertEqual(code, 0)
        self.assertTrue(result["healthy"])
        self.assertNotIn("private-1", str(result))


if __name__ == "__main__":
    unittest.main()
