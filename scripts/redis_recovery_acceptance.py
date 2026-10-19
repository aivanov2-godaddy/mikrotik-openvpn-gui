"""Produce and validate redacted, source-revision-bound Redis recovery CI evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unittest
from typing import Any, Iterable


REPORT_FORMAT = "vpn-dashboard-redis-recovery-ci-v1"
MAX_REPORT_AGE = timedelta(days=7)
REVISION = re.compile(r"^[0-9a-f]{40}$")
REQUIRED_TESTS = {
    "outage_queue_drain": (
        "test_outbox_survives_redis_restart_and_drains_without_leaking_secrets",
        "test_large_outage_backlog_drains_in_bounded_batches_after_recovery",
    ),
    "dispatcher_restart": ("test_background_dispatcher_recovers_and_drains_after_redis_restart",),
    "ambiguous_publish_retry": (
        "test_ambiguous_publish_retry_keeps_stable_id_for_consumer_deduplication",
        "test_worker_restart_after_xadd_retries_durable_event_with_same_id",
    ),
    "duplicate_delivery_idempotency": ("test_duplicate_stream_delivery_has_one_idempotent_consumer_effect",),
    "pending_outbox_recovery": ("test_pending_outbox_recovers_when_redis_loses_unacknowledged_stream_data",),
}
REQUIRED_TEST_NAMES = frozenset(name for names in REQUIRED_TESTS.values() for name in names)
REPORT_FIELDS = frozenset({
    "format", "source_revision", "started_at", "ended_at", "test_results",
    "scope", "runtime_image_digest_verified",
})


def _timestamp(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        return None
    return parsed.astimezone(timezone.utc)


def validate_report(report: Any, *, expected_revision: str, now: datetime) -> tuple[dict[str, Any] | None, list[str]]:
    """Accept only a recent source-level CI result for the exact candidate revision."""
    failures: list[str] = []
    if not isinstance(report, dict) or set(report) != REPORT_FIELDS:
        return None, ["redis_recovery_ci_schema_invalid"]
    if report.get("format") != REPORT_FORMAT or report.get("scope") != "source-integration-tests":
        failures.append("redis_recovery_ci_identity_invalid")
    if report.get("runtime_image_digest_verified") is not False:
        failures.append("redis_recovery_ci_scope_invalid")
    source_revision = report.get("source_revision")
    if (
        not isinstance(expected_revision, str)
        or REVISION.fullmatch(expected_revision) is None
        or source_revision != expected_revision
    ):
        failures.append("redis_recovery_ci_candidate_mismatch")
    started = _timestamp(report.get("started_at"))
    ended = _timestamp(report.get("ended_at"))
    if started is None or ended is None or ended < started or now.tzinfo is None or now.utcoffset() is None:
        failures.append("redis_recovery_ci_window_invalid")
    elif (now.astimezone(timezone.utc) - ended) > MAX_REPORT_AGE or (
        now.astimezone(timezone.utc) - ended
    ).total_seconds() < -300:
        failures.append("redis_recovery_ci_stale")
    test_results = report.get("test_results")
    if not isinstance(test_results, dict) or set(test_results) != REQUIRED_TEST_NAMES:
        failures.append("redis_recovery_ci_test_set_invalid")
    elif any(value != "passed" for value in test_results.values()):
        failures.append("redis_recovery_ci_tests_failed")
    if failures:
        return None, sorted(set(failures))
    return {
        "format": REPORT_FORMAT,
        "source_revision": expected_revision,
        "started_at": started.isoformat(),
        "ended_at": ended.isoformat(),
        "test_results": {name: "passed" for name in sorted(REQUIRED_TEST_NAMES)},
        "scope": "source-integration-tests",
        "runtime_image_digest_verified": False,
    }, []


def _source_revision() -> str:
    revision = subprocess.run(
        ["git", "rev-parse", "HEAD"], check=True, capture_output=True, text=True, timeout=5
    ).stdout.strip()
    if REVISION.fullmatch(revision) is None:
        raise ValueError("Git did not return a full commit revision")
    if subprocess.run(
        ["git", "status", "--porcelain"], check=True, capture_output=True, text=True, timeout=5
    ).stdout.strip():
        raise ValueError("Redis acceptance evidence requires a clean checkout")
    github_revision = os.environ.get("GITHUB_SHA")
    if github_revision and github_revision != revision:
        raise ValueError("workflow revision does not match the checked-out source")
    return revision


def _suite() -> unittest.TestSuite:
    from tests.test_redis_integration import RedisOutboxRecoveryTests

    loader = unittest.defaultTestLoader
    return unittest.TestSuite(
        loader.loadTestsFromName(f"{RedisOutboxRecoveryTests.__module__}.RedisOutboxRecoveryTests.{name}")
        for name in sorted(REQUIRED_TEST_NAMES)
    )


def _write_report(path: Path, report: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent, text=True)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8", newline="\n") as handle:
            json.dump(report, handle, sort_keys=True, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)


def run(output: Path) -> int:
    started = datetime.now(timezone.utc)
    revision: str | None = None
    test_results: dict[str, str] = {}
    runner = unittest.TextTestRunner(verbosity=2)
    try:
        revision = _source_revision()
        suite = _suite()
        planned = {case.id().rsplit(".", 1)[-1] for case in _iter_cases(suite)}
        result = runner.run(suite)
        failed = {
            case.id().rsplit(".", 1)[-1]
            for case, _message in [*result.failures, *result.errors, *result.skipped]
            if hasattr(case, "id")
        }
        skipped = {
            case.id().rsplit(".", 1)[-1]
            for case, _message in result.skipped
            if hasattr(case, "id")
        }
        if planned != REQUIRED_TEST_NAMES:
            raise ValueError("required Redis recovery tests are unavailable")
        if result.wasSuccessful() and result.testsRun == len(REQUIRED_TEST_NAMES):
            test_results = {name: "passed" for name in REQUIRED_TEST_NAMES}
            exit_code = 0
        else:
            for name in REQUIRED_TEST_NAMES:
                test_results[name] = (
                    "skipped" if name in skipped
                    else "failed" if name in failed
                    else "not-run"
                )
            exit_code = 1
    except Exception:
        exit_code = 2
        test_results = {name: "not-run" for name in REQUIRED_TEST_NAMES}
    ended = datetime.now(timezone.utc)
    report = {
        "format": REPORT_FORMAT,
        "source_revision": revision,
        "started_at": started.isoformat(),
        "ended_at": ended.isoformat(),
        "test_results": test_results,
        "scope": "source-integration-tests",
        "runtime_image_digest_verified": False,
    }
    _write_report(output, report)
    print(json.dumps({"passed": exit_code == 0, "test_count": len(test_results), "exit_code": exit_code}))
    return exit_code


def _iter_cases(suite: Iterable[Any]) -> Iterable[unittest.TestCase]:
    for item in suite:
        if isinstance(item, unittest.TestSuite):
            yield from _iter_cases(item)
        elif isinstance(item, unittest.TestCase):
            yield item


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="safe JSON output path")
    arguments = parser.parse_args()
    return run(Path(arguments.output))


if __name__ == "__main__":
    raise SystemExit(main())
