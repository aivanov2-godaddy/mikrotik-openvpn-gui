"""Produce and validate redacted, source-revision-bound Redis recovery CI evidence."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tempfile
import unittest
from typing import Any, Iterable


REPORT_FORMAT = "vpn-dashboard-redis-recovery-ci-v1"
CI_REPOSITORY = "aivanov2-godaddy/mikrotik-openvpn-gui"
CI_WORKFLOW_PATH = ".github/workflows/ci.yml"
MAX_REPORT_AGE = timedelta(days=7)
MAX_CI_ARTIFACT_BYTES = 65_536
REVISION = re.compile(r"^[0-9a-f]{40}$")
DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
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
CI_PROVENANCE_FIELDS = frozenset({
    "repository", "workflow_path", "event", "branch", "status", "conclusion",
    "head_sha", "run_id", "artifact_id", "artifact_name", "attestation_verified_during_collection",
    "report_sha256",
})
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


def report_projection_sha256(report: dict[str, Any]) -> str:
    """Hash the canonical, redacted projection that is carried into release evidence."""
    canonical = json.dumps(report, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def validate_report(report: Any, *, expected_revision: str, now: datetime) -> tuple[dict[str, Any] | None, list[str]]:
    """Accept only a recent source-level CI result for the exact candidate revision."""
    failures: list[str] = []
    if not isinstance(report, dict) or set(report) not in (REPORT_FIELDS, REPORT_FIELDS | {"ci_provenance"}):
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
    safe_report = {
        "format": REPORT_FORMAT,
        "source_revision": expected_revision,
        "started_at": started.isoformat(),
        "ended_at": ended.isoformat(),
        "test_results": {name: "passed" for name in sorted(REQUIRED_TEST_NAMES)},
        "scope": "source-integration-tests",
        "runtime_image_digest_verified": False,
    }
    if "ci_provenance" in report:
        provenance, provenance_failures = validate_ci_provenance(
            report["ci_provenance"], expected_revision=expected_revision
        )
        if provenance_failures:
            return None, provenance_failures
        if provenance["report_sha256"] != report_projection_sha256(safe_report):
            return None, ["redis_recovery_ci_report_hash_mismatch"]
        safe_report["ci_provenance"] = provenance
    return safe_report, []


def validate_ci_provenance(
    provenance: Any, *, expected_revision: str
) -> tuple[dict[str, Any] | None, list[str]]:
    """Validate collector-reported provenance shape; this does not reverify its signature."""
    if not isinstance(provenance, dict) or set(provenance) != CI_PROVENANCE_FIELDS:
        return None, ["redis_recovery_ci_provenance_missing"]
    run_id = provenance.get("run_id")
    artifact_id = provenance.get("artifact_id")
    valid = (
        provenance.get("repository") == CI_REPOSITORY
        and provenance.get("workflow_path") == CI_WORKFLOW_PATH
        and provenance.get("event") == "push"
        and provenance.get("branch") == "main"
        and provenance.get("status") == "completed"
        and provenance.get("conclusion") == "success"
        and provenance.get("head_sha") == expected_revision
        and isinstance(run_id, str)
        and run_id.isascii()
        and run_id.isdigit()
        and 0 < len(run_id) <= 20
        and isinstance(artifact_id, str)
        and artifact_id.isascii()
        and artifact_id.isdigit()
        and 0 < len(artifact_id) <= 20
        and provenance.get("artifact_name") == f"redis-recovery-{expected_revision}"
        and provenance.get("attestation_verified_during_collection") is True
        and isinstance(provenance.get("report_sha256"), str)
        and DIGEST.fullmatch(f"sha256:{provenance['report_sha256']}") is not None
    )
    if not valid:
        return None, ["redis_recovery_ci_provenance_invalid"]
    return {key: provenance[key] for key in sorted(CI_PROVENANCE_FIELDS)}, []


def download_verified_ci_report(
    run_id: str, *, expected_revision: str, now: datetime | None = None
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Download the exact successful main CI artifact using the authenticated gh CLI."""
    if not isinstance(run_id, str) or not run_id.isascii() or not run_id.isdigit() or len(run_id) > 20:
        raise ValueError("GitHub Actions run id is invalid")
    if REVISION.fullmatch(expected_revision) is None:
        raise ValueError("candidate revision is invalid")

    def gh_json(arguments: list[str]) -> dict[str, Any]:
        try:
            result = subprocess.run(
                ["gh", "api", *arguments], check=False, capture_output=True,
                text=True, timeout=30,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("GitHub CLI is unavailable for CI artifact verification") from error
        if result.returncode != 0 or len(result.stdout) > 1_000_000:
            raise ValueError("GitHub Actions metadata could not be verified")
        try:
            value = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ValueError("GitHub Actions metadata was invalid") from error
        if not isinstance(value, dict):
            raise ValueError("GitHub Actions metadata was invalid")
        return value

    run = gh_json([f"repos/{CI_REPOSITORY}/actions/runs/{run_id}"])
    artifacts = gh_json([f"repos/{CI_REPOSITORY}/actions/runs/{run_id}/artifacts?per_page=100"])
    repository = run.get("repository")
    artifact_name = f"redis-recovery-{expected_revision}"
    artifact_list = artifacts.get("artifacts")
    matches = [
        item for item in artifact_list
        if isinstance(item, dict) and item.get("name") == artifact_name
    ] if isinstance(artifact_list, list) else []
    artifact = matches[0] if len(matches) == 1 else None
    if (
        not isinstance(repository, dict)
        or repository.get("full_name") != CI_REPOSITORY
        or run.get("path") != CI_WORKFLOW_PATH
        or run.get("event") != "push"
        or run.get("head_branch") != "main"
        or run.get("status") != "completed"
        or run.get("conclusion") != "success"
        or run.get("head_sha") != expected_revision
        or str(run.get("id")) != run_id
        or not isinstance(artifact, dict)
        or artifact.get("expired") is not False
        or not isinstance(artifact.get("id"), int)
        or not isinstance(artifact.get("workflow_run"), dict)
        or str(artifact["workflow_run"].get("id")) != run_id
        or artifact["workflow_run"].get("head_sha") != expected_revision
    ):
        raise ValueError("No successful main-branch Redis recovery artifact matches this candidate")

    with tempfile.TemporaryDirectory(prefix="redis-ci-evidence-") as directory:
        try:
            downloaded = subprocess.run(
                ["gh", "run", "download", run_id, "--repo", CI_REPOSITORY,
                 "--name", artifact_name, "--dir", directory],
                check=False, capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("GitHub Actions artifact download failed") from error
        path = Path(directory) / "redis-recovery-acceptance.json"
        if downloaded.returncode != 0 or not path.is_file() or path.is_symlink():
            raise ValueError("GitHub Actions artifact is missing or could not be downloaded")
        if path.stat().st_size > MAX_CI_ARTIFACT_BYTES:
            raise ValueError("GitHub Actions Redis recovery artifact exceeds its size limit")
        raw = path.read_bytes()
        try:
            attestation = subprocess.run(
                [
                    "gh", "attestation", "verify", str(path), "--repo", CI_REPOSITORY,
                    "--signer-workflow", f"{CI_REPOSITORY}/{CI_WORKFLOW_PATH}",
                    "--source-ref", "refs/heads/main", "--source-digest", expected_revision,
                    "--deny-self-hosted-runners", "--format", "json",
                ],
                check=False, capture_output=True, text=True, timeout=60,
            )
        except (OSError, subprocess.TimeoutExpired) as error:
            raise ValueError("GitHub CLI could not verify the Redis report attestation") from error
        if (
            attestation.returncode != 0
            or len(attestation.stdout) > 1_000_000
            or len(attestation.stderr) > 16_384
        ):
            raise ValueError("Redis recovery report lacks a valid CI artifact attestation")
        try:
            attestation_results = json.loads(attestation.stdout)
        except json.JSONDecodeError as error:
            raise ValueError("GitHub CLI returned invalid attestation verification output") from error
        if not isinstance(attestation_results, list) or not attestation_results:
            raise ValueError("Redis recovery report attestation was not verified")
        try:
            report = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError("GitHub Actions Redis recovery artifact is invalid") from error

    provenance = {
        "repository": CI_REPOSITORY,
        "workflow_path": CI_WORKFLOW_PATH,
        "event": run["event"],
        "branch": run["head_branch"],
        "status": run["status"],
        "conclusion": run["conclusion"],
        "head_sha": run["head_sha"],
        "run_id": run_id,
        "artifact_id": str(artifact["id"]),
        "artifact_name": artifact_name,
        "attestation_verified_during_collection": True,
    }
    safe_report, report_failures = validate_report(
        report, expected_revision=expected_revision, now=now or datetime.now(timezone.utc)
    )
    if report_failures or safe_report is None:
        raise ValueError("GitHub Actions Redis recovery report failed validation")
    provenance["report_sha256"] = report_projection_sha256(safe_report)
    safe_provenance, failures = validate_ci_provenance(
        provenance, expected_revision=expected_revision
    )
    if failures or safe_provenance is None:
        raise ValueError("GitHub Actions Redis recovery artifact provenance did not match")
    return report, safe_provenance


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
    repository_root = Path(__file__).resolve().parents[1]
    if str(repository_root) not in sys.path:
        sys.path.insert(0, str(repository_root))
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
            for case, _message in [*result.failures, *result.errors]
            if hasattr(case, "id")
        }
        skipped = {
            case.id().rsplit(".", 1)[-1]
            for case, _message in result.skipped
            if hasattr(case, "id")
        }
        if planned != REQUIRED_TEST_NAMES:
            raise ValueError("required Redis recovery tests are unavailable")
        if (
            result.wasSuccessful()
            and result.testsRun == len(REQUIRED_TEST_NAMES)
            and not result.skipped
        ):
            test_results = {name: "passed" for name in REQUIRED_TEST_NAMES}
            exit_code = 0
        else:
            for name in REQUIRED_TEST_NAMES:
                test_results[name] = (
                    "skipped" if name in skipped
                    else "failed" if name in failed
                    else "passed" if result.testsRun == len(REQUIRED_TEST_NAMES)
                    else "not-run"
                )
            exit_code = 1
    except Exception as exc:
        print(f"Redis recovery acceptance setup failed ({type(exc).__name__})", file=sys.stderr)
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
