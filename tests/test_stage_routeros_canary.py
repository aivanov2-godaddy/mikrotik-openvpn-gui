from __future__ import annotations

from contextlib import redirect_stderr
import io
import json
import unittest
from unittest.mock import patch

from scripts.deploy_routeros_release import DeploymentError
from scripts.stage_routeros_canary import (
    BACKUP_FORMAT,
    BACKUP_RECEIPT,
    CanaryStageFailure,
    CanaryStageSettings,
    StageFailureDiagnostic,
    _verify_backup_receipt,
    main,
    stage_canary,
)


IMAGE_REPOSITORY = "ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui"
PRIOR_IMAGE = f"{IMAGE_REPOSITORY}:sha-{'a' * 40}-arm64@sha256:{'e' * 64}"
PRODUCTION_IMAGE = f"{IMAGE_REPOSITORY}:sha-{'c' * 40}-arm64@sha256:{'d' * 64}"
CANDIDATE_IMAGE = f"{IMAGE_REPOSITORY}:sha-{'b' * 40}-arm64@sha256:{'f' * 64}"


def settings() -> CanaryStageSettings:
    return CanaryStageSettings(
        rest_url="https://router.example.test/rest",
        username="operator",
        password="not-used-by-fake",
        candidate_image=CANDIDATE_IMAGE,
        canary_ready_url="http://192.168.250.2:8080/readyz",
        production_ready_url="http://192.168.251.2:8080/readyz",
        timeout_seconds=30,
        poll_seconds=0,
    )


class FakeRouterOS:
    def __init__(self, *, canary_status: str = "running", production_status: str = "running") -> None:
        self.records = {
            "*1": {
                ".id": "*1",
                "name": "vpn-dashboard-canary",
                "status": canary_status,
                "remote-image": PRIOR_IMAGE,
            },
            "*2": {
                ".id": "*2",
                "name": "vpn-dashboard-production",
                "status": production_status,
                "remote-image": PRODUCTION_IMAGE,
            },
        }
        self.calls: list[tuple[str, str, object]] = []

    def containers(self) -> list[dict[str, str]]:
        return [dict(record) for record in self.records.values()]

    def container(self, container_id: str) -> dict[str, str]:
        return dict(self.records[container_id])

    def patch_container(self, container_id: str, values: dict[str, str]) -> None:
        self.calls.append(("patch", container_id, dict(values)))
        self.records[container_id].update(values)

    def command(self, command: str, container_id: str) -> None:
        self.calls.append(("command", command, container_id))
        if command == "stop":
            self.records[container_id]["status"] = "stopped"
        elif command == "start":
            self.records[container_id]["status"] = "running"


class FakeClock:
    def request(self, method: str, path: str, body: object = None) -> object:
        if method == "GET" and path == "/system/clock":
            return {"date": "nov/12/2026", "time": "10:00:00", "gmt-offset": "+02:00"}
        raise AssertionError(f"unexpected RouterOS read: {method} {path}")


class CanaryStageTests(unittest.TestCase):
    def setUp(self) -> None:
        self.receipt = patch("scripts.stage_routeros_canary._verify_backup_receipt")
        self.receipt_mock = self.receipt.start()
        self.addCleanup(self.receipt.stop)

    def test_check_only_requires_healthy_ready_baselines_and_does_not_write(self) -> None:
        router = FakeRouterOS()
        revision = stage_canary(
            settings(),
            client=router,
            ready_probe=lambda *_: True,
            check_only=True,
        )

        self.assertEqual(revision, "b" * 40)
        self.assertEqual(router.calls, [])
        self.receipt_mock.assert_called_once_with(router, prior_canary_image=PRIOR_IMAGE.removeprefix("ghcr.io/"))

    def test_unhealthy_canary_blocks_before_receipt_or_any_write(self) -> None:
        router = FakeRouterOS(canary_status="unhealthy")

        with self.assertRaises(CanaryStageFailure) as caught:
            stage_canary(settings(), client=router, ready_probe=lambda *_: True)

        self.assertEqual(caught.exception.diagnostic.result, "preflight_blocked")
        self.assertEqual(caught.exception.diagnostic.phase, "baseline")
        self.assertEqual(caught.exception.diagnostic.code, "canary_unhealthy")
        self.assertFalse(caught.exception.diagnostic.router_writes_may_have_started)
        self.assertEqual(router.calls, [])
        self.receipt_mock.assert_not_called()

    def test_unhealthy_production_blocks_before_receipt_or_any_write(self) -> None:
        router = FakeRouterOS(production_status="unhealthy")

        with self.assertRaises(CanaryStageFailure) as caught:
            stage_canary(settings(), client=router, ready_probe=lambda *_: True)

        self.assertEqual(caught.exception.diagnostic.result, "preflight_blocked")
        self.assertEqual(caught.exception.diagnostic.phase, "baseline")
        self.assertEqual(caught.exception.diagnostic.code, "production_unhealthy")
        self.assertFalse(caught.exception.diagnostic.router_writes_may_have_started)
        self.assertEqual(router.calls, [])
        self.receipt_mock.assert_not_called()

    def test_failed_backup_receipt_preflight_blocks_before_any_write(self) -> None:
        router = FakeRouterOS()
        self.receipt_mock.side_effect = DeploymentError("encrypted backup receipt is stale")

        with self.assertRaises(CanaryStageFailure) as caught:
            stage_canary(settings(), client=router, ready_probe=lambda *_: True)

        self.assertEqual(caught.exception.diagnostic.result, "preflight_blocked")
        self.assertEqual(caught.exception.diagnostic.phase, "backup")
        self.assertEqual(caught.exception.diagnostic.code, "backup_receipt_invalid")
        self.assertFalse(caught.exception.diagnostic.router_writes_may_have_started)
        self.assertEqual(router.calls, [])

    def test_staging_readiness_failure_restores_exact_canary_and_leaves_production(self) -> None:
        router = FakeRouterOS()

        def deploy_candidate(deploy_settings, client, *, rollback_image):
            self.assertEqual(deploy_settings.container_name, "vpn-dashboard-canary")
            self.assertEqual(rollback_image, PRIOR_IMAGE.removeprefix("ghcr.io/"))
            client.records["*1"]["remote-image"] = CANDIDATE_IMAGE.removeprefix("ghcr.io/")
            client.records["*1"]["status"] = "running"
            return "b" * 40

        def readiness(_url: str, revision: str, _timeout: float, _ca: str | None) -> bool:
            return revision != "b" * 40

        with patch("scripts.stage_routeros_canary.deploy", side_effect=deploy_candidate):
            with self.assertRaises(CanaryStageFailure) as caught:
                stage_canary(settings(), client=router, ready_probe=readiness)

        diagnostic = caught.exception.diagnostic
        self.assertEqual(diagnostic.result, "stage_failed_prior_state_verified")
        self.assertEqual(diagnostic.code, "candidate_readiness_failed")
        self.assertTrue(diagnostic.router_writes_may_have_started)
        self.assertTrue(diagnostic.rollback_attempted)
        self.assertTrue(diagnostic.canary_prior_state_verified)
        self.assertTrue(diagnostic.production_unchanged_verified)
        self.assertFalse(diagnostic.manual_recovery_required)
        self.assertEqual(router.records["*1"]["remote-image"], PRIOR_IMAGE.removeprefix("ghcr.io/"))
        self.assertEqual(router.records["*1"]["status"], "running")
        self.assertEqual(router.records["*2"]["remote-image"], PRODUCTION_IMAGE)
        self.assertEqual(router.records["*2"]["status"], "running")
        self.assertEqual(
            [(call[0], call[1], call[2]) for call in router.calls],
            [
                ("command", "stop", "*1"),
                ("patch", "*1", {"remote-image": PRIOR_IMAGE.removeprefix("ghcr.io/")}),
                ("command", "update", "*1"),
                ("command", "start", "*1"),
            ],
        )

    def test_rollback_failure_requires_manual_recovery_without_raw_error(self) -> None:
        router = FakeRouterOS()

        def deploy_candidate(_deploy_settings, client, *, rollback_image):
            self.assertEqual(rollback_image, PRIOR_IMAGE.removeprefix("ghcr.io/"))
            client.records["*1"]["remote-image"] = CANDIDATE_IMAGE.removeprefix("ghcr.io/")
            client.records["*1"]["status"] = "running"
            return "b" * 40

        def readiness(_url: str, revision: str, _timeout: float, _ca: str | None) -> bool:
            return revision != "b" * 40

        with patch("scripts.stage_routeros_canary.deploy", side_effect=deploy_candidate), patch(
            "scripts.stage_routeros_canary._restore_canary",
            side_effect=RuntimeError("private-router-sentinel https://private.example.test/secret"),
        ):
            with self.assertRaises(CanaryStageFailure) as caught:
                stage_canary(settings(), client=router, ready_probe=readiness)

        diagnostic = caught.exception.diagnostic
        self.assertEqual(diagnostic.result, "recovery_unverified")
        self.assertEqual(diagnostic.code, "rollback_unverified")
        self.assertTrue(diagnostic.router_writes_may_have_started)
        self.assertTrue(diagnostic.rollback_attempted)
        self.assertIsNone(diagnostic.canary_prior_state_verified)
        self.assertIsNone(diagnostic.production_unchanged_verified)
        self.assertTrue(diagnostic.manual_recovery_required)
        self.assertNotIn("private-router-sentinel", str(caught.exception))

    def test_cli_emits_allowlisted_json_without_exception_details(self) -> None:
        diagnostic = StageFailureDiagnostic(
            result="recovery_unverified",
            phase="recovery",
            code="rollback_unverified",
            router_writes_may_have_started=True,
            rollback_attempted=True,
            canary_prior_state_verified=None,
            production_unchanged_verified=None,
            manual_recovery_required=True,
        )

        def raise_diagnostic(*_args, **_kwargs):
            try:
                raise RuntimeError("secret-sentinel private URL and local path")
            except RuntimeError as cause:
                raise CanaryStageFailure(diagnostic) from cause

        stderr = io.StringIO()
        with patch("scripts.stage_routeros_canary._settings_from_environment", return_value=settings()), patch(
            "scripts.stage_routeros_canary.stage_canary", side_effect=raise_diagnostic
        ), redirect_stderr(stderr):
            exit_code = main(["--image", CANDIDATE_IMAGE])

        self.assertEqual(exit_code, 2)
        output = stderr.getvalue()
        self.assertNotIn("secret-sentinel", output)
        self.assertNotIn("private URL", output)
        self.assertNotIn("local path", output)
        self.assertEqual(
            json.loads(output),
            {
                "schema": "mikrotik-canary-stage-diagnostic-v1",
                "result": "recovery_unverified",
                "phase": "recovery",
                "code": "rollback_unverified",
                "router_writes_may_have_started": True,
                "rollback_attempted": True,
                "canary_prior_state_verified": None,
                "production_unchanged_verified": None,
                "manual_recovery_required": True,
                "review_before_retry": True,
            },
        )

    def test_cli_unknown_stage_error_reports_uncertain_state_without_raw_details(self) -> None:
        def fail_unexpectedly(*_args, **_kwargs):
            raise RuntimeError("private-router-sentinel https://private.example.test/secret")

        stderr = io.StringIO()
        with patch("scripts.stage_routeros_canary._settings_from_environment", return_value=settings()), patch(
            "scripts.stage_routeros_canary.stage_canary", side_effect=fail_unexpectedly
        ), redirect_stderr(stderr):
            exit_code = main(["--image", CANDIDATE_IMAGE])

        self.assertEqual(exit_code, 2)
        output = stderr.getvalue()
        self.assertNotIn("private-router-sentinel", output)
        self.assertNotIn("private.example.test", output)
        self.assertEqual(
            json.loads(output),
            {
                "schema": "mikrotik-canary-stage-diagnostic-v1",
                "result": "recovery_unverified",
                "phase": "recovery",
                "code": "unclassified_stage_failure",
                "router_writes_may_have_started": True,
                "rollback_attempted": False,
                "canary_prior_state_verified": None,
                "production_unchanged_verified": None,
                "manual_recovery_required": True,
                "review_before_retry": True,
            },
        )

    def test_cli_unknown_configuration_error_remains_zero_write(self) -> None:
        stderr = io.StringIO()
        with patch(
            "scripts.stage_routeros_canary._settings_from_environment",
            side_effect=RuntimeError("private configuration sentinel"),
        ), redirect_stderr(stderr):
            exit_code = main(["--image", CANDIDATE_IMAGE])

        self.assertEqual(exit_code, 2)
        output = stderr.getvalue()
        self.assertNotIn("private configuration sentinel", output)
        diagnostic = json.loads(output)
        self.assertEqual(diagnostic["result"], "preflight_blocked")
        self.assertEqual(diagnostic["code"], "unclassified_preflight_failure")
        self.assertFalse(diagnostic["router_writes_may_have_started"])
        self.assertFalse(diagnostic["manual_recovery_required"])


class BackupReceiptTests(unittest.TestCase):
    def setUp(self) -> None:
        self.fields = {
            "format": BACKUP_FORMAT,
            "encrypted": "true",
            "backup-file": "disk1/vpn-dashboard/backups/vpn-dashboard-predeploy-2.backup",
            "backup-size": "4096",
            "prior-canary-image": PRIOR_IMAGE.removeprefix("ghcr.io/"),
            "created-date": "nov/12/2026",
            "created-time": "09:45:00",
            "created-gmt-offset": "+02:00",
        }
        self.text = "".join(f"{key}={value}\n" for key, value in self.fields.items())

    def _verify(self, *, size: str = "4096") -> None:
        client = FakeClock()
        with (
            patch("scripts.stage_routeros_canary._read_file_text", return_value=self.text) as read_text,
            patch(
                "scripts.stage_routeros_canary._file_record",
                return_value={".id": "*3", "name": self.fields["backup-file"], "size": size},
            ),
        ):
            _verify_backup_receipt(
                client,
                prior_canary_image=PRIOR_IMAGE.removeprefix("ghcr.io/"),
            )
        read_text.assert_called_once_with(client, BACKUP_RECEIPT)

    def test_fresh_encrypted_receipt_matching_prior_image_and_file_is_accepted(self) -> None:
        self._verify()

    def test_backup_size_mismatch_is_rejected(self) -> None:
        with self.assertRaisesRegex(DeploymentError, "does not match its receipt"):
            self._verify(size="4095")

    def test_stale_receipt_is_rejected(self) -> None:
        self.fields["created-time"] = "08:00:00"
        self.text = "".join(f"{key}={value}\n" for key, value in self.fields.items())

        with self.assertRaisesRegex(DeploymentError, "receipt is stale"):
            self._verify()

    def test_different_canary_image_receipt_is_rejected(self) -> None:
        self.fields["prior-canary-image"] = PRODUCTION_IMAGE.removeprefix("ghcr.io/")
        self.text = "".join(f"{key}={value}\n" for key, value in self.fields.items())

        with self.assertRaisesRegex(DeploymentError, "does not match the current canary baseline"):
            self._verify()


if __name__ == "__main__":
    unittest.main()
