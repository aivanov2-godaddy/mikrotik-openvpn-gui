from __future__ import annotations

import io
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import Mock, patch
from urllib.error import HTTPError

from scripts.deploy_routeros_release import (
    DeploymentError,
    DeploymentSettings,
    RouterOSRest,
    _wait_for,
    _status,
    current_image,
    deploy,
)


IMAGE_REPOSITORY = "ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui"
OLD_TAG = f"{IMAGE_REPOSITORY}:sha-{'a' * 40}-arm64"
OLD_IMAGE = OLD_TAG + "@sha256:" + "c" * 64
NEW_IMAGE = f"{IMAGE_REPOSITORY}:sha-{'b' * 40}-arm64@sha256:" + "d" * 64
NEW_ARM64_IMAGE = NEW_IMAGE
OLD_RELATIVE_IMAGE = OLD_IMAGE.removeprefix("ghcr.io/")
NEW_RELATIVE_IMAGE = NEW_IMAGE.removeprefix("ghcr.io/")


class FakeRouterOS:
    def __init__(self, *, fail_start: bool = False, image: str = OLD_IMAGE) -> None:
        self.record = {
            ".id": "*1",
            "name": "vpn-dashboard",
            "status": "running",
            "remote-image": image,
        }
        self.calls: list[tuple[str, str, object]] = []
        self.fail_start = fail_start
        self.failed_once = False

    def containers(self) -> list[dict[str, str]]:
        return [dict(self.record)]

    def container(self, _container_id: str) -> dict[str, str]:
        return dict(self.record)

    def patch_container(self, container_id: str, values: dict[str, str]) -> None:
        self.calls.append(("patch", container_id, dict(values)))
        self.record.update(values)

    def command(self, command: str, container_id: str) -> None:
        self.calls.append(("command", command, container_id))
        if command == "stop":
            self.record["status"] = "stopped"
        elif command == "start":
            if self.fail_start and not self.failed_once:
                self.failed_once = True
                self.record["status"] = "failed"
            else:
                self.record["status"] = "running"
        elif command == "update":
            self.record["status"] = "stopped"


class EmptyStopRouterOS(FakeRouterOS):
    """RouterOS 7.24 shape observed while an explicit stop is completing."""

    def __init__(self) -> None:
        super().__init__()
        self.empty_reads = 0

    def container(self, _container_id: str) -> dict[str, str]:
        if self.empty_reads and self.empty_reads < 3:
            self.empty_reads += 1
            return {".id": "*1", "name": "vpn-dashboard", "remote-image": OLD_IMAGE}
        return super().container(_container_id)

    def command(self, command: str, container_id: str) -> None:
        super().command(command, container_id)
        if command == "stop":
            self.empty_reads = 1


def settings(image: str = NEW_IMAGE) -> DeploymentSettings:
    return DeploymentSettings(
        rest_url="https://router.example.test/rest",
        username="deployer",
        password="not-used-by-fake",
        container_name="vpn-dashboard",
        release_image=image,
        timeout_seconds=30,
        poll_seconds=0,
    )


class DeploymentTests(unittest.TestCase):
    def test_deployment_settings_repr_redacts_password(self) -> None:
        secret = "deployment-password-sentinel"
        configured = DeploymentSettings(
            rest_url="https://router.example.test/rest",
            username="deployer",
            password=secret,
            container_name="vpn-dashboard",
            release_image=NEW_IMAGE,
        )

        self.assertNotIn(secret, repr(configured))

    def test_routeros_error_body_is_not_returned_to_logs(self) -> None:
        client = RouterOSRest(settings())
        secret = "environment-secret-must-not-be-logged"
        error = HTTPError(
            "https://router.example.test/rest/container/print",
            400,
            "Bad Request",
            {},
            io.BytesIO(secret.encode()),
        )
        with patch.object(client._opener, "open", side_effect=error):
            with self.assertRaises(DeploymentError) as raised:
                client.request("POST", "/container/print")

        self.assertIn("failed (400)", str(raised.exception))
        self.assertNotIn(secret, str(raised.exception))

    def test_deployer_credentials_are_not_forwarded_to_redirect_target(self) -> None:
        forwarded_authorization: list[str | None] = []
        target_url = ""

        class RedirectHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                self.send_response(302)
                self.send_header("Location", target_url)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        class TargetHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                forwarded_authorization.append(self.headers.get("Authorization"))
                payload = b"[]"
                self.send_response(200)
                self.send_header("Content-Length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, format: str, *args: object) -> None:
                return

        redirect_server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        target_server = ThreadingHTTPServer(("127.0.0.1", 0), TargetHandler)
        target_url = f"http://127.0.0.1:{target_server.server_port}/capture"
        servers = (redirect_server, target_server)
        threads = [
            threading.Thread(target=server.serve_forever, daemon=True)
            for server in servers
        ]
        for thread in threads:
            thread.start()
        try:
            client = RouterOSRest(settings())
            client.base_url = f"http://127.0.0.1:{redirect_server.server_port}"
            with self.assertRaises(DeploymentError) as raised:
                client.request("GET", "/redirect")
        finally:
            for server in servers:
                server.shutdown()
                server.server_close()
            for thread in threads:
                thread.join(timeout=2)

        self.assertIn("failed (302)", str(raised.exception))
        self.assertEqual(forwarded_authorization, [])

    def test_routeros_commands_use_plural_numbers_selector(self) -> None:
        client = RouterOSRest(settings())
        client.request = Mock(return_value=[])

        client.command("stop", "*1")

        client.request.assert_called_once_with("POST", "/container/stop", {"numbers": "*1"})

    def test_routeros_update_uses_singular_number_selector(self) -> None:
        client = RouterOSRest(settings())
        client.request = Mock(return_value=[])

        client.command("update", "*1")

        client.request.assert_called_once_with("POST", "/container/update", {"number": "*1"})

    def test_updates_immutable_image_and_starts_container(self) -> None:
        router = FakeRouterOS()

        revision = deploy(settings(), router)

        self.assertEqual(revision, "b" * 40)
        self.assertEqual(router.record["remote-image"], NEW_RELATIVE_IMAGE)
        self.assertEqual(router.record["status"], "running")
        self.assertEqual(
            router.calls,
            [
                ("command", "stop", "*1"),
                ("patch", "*1", {"remote-image": NEW_RELATIVE_IMAGE}),
                ("command", "update", "*1"),
                ("command", "start", "*1"),
            ],
        )

    def test_accepts_empty_routeros_record_after_stop(self) -> None:
        router = EmptyStopRouterOS()

        revision = deploy(settings(), router)

        self.assertEqual(revision, "b" * 40)
        self.assertEqual(router.record["status"], "running")

    def test_pull_failure_overrides_stale_healthcheck(self) -> None:
        self.assertEqual(
            _status({"download/extract failed": "true", "healthcheck-status": "good"}),
            "failed",
        )

    def test_empty_stop_state_is_not_accepted_for_update_waits(self) -> None:
        client = Mock()
        client.container.return_value = {".id": "*1", "name": "vpn-dashboard"}
        short_settings = DeploymentSettings(
            rest_url="https://router.example.test/rest",
            username="deployer",
            password="not-used-by-fake",
            container_name="vpn-dashboard",
            release_image=NEW_IMAGE,
            timeout_seconds=0.01,
            poll_seconds=0,
        )

        with self.assertRaises(DeploymentError):
            _wait_for(client, "*1", "stopped", short_settings)

    def test_running_requested_image_is_a_noop(self) -> None:
        router = FakeRouterOS()

        revision = deploy(settings(OLD_IMAGE), router)

        self.assertEqual(revision, "a" * 40)
        self.assertEqual(router.calls, [])

    def test_failed_start_rolls_back_previous_image(self) -> None:
        router = FakeRouterOS(fail_start=True)

        with self.assertRaises(DeploymentError):
            deploy(settings(), router)

        self.assertEqual(router.record["status"], "running")
        self.assertEqual(router.record["remote-image"], OLD_RELATIVE_IMAGE)
        self.assertIn(("patch", "*1", {"remote-image": OLD_RELATIVE_IMAGE}), router.calls)

    def test_rejects_mutable_or_non_ghcr_image(self) -> None:
        invalid = settings(f"{IMAGE_REPOSITORY}:edge")
        with self.assertRaises(DeploymentError):
            invalid.validate()

    def test_rejects_tag_only_candidate(self) -> None:
        invalid = settings(OLD_TAG)
        with self.assertRaises(DeploymentError):
            invalid.validate()

    def test_legacy_current_tag_requires_digest_resolution_before_mutation(self) -> None:
        router = FakeRouterOS(image=OLD_TAG.removeprefix("ghcr.io/"))
        calls: list[tuple[str, float]] = []

        def resolve(image: str, *, timeout: float) -> str:
            calls.append((image, timeout))
            return "sha256:" + "c" * 64

        deploy(settings(), router, digest_resolver=resolve)

        self.assertEqual(router.record["remote-image"], NEW_RELATIVE_IMAGE)
        self.assertEqual(calls[0][0], OLD_TAG.removeprefix("ghcr.io/"))

    def test_unresolved_legacy_rollback_image_causes_zero_mutations(self) -> None:
        router = FakeRouterOS(image=OLD_TAG.removeprefix("ghcr.io/"))

        with self.assertRaisesRegex(DeploymentError, "exact rollback digest"):
            deploy(settings(), router, digest_resolver=lambda *_args, **_kwargs: None)

        self.assertEqual(router.calls, [])

    def test_supplied_rollback_digest_must_match_exact_installed_digest(self) -> None:
        router = FakeRouterOS()
        same_revision_wrong_digest = f"{OLD_TAG}@sha256:{'e' * 64}"

        with self.assertRaisesRegex(DeploymentError, "exact currently installed image"):
            deploy(settings(), router, rollback_image=same_revision_wrong_digest)

        self.assertEqual(router.calls, [])

    def test_supplied_rollback_digest_resolves_and_matches_legacy_installed_tag(self) -> None:
        router = FakeRouterOS(image=OLD_TAG.removeprefix("ghcr.io/"))
        resolved: list[str] = []

        def resolve(image: str, *, timeout: float) -> str:
            del timeout
            resolved.append(image)
            return "sha256:" + "c" * 64

        deploy(settings(), router, rollback_image=f"{OLD_TAG}@sha256:{'c' * 64}", digest_resolver=resolve)

        self.assertEqual(resolved, [OLD_TAG.removeprefix("ghcr.io/")])
        self.assertEqual(router.record["remote-image"], NEW_RELATIVE_IMAGE)

    def test_accepts_registry_relative_immutable_image(self) -> None:
        relative = settings(NEW_RELATIVE_IMAGE)
        relative.validate()
        self.assertEqual(relative.revision, "b" * 40)

    def test_accepts_architecture_specific_immutable_image(self) -> None:
        settings(NEW_ARM64_IMAGE).validate()

    def test_reads_installed_immutable_image_without_mutation(self) -> None:
        router = FakeRouterOS()

        image = current_image(settings(), router)

        self.assertEqual(image, OLD_RELATIVE_IMAGE)
        self.assertEqual(router.calls, [])

    def test_accepts_routeros_running_flag_shape(self) -> None:
        self.assertEqual(_status({"running": "true"}), "running")
        self.assertEqual(_status({".running": "false"}), "stopped")
        self.assertEqual(_status({"status": "healthy"}), "running")

    def test_accepts_routeros_stopped_flag_shape(self) -> None:
        self.assertEqual(_status({"stopped": "true"}), "stopped")
        self.assertEqual(_status({"stopped": "false"}), "")
        self.assertEqual(_status({"healthy": "true"}), "running")
        self.assertEqual(_status({"healthy": "false"}), "unhealthy")
        self.assertEqual(_status({"healthcheck-status": "good, output: "}), "running")
        self.assertEqual(_status({"healthcheck-status": "failed, output: timeout"}), "unhealthy")
        self.assertEqual(
            _status({"stopped": "true", "healthcheck-status": "good, output: "}),
            "stopped",
        )

    def test_explicit_unhealthy_probe_overrides_running_flag(self) -> None:
        self.assertEqual(_status({"running": "true", "healthy": "false"}), "unhealthy")
        self.assertEqual(
            _status({"status": "running", "healthcheck-status": "failed, output: timeout"}),
            "unhealthy",
        )

    def test_routeros_transitional_flags_are_not_treated_as_stopped(self) -> None:
        self.assertEqual(_status({"running": "false", "starting": "true"}), "starting")
        self.assertEqual(_status({"running": "false", "stopping": "true"}), "stopping")
        self.assertEqual(_status({"starting": "true", "stopping": "true"}), "")
        self.assertEqual(_status({"running": "true", "stopped": "true"}), "")
        self.assertEqual(_status({"running": "true", "starting": "true"}), "")
        self.assertEqual(_status({".running": "true", "stopped": "true"}), "")
        self.assertEqual(_status({"running": "true", ".running": "false"}), "")


if __name__ == "__main__":
    unittest.main()
