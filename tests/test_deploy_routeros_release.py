from __future__ import annotations

import unittest
from unittest.mock import Mock

from scripts.deploy_routeros_release import (
    DeploymentError,
    DeploymentSettings,
    RouterOSRest,
    _wait_for,
    _status,
    current_image,
    deploy,
)


OLD_IMAGE = "ghcr.io/example-owner/mikrotik-openvpn-gui-public:sha-" + "a" * 40
NEW_IMAGE = "ghcr.io/example-owner/mikrotik-openvpn-gui-public:sha-" + "b" * 40
NEW_ARM64_IMAGE = NEW_IMAGE + "-arm64"
OLD_RELATIVE_IMAGE = OLD_IMAGE.removeprefix("ghcr.io/")
NEW_RELATIVE_IMAGE = NEW_IMAGE.removeprefix("ghcr.io/")


class FakeRouterOS:
    def __init__(self, *, fail_start: bool = False) -> None:
        self.record = {
            ".id": "*1",
            "name": "vpn-dashboard",
            "status": "running",
            "remote-image": OLD_IMAGE,
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
        invalid = settings("ghcr.io/example-owner/mikrotik-openvpn-gui-public:edge")
        with self.assertRaises(DeploymentError):
            invalid.validate()

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


if __name__ == "__main__":
    unittest.main()
