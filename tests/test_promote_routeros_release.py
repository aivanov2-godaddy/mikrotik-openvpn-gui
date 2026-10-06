from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
import unittest
from unittest.mock import patch

from scripts.deploy_routeros_release import DeploymentError
from scripts.promote_routeros_release import (
    PromotionSettings,
    _safe_ready_url,
    _write_last_good,
    _write_quarantine,
    promote,
)


PRIOR_IMAGE = "ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-" + "a" * 40 + "-arm64"
CANDIDATE_IMAGE = "ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-" + "b" * 40 + "-arm64"
NOW = datetime(2026, 10, 6, 9, 0, tzinfo=timezone.utc)
REPORT = {
    "promotion_eligible": True,
    "deployments": [
        {"environment": "canary", "image": CANDIDATE_IMAGE, "digest": "sha256:" + "c" * 64},
        {"environment": "production", "image": PRIOR_IMAGE, "digest": None},
    ],
}


class FakeRouterOS:
    def __init__(self, production_image: str = PRIOR_IMAGE, canary_image: str = CANDIDATE_IMAGE) -> None:
        self.records = {
            "*1": {".id": "*1", "name": "vpn-dashboard-canary", "status": "running", "remote-image": canary_image},
            "*2": {".id": "*2", "name": "vpn-dashboard-production", "status": "running", "remote-image": production_image},
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
        elif command == "update":
            self.records[container_id]["status"] = "stopped"
        elif command == "start":
            self.records[container_id]["status"] = "running"


class FakeRouterFiles:
    def __init__(self) -> None:
        self.files: dict[str, dict[str, str]] = {
            "*1": {".id": "*1", "name": "disk1/vpn-dashboard/routeros-update-state.txt", "contents": "old-state"}
        }

    def request(self, method: str, path: str, body: dict[str, object] | None = None) -> object:
        if method == "POST" and path == "/file/print":
            assert body is not None
            target = str(body[".query"][0]).partition("=")[2]  # type: ignore[index]
            return [
                {key: value for key, value in record.items() if key in body[".proplist"]}  # type: ignore[operator]
                for record in self.files.values()
                if record["name"] == target
            ]
        if method == "GET" and path.startswith("/file/"):
            identifier = path.removeprefix("/file/")
            return dict(self.files[identifier])
        if method == "POST" and path == "/file/set":
            assert body is not None
            self.files[str(body["numbers"])]["contents"] = str(body["contents"])
            return []
        if method == "PUT" and path == "/file":
            assert body is not None
            identifier = f"*{len(self.files) + 1}"
            self.files[identifier] = {
                ".id": identifier,
                "name": str(body["name"]),
                "contents": str(body["contents"]),
            }
            return dict(self.files[identifier])
        raise AssertionError(f"unexpected file REST operation: {method} {path}")


def settings() -> PromotionSettings:
    return PromotionSettings(
        rest_url="https://router.example.test/rest",
        username="operator",
        password="not-used-by-fake",
        canary_container="vpn-dashboard-canary",
        production_container="vpn-dashboard-production",
        canary_ready_url="http://192.168.250.2:8080/readyz",
        production_ready_url="http://192.168.251.2:8080/readyz",
        timeout_seconds=30,
        poll_seconds=0,
    )


class PromotionTests(unittest.TestCase):
    def test_passing_fresh_evidence_and_matching_router_promotes_candidate(self) -> None:
        router = FakeRouterOS()
        with (
            patch("scripts.promote_routeros_release.evaluate", return_value=(0, deepcopy(REPORT))) as evaluator,
            patch("scripts.promote_routeros_release._verify_staged_record"),
            patch("scripts.promote_routeros_release._write_last_good"),
        ):
            revision = promote(
                {"private": "evidence"},
                settings(),
                client=router,
                ready_probe=lambda *_: True,
                clock=lambda: NOW,
                sleep=lambda _: None,
            )

        self.assertEqual(revision, "b" * 40)
        self.assertEqual(router.records["*2"]["remote-image"], CANDIDATE_IMAGE.removeprefix("ghcr.io/"))
        self.assertTrue(any(call[0] == "patch" and call[1] == "*2" for call in router.calls))
        evaluator.assert_called_once_with({"private": "evidence"}, now=NOW, phase="canary-prepromotion")

    def test_failed_acceptance_evidence_causes_zero_router_writes(self) -> None:
        router = FakeRouterOS()
        with patch(
            "scripts.promote_routeros_release.evaluate",
            return_value=(1, {"promotion_eligible": False, "deployments": []}),
        ):
            with self.assertRaisesRegex(DeploymentError, "acceptance did not pass"):
                promote({}, settings(), client=router, ready_probe=lambda *_: True, clock=lambda: NOW)
        self.assertEqual(router.calls, [])

    def test_candidate_or_production_drift_causes_zero_router_writes(self) -> None:
        cases = (
            FakeRouterOS(canary_image=PRIOR_IMAGE),
            FakeRouterOS(production_image=CANDIDATE_IMAGE),
        )
        for router in cases:
            with self.subTest(router=router.records):
                with patch("scripts.promote_routeros_release.evaluate", return_value=(0, deepcopy(REPORT))):
                    with self.assertRaises(DeploymentError):
                        promote({}, settings(), client=router, ready_probe=lambda *_: True, clock=lambda: NOW)
                self.assertEqual(router.calls, [])

    def test_check_only_verifies_without_mutating_router(self) -> None:
        router = FakeRouterOS()
        with (
            patch("scripts.promote_routeros_release.evaluate", return_value=(0, deepcopy(REPORT))),
            patch("scripts.promote_routeros_release._verify_staged_record"),
        ):
            revision = promote(
                {}, settings(), client=router, ready_probe=lambda *_: True, clock=lambda: NOW, check_only=True
            )
        self.assertEqual(revision, "b" * 40)
        self.assertEqual(router.calls, [])

    def test_postpromotion_readiness_failure_restores_previous_image(self) -> None:
        router = FakeRouterOS()
        with (
            patch("scripts.promote_routeros_release.evaluate", return_value=(0, deepcopy(REPORT))),
            patch("scripts.promote_routeros_release._verify_staged_record"),
            patch("scripts.promote_routeros_release._write_last_good"),
            patch("scripts.promote_routeros_release._write_quarantine"),
        ):
            def probe(_url: str, revision: str, _timeout: float, _ca: str | None) -> bool:
                production_image = router.records["*2"]["remote-image"]
                if revision == "b" * 40 and production_image.endswith("b" * 40 + "-arm64"):
                    return False
                return True

            with self.assertRaisesRegex(DeploymentError, "prior production image was restored"):
                promote({}, settings(), client=router, ready_probe=probe, clock=lambda: NOW, sleep=lambda _: None)
        self.assertTrue(router.records["*2"]["remote-image"].endswith("a" * 40 + "-arm64"))

    def test_last_good_journal_failure_rolls_back_and_resets_previous_state(self) -> None:
        router = FakeRouterOS()
        with (
            patch("scripts.promote_routeros_release.evaluate", return_value=(0, deepcopy(REPORT))),
            patch("scripts.promote_routeros_release._verify_staged_record"),
            patch(
                "scripts.promote_routeros_release._write_last_good",
                side_effect=[DeploymentError("journal verification failed"), None],
            ) as write_last_good,
            patch("scripts.promote_routeros_release._write_quarantine"),
        ):
            with self.assertRaisesRegex(DeploymentError, "prior production image was restored"):
                promote({}, settings(), client=router, ready_probe=lambda *_: True, clock=lambda: NOW)

        self.assertTrue(router.records["*2"]["remote-image"].endswith("a" * 40 + "-arm64"))
        self.assertEqual(
            write_last_good.call_args_list[-1].args[2:4],
            (PRIOR_IMAGE, "a" * 40),
        )

    def test_plain_http_readiness_is_private_ipv4_only(self) -> None:
        _safe_ready_url("http://10.20.30.40:8080/readyz")
        for url in (
            "http://public.example:8080/readyz",
            "http://192.168.1.2/readyz",
            "http://127.0.0.1:8080/readyz",
            "http://192.168.1.2:8080/readyz?token=x",
        ):
            with self.subTest(url=url), self.assertRaises(DeploymentError):
                _safe_ready_url(url)

    def test_last_good_and_failure_journal_are_written_only_to_named_metadata_files(self) -> None:
        router = FakeRouterFiles()
        _write_last_good(router, "disk1/vpn-dashboard/routeros-update-state.txt", CANDIDATE_IMAGE, "b" * 40, NOW)
        _write_quarantine(router, "disk1/vpn-dashboard/routeros-update-state.txt.failed", CANDIDATE_IMAGE, NOW)

        self.assertIn(f"last-good-image={CANDIDATE_IMAGE}", router.files["*1"]["contents"])
        self.assertIn(f"failed-image={CANDIDATE_IMAGE}", router.files["*2"]["contents"])
        self.assertIn("failure-count=3", router.files["*2"]["contents"])


if __name__ == "__main__":
    unittest.main()
