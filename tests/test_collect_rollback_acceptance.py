from __future__ import annotations

from datetime import datetime, timezone
import json
import unittest
from unittest.mock import Mock, patch

from scripts.collect_rollback_acceptance import (
    _validate_origin,
    build_report,
    collect_checkpoint,
)
from scripts.rollback_acceptance import READBACKS


REVISION = "a" * 40
PRIOR = "c" * 40
PRODUCTION = "d" * 40
CANDIDATE_IMAGE = f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{REVISION}-arm64"
PRIOR_IMAGE = f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{PRIOR}-arm64"
PRODUCTION_IMAGE = f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-{PRODUCTION}-arm64"


def checkpoint(canary_revision: str, at: str) -> dict[str, object]:
    containers = {
        "canary": {"healthy": True, "revision": canary_revision},
        "production": {"healthy": True, "revision": PRODUCTION},
    }
    return {
        "observed_at": at,
        "containers": containers,
        "readiness": {
            "canary": {"status": "ready", "revision": canary_revision},
            "production": {"status": "ready", "revision": PRODUCTION},
        },
        "source": {
            "collector": "authenticated-routeros-api-rest-readyz-v1",
            "captured_at": at,
            "api_authenticated": True,
            "rest_authenticated": True,
            "rest_parity_verified": True,
            "canary_revision": canary_revision,
            "production_revision": PRODUCTION,
            "canary_ready_revision": canary_revision,
            "production_ready_revision": PRODUCTION,
            "canary_healthy": True,
            "production_healthy": True,
            "canary_ready": True,
            "production_ready": True,
        },
    }


class CollectRollbackAcceptanceTests(unittest.TestCase):
    def test_rejects_plaintext_readiness_to_public_hostname(self) -> None:
        with self.assertRaisesRegex(ValueError, "configured HTTPS"):
            _validate_origin("http://example.test", expected_host="vpn-dev.wanted.sx")

    def test_rejects_arbitrary_public_https_hosts_and_cross_environment_hosts(self) -> None:
        for url, expected_host in (
            ("https://example.test", "vpn-dev.wanted.sx"),
            ("https://vpn.wanted.sx", "vpn-dev.wanted.sx"),
            ("https://vpn-dev.wanted.sx:8443", "vpn-dev.wanted.sx"),
            ("https://8.8.8.8", "vpn-dev.wanted.sx"),
            ("http://127.0.0.1:8080", "vpn-dev.wanted.sx"),
            ("https://169.254.169.254", "vpn-dev.wanted.sx"),
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                _validate_origin(url, expected_host=expected_host)

    def test_allows_only_exact_configured_environment_https_hosts(self) -> None:
        self.assertEqual(
            _validate_origin("https://vpn-dev.wanted.sx", expected_host="vpn-dev.wanted.sx"),
            "https://vpn-dev.wanted.sx",
        )
        for url in (
            "https://192.168.1.10:8443",
            "https://10.10.10.1:8443",
            "http://vpn-dev.wanted.sx",
        ):
            with self.subTest(url=url), self.assertRaises(ValueError):
                _validate_origin(url, expected_host="vpn-dev.wanted.sx")

    def test_checkpoint_uses_authenticated_binary_rest_and_readyz_sources(self) -> None:
        source_snapshot = {
            "containers": {
                "canary": {"healthy": True, "revision": REVISION},
                "production": {"healthy": True, "revision": PRODUCTION},
            }
        }
        connection = Mock()
        rest_reader = Mock()
        rest_reader.snapshot.return_value = source_snapshot
        def probe(url: str, *, timeout: float) -> tuple[int, bytes]:
            revision = PRODUCTION if "vpn.wanted.sx" in url else REVISION
            return 200, json.dumps({"status": "ready", "revision": revision}).encode()

        with (
            patch("scripts.collect_rollback_acceptance._snapshot", return_value=source_snapshot),
            patch("scripts.collect_rollback_acceptance._snapshot_mismatches", return_value=[]),
        ):
            result = collect_checkpoint(
                connection,
                rest_reader,
                username="read-only",
                password="not-recorded",
                readyz_origins={"canary": "https://vpn-dev.wanted.sx", "production": "https://vpn.wanted.sx"},
                probe=probe,
                clock=lambda: datetime(2026, 10, 19, tzinfo=timezone.utc),
            )

        connection.connect.assert_called_once_with("read-only", "not-recorded")
        connection.close.assert_called_once()
        rest_reader.close.assert_called_once()
        self.assertEqual(result["source"]["collector"], "authenticated-routeros-api-rest-readyz-v1")
        self.assertTrue(result["source"]["rest_parity_verified"])
        self.assertNotIn("not-recorded", str(result))

    def test_build_report_derives_records_from_each_direct_checkpoint(self) -> None:
        values = [PRIOR, PRIOR, REVISION, PRIOR, PRIOR, REVISION]
        checkpoints = {
            name: checkpoint(revision, f"2026-10-19T10:{index:02}:00+00:00")
            for index, (name, revision) in enumerate(zip(READBACKS, values, strict=True))
        }
        report = build_report(
            candidate_image=CANDIDATE_IMAGE,
            candidate_digest="sha256:" + "b" * 64,
            previous_canary_image=PRIOR_IMAGE,
            production_image=PRODUCTION_IMAGE,
            checkpoints=checkpoints,
        )
        self.assertEqual(report["format"], "vpn-dashboard-rollback-rehearsal-v2")
        self.assertEqual(report["canary_candidate"]["image"], CANDIDATE_IMAGE)
        self.assertTrue(report["production_after"]["source"]["rest_parity_verified"])

        checkpoints["production_after"] = checkpoint(PRIOR, "2026-10-19T10:04:00+00:00")
        checkpoints["production_after"]["containers"]["production"]["revision"] = "e" * 40
        with self.assertRaisesRegex(ValueError, "expected rollback checkpoint"):
            build_report(
                candidate_image=CANDIDATE_IMAGE,
                candidate_digest="sha256:" + "b" * 64,
                previous_canary_image=PRIOR_IMAGE,
                production_image=PRODUCTION_IMAGE,
                checkpoints=checkpoints,
            )


if __name__ == "__main__":
    unittest.main()
