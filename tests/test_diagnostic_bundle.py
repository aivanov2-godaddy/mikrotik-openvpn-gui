from __future__ import annotations

import io
import json
import unittest
import zipfile

from diagnostic_bundle import MAX_DIAGNOSTIC_BUNDLE_BYTES, build_diagnostic_bundle


class DiagnosticBundleTests(unittest.TestCase):
    def test_bundle_contains_only_allowlisted_redacted_fields(self) -> None:
        markers = [
            "PRIVATE-USER-7f3", "198.51.100.77", "router-password-marker",
            "PRIVATE-KEY-MARKER", "CERTIFICATE-MARKER", "PROFILE-MARKER",
            "raw-router-record-marker", "secret-token-marker", "private-host-marker",
        ]
        health = {
            "overall": "healthy", "checked_at": 1_800_000_000,
            "checks": [{
                "id": "routeros-rest", "status": "healthy", "name": markers[0],
                "impact": markers[1], "remediation": markers[2], "certificate": markers[4],
                "raw_record": markers[6], "profile": markers[5],
            }],
            "username": markers[0], "source_address": markers[1],
            "credentials": markers[2], "certificate": markers[4], "profile": markers[5],
        }
        telemetry = {
            "state": "healthy", "transport": "socketio", "last_event_at": 1_800_000_000,
            "reconnects": 2, "last_error": markers[7], "host": markers[8],
            "username": markers[0], "raw_event": markers[6], "credentials": markers[2],
            "supervisor": {
                "status": "healthy", "enabled": True, "attempts": 3, "reconnects": 1,
                "last_error_code": markers[7], "router_record": markers[6], "password": markers[2],
            },
        }

        result = build_diagnostic_bundle(
            version="1.2.3", revision="0123456789abcdef0123456789abcdef01234567",
            generated_at=1_800_000_001, health=health, telemetry=telemetry,
        )

        self.assertLessEqual(len(result), MAX_DIAGNOSTIC_BUNDLE_BYTES)
        with zipfile.ZipFile(io.BytesIO(result)) as archive:
            self.assertEqual(archive.namelist(), ["diagnostics.json"])
            document = json.loads(archive.read("diagnostics.json"))
        serialized = json.dumps(document)
        for marker in markers:
            self.assertNotIn(marker, serialized)
        self.assertEqual(document["health"]["checks"], [{"id": "routeros-rest", "status": "healthy"}])
        self.assertEqual(document["telemetry"]["supervisor"]["attempts"], 3)
        self.assertFalse(document["privacy"]["contains_identifiers"])

    def test_invalid_free_text_and_unbounded_values_collapse_to_safe_defaults(self) -> None:
        result = build_diagnostic_bundle(
            version="router.example.test/private", revision="revision-secret", generated_at=-1,
            health={"overall": {"secret": "value"}, "checks": [{"id": "private-user", "status": []}]},
            telemetry={"state": "password-marker", "transport": "198.51.100.1", "reconnects": 10**1000},
        )
        with zipfile.ZipFile(io.BytesIO(result)) as archive:
            document = json.loads(archive.read("diagnostics.json"))
        self.assertEqual(document["application"], {"revision": "unknown", "version": "unknown"})
        self.assertIsNone(document["generated_at"])
        self.assertEqual(document["health"]["overall"], "unknown")
        self.assertEqual(document["health"]["checks"], [])
        self.assertEqual(document["telemetry"]["state"], "unknown")
        self.assertEqual(document["telemetry"]["transport"], "unknown")
        self.assertNotIn("password-marker", json.dumps(document))


if __name__ == "__main__":
    unittest.main()
