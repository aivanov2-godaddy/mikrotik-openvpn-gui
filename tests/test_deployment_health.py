from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from scripts.check_deployment_health import HealthCheckError, verify_ready


class _Response:
    status = 200

    def __init__(self, payload: object) -> None:
        self.payload = payload

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *_: object) -> None:
        return None

    def read(self, _size: int) -> bytes:
        return json.dumps(self.payload).encode("utf-8")


class DeploymentHealthTests(unittest.TestCase):
    @patch("scripts.check_deployment_health.urllib.request.urlopen")
    def test_accepts_ready_exact_revision(self, open_url: object) -> None:
        revision = "a" * 40
        open_url.return_value = _Response({"status": "ready", "revision": revision})  # type: ignore[attr-defined]

        verify_ready("https://canary.example.test/readyz", revision)

    def test_rejects_non_ready_url_or_response(self) -> None:
        with self.assertRaises(HealthCheckError):
            verify_ready("http://canary.example.test/readyz", "a" * 40)
        with patch("scripts.check_deployment_health.urllib.request.urlopen", return_value=_Response({"status": "ready", "revision": "b" * 40})):
            with self.assertRaises(HealthCheckError):
                verify_ready("https://canary.example.test/readyz", "a" * 40)
