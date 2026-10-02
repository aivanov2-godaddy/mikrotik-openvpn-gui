from __future__ import annotations

import unittest

from error_guidance import routeros_error_payload
from routeros import RouterOSError


class RouterOSErrorGuidanceTests(unittest.TestCase):
    def test_http_statuses_map_to_stable_codes_and_safe_next_steps(self) -> None:
        expected = {
            401: "routeros.authentication_failed",
            403: "routeros.permission_denied",
            404: "routeros.endpoint_unavailable",
            503: "routeros.request_failed",
        }
        for status, code in expected.items():
            with self.subTest(status=status):
                payload = routeros_error_payload(RouterOSError("sensitive remote detail", status))
                self.assertEqual(payload["code"], code)
                self.assertTrue(payload["error"])
                self.assertTrue(payload["next_step"])
                self.assertNotIn("sensitive remote detail", str(payload))

    def test_transport_error_does_not_echo_host_or_router_response(self) -> None:
        payload = routeros_error_payload(
            RouterOSError("RouterOS is unavailable: private-router.example:8443 timed out")
        )
        self.assertEqual(payload["code"], "routeros.unavailable")
        self.assertNotIn("private-router.example", str(payload))
        self.assertNotIn("timed out", str(payload))


if __name__ == "__main__":
    unittest.main()
