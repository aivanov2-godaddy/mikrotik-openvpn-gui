from __future__ import annotations

import unittest
import ssl
import urllib.error
from unittest.mock import patch

from error_guidance import routeros_error_payload
from routeros import RouterOSError, RouterOSClient, RouterOSCredentials, _records


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

    def test_existing_response_shape_and_http_guidance_remain_compatible(self) -> None:
        payload = routeros_error_payload(RouterOSError("private response", 403))
        self.assertEqual(set(payload), {"code", "error", "next_step"})
        self.assertEqual(payload["code"], "routeros.permission_denied")
        self.assertIn("do not grant broad policies", payload["next_step"])

    def test_transport_error_does_not_echo_host_or_router_response(self) -> None:
        payload = routeros_error_payload(
            RouterOSError("RouterOS is unavailable: private-router.example:8443 timed out")
        )
        self.assertEqual(payload["code"], "routeros.unavailable")
        self.assertNotIn("private-router.example", str(payload))
        self.assertNotIn("timed out", str(payload))

    def test_typed_failure_catalog_maps_to_safe_guidance(self) -> None:
        expected = {
            "tls": ("routeros.tls_untrusted", "trusted CA"),
            "timeout": ("routeros.timeout", "network reachability"),
            "invalid_response": ("routeros.invalid_response", "version compatibility"),
        }
        sensitive = (
            "router-password-marker",
            "bearer-token-marker",
            "private-key-marker",
            "vpn-profile-marker",
            "10.20.30.40",
            "router.example.invalid",
            "RouterOS raw response marker",
        )
        for failure_kind, (code, guidance_fragment) in expected.items():
            with self.subTest(failure_kind=failure_kind):
                error = RouterOSError(" ".join(sensitive), failure_kind=failure_kind)
                payload = routeros_error_payload(error)
                self.assertEqual(payload["code"], code)
                self.assertIn(guidance_fragment, payload["next_step"])
                self.assertEqual(set(payload), {"code", "error", "next_step"})
                serialized = str(payload)
                for marker in sensitive:
                    self.assertNotIn(marker, serialized)

    def test_unknown_failure_kind_keeps_generic_safe_fallback(self) -> None:
        payload = routeros_error_payload(RouterOSError("private exception marker", failure_kind="unrecognized"))
        self.assertEqual(payload["code"], "routeros.unavailable")
        self.assertNotIn("private exception marker", str(payload))

    def test_unexpected_routeros_shape_uses_safe_invalid_response_guidance(self) -> None:
        with self.assertRaises(RouterOSError) as caught:
            _records("router-record-marker")
        payload = routeros_error_payload(caught.exception)
        self.assertEqual(payload["code"], "routeros.invalid_response")
        self.assertNotIn("router-record-marker", str(payload))

    def test_router_api_classifies_tls_timeout_and_invalid_json_without_echoing(self) -> None:
        client = RouterOSClient("https://router.example.invalid")
        credentials = RouterOSCredentials("private-user", "private-password")
        cases = (
            (urllib.error.URLError(ssl.SSLCertVerificationError("private cert detail")), "tls"),
            (TimeoutError("private host timed out"), "timeout"),
        )
        for raised, expected_kind in cases:
            with self.subTest(expected_kind=expected_kind):
                with patch("routeros.urllib.request.urlopen", side_effect=raised):
                    with self.assertRaises(RouterOSError) as caught:
                        client._request("GET", "/system/resource", credentials)
                self.assertEqual(caught.exception.failure_kind, expected_kind)
                payload = routeros_error_payload(caught.exception)
                self.assertNotIn("private", str(payload))

        class InvalidJsonResponse:
            def __enter__(self):
                return self

            def __exit__(self, *_args):
                return False

            def read(self):
                return b"raw-router-data-marker"

        with patch("routeros.urllib.request.urlopen", return_value=InvalidJsonResponse()):
            with self.assertRaises(RouterOSError) as caught:
                client._request("GET", "/system/resource", credentials)
        self.assertEqual(caught.exception.failure_kind, "invalid_response")
        payload = routeros_error_payload(caught.exception)
        self.assertEqual(payload["code"], "routeros.invalid_response")
        self.assertNotIn("raw-router-data-marker", str(payload))


if __name__ == "__main__":
    unittest.main()
