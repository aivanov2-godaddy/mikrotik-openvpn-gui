from __future__ import annotations

import base64
import contextlib
import csv
import hashlib
import http.client
import io
import inspect
import json
import re
import sqlite3
import tempfile
import threading
import time
import unittest
import urllib.parse
import zipfile
from http import HTTPStatus
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from app import AppContext, DashboardHandler, DashboardServer, ProfileShareStore, RedirectHandler, _certificate_remaining_seconds, _origin_header_relation, container_image_target, operations_timeline, resolve_client_ip, service_health_snapshot
from config import RuntimeConfig
from routeros import RouterOSClient, RouterOSCredentials, RouterOSError
from routeros_binary import RouterOSReply
from security import (
    LIVE_STREAM_ROLE_REVALIDATION_SECONDS,
    LoginRateLimiter,
    SessionStore,
    has_capability,
)
from store import MetadataStore
from templates import ASSET_VERSION, _asset_version, _page, dashboard_page, evaluate_device_posture
from telemetry_socketio_polling import SocketIOPollingBridge
from tests.mock_routeros import MockRouterOS


def test_runtime_config() -> RuntimeConfig:
    return RuntimeConfig.from_environ(
        {
            "PUBLIC_ORIGIN": "https://dashboard.example.test",
            "ROUTEROS_REST_URL": "https://router.example.test:8443/rest",
            "OVPN_PPP_PROFILE": "vpn-full-tunnel",
            "OVPN_SERVER_NAME": "vpn-server",
            "OVPN_CA_NAME": "vpn-ca",
            "OVPN_HOST": "vpn.example.test",
            "VPN_LAN_CIDR": "192.0.2.0/24",
            "VPN_ROUTER_DNS": "192.0.2.1",
            "ROUTER_DISPLAY_NAME": "router.example.test",
        }
    )


class EmailValidationTests(unittest.TestCase):
    def test_email_validation_accepts_normalized_ascii_and_idn_addresses(self) -> None:
        self.assertEqual(DashboardHandler._validate_email(" Alice+vpn@Example.TEST "), "alice+vpn@example.test")
        self.assertEqual(DashboardHandler._validate_email("owner@bücher.example"), "owner@bücher.example")

    def test_email_validation_rejects_invalid_and_adversarial_shapes(self) -> None:
        invalid = (
            "",
            "missing-at.example",
            "two@@example.test",
            "user@invalid",
            "user@.example.test",
            "user@example..test",
            "user@-example.test",
            "user@example-.test",
            "user name@example.test",
            "a@" + "a." * 126,
            "a@" + "a" * 253,
        )
        for address in invalid:
            with self.subTest(address_length=len(address)):
                with self.assertRaisesRegex(ValueError, "valid email"):
                    DashboardHandler._validate_email(address)


class ResponseHeaderValidationTests(unittest.TestCase):
    def test_extra_header_controls_are_rejected_before_response_bytes(self) -> None:
        for extra in (
            {"X-Test": "safe\r\nX-Injected: yes"},
            {"X-Test\r\nX-Injected": "yes"},
        ):
            handler = DashboardHandler.__new__(DashboardHandler)
            handler._session_touch_candidate = None
            handler.send_response = mock.Mock()
            handler.send_header = mock.Mock()
            handler.end_headers = mock.Mock()
            with self.subTest(extra=extra), self.assertRaisesRegex(ValueError, "Invalid response header"):
                handler._headers(200, "text/plain; charset=utf-8", 0, extra=extra)
            handler.send_response.assert_not_called()
            handler.send_header.assert_not_called()

    def test_final_header_write_strips_line_breaks_as_defense_in_depth(self) -> None:
        handler = DashboardHandler.__new__(DashboardHandler)
        handler._session_touch_candidate = None
        handler.send_response = mock.Mock()
        handler.send_header = mock.Mock()
        handler.end_headers = mock.Mock()
        unsafe_extra = {"X-Test": "safe\r\nX-Injected: yes"}

        with mock.patch("app._validated_response_headers", return_value=list(unsafe_extra.items())):
            handler._headers(200, "text/plain; charset=utf-8", 0, extra=unsafe_extra)

        handler.send_header.assert_any_call("X-Test", "safeX-Injected: yes")
        self.assertFalse(any("\r" in call.args[1] or "\n" in call.args[1] for call in handler.send_header.call_args_list))


class ContainerImageTargetTests(unittest.TestCase):
    def test_supported_router_architectures_map_to_published_suffixes(self) -> None:
        self.assertEqual(container_image_target("arm64")["image_suffix"], "arm64")
        self.assertEqual(container_image_target("amd64")["image_suffix"], "amd64")
        self.assertEqual(container_image_target("x86")["image_suffix"], "amd64")

    def test_unknown_architecture_is_a_hard_stop(self) -> None:
        result = container_image_target("arm")
        self.assertFalse(result["supported"])
        self.assertEqual(result["status"], "fail")
        self.assertIsNone(result["image_suffix"])


class OriginHeaderRelationTests(unittest.TestCase):
    def test_origin_header_relation_returns_only_bounded_classes(self) -> None:
        expected = "https://dashboard.example.test"
        cases = (
            ([], False, "absent"),
            ([], True, "absent"),
            (["https://dashboard.example.test", "https://attacker.example"], False, "duplicate"),
            (["https://dashboard.example.test/a", "https://attacker.example/b"], True, "duplicate"),
            (["null"], False, "null"),
            ([" null "], False, "null"),
            (["HTTPS://DASHBOARD.EXAMPLE.TEST:443"], False, "same"),
            (["https://dashboard.example.test "], False, "other"),
            (["https://attacker.example"], False, "other"),
            (["not an origin"], False, "invalid"),
            (["https://dashboard.example.test:invalid"], False, "invalid"),
            (["https://dashboard.example.test/private?secret=fixture"], True, "same"),
            (["https://attacker.example/private?secret=fixture"], True, "other"),
            (["not a referer"], True, "invalid"),
        )

        for values, is_referer, expected_relation in cases:
            with self.subTest(values=len(values), is_referer=is_referer):
                self.assertEqual(
                    _origin_header_relation(values, expected, referer=is_referer),
                    expected_relation,
                )


class StaticAssetVersionTests(unittest.TestCase):
    def test_asset_version_changes_when_a_versioned_asset_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary_directory:
            static_dir = Path(temporary_directory)
            for name in ("app.css", "app.js", "manifest.webmanifest", "openvpn-logo.svg", "socket.io.min.js"):
                (static_dir / name).write_bytes(name.encode("utf-8"))

            original_version = _asset_version(static_dir)
            (static_dir / "app.js").write_bytes(b"changed application bundle")

            self.assertNotEqual(original_version, _asset_version(static_dir))

    def test_asset_version_is_used_by_dashboard_asset_urls(self) -> None:
        self.assertRegex(ASSET_VERSION, r"^[0-9a-f]{16}$")
        page = _page("test", "", script=True)
        self.assertIn(f"/static/app.js?v={ASSET_VERSION}", page)


class CertificateExpiryParsingTests(unittest.TestCase):
    def test_routeros_relative_expiry_time_is_parsed_strictly(self) -> None:
        self.assertEqual(
            _certificate_remaining_seconds("2w3d4h5m6s"),
            (2 * 7 * 86400) + (3 * 86400) + (4 * 3600) + (5 * 60) + 6,
        )
        self.assertEqual(_certificate_remaining_seconds("0s"), 0)
        self.assertEqual(_certificate_remaining_seconds("-1s"), -1)
        self.assertIsNone(_certificate_remaining_seconds("2h3d"))


class ProfileShareStoreTests(unittest.TestCase):
    def test_profile_download_link_expires_at_its_advertised_deadline(self) -> None:
        shares = ProfileShareStore()
        with mock.patch("app.time.time", return_value=1_000):
            token, ttl = shares.put(b"synthetic-profile", "user-device.zip")

        self.assertEqual(ttl, 600)
        with mock.patch("app.time.time", return_value=1_599):
            available = shares.take(token)
        self.assertIsNotNone(available)
        self.assertEqual(available.payload, b"synthetic-profile")

        with mock.patch("app.time.time", return_value=1_600):
            self.assertIsNone(shares.take(token))


class OperationsTimelineTests(unittest.TestCase):
    def test_sensitive_timeline_fields_match_the_allowlisted_contract(self) -> None:
        result = operations_timeline(
            [{"id": 7, "created_at": 98, "actor": "operator", "action": "user.update", "target": "alice", "status": "success", "details": {"password": "must-not-escape"}}],
            [{"id": 4, "created_at": 99, "version": "1.2.3", "revision": "abc", "status": "running", "channel": "canary", "details": {"token": "must-not-escape"}}],
            [{"id": 8, "created_at": 100, "overall": "healthy", "healthy_count": 3, "warning_count": 0, "unavailable_count": 0, "checks": [{"private": "must-not-escape"}]}],
            integrations=[{"source_id": 7, "event_type": "audit", "created_at": 99, "delivered_at": 101, "attempts": 1, "payload": "must-not-escape"}],
            connections=[{"id": 12, "vpn_user": "alice", "connected_at": 100, "disconnected_at": 0, "session_id": "must-not-escape", "source_address": "192.0.2.8"}],
            now=110,
        )

        self.assertEqual(set(result), {"events", "generated_at", "coverage"})
        self.assertEqual(set(result["coverage"]), {"complete", "message"})
        expected_event_fields = {
            "id", "occurred_at", "source", "type", "actor", "target", "outcome",
            "severity", "summary", "clock_skew_seconds", "age_seconds", "related_events",
            "relationship_summary",
        }
        event_types = {item["type"] for item in result["events"]}
        self.assertEqual(event_types, {"change", "deployment", "health", "integration", "session"})
        for event in result["events"]:
            expected = expected_event_fields | ({"timestamp_quality"} if event["type"] == "session" else set())
            self.assertEqual(set(event), expected, event["type"])
            for relation in event["related_events"]:
                self.assertEqual(set(relation), {"event_id", "source", "relation", "delta_seconds"})
        serialized = json.dumps(result)
        for forbidden in ("must-not-escape", "192.0.2.8", "session_id", "source_address", "payload", "details"):
            self.assertNotIn(forbidden, serialized)

    def test_session_rows_are_redacted_and_linked_as_noncausal_context(self) -> None:
        result = operations_timeline(
            [{"id": 7, "created_at": 98, "actor": "operator", "action": "user.update", "target": "alice", "status": "success"}],
            [], [],
            connections=[{"id": 12, "vpn_user": "alice", "connected_at": 100, "disconnected_at": 0,
                          "session_id": "private-session", "source_address": "192.0.2.8"}],
            now=110,
        )
        session = next(item for item in result["events"] if item["type"] == "session")
        self.assertEqual(session["timestamp_quality"], "uptime-derived")
        self.assertIn("not proof of cause", session["relationship_summary"])
        self.assertNotIn("private-session", json.dumps(result))
        self.assertNotIn("192.0.2.8", json.dumps(result))
        without_sessions = operations_timeline([], [], [], now=110)
        self.assertFalse(without_sessions["coverage"]["complete"])
        self.assertNotIn("Session starts", without_sessions["coverage"]["message"])

    def test_audit_delivery_and_session_context_are_linked_without_payloads(self) -> None:
        result = operations_timeline(
            [{"id": 7, "created_at": 98, "actor": "operator", "action": "user.update", "target": "alice", "status": "success"}],
            [], [], integrations=[{"source_id": 7, "event_type": "audit", "created_at": 99, "delivered_at": 100, "attempts": 1}],
            connections=[{"id": 12, "vpn_user": "alice", "connected_at": 100}], now=110,
        )
        audit = next(item for item in result["events"] if item["type"] == "change")
        self.assertEqual({item["relation"] for item in audit["related_events"]}, {"same-account-near-time", "delivery-status"})

    def test_related_events_render_as_accessible_links_to_redacted_rows(self) -> None:
        result = operations_timeline(
            [{"id": 7, "created_at": 98, "actor": "operator", "action": "user.update", "target": "alice", "status": "success", "details": {"password": "private-password"}}],
            [], [],
            integrations=[{"source_id": 7, "event_type": "audit", "created_at": 99, "delivered_at": 100, "attempts": 1, "payload": "private-payload"}],
            connections=[{"id": 12, "vpn_user": "alice", "connected_at": 100, "session_id": "private-session", "source_address": "192.0.2.8"}],
            now=110,
        )
        page = dashboard_page(
            actor="operator", csrf="csrf", users=[], sessions=[], admin_sessions=[], devices=[],
            connections=[], connection_summaries={}, certificates=[], profile_migrations={},
            current_ca="", ovpn_server={}, warnings=[], audit=[], alerts=[],
            policy_templates=[], admin_role="owner", router={}, health={},
            observability={"operations_timeline": result},
        )

        targets = re.findall(r'<a class="operation-related-link"[^>]*href="#([^"]+)"', page)
        self.assertEqual(len(targets), 4)
        for target in targets:
            self.assertRegex(page, rf'<tr id="{re.escape(target)}" tabindex="-1" data-operation-row')
        self.assertIn('aria-label="Related events"', page)
        self.assertIn('aria-label="View related event:', page)
        self.assertNotIn("private-password", page)
        self.assertNotIn("private-payload", page)
        self.assertNotIn("private-session", page)
        self.assertNotIn("192.0.2.8", page)

    def test_join_is_ordered_redacted_and_explicitly_incomplete(self) -> None:
        result = operations_timeline(
            [{
                "created_at": 90, "actor": "owner", "action": "user.create",
                "target": "alice", "status": "success", "details": '{"password":"secret"}',
            }],
            [{
                "id": 4, "created_at": 95, "version": "1.2.3", "revision": "abc",
                "status": "running", "channel": "canary", "details": '{"token":"secret"}',
            }],
            [{
                "id": 8, "created_at": 100, "overall": "warning", "healthy_count": 3,
                "warning_count": 1, "unavailable_count": 0, "checks": '["private"]',
            }],
            now=110,
        )
        self.assertEqual([item["source"] for item in result["events"]], [
            "health checks", "deployment ledger", "dashboard audit",
        ])
        self.assertEqual([item["age_seconds"] for item in result["events"]], [10, 15, 20])
        self.assertEqual(result["events"][-1]["type"], "change")
        self.assertFalse(result["coverage"]["complete"])
        serialized = json.dumps(result)
        self.assertNotIn("secret", serialized)
        self.assertNotIn("private", serialized)

    def test_audit_event_identity_is_stable_when_newer_rows_arrive(self) -> None:
        original = {
            "id": 42, "created_at": 90, "actor": "owner", "action": "user.create",
            "target": "alice", "status": "success",
        }
        before = operations_timeline([original], [], [], now=100)["events"][0]["id"]
        after = operations_timeline([
            {"id": 43, "created_at": 95, "actor": "owner", "action": "user.update", "target": "bob", "status": "success"},
            original,
        ], [], [], now=100)["events"][1]["id"]

        self.assertEqual(before, "audit:42")
        self.assertEqual(after, before)

    def test_future_timestamps_are_flagged_as_clock_skew_not_fresh(self) -> None:
        result = operations_timeline(
            [{"id": 17, "created_at": 115, "actor": "operator", "action": "user.update", "target": "alice", "status": "success"}],
            [], [], now=100,
        )

        event = result["events"][0]
        self.assertEqual(event["age_seconds"], 0)
        self.assertEqual(event["clock_skew_seconds"], 15)
        page = dashboard_page(
            actor="operator", csrf="csrf", users=[], sessions=[], admin_sessions=[], devices=[],
            connections=[], connection_summaries={}, certificates=[], profile_migrations={},
            current_ca="", ovpn_server={}, warnings=[], audit=[], alerts=[],
            policy_templates=[], admin_role="owner", router={}, health={},
            observability={"operations_timeline": result},
        )
        self.assertIn("Timestamp 15s in the future · check clock", page)
        self.assertNotIn("0s ago", page)

    def test_integration_delivery_events_are_bounded_redacted_and_status_only(self) -> None:
        result = operations_timeline(
            [], [], [],
            integrations=[
                {"source_id": 8, "event_type": "audit", "created_at": 90, "attempts": 2},
                {"source_id": 9, "event_type": "audit", "created_at": 91, "delivered_at": 95, "attempts": 1,
                 "event_id": "private-event-id", "payload": "private payload"},
                {"source_id": 10, "event_type": "other", "created_at": 96, "attempts": 1},
            ],
            now=100,
        )
        self.assertEqual([event["id"] for event in result["events"]], ["integration:9", "integration:8"])
        self.assertEqual([event["outcome"] for event in result["events"]], ["delivered", "pending"])
        self.assertIn("integration-delivery", result["coverage"]["message"])
        serialized = json.dumps(result)
        self.assertNotIn("private-event-id", serialized)
        self.assertNotIn("private payload", serialized)


class DevicePostureTests(unittest.TestCase):
    def test_posture_requires_present_non_revoked_certificate_from_current_ca(self) -> None:
        devices = [
            {
                "id": "approved", "certificate_name": "client-current",
                "certificate_id": "*CURRENT", "fingerprint": "AA:BB",
            },
            {"id": "missing", "certificate_name": "client-missing"},
            {
                "id": "revoked", "certificate_name": "client-revoked",
                "certificate_id": "*REVOKED", "fingerprint": "CC:DD",
            },
            {
                "id": "legacy", "certificate_name": "client-legacy",
                "certificate_id": "*LEGACY", "fingerprint": "EE:FF",
            },
            {
                "id": "unknown-issuer", "certificate_name": "client-unknown",
                "certificate_id": "*UNKNOWN", "fingerprint": "11:22",
            },
        ]
        certificates = [
            {
                "id": "*CURRENT", "name": "client-current", "fingerprint": "aa:bb",
                "certificate_authority": "vpn-ca", "revoked": False,
                "expires_after": "260w",
            },
            {
                "id": "*REVOKED", "name": "client-revoked", "fingerprint": "cc:dd",
                "certificate_authority": "vpn-ca", "revoked": True,
            },
            {
                "id": "*LEGACY", "name": "client-legacy", "fingerprint": "ee:ff",
                "certificate_authority": "old-ca", "revoked": False,
            },
            {
                "id": "*UNKNOWN", "name": "client-unknown", "fingerprint": "11:22",
                "revoked": False,
            },
        ]

        result = evaluate_device_posture(devices, certificates, "vpn-ca")

        self.assertEqual([item["state"] for item in result], ["approved", "warning", "revoked", "warning", "warning"])
        self.assertEqual(result[0]["label"], "Inventory match")
        self.assertIn("not present", result[1]["reason"])
        self.assertIn("revoked", result[2]["reason"])
        self.assertIn("old-ca", result[3]["reason"])
        self.assertIn("unknown CA", result[4]["reason"])

    def test_posture_requires_matching_routeros_id_and_fingerprint(self) -> None:
        devices = [
            {
                "id": "replaced", "certificate_name": "same-name-replaced",
                "certificate_id": "*OLD", "fingerprint": "AA:BB",
            },
            {
                "id": "changed-fingerprint", "certificate_name": "same-id-changed-fingerprint",
                "certificate_id": "*STABLE", "fingerprint": "AA:BB",
            },
            {"id": "missing-identity", "certificate_name": "identity-not-recorded"},
        ]
        certificates = [
            {
                "id": "*NEW", "name": "same-name-replaced", "fingerprint": "AA:BB",
                "certificate_authority": "vpn-ca", "revoked": False,
                "expires_after": "260w",
            },
            {
                "id": "*STABLE", "name": "same-id-changed-fingerprint", "fingerprint": "CC:DD",
                "certificate_authority": "vpn-ca", "revoked": False,
                "expires_after": "260w",
            },
            {
                "id": "*IDENTITY", "name": "identity-not-recorded", "fingerprint": "EE:FF",
                "certificate_authority": "vpn-ca", "revoked": False,
                "expires_after": "260w",
            },
        ]

        result = evaluate_device_posture(devices, certificates, "vpn-ca")

        self.assertEqual([item["state"] for item in result], ["warning", "warning", "warning"])
        self.assertTrue(all(item["label"] == "Needs review" for item in result))
        self.assertTrue(all("ID or fingerprint" in item["reason"] for item in result))

    def test_posture_marks_expired_expiring_and_unknown_certificates_for_review(self) -> None:
        now = int(time.mktime(time.strptime("2030-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")))
        devices = [
            {"id": "expired", "certificate_name": "expired-cert"},
            {"id": "soon", "certificate_name": "soon-cert"},
            {"id": "unknown", "certificate_name": "unknown-cert"},
            {
                "id": "valid", "certificate_name": "valid-cert",
                "certificate_id": "*VALID", "fingerprint": "AA:BB",
            },
        ]
        certificates = [
            {"name": "expired-cert", "certificate_authority": "vpn-ca", "revoked": False, "expires_after": "0s"},
            {"name": "soon-cert", "certificate_authority": "vpn-ca", "revoked": False, "expires_after": "2w"},
            {"name": "unknown-cert", "certificate_authority": "vpn-ca", "revoked": False},
            {"id": "*VALID", "name": "valid-cert", "fingerprint": "aa:bb", "certificate_authority": "vpn-ca", "revoked": False, "expires_after": "40w"},
        ]

        result = evaluate_device_posture(devices, certificates, "vpn-ca", now=now)

        self.assertEqual([item["state"] for item in result], ["expired", "warning", "warning", "approved"])
        self.assertEqual(result[1]["label"], "Expiring soon")
        self.assertIn("unavailable or unparseable", result[2]["reason"])
        self.assertIn("live rejection was not tested", result[3]["reason"])

    def test_posture_does_not_approve_when_current_ca_is_unavailable(self) -> None:
        result = evaluate_device_posture(
            [{"id": "client", "certificate_name": "client"}],
            [{"name": "client", "certificate_authority": "vpn-ca", "revoked": False}],
            "",
        )

        self.assertEqual(result[0]["state"], "warning")
        self.assertIn("cannot be verified", result[0]["reason"])


class DashboardIntegrationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.mock = MockRouterOS()
        self.mock.__enter__()
        self.config = test_runtime_config()
        context = AppContext(
            router=RouterOSClient(self.mock.url, topology=self.config.topology),
            store=MetadataStore(str(Path(self.temporary.name) / "dashboard.sqlite")),
            sessions=SessionStore(),
            limiter=LoginRateLimiter(),
            config=self.config,
            release_version="1.2.3",
            release_revision="0123456789abcdef",
        )
        self.server = DashboardServer(("127.0.0.1", 0), context)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.cookie = ""
        self.csrf = ""

    def tearDown(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=2)
        self.mock.__exit__(None, None, None)
        self.temporary.cleanup()

    def request(
        self,
        method: str,
        path: str,
        *,
        body: bytes = b"",
        headers: dict[str, str] | None = None,
    ) -> tuple[int, dict[str, str], bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        outgoing = dict(headers or {})
        if self.cookie:
            outgoing.setdefault("Cookie", self.cookie)
        connection.request(method, path, body=body, headers=outgoing)
        response = connection.getresponse()
        payload = response.read()
        result = response.status, {key.lower(): value for key, value in response.getheaders()}, payload
        connection.close()
        return result

    def raw_request(
        self,
        method: str,
        path: str,
        headers: list[tuple[str, str]],
        *,
        body: bytes = b"",
    ) -> tuple[int, bytes]:
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        connection.putrequest(method, path)
        if self.cookie:
            connection.putheader("Cookie", self.cookie)
        for name, value in headers:
            connection.putheader(name, value)
        if body:
            connection.putheader("Content-Length", str(len(body)))
        connection.endheaders(body if body else None)
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        connection.close()
        return status, payload

    def login(self) -> None:
        body = urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode()
        status, headers, payload = self.request(
            "POST",
            "/login",
            body=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.config.public_origin,
            },
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["location"], "/dashboard")
        set_cookie = headers["set-cookie"]
        self.assertTrue(set_cookie.startswith("__Host-vpn_session="))
        self.assertIn("Path=/", set_cookie)
        self.assertNotIn("Domain=", set_cookie)
        self.assertIn("Secure", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)
        self.assertLess(len(set_cookie.split(";", 1)[0].encode("ascii")), 4096)
        cookie_value = set_cookie.split("=", 1)[1].split(";", 1)[0]
        self.assertNotIn(cookie_value.encode("ascii"), payload)
        self.cookie = set_cookie.split(";", 1)[0]

        status, headers, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn("default-src 'self'", headers["content-security-policy"])
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        match = re.search(rb'<meta name="csrf-token" content="([^"]+)">', page)
        self.assertIsNotNone(match)
        self.csrf = match.group(1).decode("ascii")

    def test_login_rejects_foreign_or_missing_origin_before_routeros_authentication(self) -> None:
        body = urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode()
        cases = (
            {"Origin": "https://attacker.example", "Referer": f"{self.config.public_origin}/login"},
            {},
        )
        for headers in cases:
            with self.subTest(headers=headers), mock.patch.object(
                self.server.context.router, "verify_credentials",
            ) as verify_credentials:
                status, response_headers, page = self.request(
                    "POST", "/login", body=body,
                    headers={"Content-Type": "application/x-www-form-urlencoded", **headers},
                )
                self.assertEqual(status, 403)
                self.assertNotIn("set-cookie", response_headers)
                self.assertIn(b"origin could not be verified", page)
                verify_credentials.assert_not_called()

    def test_login_rejects_duplicate_origin_and_fallback_referer_headers(self) -> None:
        body = urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode()
        duplicate_header_cases = (
            (
                ("Origin", self.config.public_origin),
                ("Origin", "https://attacker.example"),
            ),
            (
                ("Origin", "null"),
                ("Referer", f"{self.config.public_origin}/login"),
                ("Referer", "https://attacker.example/login"),
            ),
        )
        for headers in duplicate_header_cases:
            with self.subTest(headers=headers), mock.patch.object(
                self.server.context.router, "verify_credentials",
            ) as verify_credentials:
                connection = http.client.HTTPConnection(
                    "127.0.0.1", self.server.server_port, timeout=5,
                )
                connection.putrequest("POST", "/login")
                connection.putheader("Content-Type", "application/x-www-form-urlencoded")
                connection.putheader("Content-Length", str(len(body)))
                for name, value in headers:
                    connection.putheader(name, value)
                connection.endheaders(body)
                response = connection.getresponse()
                payload = response.read()
                status = response.status
                response_headers = {name.casefold() for name, _ in response.getheaders()}
                connection.close()

                self.assertEqual(status, 403, payload.decode())
                self.assertNotIn("set-cookie", response_headers)
                self.assertIn(b"origin could not be verified", payload)
                verify_credentials.assert_not_called()

    def test_login_accepts_same_origin_referer_when_origin_is_absent(self) -> None:
        body = urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode()
        status, headers, _ = self.request(
            "POST", "/login", body=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": f"{self.config.public_origin}/login",
            },
        )
        self.assertEqual(status, 303)
        self.assertIn("__Host-vpn_session=", headers["set-cookie"])

    def test_login_accepts_null_origin_only_with_same_origin_referer(self) -> None:
        body = urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode()
        status, headers, _ = self.request(
            "POST", "/login", body=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "null",
                "Referer": f"{self.config.public_origin}/login",
            },
        )
        self.assertEqual(status, 303)
        self.assertIn("__Host-vpn_session=", headers["set-cookie"])

    def test_legacy_unprefixed_session_cookie_is_not_accepted(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]

        status, _, payload = self.request(
            "GET",
            "/api/telemetry",
            headers={"Cookie": f"vpn_session={session_id}"},
        )

        self.assertEqual(status, 401, payload.decode())

    def test_login_page_uses_same_origin_referrer_policy_for_form_submission(self) -> None:
        status, headers, page = self.request("GET", "/login")
        self.assertEqual(status, 200)
        self.assertEqual(headers["referrer-policy"], "same-origin")
        self.assertNotIn("set-cookie", headers)
        self.assertIn(b'<form method="post" action="/login"', page)
        self.assertIn(b'<button class="primary" type="submit">Connect</button>', page)

    def test_dashboard_uses_same_origin_referrer_policy_for_originless_live_polling(self) -> None:
        self.login()
        status, headers, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertEqual(headers["referrer-policy"], "same-origin")
        self.assertIn(b"Live ", page)

    def test_login_session_cookie_has_required_host_security_and_size_properties(self) -> None:
        body = urllib.parse.urlencode(
            {"username": "admin", "password": "routerpass"}
        ).encode()
        status, headers, payload = self.request(
            "POST",
            "/login",
            body=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.config.public_origin,
            },
        )

        self.assertEqual(status, 303)
        set_cookie = headers["set-cookie"]
        self.assertTrue(set_cookie.startswith("__Host-vpn_session="))
        self.assertIn("Path=/", set_cookie)
        self.assertNotIn("Domain=", set_cookie)
        self.assertIn("Secure", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)
        cookie_pair = set_cookie.split(";", 1)[0]
        self.assertLess(len(cookie_pair.encode("ascii")), 4096)
        self.assertNotIn(cookie_pair.split("=", 1)[1].encode("ascii"), payload)

    def test_login_audit_transaction_failure_does_not_create_or_issue_session(self) -> None:
        self.server.context.store._audit_hook = lambda _event: None
        with self.server.context.store._connection() as connection:
            connection.execute(
                """
                CREATE TRIGGER fail_role_audit BEFORE INSERT ON audit
                WHEN NEW.action = 'routeros.role.verified'
                BEGIN
                    SELECT RAISE(ABORT, 'injected audit failure');
                END;
                """
            )

        status, headers, payload = self.request(
            "POST",
            "/login",
            body=urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.config.public_origin,
            },
        )

        self.assertEqual(status, 503, payload.decode())
        self.assertNotIn("set-cookie", headers)
        self.assertNotIn(b"injected audit failure", payload)
        self.assertEqual(self.server.context.sessions.active(), [])
        with self.server.context.store._connection() as connection:
            self.assertEqual(connection.execute("SELECT COUNT(*) FROM audit").fetchone()[0], 0)
            self.assertEqual(
                connection.execute("SELECT COUNT(*) FROM integration_outbox").fetchone()[0], 0
            )

        with self.server.context.store._connection() as connection:
            connection.execute("DROP TRIGGER fail_role_audit")
        self.login()
        self.assertEqual(len(self.server.context.sessions.active()), 1)

    def test_login_failure_audit_error_returns_sanitized_service_unavailable(self) -> None:
        with self.server.context.store._connection() as connection:
            connection.execute(
                """
                CREATE TRIGGER fail_login_failure BEFORE INSERT ON audit
                WHEN NEW.action = 'login.failure'
                BEGIN
                    SELECT RAISE(ABORT, 'injected audit failure');
                END;
                """
            )

        status, headers, payload = self.request(
            "POST",
            "/login",
            body=urllib.parse.urlencode({"username": "admin", "password": "wrong"}).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.config.public_origin,
            },
        )

        self.assertEqual(status, 503)
        self.assertNotIn("set-cookie", headers)
        self.assertNotIn(b"injected audit failure", payload)
        self.assertEqual(self.server.context.sessions.active(), [])

    def test_login_rate_limit_audit_error_returns_sanitized_service_unavailable(self) -> None:
        with self.server.context.store._connection() as connection:
            connection.execute(
                """
                CREATE TRIGGER fail_login_rate_limited BEFORE INSERT ON audit
                WHEN NEW.action = 'login.rate_limited'
                BEGIN
                    SELECT RAISE(ABORT, 'injected audit failure');
                END;
                """
            )

        with mock.patch.object(self.server.context.limiter, "reserve", return_value=None):
            status, headers, payload = self.request(
                "POST",
                "/login",
                body=urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode(),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": self.config.public_origin,
                },
            )

        self.assertEqual(status, 503)
        self.assertNotIn("set-cookie", headers)
        self.assertNotIn(b"injected audit failure", payload)
        self.assertEqual(self.server.context.sessions.active(), [])

    def test_access_logs_omit_bearer_share_tokens_and_peer_addresses(self) -> None:
        token = "x" * 40
        captured = io.StringIO()
        with contextlib.redirect_stdout(captured):
            status, _, _ = self.request("GET", f"/share/{token}")
        self.assertEqual(status, 410)
        output = captured.getvalue()
        self.assertIn("http method=GET status=410", output)
        self.assertNotIn(token, output)
        self.assertNotIn("127.0.0.1", output)

    def test_sensitive_exports_disclose_their_real_data_scope(self) -> None:
        self.login()
        self.server.context.store.observe_sessions([{
            "id": "synthetic-router-session-id",
            "name": "synthetic-export-user",
            "source_address": "203.0.113.77",
            "vpn_address": "10.8.0.77",
            "encoding": "AES-256-GCM/test-only",
            "uptime": "0s",
            "rx_bytes": 123,
            "tx_bytes": 456,
            "rx_packets": 2,
            "tx_packets": 3,
        }])
        self.server.context.store.audit(
            actor="synthetic-operator", action="synthetic.audit.export-test",
            target="synthetic-export-user", status="success",
            details={"source": "203.0.113.88"},
        )

        status, _, observability_payload = self.request("GET", "/api/observability")
        self.assertEqual(status, 200)
        observability = json.loads(observability_payload)
        self.assertEqual(
            set(observability),
            {"current", "deployments", "health_timeline", "operations_timeline", "rollback", "generated_at"},
        )
        self.assertEqual(set(observability["current"]), {"version", "revision", "status"})
        self.assertEqual(
            set(observability["rollback"]),
            {"available", "revision", "version", "message", "data_preserved"},
        )
        self.assertEqual(set(observability["operations_timeline"]), {"events", "generated_at", "coverage"})

        status, _, connection_csv = self.request("GET", "/api/connections.csv")
        self.assertEqual(status, 200)
        self.assertIn(b"source_ip,vpn_ip", connection_csv)
        self.assertIn(b"203.0.113.77", connection_csv)
        self.assertIn(b"10.8.0.77", connection_csv)
        self.assertNotIn(b"synthetic-router-session-id", connection_csv)

        status, _, compliance = self.request("GET", "/api/reports/compliance.zip")
        self.assertEqual(status, 200)
        with zipfile.ZipFile(io.BytesIO(compliance)) as archive:
            compliance_summary = json.loads(archive.read("summary.json"))
            compliance_audit = archive.read("audit.csv")
            compliance_csv = archive.read("connections.csv")
        self.assertEqual(
            set(compliance_summary),
            {"format", "version", "generated_at", "range", "counts", "redaction"},
        )
        self.assertEqual(set(compliance_summary["range"]), {"from", "to"})
        self.assertEqual(
            set(compliance_summary["counts"]),
            {"audit_entries", "connection_entries", "failed_audit_entries"},
        )
        self.assertEqual(
            next(csv.reader(io.StringIO(compliance_audit.decode("utf-8-sig")))),
            ["timestamp", "operator", "action", "target", "result", "details"],
        )
        self.assertEqual(
            next(csv.reader(io.StringIO(compliance_csv.decode("utf-8-sig")))),
            ["user", "connected", "disconnected", "source_ip", "vpn_ip", "encryption",
             "received_bytes", "sent_bytes"],
        )
        self.assertIn("source_ip", compliance_csv.decode("utf-8"))
        self.assertIn(b"203.0.113.77", compliance_csv)
        self.assertIn(b"10.8.0.77", compliance_csv)
        self.assertIn("operator/client/VPN IP addresses", compliance_summary["redaction"])
        self.assertIn(b"203.0.113.88", compliance_audit)

        status, _, backup = self.request("GET", "/api/backups/metadata.zip")
        self.assertEqual(status, 200)
        with zipfile.ZipFile(io.BytesIO(backup)) as archive:
            backup_manifest = json.loads(archive.read("manifest.json"))
            metadata = json.loads(archive.read("metadata.json"))
        history = metadata["tables"]["connection_history"]
        row = next(item for item in history if item["session_id"] == "synthetic-router-session-id")
        self.assertEqual(row["source_address"], "203.0.113.77")
        self.assertEqual(row["vpn_address"], "10.8.0.77")
        self.assertIn("session identifiers", backup_manifest["contains"])
        self.assertIn("203.0.113.88", json.dumps(metadata))
        self.assertNotIn("routerpass", json.dumps(metadata))
        self.assertNotIn("PRIVATE KEY", json.dumps(metadata))

    def test_socketio_polling_rejects_foreign_origin_before_handshake(self) -> None:
        self.login()
        calls: list[str] = []

        class Bridge:
            def handshake(self, session_id: str) -> tuple[str, str]:
                calls.append(session_id)
                return "test-sid", "0{}"

        self.server.socketio_bridge = Bridge()
        status, _, _ = self.request(
            "GET",
            "/socket.io/?EIO=4&transport=polling",
            headers={"Origin": "https://attacker.example"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(calls, [])

    def test_socketio_polling_accepts_configured_origin_and_default_port(self) -> None:
        self.login()
        calls: list[str] = []

        class Bridge:
            def handshake(self, session_id: str) -> tuple[str, str]:
                calls.append(session_id)
                return "test-sid", "0{}"

        self.server.socketio_bridge = Bridge()
        status, _, body = self.request(
            "GET",
            "/socket.io/?EIO=4&transport=polling",
            headers={"Origin": "https://DASHBOARD.example.test:443"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"0{}")
        self.assertEqual(len(calls), 1)

    def test_socketio_polling_rejects_missing_origin_and_referer_before_handshake(self) -> None:
        self.login()
        calls: list[str] = []

        class Bridge:
            def handshake(self, session_id: str) -> tuple[str, str]:
                calls.append(session_id)
                return "test-sid", "0{}"

        self.server.socketio_bridge = Bridge()
        status, _, _ = self.request(
            "GET", "/socket.io/?EIO=4&transport=polling",
        )
        self.assertEqual(status, 403)
        self.assertEqual(calls, [])

    def test_socketio_polling_accepts_missing_origin_with_same_origin_referer(self) -> None:
        self.login()
        calls: list[str] = []

        class Bridge:
            def handshake(self, session_id: str) -> tuple[str, str]:
                calls.append(session_id)
                return "test-sid", "0{}"

        self.server.socketio_bridge = Bridge()
        status, _, body = self.request(
            "GET",
            "/socket.io/?EIO=4&transport=polling",
            headers={"Referer": f"{self.config.public_origin}/dashboard"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(body, b"0{}")
        self.assertEqual(len(calls), 1)

    def test_socketio_polling_rejects_missing_origin_with_foreign_referer(self) -> None:
        self.login()
        calls: list[str] = []

        class Bridge:
            def handshake(self, session_id: str) -> tuple[str, str]:
                calls.append(session_id)
                return "test-sid", "0{}"

        self.server.socketio_bridge = Bridge()
        status, _, _ = self.request(
            "GET",
            "/socket.io/?EIO=4&transport=polling",
            headers={"Referer": "https://attacker.example/"},
        )
        self.assertEqual(status, 403)
        self.assertEqual(calls, [])

    def test_socketio_polling_rejects_duplicate_referers_before_handshake(self) -> None:
        self.login()
        calls: list[str] = []

        class Bridge:
            def handshake(self, session_id: str) -> tuple[str, str]:
                calls.append(session_id)
                return "test-sid", "0{}"

        self.server.socketio_bridge = Bridge()
        referer = f"{self.config.public_origin}/dashboard"
        status, _ = self.raw_request(
            "GET",
            "/socket.io/?EIO=4&transport=polling",
            [("Referer", referer), ("Referer", referer)],
        )
        self.assertEqual(status, 403)
        self.assertEqual(calls, [])

    def test_socketio_polling_capacity_returns_retryable_service_unavailable(self) -> None:
        self.login()
        bridge = SocketIOPollingBridge(
            self.server.telemetry_runtime.gateway,
            self.server.telemetry_runtime.principal_for_session,
            max_clients=1,
        )
        self.server.socketio_bridge = bridge
        headers = {"Cookie": self.cookie, "Origin": self.config.public_origin}

        first_status, _, _ = self.request(
            "GET", "/socket.io/?EIO=4&transport=polling", headers=headers,
        )
        self.assertEqual(first_status, 200)

        status, response_headers, payload = self.request(
            "GET", "/socket.io/?EIO=4&transport=polling", headers=headers,
        )
        self.assertEqual(status, 503, payload.decode("utf-8"))
        self.assertEqual(response_headers.get("retry-after"), "1")
        self.assertEqual(len(bridge._clients), 1)
        self.assertEqual(bridge.gateway.client_count, 0)

    def test_socketio_polling_rejects_foreign_origin_before_post_dispatch(self) -> None:
        self.login()
        calls: list[tuple[str, str, bytes]] = []

        class Bridge:
            def post(self, sid: str, session_id: str, body: bytes) -> bool:
                calls.append((sid, session_id, body))
                return True

        self.server.socketio_bridge = Bridge()
        status, _, _ = self.request(
            "POST",
            "/socket.io/?EIO=4&transport=polling&sid=test-sid",
            body=b"40/telemetry,",
            headers={
                "Content-Type": "text/plain; charset=UTF-8",
                "Origin": "https://attacker.example",
            },
        )
        self.assertEqual(status, 403)
        self.assertEqual(calls, [])

    def test_socketio_polling_rejects_duplicate_origins_before_dispatch(self) -> None:
        self.login()
        calls: list[str] = []

        class Bridge:
            def handshake(self, _session_id: str) -> tuple[str, str]:
                calls.append("handshake")
                return "test-sid", "0{}"

            def post(self, _sid: str, _session_id: str, _body: bytes) -> bool:
                calls.append("post")
                return True

        self.server.socketio_bridge = Bridge()
        same_origin = self.config.public_origin
        foreign_origin = "https://attacker.example"
        cases = (
            ("GET", same_origin, foreign_origin, b"", []),
            ("GET", foreign_origin, same_origin, b"", []),
            ("GET", same_origin, same_origin, b"", []),
            (
                "POST",
                same_origin,
                foreign_origin,
                b"40/telemetry,",
                [("Content-Type", "text/plain; charset=UTF-8")],
            ),
            (
                "POST",
                foreign_origin,
                same_origin,
                b"40/telemetry,",
                [("Content-Type", "text/plain; charset=UTF-8")],
            ),
            (
                "POST",
                same_origin,
                same_origin,
                b"40/telemetry,",
                [("Content-Type", "text/plain; charset=UTF-8")],
            ),
        )
        for method, first, second, body, extra_headers in cases:
            path = "/socket.io/?EIO=4&transport=polling"
            if method == "POST":
                path += "&sid=test-sid"
            with self.subTest(method=method, first=first, second=second):
                status, payload = self.raw_request(
                    method,
                    path,
                    [*extra_headers, ("Origin", first), ("Origin", second)],
                    body=body,
                )
                self.assertEqual(status, 403, payload.decode())
                self.assertIn(b"origin", payload.lower())
                self.assertEqual(calls, [])

    def test_socketio_polling_requires_origin_on_post(self) -> None:
        self.login()
        self.server.socketio_bridge = object()
        status, _, _ = self.request(
            "POST",
            "/socket.io/?EIO=4&transport=polling&sid=test-sid",
            body=b"40/telemetry,",
            headers={"Content-Type": "text/plain; charset=UTF-8"},
        )
        self.assertEqual(status, 403)

    def json_request(
        self,
        method: str,
        path: str,
        value: dict[str, Any] | None = None,
        *,
        csrf: bool = True,
    ) -> tuple[int, dict[str, str], bytes]:
        headers = {"Content-Type": "application/json"}
        if csrf:
            headers["X-CSRF-Token"] = self.csrf
        return self.request(method, path, body=json.dumps(value or {}).encode(), headers=headers)

    def preview_user_suspend(self, user_id: str) -> dict[str, Any]:
        reason = "Quarterly VPN access review"
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/suspend/preview",
            {"reason": reason},
        )
        self.assertEqual(status, 200, payload.decode("utf-8"))
        return json.loads(payload)

    @staticmethod
    def user_suspend_apply(review: dict[str, Any], confirmation: str) -> dict[str, str]:
        return {
            "confirmation": confirmation,
            "reason": review["reason"],
            "review_token": review["review_token"],
        }

    def preview_user_restore(self, user_id: str) -> dict[str, Any]:
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/restore/preview", {},
        )
        self.assertEqual(status, 200, payload.decode("utf-8"))
        return json.loads(payload)

    def preview_profile(
        self, user_id: str, device_name: str, *, delivery: str = "zip", legacy_certificate: str = "",
    ) -> dict[str, Any]:
        reason = "Approved additional device access"
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/profiles/preview",
            {
                "device_name": device_name, "delivery": delivery,
                "legacy_certificate": legacy_certificate, "reason": reason,
            },
        )
        self.assertEqual(status, 200, payload.decode("utf-8"))
        return json.loads(payload)

    def preview_user_provision(
        self, data: dict[str, Any], *, source_id: str = "",
    ) -> dict[str, Any]:
        endpoint = (
            f"/api/users/{urllib.parse.quote(source_id, safe='*')}/duplicate/preview"
            if source_id else "/api/users/preview"
        )
        status, _, payload = self.json_request("POST", endpoint, data)
        self.assertEqual(status, 200, payload.decode("utf-8"))
        return json.loads(payload)

    def preview_user_delete(self, user_id: str) -> dict[str, Any]:
        reason = "Remove access after owner request"
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/delete/preview", {"reason": reason},
        )
        self.assertEqual(status, 200, payload.decode("utf-8"))
        return json.loads(payload)

    @staticmethod
    def user_delete_apply(review: dict[str, Any], confirmation: str) -> dict[str, str]:
        return {
            "confirmation": confirmation,
            "reason": review["reason"],
            "review_token": review["review_token"],
        }

    def preview_session_termination(self, session_id: str) -> dict[str, Any]:
        reason = "Operator requested session disconnect"
        status, _, payload = self.json_request(
            "POST", f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}/preview", {"reason": reason},
        )
        self.assertEqual(status, 200, payload.decode("utf-8"))
        return {**json.loads(payload), "reason": reason}

    def connect_socketio_polling(self, cookie: str | None = None) -> tuple[str, bytes]:
        if self.server.socketio_bridge is None:
            self.server.socketio_bridge = SocketIOPollingBridge(
                self.server.telemetry_runtime.gateway,
                self.server.telemetry_runtime.principal_for_session,
            )
        session_cookie = cookie or self.cookie
        headers = {"Cookie": session_cookie, "Origin": self.config.public_origin}
        status, _, handshake = self.request(
            "GET", "/socket.io/?EIO=4&transport=polling", headers=headers,
        )
        self.assertEqual(status, 200, handshake.decode("utf-8"))
        packet = json.loads(handshake[1:])
        sid = packet["sid"]
        status, _, posted = self.request(
            "POST",
            f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
            body=b"40/telemetry,",
            headers={**headers, "Content-Type": "text/plain;charset=UTF-8"},
        )
        self.assertEqual(status, 200, posted.decode("utf-8"))
        status, _, namespace = self.request(
            "GET",
            f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
            headers=headers,
        )
        self.assertEqual(status, 200, namespace.decode("utf-8"))
        self.assertEqual(namespace, b"40/telemetry,")
        return sid, session_cookie

    def queue_socketio_test_event(self, sid: str) -> str:
        """Queue a real broker event behind the active polling subscription."""
        runtime = self.server.telemetry_runtime
        events = runtime.broker.apply(
            RouterOSReply("re", {".id": "*POLL-TEST", "name": "polling-test-user"}),
        )
        self.assertTrue(events)
        self.assertEqual(runtime.gateway.publish(events), len(events))
        self.assertEqual(runtime.gateway.metrics()["buffered_events"], len(events))
        subscription_id = self.server.socketio_bridge._clients[sid].subscription
        self.assertIsNotNone(subscription_id)
        cursor = runtime.gateway._clients[subscription_id].last_seen_sequence
        self.assertTrue(any(
            frame["payload"].get("name") == "polling-test-user"
            and frame["sequence"] > cursor
            for frame, _published_at in runtime.gateway._events
        ))
        return "polling-test-user"

    def preview_bulk_action(
        self, action: str, user_ids: list[str], *, tag: str = "",
    ) -> dict[str, Any]:
        reason = "Quarterly VPN access review" if action in {"suspend", "revoke"} else ""
        status, _, payload = self.json_request(
            "POST", "/api/bulk/preview", {"action": action, "user_ids": user_ids, "tag": tag, "reason": reason},
        )
        self.assertEqual(status, 200, payload.decode("utf-8"))
        return {**json.loads(payload), "reason": reason}

    def test_logout_rejects_missing_or_invalid_csrf_without_revoking_session(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        session.last_seen -= 60
        original_last_seen = session.last_seen

        for token in ("", "not-the-session-token"):
            body = urllib.parse.urlencode({"csrf": token}).encode()
            status, _, _ = self.request(
                "POST",
                "/logout",
                body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            self.assertEqual(status, 403)
            self.assertIsNotNone(self.server.context.sessions.get(session_id, touch=False))
            self.assertEqual(session.last_seen, original_last_seen)

        body = urllib.parse.urlencode({"csrf": self.csrf}).encode()
        status, headers, _ = self.request(
            "POST",
            "/logout",
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 303)
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertTrue(headers["set-cookie"].startswith("__Host-vpn_session="))
        self.assertIn("Path=/", headers["set-cookie"])
        self.assertNotIn("Domain=", headers["set-cookie"])
        self.assertIn("Secure", headers["set-cookie"])
        self.assertIn("HttpOnly", headers["set-cookie"])
        self.assertIn("SameSite=Strict", headers["set-cookie"])
        self.assertIn("Max-Age=0", headers["set-cookie"])

    def test_logout_rejects_foreign_origin_even_with_valid_csrf_token(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        before_routeros_mutations = list(self.mock.state.mutation_requests)
        body = urllib.parse.urlencode({"csrf": self.csrf}).encode()

        status, _, payload = self.request(
            "POST",
            "/logout",
            body=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": "https://attacker.example",
            },
        )

        self.assertEqual(status, 403, payload.decode())
        self.assertIn(b"origin", payload.lower())
        self.assertIsNotNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertEqual(self.mock.state.mutation_requests, before_routeros_mutations)

    def test_logout_logs_trailing_space_origin_as_nonmatching(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        body = urllib.parse.urlencode({"csrf": self.csrf}).encode()

        with contextlib.redirect_stdout(io.StringIO()) as output:
            status, _, payload = self.request(
                "POST",
                "/logout",
                body=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": f"{self.config.public_origin} ",
                },
            )

        self.assertEqual(status, 403, payload.decode())
        self.assertIn("origin_count=1 origin_relation=other", output.getvalue())
        self.assertNotIn(self.config.public_origin, output.getvalue())
        self.assertIsNotNone(self.server.context.sessions.get(session_id, touch=False))

    def test_logout_revokes_live_access_when_audit_write_fails(self) -> None:
        self.login()
        sid, cookie = self.connect_socketio_polling()
        queued_marker = self.queue_socketio_test_event(sid)
        session_id = cookie.split("=", 1)[1]

        with (
            mock.patch.object(
                self.server.context.store,
                "audit",
                side_effect=sqlite3.OperationalError("injected database failure"),
            ),
            contextlib.redirect_stdout(io.StringIO()) as output,
        ):
            status, headers, payload = self.request(
                "POST",
                "/logout",
                body=urllib.parse.urlencode({"csrf": self.csrf}).encode(),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": self.config.public_origin,
                },
            )

        self.assertEqual(status, 303, payload.decode("utf-8"))
        self.assertEqual(headers["location"], "/login")
        self.assertIn("Max-Age=0", headers["set-cookie"])
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertIn("audit event=session.revoked status=failed", output.getvalue())
        self.assertNotIn("injected database failure", output.getvalue())

        status, _, payload = self.request(
            "GET", "/api/events", headers={"Cookie": cookie},
        )
        self.assertEqual(status, 401)
        self.assertNotIn(b"event: status", payload)

        status, _, payload = self.request(
            "GET",
            f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
            headers={"Cookie": cookie, "Origin": self.config.public_origin},
        )
        self.assertEqual(status, 401)
        self.assertNotIn(queued_marker.encode(), payload)
        self.assertNotIn(sid, self.server.socketio_bridge._clients)
        self.assertEqual(self.server.socketio_bridge.gateway.client_count, 0)

    def test_logout_rejects_duplicate_origin_headers_even_with_valid_csrf_token(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        before_routeros_mutations = list(self.mock.state.mutation_requests)
        body = urllib.parse.urlencode({"csrf": self.csrf}).encode()
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        connection.putrequest("POST", "/logout")
        connection.putheader("Content-Type", "application/x-www-form-urlencoded")
        connection.putheader("Content-Length", str(len(body)))
        connection.putheader("Cookie", self.cookie)
        connection.putheader("Origin", self.config.public_origin)
        connection.putheader("Origin", "https://attacker.example")
        connection.endheaders(body)
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        connection.close()

        self.assertEqual(status, 403, payload.decode())
        self.assertIn(b"origin", payload.lower())
        self.assertIsNotNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertEqual(self.mock.state.mutation_requests, before_routeros_mutations)

    def test_logout_logs_opaque_origin_and_foreign_referer_without_raw_values(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        body = urllib.parse.urlencode({"csrf": self.csrf}).encode()

        with contextlib.redirect_stdout(io.StringIO()) as output:
            status, _, payload = self.request(
                "POST",
                "/logout",
                body=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "null",
                    "Referer": "https://attacker.example/private?token=fixture-secret",
                },
            )

        self.assertEqual(status, 403, payload.decode())
        self.assertIn("origin_count=1 origin_relation=null", output.getvalue())
        self.assertIn("referer_count=1 referer_relation=other", output.getvalue())
        self.assertNotIn("attacker.example", output.getvalue())
        self.assertNotIn("fixture-secret", output.getvalue())
        self.assertIsNotNone(self.server.context.sessions.get(session_id, touch=False))

    def test_logout_rejects_duplicate_csrf_headers_even_with_valid_body_token(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        before_routeros_mutations = list(self.mock.state.mutation_requests)
        body = urllib.parse.urlencode({"csrf": self.csrf}).encode()
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        connection.putrequest("POST", "/logout")
        connection.putheader("Content-Type", "application/x-www-form-urlencoded")
        connection.putheader("Content-Length", str(len(body)))
        connection.putheader("Cookie", self.cookie)
        connection.putheader("Origin", self.config.public_origin)
        connection.putheader("X-CSRF-Token", self.csrf)
        connection.putheader("x-csrf-token", "attacker-supplied-token")
        connection.endheaders(body)
        response = connection.getresponse()
        payload = response.read()
        status = response.status
        connection.close()

        self.assertEqual(status, 403, payload.decode())
        self.assertIn(b"csrf", payload.lower())
        self.assertIsNotNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertEqual(self.mock.state.mutation_requests, before_routeros_mutations)

    def test_successful_authenticated_request_refreshes_idle_timestamp(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        session.last_seen -= 60
        previous_last_seen = session.last_seen

        status, _, _ = self.request("GET", "/dashboard")

        self.assertEqual(status, 200)
        self.assertGreater(session.last_seen, previous_last_seen)

    def test_sse_stops_emitting_when_server_session_is_revoked(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        logout_results: list[int] = []

        def revoke_after_first_event(_seconds: float) -> None:
            body = urllib.parse.urlencode({"csrf": self.csrf}).encode()
            status, _, _ = self.request(
                "POST", "/logout", body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            logout_results.append(status)

        with mock.patch("app.time.sleep", side_effect=revoke_after_first_event):
            connection.request(
                "GET",
                "/api/events",
                headers={"Cookie": self.cookie, "Origin": self.config.public_origin},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
        connection.close()

        self.assertEqual(logout_results, [303])
        self.assertEqual(body.count(b"event: status"), 1)
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))

    def test_sse_rejects_duplicate_origins_before_router_fetch(self) -> None:
        self.login()
        same_origin = self.config.public_origin
        foreign_origin = "https://attacker.example"
        origin_pairs = (
            (same_origin, foreign_origin),
            (foreign_origin, same_origin),
            (same_origin, same_origin),
        )
        with mock.patch.object(
            self.server.context.router,
            "list_active_ovpn_sessions",
        ) as list_sessions:
            for first, second in origin_pairs:
                with self.subTest(first=first, second=second):
                    status, payload = self.raw_request(
                        "GET",
                        "/api/events",
                        [("Origin", first), ("Origin", second)],
                    )
                    self.assertEqual(status, 403, payload.decode())
                    self.assertIn(b"origin", payload.lower())
            list_sessions.assert_not_called()

    def test_sse_projects_routeros_sessions_onto_redacted_live_schema(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        router_row = {
            "id": "*SESSION-1",
            "name": "alice",
            "vpn_address": "10.8.0.2",
            "source_address": "198.51.100.25",
            "uptime": "00:10:00",
            "encoding": "AES-256-GCM",
            "service": "ovpn",
            "rx_bytes": 1234,
            "tx_bytes": 5678,
            "rx_packets": 12,
            "tx_packets": 34,
            "counter_complete": True,
            "session_id": "private-router-session-id",
            "comment": "private comment sentinel",
            "interface": "private-interface-sentinel",
            "mtu": 1400,
            "password": "private-password-sentinel",
            "certificate": "private-certificate-sentinel",
        }
        logout_results: list[int] = []

        def revoke_after_first_event(_seconds: float) -> None:
            body = urllib.parse.urlencode({"csrf": self.csrf}).encode()
            status, _, _ = self.request(
                "POST", "/logout", body=body,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            logout_results.append(status)

        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        with (
            mock.patch.object(
                self.server.context.router,
                "list_active_ovpn_sessions",
                return_value=[router_row],
            ),
            mock.patch("app.time.sleep", side_effect=revoke_after_first_event),
        ):
            connection.request(
                "GET",
                "/api/events",
                headers={"Cookie": self.cookie, "Origin": self.config.public_origin},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
        connection.close()

        frames = [json.loads(line[6:]) for line in body.splitlines() if line.startswith(b"data: ")]
        self.assertEqual(logout_results, [303])
        self.assertEqual(len(frames), 1)
        self.assertEqual(
            set(frames[0]["sessions"][0]),
            {
                "id", "name", "vpn_address", "source_address", "uptime", "encoding",
                "service", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets",
                "counter_complete",
            },
        )
        self.assertEqual(frames[0]["sessions"][0]["name"], "alice")
        for forbidden in (
            "private-router-session-id", "private comment sentinel",
            "private-interface-sentinel", "private-password-sentinel",
            "private-certificate-sentinel", "session_id", "comment", "interface",
            "password", "certificate",
        ):
            self.assertNotIn(forbidden, body.decode())
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))

    def test_sse_stops_emitting_when_session_is_rotated_by_reauthentication(self) -> None:
        self.login()
        old_cookie = self.cookie
        old_csrf = self.csrf
        old_session_id = old_cookie.split("=", 1)[1]
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        reauth_results: list[tuple[int, dict[str, str], bytes]] = []

        def rotate_after_first_event(_seconds: float) -> None:
            reauth_results.append(self.request(
                "POST",
                "/api/auth/reauthenticate",
                body=json.dumps({"password": "routerpass"}).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": old_cookie,
                    "X-CSRF-Token": old_csrf,
                    "Origin": self.config.public_origin,
                },
            ))

        with mock.patch("app.time.sleep", side_effect=rotate_after_first_event):
            connection.request(
                "GET",
                "/api/events",
                headers={"Cookie": old_cookie, "Origin": self.config.public_origin},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
        connection.close()

        self.assertEqual(len(reauth_results), 1)
        self.assertEqual(reauth_results[0][0], 200, reauth_results[0][2].decode())
        self.cookie = reauth_results[0][1]["set-cookie"].split(";", 1)[0]
        self.csrf = json.loads(reauth_results[0][2])["csrf_token"]
        self.assertEqual(body.count(b"event: status"), 1)
        self.assertIsNone(self.server.context.sessions.get(old_session_id, touch=False))
        status, _, payload = self.request("GET", "/api/telemetry", headers={"Cookie": old_cookie})
        self.assertEqual(status, 401, payload.decode())
        status, _, payload = self.request("GET", "/api/telemetry")
        self.assertEqual(status, 200, payload.decode())

    def test_reauthentication_rotates_cookie_csrf_and_uses_current_routeros_capabilities(self) -> None:
        self.login()
        old_cookie = self.cookie
        old_csrf = self.csrf
        old_session_id = old_cookie.split("=", 1)[1]

        with mock.patch.object(self.server.context.router, "get_admin_role", return_value="read"):
            status, headers, payload = self.request(
                "POST",
                "/api/auth/reauthenticate",
                body=json.dumps({"password": "routerpass"}).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": old_cookie,
                    "X-CSRF-Token": old_csrf,
                    "Origin": self.config.public_origin,
                },
            )

        self.assertEqual(status, 200, payload.decode())
        result = json.loads(payload)
        self.assertEqual(result["role"], "read_only")
        self.assertNotEqual(result["csrf_token"], old_csrf)
        self.assertIn("Secure", headers["set-cookie"])
        self.assertIn("HttpOnly", headers["set-cookie"])
        self.assertIn("SameSite=Strict", headers["set-cookie"])
        self.assertTrue(headers["set-cookie"].startswith("__Host-vpn_session="))
        self.assertIn("Path=/", headers["set-cookie"])
        self.assertNotIn("Domain=", headers["set-cookie"])
        self.cookie = headers["set-cookie"].split(";", 1)[0]
        self.csrf = result["csrf_token"]
        new_session_id = self.cookie.split("=", 1)[1]
        self.assertNotIn(new_session_id, payload.decode())
        self.assertNotEqual(new_session_id, old_session_id)
        self.assertIsNone(self.server.context.sessions.get(old_session_id, touch=False))
        self.assertEqual(self.server.context.sessions.get(new_session_id, touch=False).role, "read_only")

        status, _, payload = self.request("GET", "/api/telemetry", headers={"Cookie": old_cookie})
        self.assertEqual(status, 401, payload.decode())
        status, _, payload = self.request("GET", "/api/telemetry")
        self.assertEqual(status, 200, payload.decode())
        status, _, payload = self.request("GET", "/api/admin/api-tokens")
        self.assertEqual(status, 403, payload.decode())
        self.assertIn(b"security.manage", payload)

        with mock.patch.object(self.server.context.router, "verify_credentials") as verify:
            status, _, payload = self.request(
                "POST",
                "/api/auth/reauthenticate",
                body=json.dumps({"password": "routerpass"}).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": self.cookie,
                    "X-CSRF-Token": old_csrf,
                    "Origin": self.config.public_origin,
                },
            )
        self.assertEqual(status, 403)
        self.assertIn(b"CSRF", payload)
        verify.assert_not_called()

    def test_reauthentication_audit_failure_keeps_existing_session_usable(self) -> None:
        self.login()
        cookie = self.cookie
        csrf = self.csrf
        session_id = cookie.split("=", 1)[1]
        original = self.server.context.sessions.get(session_id, touch=False)
        original_secrets = (
            original.password,
            original.csrf_token,
            original.revocation_ref,
            original.authorization_ref,
        )
        body = json.dumps({"password": "routerpass"}).encode()

        with mock.patch.object(
            self.server.context.store,
            "audit_many",
            side_effect=sqlite3.OperationalError("injected database failure"),
        ):
            status, headers, payload = self.request(
                "POST",
                "/api/auth/reauthenticate",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "X-CSRF-Token": csrf,
                    "Origin": self.config.public_origin,
                },
            )

        self.assertEqual(status, 503, payload.decode())
        self.assertNotIn("set-cookie", headers)
        self.assertNotIn(b"injected database failure", payload)
        self.assertIs(self.server.context.sessions.get(session_id, touch=False), original)
        self.assertEqual(
            (
                original.password,
                original.csrf_token,
                original.revocation_ref,
                original.authorization_ref,
            ),
            original_secrets,
        )
        self.assertEqual(len(self.server.context.sessions.active()), 1)
        status, _, payload = self.request("GET", "/api/telemetry", headers={"Cookie": cookie})
        self.assertEqual(status, 200, payload.decode())

    def test_reauthentication_audit_records_denial_when_session_is_revoked_midflight(self) -> None:
        self.login()
        cookie = self.cookie
        csrf = self.csrf
        session_id = cookie.split("=", 1)[1]
        store = self.server.context.store
        sessions = self.server.context.sessions
        original_audit_many = store.audit_many
        revocation_started = threading.Event()

        def audit_then_revoke(events: list[dict[str, Any]]) -> None:
            original_audit_many(events)
            if not any(
                event.get("action") == "routeros.reauthentication.credentials_verified"
                for event in events
            ):
                return

            def revoke() -> None:
                sessions.destroy(session_id)
                revocation_started.set()

            worker = threading.Thread(target=revoke)
            worker.start()
            deadline = time.monotonic() + 1
            while sessions._invalidating.get(session_id, 0) < 2:
                if time.monotonic() >= deadline:
                    raise TimeoutError("session revocation did not begin")
                time.sleep(0.005)
            worker.join(timeout=1)

        with mock.patch.object(store, "audit_many", side_effect=audit_then_revoke):
            status, headers, payload = self.request(
                "POST",
                "/api/auth/reauthenticate",
                body=json.dumps({"password": "routerpass"}).encode(),
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "X-CSRF-Token": csrf,
                    "Origin": self.config.public_origin,
                },
            )

        self.assertEqual(status, 401, payload.decode())
        self.assertNotIn("set-cookie", headers)
        self.assertTrue(revocation_started.wait(timeout=1))
        self.assertIsNone(sessions.get(session_id, touch=False))
        events = store.recent_audit(10)
        self.assertTrue(any(
            event["action"] == "routeros.reauthentication.credentials_verified"
            and event["status"] == "success"
            for event in events
        ))
        self.assertTrue(any(
            event["action"] == "session.reauthentication" and event["status"] == "denied"
            for event in events
        ))

    def test_reauthentication_rejects_foreign_or_unverifiable_origins_before_router_auth(self) -> None:
        self.login()
        cookie = self.cookie
        csrf = self.csrf
        session_id = cookie.split("=", 1)[1]
        body = json.dumps({"password": "routerpass"}).encode()

        with mock.patch.object(self.server.context.router, "verify_credentials") as verify:
            status, _, payload = self.request(
                "POST",
                "/api/auth/reauthenticate",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "X-CSRF-Token": csrf,
                    "Origin": "https://attacker.example",
                },
            )
            self.assertEqual(status, 403, payload.decode())

            status, _, payload = self.request(
                "POST",
                "/api/auth/reauthenticate",
                body=body,
                headers={
                    "Content-Type": "application/json",
                    "Cookie": cookie,
                    "X-CSRF-Token": csrf,
                },
            )
            self.assertEqual(status, 403, payload.decode())
            verify.assert_not_called()

        self.assertIsNotNone(self.server.context.sessions.get(session_id, touch=False))

    def test_reauthentication_accepts_null_origin_with_same_origin_referer(self) -> None:
        self.login()
        old_cookie = self.cookie
        old_session_id = old_cookie.split("=", 1)[1]
        status, headers, payload = self.request(
            "POST",
            "/api/auth/reauthenticate",
            body=json.dumps({"password": "routerpass"}).encode(),
            headers={
                "Content-Type": "application/json",
                "Cookie": old_cookie,
                "X-CSRF-Token": self.csrf,
                "Origin": "null",
                "Referer": f"{self.config.public_origin}/dashboard",
            },
        )

        self.assertEqual(status, 200, payload.decode())
        self.assertTrue(headers["set-cookie"].startswith("__Host-vpn_session="))
        self.assertIsNone(self.server.context.sessions.get(old_session_id, touch=False))

    def test_reauthentication_failure_keeps_session_and_rate_limits_bad_passwords(self) -> None:
        self.login()
        old_cookie = self.cookie
        old_csrf = self.csrf
        session_id = old_cookie.split("=", 1)[1]
        headers = {
            "Content-Type": "application/json",
            "Cookie": old_cookie,
            "X-CSRF-Token": old_csrf,
            "Origin": self.config.public_origin,
        }
        for _ in range(5):
            status, _, payload = self.request(
                "POST", "/api/auth/reauthenticate",
                body=json.dumps({"password": "wrong-password"}).encode(),
                headers=headers,
            )
            self.assertEqual(status, 401, payload.decode())
            self.assertNotIn(b"wrong-password", payload)
            self.assertIsNotNone(self.server.context.sessions.get(session_id, touch=False))
        status, _, payload = self.request(
            "POST", "/api/auth/reauthenticate",
            body=json.dumps({"password": "routerpass"}).encode(),
            headers=headers,
        )
        self.assertEqual(status, 429, payload.decode())
        self.assertIsNotNone(self.server.context.sessions.get(session_id, touch=False))

    def test_routeros_role_lookup_outage_does_not_consume_reauthentication_budget(self) -> None:
        self.login()
        old_cookie = self.cookie
        old_csrf = self.csrf
        session_id = old_cookie.split("=", 1)[1]
        headers = {
            "Content-Type": "application/json",
            "Cookie": old_cookie,
            "X-CSRF-Token": old_csrf,
            "Origin": self.config.public_origin,
        }
        with mock.patch.object(
            self.server.context.router,
            "get_admin_role",
            side_effect=RouterOSError("RouterOS is unavailable", failure_kind="timeout"),
        ):
            for attempt in range(6):
                with self.subTest(attempt=attempt + 1):
                    status, _, payload = self.request(
                        "POST",
                        "/api/auth/reauthenticate",
                        body=json.dumps({"password": "routerpass"}).encode(),
                        headers=headers,
                    )
                    self.assertEqual(status, HTTPStatus.SERVICE_UNAVAILABLE, payload.decode())
                    self.assertIn(b"could not verify the password right now", payload)
                    self.assertIsNotNone(self.server.context.sessions.get(session_id, touch=False))

        self.assertEqual(self.server.context.limiter._attempts, {})
        self.assertEqual(
            self.server.context.store.recent_audit(1)[0]["action"],
            "session.reauth.unavailable",
        )
        status, _, payload = self.request(
            "POST",
            "/api/auth/reauthenticate",
            body=json.dumps({"password": "routerpass"}).encode(),
            headers=headers,
        )
        self.assertEqual(status, HTTPStatus.OK, payload.decode())

    def test_sse_reconnect_rejects_revoked_or_expired_cookie_before_router_read(self) -> None:
        for state in ("revoked", "expired"):
            with self.subTest(state=state):
                self.login()
                session_id = self.cookie.split("=", 1)[1]
                session = self.server.context.sessions.get(session_id, touch=False)
                self.assertIsNotNone(session)

                if state == "revoked":
                    self.server.context.sessions.destroy(session_id)
                else:
                    self.server.context.sessions.idle_seconds = 1
                    session.last_seen = 0

                with mock.patch.object(
                    self.server.context.router,
                    "list_active_ovpn_sessions",
                    side_effect=AssertionError("unauthorized SSE reconnect reached RouterOS"),
                ) as list_sessions:
                    status, _, payload = self.request(
                        "GET",
                        "/api/events",
                        headers={
                            "Cookie": self.cookie,
                            "Origin": self.config.public_origin,
                        },
                    )

                self.assertEqual(status, 401)
                self.assertNotIn(b"event: status", payload)
                list_sessions.assert_not_called()

    def test_sse_request_does_not_refresh_session_idle_timestamp(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        last_seen = session.last_seen
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)

        with (
            mock.patch.object(
                self.server.context.router,
                "list_active_ovpn_sessions",
                return_value=[],
            ),
            mock.patch("app.time.sleep", side_effect=RouterOSError("end test stream")),
        ):
            connection.request(
                "GET",
                "/api/events",
                headers={"Cookie": self.cookie, "Origin": self.config.public_origin},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
        connection.close()

        self.assertEqual(body.count(b"event: status"), 1)
        self.assertEqual(session.last_seen, last_seen)

    def test_socketio_stream_stops_after_administrator_revokes_real_session(self) -> None:
        self.login()
        target = self.server.context.sessions.create("admin", "routerpass", role="owner")
        target_cookie = f"__Host-vpn_session={target.session_id}"
        sid, target_cookie = self.connect_socketio_polling(target_cookie)
        self.assertEqual(self.server.socketio_bridge.gateway.client_count, 1)
        queued_marker = self.queue_socketio_test_event(sid)

        path = f"/api/admin/sessions/{urllib.parse.quote(target.revocation_ref, safe='')}"
        status, _, payload = self.json_request("DELETE", path, {"password": "routerpass"})
        self.assertEqual(status, 200, payload.decode("utf-8"))
        self.assertIsNone(self.server.context.sessions.get(target.session_id, touch=False))

        status, _, payload = self.request(
            "GET",
            f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
            headers={"Cookie": target_cookie, "Origin": self.config.public_origin},
        )
        self.assertEqual(status, 401)
        self.assertNotIn(b"telemetry", payload)
        self.assertNotIn(queued_marker.encode(), payload)
        self.assertNotIn(sid, self.server.socketio_bridge._clients)
        self.assertEqual(self.server.socketio_bridge.gateway.client_count, 0)

    def test_socketio_stream_stops_after_session_reauthentication_rotates_cookie(self) -> None:
        self.login()
        old_cookie = self.cookie
        old_csrf = self.csrf
        sid, _ = self.connect_socketio_polling(old_cookie)
        queued_marker = self.queue_socketio_test_event(sid)

        status, headers, payload = self.request(
            "POST",
            "/api/auth/reauthenticate",
            body=json.dumps({"password": "routerpass"}).encode(),
            headers={
                "Content-Type": "application/json",
                "Cookie": old_cookie,
                "X-CSRF-Token": old_csrf,
                "Origin": self.config.public_origin,
            },
        )
        self.assertEqual(status, 200, payload.decode())
        self.cookie = headers["set-cookie"].split(";", 1)[0]
        self.csrf = json.loads(payload)["csrf_token"]

        status, _, payload = self.request(
            "GET",
            f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
            headers={"Cookie": old_cookie, "Origin": self.config.public_origin},
        )
        self.assertEqual(status, 401)
        self.assertNotIn(queued_marker.encode(), payload)
        self.assertNotIn(sid, self.server.socketio_bridge._clients)
        self.assertEqual(self.server.socketio_bridge.gateway.client_count, 0)

        status, _, payload = self.request("GET", "/api/telemetry")
        self.assertEqual(status, 200, payload.decode())

    def test_socketio_stream_stops_after_real_logout_with_queued_telemetry(self) -> None:
        self.login()
        sid, cookie = self.connect_socketio_polling()
        queued_marker = self.queue_socketio_test_event(sid)

        status, _, payload = self.request(
            "POST",
            "/logout",
            body=urllib.parse.urlencode({"csrf": self.csrf}).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.config.public_origin,
            },
        )
        self.assertEqual(status, 303, payload.decode("utf-8"))
        session_id = cookie.split("=", 1)[1]
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))

        status, _, payload = self.request(
            "GET",
            f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
            headers={"Cookie": cookie, "Origin": self.config.public_origin},
        )
        self.assertEqual(status, 401)
        self.assertNotIn(queued_marker.encode(), payload)
        self.assertNotIn(sid, self.server.socketio_bridge._clients)
        self.assertEqual(self.server.socketio_bridge.gateway.client_count, 0)

    def test_socketio_poll_closes_stream_after_real_idle_expiry(self) -> None:
        self.login()
        sid, cookie = self.connect_socketio_polling()
        session_id = cookie.split("=", 1)[1]
        queued_marker = self.queue_socketio_test_event(sid)
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        self.server.context.sessions.idle_seconds = 1
        session.last_seen = 0

        status, _, payload = self.request(
            "GET",
            f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
            headers={"Cookie": cookie, "Origin": self.config.public_origin},
        )
        self.assertEqual(status, 401)
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertNotIn(sid, self.server.socketio_bridge._clients)
        self.assertEqual(self.server.socketio_bridge.gateway.client_count, 0)
        self.assertNotIn(b"telemetry", payload)
        self.assertNotIn(queued_marker.encode(), payload)

    def test_socketio_poll_closes_stream_after_real_absolute_expiry(self) -> None:
        self.login()
        sid, cookie = self.connect_socketio_polling()
        session_id = cookie.split("=", 1)[1]
        queued_marker = self.queue_socketio_test_event(sid)
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        self.server.context.sessions.absolute_seconds = 1
        session.created_at = 0

        status, _, payload = self.request(
            "GET",
            f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
            headers={"Cookie": cookie, "Origin": self.config.public_origin},
        )
        self.assertEqual(status, 401)
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertNotIn(sid, self.server.socketio_bridge._clients)
        self.assertEqual(self.server.socketio_bridge.gateway.client_count, 0)
        self.assertNotIn(b"telemetry", payload)
        self.assertNotIn(queued_marker.encode(), payload)

    def test_socketio_poll_suppresses_packet_if_session_is_revoked_before_http_write(self) -> None:
        self.login()
        sid, cookie = self.connect_socketio_polling()
        session_id = cookie.split("=", 1)[1]
        private_marker = "poll-packet-after-revocation-sentinel"

        def revoke_after_poll(_sid: str, _session_id: str) -> str:
            self.server.context.sessions.revoke(session_id)
            return f"42/telemetry,{json.dumps(['vpn.session.updated', {'marker': private_marker}])}"

        with mock.patch.object(
            self.server.socketio_bridge,
            "poll",
            side_effect=revoke_after_poll,
        ):
            status, _, payload = self.request(
                "GET",
                f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
                headers={"Cookie": cookie, "Origin": self.config.public_origin},
            )

        self.assertEqual(status, 401)
        self.assertNotIn(private_marker.encode(), payload)
        self.assertNotIn(sid, self.server.socketio_bridge._clients)
        self.assertEqual(self.server.socketio_bridge.gateway.client_count, 0)

    def test_socketio_stream_revalidates_routeros_role_change_on_real_session(self) -> None:
        self.login()
        sid, cookie = self.connect_socketio_polling()
        session_id = cookie.split("=", 1)[1]

        # A role downgrade remains authorized for live sessions because
        # read_only retains sessions.read. It must still be revalidated by the
        # real RouterOS-derived role resolver while the polling stream is open.
        self.mock.state.admin_group = "read"
        self.server.context.sessions._role_checked_monotonic[session_id] = 0
        runtime = self.server.context.telemetry_runtime
        with mock.patch.object(
            runtime, "revalidate_session", wraps=runtime.revalidate_session
        ) as revalidate_session:
            status, _, packet = self.request(
                "GET",
                f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
                headers={"Cookie": cookie, "Origin": self.config.public_origin},
            )
        self.assertTrue(
            any(
                call.kwargs.get("role_revalidation_interval_seconds")
                == LIVE_STREAM_ROLE_REVALIDATION_SECONDS
                for call in revalidate_session.call_args_list
            ),
            "threaded Socket.IO polling must use the short live-stream role cache",
        )
        self.assertEqual(status, 200, packet.decode("utf-8"))
        self.assertEqual(packet, b"2")
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        self.assertEqual(session.role, "read_only")
        self.assertIn(sid, self.server.socketio_bridge._clients)
        self.assertEqual(self.server.socketio_bridge.gateway.client_count, 1)

        # A now-disabled RouterOS account must lose its established stream on
        # the next poll, and the gateway subscription must be released.
        self.mock.state.admin_disabled = True
        self.server.context.sessions._role_checked_monotonic[session_id] = 0
        status, _, payload = self.request(
            "GET",
            f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
            headers={"Cookie": cookie, "Origin": self.config.public_origin},
        )
        self.assertEqual(status, 401)
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertNotIn(sid, self.server.socketio_bridge._clients)
        self.assertEqual(self.server.socketio_bridge.gateway.client_count, 0)
        self.assertNotIn(b"telemetry", payload)

    def test_sse_rejects_foreign_origin_before_router_fetch(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id)
        self.assertIsNotNone(session)

        def expire_session(_seconds: float) -> None:
            session.last_seen = 0

        with (
            mock.patch("app.time.sleep", side_effect=expire_session),
            mock.patch.object(
                self.server.context.router,
                "list_active_ovpn_sessions",
                return_value=[],
            ) as list_sessions,
        ):
            status, _, body = self.request(
                "GET",
                "/api/events",
                headers={"Origin": "https://attacker.example"},
            )

        self.assertEqual(status, 403)
        self.assertNotIn(b"event: status", body)
        list_sessions.assert_not_called()

    def test_sse_does_not_emit_snapshot_if_session_is_revoked_during_router_fetch(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        private_marker = "snapshot-fetched-before-revocation"
        active = [{"id": "*revoked-during-fetch", "name": private_marker, "uptime": "1m"}]

        def revoke_during_fetch(_credentials: Any) -> list[dict[str, Any]]:
            self.server.context.sessions.destroy(session_id)
            return active

        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        with (
            mock.patch.object(
                self.server.context.router,
                "list_active_ovpn_sessions",
                side_effect=revoke_during_fetch,
            ),
            mock.patch.object(self.server.context.store, "observe_sessions") as observe_sessions,
        ):
            connection.request("GET", "/api/events", headers={"Cookie": self.cookie})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
        connection.close()

        self.assertNotIn(b"event: status", body)
        self.assertNotIn(private_marker.encode(), body)
        observe_sessions.assert_not_called()
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))

    def test_sse_serializes_final_frame_with_session_revocation(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        revocation_started = threading.Event()
        revocation_completed = threading.Event()
        revoke_threads: list[threading.Thread] = []
        write_after_revocation: list[bool] = []
        original_observe = self.server.context.store.observe_sessions
        original_write = DashboardHandler._write_sse_event

        def revoke_session() -> None:
            revocation_started.set()
            self.server.context.sessions.revoke(session_id)
            revocation_completed.set()

        def observe_then_revoke(active: list[dict[str, Any]]) -> None:
            original_observe(active)
            thread = threading.Thread(target=revoke_session, daemon=True)
            revoke_threads.append(thread)
            thread.start()
            self.assertTrue(revocation_started.wait(timeout=1))
            role_lock = self.server.telemetry_runtime.role_check_lock_for_session(session_id)
            self.assertIsNotNone(role_lock)
            if role_lock is not None and role_lock.locked():
                # Revocation must wait for the in-flight, already-authorized
                # write to finish before it can report the session revoked.
                self.assertFalse(revocation_completed.wait(timeout=0.05))
            else:
                # The old check-then-write path lets revocation finish here,
                # leaving the following frame unauthorized.
                self.assertTrue(revocation_completed.wait(timeout=1))

        def record_write(handler: DashboardHandler, payload: bytes) -> None:
            write_after_revocation.append(revocation_completed.is_set())
            original_write(handler, payload)

        with (
            mock.patch.object(self.server.context.store, "observe_sessions", side_effect=observe_then_revoke),
            mock.patch.object(DashboardHandler, "_write_sse_event", autospec=True, side_effect=record_write),
        ):
            connection.request("GET", "/api/events", headers={"Cookie": self.cookie})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
        connection.close()

        for thread in revoke_threads:
            thread.join(timeout=1)
            self.assertFalse(thread.is_alive())
        self.assertEqual(body.count(b"event: status"), 1)
        self.assertEqual(write_after_revocation, [False])
        self.assertTrue(revocation_completed.is_set())
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))

    def test_sse_stops_emitting_when_idle_session_expires(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id)
        self.assertIsNotNone(session)
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)

        def expire_after_first_event(_seconds: float) -> None:
            # Make the session's last activity deterministically older than
            # SessionStore's idle timeout; the next SSE authorization check
            # must expire and remove it before another frame is written.
            session.last_seen = 0

        with mock.patch("app.time.sleep", side_effect=expire_after_first_event):
            connection.request("GET", "/api/events", headers={"Cookie": self.cookie})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
        connection.close()

        self.assertEqual(body.count(b"event: status"), 1)
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))

    def test_sse_stops_emitting_when_absolute_session_lifetime_expires(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id)
        self.assertIsNotNone(session)
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)

        def expire_after_first_event(_seconds: float) -> None:
            # Simulate an absolute lifetime older than SessionStore's limit,
            # while leaving last_seen recent so only the absolute check fires.
            session.created_at = 0

        with mock.patch("app.time.sleep", side_effect=expire_after_first_event):
            connection.request("GET", "/api/events", headers={"Cookie": self.cookie})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
        connection.close()

        self.assertEqual(body.count(b"event: status"), 1)
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))

    def test_sse_stops_when_effective_session_capability_is_narrowed(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id)
        self.assertIsNotNone(session)
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)

        def remove_stream_capability(_seconds: float) -> None:
            session.capabilities = frozenset()

        with mock.patch("app.time.sleep", side_effect=remove_stream_capability):
            connection.request("GET", "/api/events", headers={"Cookie": self.cookie})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
        connection.close()

        self.assertEqual(body.count(b"event: status"), 1)

    def test_sse_revalidates_routeros_role_downgrade_during_active_stream(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        self.assertEqual(session.role, "owner")
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)
        sleep_calls = 0

        def downgrade_then_stop(_seconds: float) -> None:
            nonlocal sleep_calls
            sleep_calls += 1
            if sleep_calls == 1:
                # Expire the cached RouterOS role while the SSE response stays open.
                self.mock.state.admin_group = "read"
                self.server.context.sessions._role_checked_monotonic[session_id] = 0
                return
            raise RouterOSError("end test stream after role revalidation")

        original_get_admin_role = self.server.context.router.get_admin_role
        runtime = self.server.context.telemetry_runtime
        with (
            mock.patch("app.time.sleep", side_effect=downgrade_then_stop),
            mock.patch.object(
                self.server.context.router,
                "list_active_ovpn_sessions",
                return_value=[],
            ),
            mock.patch.object(
                self.server.context.router,
                "get_admin_role",
                wraps=original_get_admin_role,
            ) as get_admin_role,
            mock.patch.object(
                runtime, "revalidate_session", wraps=runtime.revalidate_session
            ) as revalidate_session,
        ):
            connection.request(
                "GET",
                "/api/events",
                headers={"Cookie": self.cookie, "Origin": self.config.public_origin},
            )
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
        connection.close()

        self.assertEqual(body.count(b"event: status"), 2)
        self.assertEqual(session.role, "read_only")
        get_admin_role.assert_called_once()
        live_role_checks = [
            call
            for call in revalidate_session.call_args_list
            if call.kwargs.get("role_revalidation_interval_seconds")
            == LIVE_STREAM_ROLE_REVALIDATION_SECONDS
        ]
        self.assertEqual(len(live_role_checks), 2)

    def _managed_device_revoke_request(self) -> tuple[str, str]:
        self.login()
        device_id = "managed-device-revoke-test"
        self.server.context.store.add_device(
            device_id=device_id,
            vpn_user="user-one",
            device_name="Managed test phone",
            certificate_name="ovpn-user-one-device-a",
            certificate_id="*CL1",
            fingerprint="A1:EX:26",
        )
        return f"/api/devices/{device_id}/revoke", device_id

    def _review_device_revoke(self, path: str) -> dict[str, str]:
        request = {
            "confirmation": "Managed test phone",
            "reason": "Device was reported lost by its owner.",
        }
        status, _, payload = self.json_request("POST", f"{path}/preview", request)
        self.assertEqual(status, 200, payload.decode("utf-8"))
        preview = json.loads(payload)
        self.assertEqual(preview["certificate_state"], "active_on_routeros")
        self.assertIn("not terminated", preview["effect"])
        return {**request, "review_token": preview["review_token"]}

    def _legacy_migration_revoke_request(self) -> tuple[str, str]:
        self.login()
        legacy_name = "legacy-user-one-phone"
        self.mock.state.certificates["*OLD"] = {
            ".id": "*OLD", "name": legacy_name, "common-name": "user-one-phone",
            "fingerprint": "OLD:FAKE", "issuer": "legacy-ca", "ca": "legacy-ca",
            "trusted": "yes", "revoked": "no", "key-usage": "tls-client",
            "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
        }
        self.mock.state.certificates["*REPLACEMENT"] = {
            ".id": "*REPLACEMENT", "name": "user-one-phone-current", "common-name": "user-one-phone-current",
            "fingerprint": "NEW:FAKE", "issuer": "vpn-ca", "ca": "vpn-ca",
            "trusted": "yes", "revoked": "no", "key-usage": "tls-client",
            "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
        }
        store = self.server.context.store
        store.record_profile_migration(
            legacy_certificate_name=legacy_name,
            vpn_user="user-one",
            replacement_certificate_name="user-one-phone-current",
        )
        store.record_profile_migration_step(legacy_certificate_name=legacy_name, step="imported", actor="operator")
        store.record_profile_migration_step(
            legacy_certificate_name=legacy_name,
            step="tested",
            actor="operator",
            active_session_observed=True,
            active_session_ids=["*TEST-SESSION"],
        )
        return f"/api/profile-migrations/{legacy_name}/revoke", legacy_name

    def _policy_template_review(self) -> tuple[str, str, dict[str, Any]]:
        status, _, payload = self.json_request(
            "POST", "/api/policy-templates",
            {"name": "Field team", "description": "Limited field support access.", "group_name": "Field",
             "policy": "lan-only", "max_sessions": 2, "rate_limit_kbps": 10240,
             "quota_mb": 5120, "schedule": "weekdays", "dns_mode": "router", "notifications": True},
        )
        self.assertEqual(status, 201)
        template = json.loads(payload)["template"]
        users = self.server.context.router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
        target = next(item for item in users if item["name"] == "user-one")
        path = f"/api/policy-templates/{template['id']}/apply"
        rationale = "Approved field-team network restrictions"
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/preview",
            {"user_ids": [target["id"]], "reason": rationale},
        )
        self.assertEqual(status, 200)
        return path, target["id"], json.loads(payload)

    def test_login_denies_valid_account_at_concurrent_session_limit(self) -> None:
        self.login()
        for _ in range(7):
            self.server.context.sessions.create("ADMIN", "routerpass")

        body = urllib.parse.urlencode(
            {"username": "admin", "password": "routerpass"}
        ).encode()
        status, headers, page = self.request(
            "POST",
            "/login",
            body=body,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.config.public_origin,
            },
        )

        self.assertEqual(status, 429)
        self.assertNotIn("set-cookie", headers)
        self.assertIn(b"maximum of 8 active dashboard sessions", page)
        self.assertIn(b"sign out or revoke one", page)
        self.assertEqual(
            self.server.context.store.recent_audit(1)[0]["action"],
            "login.concurrent_session_limit",
        )

    def test_concurrent_session_limit_audit_error_returns_sanitized_service_unavailable(self) -> None:
        self.login()
        for _ in range(7):
            self.server.context.sessions.create("ADMIN", "routerpass")
        with self.server.context.store._connection() as connection:
            connection.execute(
                """
                CREATE TRIGGER fail_concurrent_session_limit BEFORE INSERT ON audit
                WHEN NEW.action = 'login.concurrent_session_limit'
                BEGIN
                    SELECT RAISE(ABORT, 'injected audit failure');
                END;
                """
            )

        status, headers, payload = self.request(
            "POST",
            "/login",
            body=urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode(),
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.config.public_origin,
            },
        )

        self.assertEqual(status, 503)
        self.assertNotIn("set-cookie", headers)
        self.assertNotIn(b"injected audit failure", payload)
        self.assertEqual(len(self.server.context.sessions.active()), 8)

    def test_login_authenticated_before_account_disable_cannot_escape_session_sweep(self) -> None:
        self.login()
        existing_session_id = self.cookie.split("=", 1)[1]

        def observe_disable_then_return_stale_role(_credentials):
            self.assertIsNone(
                self.server.context.sessions.revalidate_role(
                    existing_session_id,
                    lambda _session: None,
                    interval_seconds=0,
                )
            )
            # Model an already-authenticated login completing with a stale
            # RouterOS role result after another request observed disablement.
            return "owner"

        body = urllib.parse.urlencode(
            {"username": "admin", "password": "routerpass"}
        ).encode()
        with mock.patch.object(
            self.server.context.router,
            "get_admin_role",
            side_effect=observe_disable_then_return_stale_role,
        ):
            status, headers, payload = self.request(
                "POST",
                "/login",
                body=body,
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": self.config.public_origin,
                },
            )

        self.assertEqual(status, 401, payload.decode())
        self.assertNotIn("set-cookie", headers)
        self.assertEqual(self.server.context.sessions.active(), [])
        self.assertEqual(
            self.server.context.store.recent_audit(1)[0]["action"],
            "login.failure",
        )

    def test_login_authorization_change_audit_error_fails_closed(self) -> None:
        self.login()
        existing_session_id = self.cookie.split("=", 1)[1]
        with self.server.context.store._connection() as connection:
            connection.execute(
                """
                CREATE TRIGGER fail_authorization_changed_audit BEFORE INSERT ON audit
                WHEN NEW.action = 'login.failure'
                BEGIN
                    SELECT RAISE(ABORT, 'injected audit failure');
                END;
                """
            )

        def observe_disable_then_return_stale_role(_credentials):
            self.assertIsNone(
                self.server.context.sessions.revalidate_role(
                    existing_session_id,
                    lambda _session: None,
                    interval_seconds=0,
                )
            )
            return "owner"

        with mock.patch.object(
            self.server.context.router,
            "get_admin_role",
            side_effect=observe_disable_then_return_stale_role,
        ):
            status, headers, payload = self.request(
                "POST",
                "/login",
                body=urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode(),
                headers={
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": self.config.public_origin,
                },
            )

        self.assertEqual(status, 503)
        self.assertNotIn("set-cookie", headers)
        self.assertNotIn(b"injected audit failure", payload)
        self.assertEqual(self.server.context.sessions.active(), [])

    def test_status_projects_operational_records_to_allowlisted_fields(self) -> None:
        self.login()
        session = {
            "id": "*1",
            "name": "user-two",
            "vpn_address": "10.8.0.2",
            "source_address": "198.51.100.20",
            "uptime": "1m",
            "encoding": "AES-256-GCM",
            "service": "ovpn",
            "rx_bytes": 100,
            "tx_bytes": 200,
            "rx_packets": 3,
            "tx_packets": 4,
            "counter_complete": True,
            "comment": "SENSITIVE-SESSION-COMMENT",
            "session_id": "SENSITIVE-ROUTEROS-SESSION-ID",
            "interface": "SENSITIVE-INTERFACE-NAME",
            "private_key": "SENSITIVE-PRIVATE-KEY",
        }
        resource = {
            "cpu-load": "7",
            "free-memory": "805306368",
            "total-memory": "1073741824",
            "free-hdd-space": "900000000",
            "total-hdd-space": "1000000000",
            "uptime": "1d",
            "board-name": "SENSITIVE-ROUTER-BOARD",
            "serial-number": "SENSITIVE-ROUTER-SERIAL",
            "private_key": "SENSITIVE-ROUTER-PRIVATE-KEY",
        }
        connection = {
            "id": 1,
            "session_id": "*1",
            "vpn_user": "user-two",
            "source_address": "198.51.100.20",
            "vpn_address": "10.8.0.2",
            "encoding": "AES-256-GCM",
            "connected_at": 10,
            "last_seen_at": 20,
            "disconnected_at": None,
            "rx_bytes": 100,
            "tx_bytes": 200,
            "rx_packets": 3,
            "tx_packets": 4,
            "internal_note": "SENSITIVE-CONNECTION-NOTE",
        }
        alert = {
            "id": 4,
            "severity": "warning",
            "title": "Synthetic alert",
            "details": "Synthetic details",
            "created_at": 10,
            "last_seen_at": 20,
            "occurrence_count": 2,
            "action": "SENSITIVE-ALERT-ACTION",
            "target": "SENSITIVE-ALERT-TARGET",
            "acknowledged": 0,
        }
        controls = {
            "vpn_user": "user-two",
            "policy": "full-tunnel",
            "expires_at": None,
            "max_sessions": 5,
            "rate_limit_kbps": 0,
            "dns_mode": "router",
            "notifications": True,
            "quota_mb": 0,
            "schedule": "always",
            "enforcement_state": "",
            "updated_at": 0,
            "future_sensitive_field": "SENSITIVE-FUTURE-CONTROL",
        }
        with (
            mock.patch.object(self.server.context.router, "verify_credentials", return_value=resource),
            mock.patch.object(self.server.context.router, "list_active_ovpn_sessions", return_value=[session]),
            mock.patch.object(self.server.context.router, "list_ovpn_users", return_value=[{
                "id": "user-two", "name": "user-two", "profile": "default",
                "comment": "test", "disabled": False, "password": "SENSITIVE-USER-PASSWORD",
            }]),
            mock.patch.object(self.server.context.store, "user_controls", return_value=controls),
            mock.patch.object(self.server.context.store, "all_user_tags", return_value={"user-two": ["synthetic-tag"]}),
            mock.patch.object(self.server.context.store, "user_template_assignments", return_value={
                "user-two": {"template_id": "template-1", "overrides": ["rate_limit_kbps"]},
            }),
            mock.patch.object(self.server.context.store, "list_policy_templates", return_value=[{
                "id": "template-1", "name": "Synthetic template", "group_name": "default",
                "private_key": "SENSITIVE-TEMPLATE-KEY",
            }]),
            mock.patch.object(self.server.context.store, "recent_deployment_events", return_value=[{
                "id": 1, "version": "2.8.0", "revision": "a" * 40, "status": "running",
                "channel": "canary", "created_at": 10,
                "details": {
                    "source": "synthetic", "private_key": "SENSITIVE-OBSERVABILITY-DETAIL",
                    "nested": {"token": "SENSITIVE-OBSERVABILITY-NESTED-TOKEN"},
                },
            }]),
            mock.patch.object(self.server.context.store, "recent_health_snapshots", return_value=[{
                "id": 2, "overall": "healthy", "healthy_count": 1, "warning_count": 0,
                "unavailable_count": 0,
                "checks": [{
                    "id": "router", "status": "healthy", "private_key": "SENSITIVE-HEALTH-CHECK",
                    "nested": {"token": "SENSITIVE-HEALTH-NESTED-TOKEN"},
                }, {
                    "id": {"token": "SENSITIVE-HEALTH-ID-VALUE"},
                    "status": {"token": "SENSITIVE-HEALTH-STATUS-VALUE"},
                }],
                "private_key": "SENSITIVE-HEALTH-ROOT",
                "created_at": 20,
            }]),
            mock.patch.object(self.server.context.store, "recent_connections", return_value=[connection]),
            mock.patch.object(self.server.context.store, "recent_alerts", return_value=[alert]),
        ):
            status, _, payload = self.request("GET", "/api/status")
            session_id = self.cookie.split("=", 1)[1]
            self.mock.state.admin_group = "read"
            self.server.context.sessions._role_checked_monotonic[session_id] = 0
            read_status, _, read_payload = self.request("GET", "/api/observability")

        self.assertEqual(status, 200)
        self.assertEqual(read_status, 200)
        read_observability = json.loads(read_payload)
        read_only_session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(read_only_session)
        self.assertEqual(read_only_session.role, "read_only")
        self.assertEqual(
            set(read_observability["deployments"][0]),
            {"id", "version", "revision", "status", "channel", "created_at"},
        )
        self.assertEqual(
            set(read_observability["health_timeline"][0]["checks"][0]),
            {"id", "status"},
        )
        self.assertEqual(read_observability["health_timeline"][0]["checks"][1], {"id": "", "status": ""})
        snapshot = json.loads(payload)
        self.assertEqual(
            set(snapshot),
            {
                "users", "sessions", "connections", "alerts", "role", "role_label",
                "capabilities", "router", "observability", "telemetry", "generated_at",
            },
        )
        self.assertEqual(
            set(snapshot["sessions"][0]),
            {
                "id", "name", "vpn_address", "source_address", "uptime", "encoding",
                "service", "rx_bytes", "tx_bytes", "rx_packets", "tx_packets", "counter_complete",
            },
        )
        self.assertEqual(
            set(snapshot["router"]),
            {"cpu-load", "free-memory", "total-memory", "free-hdd-space", "total-hdd-space", "uptime"},
        )
        self.assertEqual(
            set(snapshot["connections"][0]),
            {
                "id", "session_id", "vpn_user", "source_address", "vpn_address", "encoding",
                "connected_at", "last_seen_at", "disconnected_at", "rx_bytes", "tx_bytes",
                "rx_packets", "tx_packets",
            },
        )
        self.assertEqual(
            set(snapshot["alerts"][0]),
            {"id", "severity", "title", "details", "created_at", "last_seen_at", "occurrence_count"},
        )
        self.assertEqual(
            set(snapshot["users"][0]),
            {"id", "name", "profile", "comment", "disabled", "email", "controls", "tags", "template"},
        )
        self.assertEqual(
            set(snapshot["users"][0]["controls"]),
            {
                "vpn_user", "policy", "expires_at", "max_sessions", "rate_limit_kbps",
                "dns_mode", "notifications", "quota_mb", "schedule", "enforcement_state",
                "updated_at", "quota_used_bytes",
            },
        )
        self.assertEqual(snapshot["users"][0]["tags"], ["synthetic-tag"])
        self.assertEqual(
            set(snapshot["users"][0]["template"]),
            {"id", "name", "group_name", "overrides"},
        )
        self.assertEqual(
            set(snapshot["observability"]),
            {"current", "deployments", "health_timeline", "operations_timeline", "rollback", "generated_at"},
        )
        self.assertEqual(set(snapshot["observability"]["current"]), {"version", "revision", "status"})
        self.assertEqual(
            set(snapshot["observability"]["rollback"]),
            {"available", "revision", "version", "message", "data_preserved"},
        )
        self.assertEqual(
            set(snapshot["observability"]["operations_timeline"]),
            {"events", "generated_at", "coverage"},
        )
        self.assertEqual(
            set(snapshot["observability"]["deployments"][0]),
            {"id", "version", "revision", "status", "channel", "created_at"},
        )
        self.assertEqual(
            set(snapshot["observability"]["health_timeline"][0]),
            {"id", "overall", "healthy_count", "warning_count", "unavailable_count", "checks", "created_at"},
        )
        self.assertEqual(set(snapshot["observability"]["health_timeline"][0]["checks"][0]), {"id", "status"})
        for event in snapshot["observability"]["operations_timeline"]["events"]:
            event_fields = {
                "id", "occurred_at", "source", "type", "actor", "target", "outcome", "severity",
                "summary", "clock_skew_seconds", "age_seconds", "related_events", "relationship_summary",
            }
            if event["type"] == "session":
                event_fields.add("timestamp_quality")
            self.assertEqual(set(event), event_fields)
            for relation in event["related_events"]:
                self.assertEqual(set(relation), {"event_id", "source", "relation", "delta_seconds"})
        self.assertEqual(
            set(snapshot["observability"]["operations_timeline"]["coverage"]),
            {"complete", "message"},
        )
        self.assertEqual(
            set(snapshot["telemetry"]),
            {
                "requested_transport", "transport", "socketio_enabled", "namespace", "fallback", "state",
                "last_event_at", "last_reconciliation_at", "event_age_seconds", "reconciliation_age_seconds",
                "event_count", "last_session_event_at", "session_event_age_seconds", "session_events",
                "last_traffic_sample_at", "traffic_sample_age_seconds", "traffic_samples", "reconnects",
                "last_error", "socketio_engine", "protocol_version", "gateway",
            },
        )
        self.assertEqual(
            set(snapshot["telemetry"]["gateway"]),
            {
                "active_clients", "buffered_events", "published_events", "replayed_events",
                "snapshot_recoveries", "rejected_clients", "delivery_observations",
                "delivery_queue_age_seconds", "delivery_queue_age_p95_seconds",
            },
        )
        for sentinel in (
            "SENSITIVE-SESSION-COMMENT", "SENSITIVE-ROUTEROS-SESSION-ID",
            "SENSITIVE-INTERFACE-NAME", "SENSITIVE-PRIVATE-KEY",
            "SENSITIVE-ROUTER-BOARD", "SENSITIVE-ROUTER-SERIAL",
            "SENSITIVE-ROUTER-PRIVATE-KEY",
            "SENSITIVE-CONNECTION-NOTE", "SENSITIVE-ALERT-ACTION", "SENSITIVE-ALERT-TARGET",
            "SENSITIVE-FUTURE-CONTROL", "SENSITIVE-USER-PASSWORD", "SENSITIVE-TEMPLATE-KEY",
            "SENSITIVE-OBSERVABILITY-DETAIL", "SENSITIVE-OBSERVABILITY-NESTED-TOKEN",
            "SENSITIVE-HEALTH-CHECK", "SENSITIVE-HEALTH-NESTED-TOKEN", "SENSITIVE-HEALTH-ROOT",
            "SENSITIVE-HEALTH-ID-VALUE", "SENSITIVE-HEALTH-STATUS-VALUE",
        ):
            self.assertNotIn(sentinel, payload.decode("utf-8"))
            self.assertNotIn(sentinel, read_payload.decode("utf-8"))

    def test_status_keeps_active_session_when_interface_counter_read_fails(self) -> None:
        self.login()
        router = self.server.context.router
        request = router._request

        def fail_interface_counters(method, path, *args, **kwargs):
            if method == "GET" and path == "/interface":
                raise RouterOSError("injected interface-counter read failure")
            return request(method, path, *args, **kwargs)

        with mock.patch.object(router, "_request", side_effect=fail_interface_counters):
            status, _, payload = self.request("GET", "/api/status")

        self.assertEqual(status, 200)
        snapshot = json.loads(payload)
        self.assertEqual(len(snapshot["sessions"]), 1)
        self.assertEqual(snapshot["sessions"][0]["name"], "user-two")
        self.assertEqual(snapshot["sessions"][0]["id"], "*A1")
        self.assertEqual(snapshot["sessions"][0]["vpn_address"], "198.18.0.48")
        self.assertFalse(snapshot["sessions"][0]["counter_complete"])
        self.assertEqual(snapshot["sessions"][0]["rx_bytes"], 0)
        self.assertEqual(snapshot["sessions"][0]["tx_bytes"], 0)

    def test_status_requires_every_data_capability_before_router_reads(self) -> None:
        self.login()
        original_has_capability = has_capability
        for denied_capability in ("users.read", "sessions.read", "health.read"):
            def capability_check(role: str, capability: str, *, denied=denied_capability) -> bool:
                if capability == denied:
                    return False
                return original_has_capability(role, capability)

            with (
                self.subTest(denied_capability=denied_capability),
                mock.patch("app.has_capability", side_effect=capability_check),
                mock.patch.object(self.server.context.router, "verify_credentials") as verify,
                mock.patch.object(self.server.context.router, "list_active_ovpn_sessions") as sessions,
            ):
                status, _, payload = self.request("GET", "/api/status")

            self.assertEqual(status, 403)
            self.assertEqual(
                json.loads(payload)["required_capability"],
                denied_capability,
            )
            verify.assert_not_called()
            sessions.assert_not_called()

    def test_status_does_not_disclose_snapshot_when_session_is_revoked_mid_request(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        router = self.server.context.router
        original_list_sessions = router.list_active_ovpn_sessions

        def revoke_while_status_is_loading(credentials: tuple[str, str]):
            active = original_list_sessions(credentials)
            self.assertTrue(self.server.context.sessions.revoke(session_id))
            return active

        with mock.patch.object(
            router,
            "list_active_ovpn_sessions",
            side_effect=revoke_while_status_is_loading,
        ):
            status, _, payload = self.request("GET", "/api/status", headers={"Cookie": self.cookie})

        self.assertEqual(status, 401)
        self.assertNotIn(b'"sessions"', payload)
        self.assertNotIn(b'"users"', payload)

    def test_automatic_dashboard_polls_do_not_extend_or_revive_idle_session(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        last_seen = session.last_seen

        for path in ("/api/status", "/api/certificate-settings"):
            with self.subTest(path=path):
                status, _, _ = self.request("GET", path)
                self.assertEqual(status, 200)
                unchanged = self.server.context.sessions.get(session_id, touch=False)
                self.assertIsNotNone(unchanged)
                self.assertEqual(unchanged.last_seen, last_seen)

        session.last_seen = time.time() - self.server.context.sessions.idle_seconds - 1
        with (
            mock.patch.object(self.server.context.router, "verify_credentials") as verify,
            mock.patch.object(self.server.context.router, "get_certificate_settings") as certificates,
        ):
            for path in ("/api/status", "/api/certificate-settings"):
                with self.subTest(expired_path=path):
                    status, _, _ = self.request("GET", path)
                    self.assertEqual(status, 401)

        verify.assert_not_called()
        certificates.assert_not_called()

    def test_login_rate_limit_uses_resolved_client_ip(self) -> None:
        body = urllib.parse.urlencode({"username": "admin", "password": "wrong-password"}).encode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.config.public_origin,
        }

        for attempt in range(5):
            with self.subTest(attempt=attempt + 1):
                status, _, _ = self.request("POST", "/login", body=body, headers=headers)
                self.assertEqual(status, 401)

        self.assertEqual(set(self.server.context.limiter._attempts), {"127.0.0.1"})
        status, _, payload = self.request("POST", "/login", body=body, headers=headers)
        self.assertEqual(status, 429, payload.decode())

    def test_routeros_unavailable_login_does_not_consume_bad_password_budget(self) -> None:
        body = urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.config.public_origin,
        }
        with mock.patch.object(
            self.server.context.router,
            "verify_credentials",
            side_effect=RouterOSError("RouterOS is unavailable", failure_kind="timeout"),
        ):
            for attempt in range(6):
                with self.subTest(attempt=attempt + 1):
                    status, _, payload = self.request("POST", "/login", body=body, headers=headers)
                    self.assertEqual(status, HTTPStatus.BAD_GATEWAY, payload.decode())
                    self.assertIn(b"temporarily unavailable", payload)

        self.assertEqual(self.server.context.limiter._attempts, {})
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["action"], "login.unavailable")
        self.login()

    def test_routeros_role_lookup_outage_does_not_consume_bad_password_budget(self) -> None:
        body = urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode()
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "Origin": self.config.public_origin,
        }
        with mock.patch.object(
            self.server.context.router,
            "get_admin_role",
            side_effect=RouterOSError("RouterOS is unavailable", failure_kind="timeout"),
        ):
            for attempt in range(6):
                with self.subTest(attempt=attempt + 1):
                    status, _, payload = self.request("POST", "/login", body=body, headers=headers)
                    self.assertEqual(status, HTTPStatus.BAD_GATEWAY, payload.decode())
                    self.assertIn(b"temporarily unavailable", payload)

        self.assertEqual(self.server.context.limiter._attempts, {})
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["action"], "login.unavailable")
        self.login()

    def test_login_health_and_authentication_boundaries(self) -> None:
        status, headers, payload = self.request("GET", "/healthz")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"status": "ok"})
        self.assertIn("strict-transport-security", headers)

        status, headers, payload = self.request("GET", "/readyz")
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(payload),
            {
                "status": "ready",
                "version": "1.2.3",
                "revision": "0123456789abcdef",
            },
        )
        self.assertIn("strict-transport-security", headers)

        status, _, _ = self.request("GET", "/api/users")
        self.assertEqual(status, 401)

        bad_login = urllib.parse.urlencode({"username": "admin", "password": "wrong"}).encode()
        status, _, page = self.request(
            "POST",
            "/login",
            body=bad_login,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.config.public_origin,
            },
        )
        self.assertEqual(status, 401)
        self.assertIn(b"MikroTik authentication failed", page)
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["action"], "login.failure")

        self.login()
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b"Connected securely", page)
        self.assertIn(b"198.18.0.48", page)
        self.assertIn(b"Terminate", page)
        self.assertIn(b"Byte Graph", page)
        self.assertIn(b"Packet Graph", page)
        self.assertIn(b'data-graph-view="both"', page)
        self.assertIn(b'aria-label="Visible traffic graphs"', page)
        self.assertIn(b"data-rx-packets=\"387\"", page)
        self.assertIn(b"router.example.test", page)
        self.assertNotIn(b">Session</span>", page)
        self.assertNotIn(b"New Terminal", page)
        self.assertNotIn(b"Workspace:", page)
        self.assertIn(b'data-view="vpn-users"', page)
        self.assertIn(b'data-view="live-sessions"', page)
        self.assertIn(b'data-view="profile-security"', page)
        self.assertIn(b'data-view="service-health"', page)
        self.assertIn(b'data-view="connection-doctor"', page)
        self.assertIn(b'data-connection-doctor-form', page)
        self.assertIn(b'data-exposure-doctor', page)
        self.assertIn(b'data-view="audit-log"', page)
        self.assertIn(b"Change History", page)

        self.assertIn(b"not a complete durable history", page)
        self.assertIn(b"up to 100 entries \xc2\xb7 audit only", page)
        self.assertIn(b'data-history-category aria-label="Filter history by event"', page)
        self.assertIn(b'data-history-outcome aria-label="Filter history by outcome"', page)
        self.assertIn(b'data-history-created=', page)
        self.assertNotIn(b"What changed", page)
        self.assertIn(b"Service health", page)
        self.assertIn(b"Profile issuing prerequisites", page)
        self.assertIn(b"1d 06:12:00s", page)
        self.assertIn(b"Security posture", page)
        self.assertIn(b'<details class="dashboard-reference">', page)
        self.assertIn(b"How this dashboard works", page)
        self.assertIn(b"View connections", page)
        self.assertIn(
            f'<img class="dashboard-openvpn-logo" src="/static/openvpn-logo.svg?v={ASSET_VERSION}" alt="OpenVPN">'.encode(),
            page,
        )
        self.assertIn(b"Manage devices", page)
        self.assertIn(b"Connection history", page)
        self.assertIn(b'<details class="user-activity-disclosure">', page)
        self.assertIn(b"Account details", page)
        self.assertIn(b">MONITOR</span>", page)
        self.assertIn(b">MANAGE</span>", page)
        self.assertIn(b">ADMINISTRATION</span>", page)
        for label in (b"Dashboard", b"VPN Users", b"Connections", b"Device Profiles", b"Policy Templates", b"Service Health", b"Connection Doctor", b"Change History", b"Setup Planner"):
            self.assertIn(b'aria-label="' + label + b'"', page)
        self.assertIn(b"RouterOS certificate inventory", page)
        self.assertIn(b'<details class="panel profile-onboarding">', page)
        self.assertIn(b"First time adding a phone?", page)
        self.assertIn(b"Device posture", page)
        self.assertIn(b"Read-only certificate checks for every managed profile", page)
        self.assertIn(b"Inventory match", page)
        self.assertIn(b"does not prove CRL enforcement", page)
        self.assertNotIn(b"Certificate revocation checks", page)
        self.assertNotIn(b"Per-device revocation needs CA migration", page)
        overview_start = page.index(b'data-view="overview"')
        profiles_start = page.index(b'data-view="profile-security"')
        self.assertNotIn(b"RouterOS CRL configuration", page[overview_start:profiles_start])
        self.assertIn(b"RouterOS CRL configuration", page[profiles_start:])

        self.assertIn(b"ovpn-user-one-device-a", page)
        self.assertIn(b"What happens under the hood", page)
        self.assertIn(b"OpenVPN foundations", page)
        self.assertIn(b"Deployment history", page)
        self.assertIn(b"Health timeline", page)
        self.assertIn(b"Rollback visibility", page)
        self.assertIn(b"Post-install verification", page)
        self.assertIn(b"data-post-install-verify", page)
        self.assertIn(b"Copy next steps", page)
        self.assertIn(b"Suspend access now", page)
        self.assertIn(b"Last activity", page)
        self.assertIn(b"Transferred", page)
        self.assertIn(b"Concurrent devices", page)
        self.assertIn(b"RouterOS DNS (192.0.2.1)", page)
        self.assertIn(b'data-user-max-sessions="5"', page)
        for speed in (b"5 Mbps", b"10 Mbps", b"25 Mbps", b"50 Mbps", b"100 Mbps"):
            self.assertIn(speed, page)
        status, _, payload = self.request("GET", "/api/users")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["name"] for item in json.loads(payload)["users"]],
            ["user-one", "user-two"],
        )

        status, _, payload = self.request("GET", "/api/status")
        self.assertEqual(status, 200)
        snapshot = json.loads(payload)
        self.assertEqual(snapshot["sessions"][0]["name"], "user-two")
        self.assertEqual(snapshot["sessions"][0]["tx_bytes"], 192455)
        self.assertEqual(snapshot["sessions"][0]["rx_packets"], 387)
        self.assertEqual(snapshot["role"], "owner")
        self.assertEqual(snapshot["role_label"], "Owner")
        self.assertIn("*", snapshot["capabilities"])

        self.assertEqual(snapshot["sessions"][0]["tx_packets"], 825)
        self.assertEqual(snapshot["router"]["cpu-load"], "7")
        self.assertIn("observability", snapshot)
        self.assertEqual(snapshot["observability"]["current"]["revision"], "0123456789abcdef")

        status, _, payload = self.request("GET", "/api/observability")
        self.assertEqual(status, 200)
        observability = json.loads(payload)
        self.assertEqual(observability["current"]["version"], "1.2.3")
        self.assertTrue(observability["health_timeline"])

        status, _, payload = self.request("GET", "/api/service-health")
        self.assertEqual(status, 200)
        health = json.loads(payload)
        self.assertEqual(health["overall"], "healthy")
        self.assertEqual(
            {item["id"] for item in health["checks"]},
            {"routeros-rest", "dashboard-storage", "openvpn-service", "profile-issuing", "certificate-inventory", "router-capacity"},
        )

        status, _, payload = self.request("GET", "/api/setup-preflight")
        self.assertEqual(status, 200)
        preflight = json.loads(payload)
        self.assertEqual(preflight["checks"][0]["status"], "pass")
        self.assertEqual(len(preflight["checks"]), 9)
        self.assertIn("Certificate authority", {item["name"] for item in preflight["checks"]})
        self.assertIn("Persistent storage", {item["name"] for item in preflight["checks"]})
        self.assertEqual(preflight["checks"][-1]["status"], "manual")

        status, _, payload = self.json_request(
            "POST",
            "/api/setup-plan",
            {
                "origin": "https://vpn.example.test",
                "image": "ghcr.io/example/mikrotik-openvpn-gui:sha-" + "a" * 40 + "-arm64@sha256:" + "b" * 64,
                "storage": "/disk1/vpn-dashboard",
                "subnet": "172.31.250.0/30",
                "lan": "192.0.2.0/24",
            },
        )
        self.assertEqual(status, 200)
        plan = json.loads(payload)["plan"]
        self.assertIn("REVIEW ONLY", plan)
        self.assertIn("CA PRESERVATION GATE", plan)
        self.assertIn("/interface/ovpn-server/server/print detail", plan)

        status, _, payload = self.json_request(
            "POST",
            "/api/setup-plan",
            {
                "origin": "https://vpn.example.test",
                "image": "ghcr.io/example/mikrotik-openvpn-gui:sha-" + "a" * 40 + "-arm64",
                "storage": "/disk1/vpn-dashboard",
                "subnet": "172.31.250.0/30",
                "lan": "192.0.2.0/24",
            },
        )
        self.assertEqual(status, 400)

        status, _, _ = self.json_request(
            "POST",
            "/api/setup-plan",
            {
                "origin": "https://vpn.example.test", "image": "ghcr.io/example/gui:latest",
                "storage": "/disk1/vpn-dashboard", "subnet": "172.31.250.0/30", "lan": "192.0.2.0/24",
            },
        )
        self.assertEqual(status, 400)

        status, _, _ = self.json_request(
            "POST",
            "/api/setup-plan",
            {
                "origin": "https://vpn.example.test",
                "image": "ghcr.io/example/mikrotik-openvpn-gui:sha-" + "a" * 40 + "-arm64@sha256:" + "b" * 64,
                "storage": "/disk1/vpn-dashboard",
                "subnet": "172.31.250.0/31",
                "lan": "192.0.2.0/24",
            },
        )
        self.assertEqual(status, 400)
        self.assertEqual(snapshot["connections"][0]["vpn_user"], "user-two")
        self.assertEqual(
            {item["name"]: item["email"] for item in snapshot["users"]},
            {"user-one": "", "user-two": ""},
        )

        status, headers, payload = self.request("GET", "/api/connections.csv")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/csv; charset=utf-8")
        self.assertIn("vpn-connection-history.csv", headers["content-disposition"])
        self.assertEqual(
            next(csv.reader(io.StringIO(payload.decode("utf-8-sig")))),
            ["user", "connected", "disconnected", "source_ip", "vpn_ip", "encryption",
             "received_bytes", "sent_bytes", "received_packets", "sent_packets"],
        )
        self.assertIn(b"user-two", payload)

        status, headers, payload = self.request("GET", "/api/usage.csv")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/csv; charset=utf-8")
        self.assertIn("vpn-monthly-usage.csv", headers["content-disposition"])
        self.assertEqual(
            next(csv.reader(io.StringIO(payload.decode("utf-8-sig")))),
            ["user", "period_start", "connections", "received_bytes", "sent_bytes",
             "total_bytes", "quota_mb", "last_seen"],
        )
        self.assertIn(b"total_bytes", payload)
        self.assertIn(b"user-two", payload)

        status, headers, payload = self.request("GET", "/api/audit.csv")
        self.assertEqual(status, 200)
        self.assertIn("vpn-change-history.csv", headers["content-disposition"])
        self.assertIn(b"operator,action,target,result", payload)

        status, headers, payload = self.request("GET", "/api/audit.json?from=2000-01-01&to=2100-01-01")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        self.assertIn("vpn-change-history.json", headers["content-disposition"])
        self.assertIn("entries", json.loads(payload))

        self.server.context.store.audit(
            actor="timeline-operator", action="user.create", target="timeline-user",
            status="success", details={"password": "must-not-export"},
        )
        status, headers, payload = self.request(
            "GET", "/api/operations-timeline.json?from=2000-01-01&to=2100-01-01"
        )
        self.assertEqual(status, 200)
        self.assertIn("vpn-operations-timeline.json", headers["content-disposition"])
        timeline = json.loads(payload)
        self.assertFalse(timeline["coverage"]["complete"])
        self.assertTrue(any(item["source"] == "dashboard audit" for item in timeline["events"]))
        self.assertNotIn(b"must-not-export", payload)

        status, _, payload = self.request("GET", "/api/operations-timeline.json?from=invalid")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(payload)["error"], "from must be a date in YYYY-MM-DD format")

        status, _, payload = self.request("GET", "/api/audit.csv?from=not-a-date")
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(payload)["error"], "from must be a date in YYYY-MM-DD format")

        status, headers, payload = self.request("GET", "/api/backups/metadata.zip")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/zip")
        self.assertIn("vpn-dashboard-backup-", headers["content-disposition"])
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertEqual(set(archive.namelist()), {"manifest.json", "metadata.json"})
            manifest = json.loads(archive.read("manifest.json"))
            metadata = archive.read("metadata.json")
        self.assertEqual(manifest["files"]["metadata.json"], hashlib.sha256(metadata).hexdigest())
        self.assertNotIn(b"routerpass", metadata)

        status, _, payload = self.json_request(
            "POST", "/api/backups/preflight",
            {"manifest": manifest, "metadata_sha256": hashlib.sha256(metadata).hexdigest()},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["compatible"])

        archive_bytes = io.BytesIO()
        with zipfile.ZipFile(archive_bytes, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("manifest.json", json.dumps(manifest))
            archive.writestr("metadata.json", metadata)
        status, _, payload = self.json_request(
            "POST", "/api/backups/validate",
            {"archive_base64": base64.b64encode(archive_bytes.getvalue()).decode("ascii")},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["compatible"])

        status, _, payload = self.json_request(
            "POST", "/api/backups/restore-plan",
            {"archive_base64": base64.b64encode(archive_bytes.getvalue()).decode("ascii")},
        )
        self.assertEqual(status, 200)
        restore_plan = json.loads(payload)
        self.assertTrue(restore_plan["compatible"])
        self.assertFalse(restore_plan["restore_available"])
        self.assertGreaterEqual(len(restore_plan["steps"]), 4)
        self.assertIn("No data was restored", restore_plan["message"])

        status, _, payload = self.json_request(
            "POST", "/api/backups/preflight",
            {"manifest": manifest, "metadata_sha256": "0" * 64},
        )
        self.assertEqual(status, 400)
        self.assertFalse(json.loads(payload)["compatible"])

    def test_user_list_api_drops_unapproved_routeros_fields(self) -> None:
        self.login()
        router_user = {
            "id": "*SECRET",
            "name": "least-privilege-user",
            "profile": "default-encryption",
            "comment": "test account",
            "disabled": False,
            "service": "ovpn",
            "password": "must-not-leak",
            "private_key": "must-not-leak",
            "future_routeros_field": "must-not-leak",
        }
        with mock.patch.object(
            self.server.context.router, "list_ovpn_users", return_value=[router_user]
        ):
            status, _, payload = self.request("GET", "/api/users")

        self.assertEqual(status, 200)
        user = json.loads(payload)["users"][0]
        self.assertEqual(
            set(user),
            {"id", "name", "profile", "comment", "disabled", "email", "controls", "tags", "template"},
        )
        self.assertEqual(user["id"], "*SECRET")
        self.assertEqual(user["name"], "least-privilege-user")
        self.assertNotIn("must-not-leak", payload.decode("utf-8"))
        self.assertNotIn("service", user)

    def test_certificate_settings_api_is_read_only_and_projects_only_safe_fields(self) -> None:
        self.login()
        observed = {
            "crl_download": True,
            "crl_use": True,
            "crl_store": "system",
            "downloaded_ovpn_ca_crl_current": True,
            "router_hosted_ovpn_ca_crl": False,
            "crl_ready": True,
            "ca_name": "PRIVATE-CA-NAME",
            "private_key": "PRIVATE-KEY-MUST-NOT-LEAK",
            "crl_contents": "CRL-CONTENTS-MUST-NOT-LEAK",
        }
        with mock.patch.object(
            self.server.context.router, "get_certificate_settings", return_value=observed
        ) as read_settings:
            status, _, payload = self.request("GET", "/api/certificate-settings")

        self.assertEqual(status, 200)
        response = json.loads(payload)
        self.assertEqual(
            set(response),
            {
                "status", "observed_at", "crl_download", "crl_use", "crl_store",
                "downloaded_ovpn_ca_crl_current", "router_hosted_ovpn_ca_crl",
            },
        )
        self.assertEqual(response["status"], "observed")
        self.assertEqual(response["crl_store"], "system")
        self.assertTrue(response["downloaded_ovpn_ca_crl_current"])
        self.assertNotIn("MUST-NOT-LEAK", payload.decode("utf-8"))
        self.assertNotIn("PRIVATE-CA-NAME", payload.decode("utf-8"))
        read_settings.assert_called_once()

    def test_certificate_settings_api_reports_unknown_when_routeros_read_fails(self) -> None:
        self.login()
        with mock.patch.object(
            self.server.context.router,
            "get_certificate_settings",
            side_effect=RouterOSError("sensitive RouterOS response must not leak"),
        ):
            status, _, payload = self.request("GET", "/api/certificate-settings")

        self.assertEqual(status, 502)
        self.assertEqual(set(json.loads(payload)), {"status", "observed_at"})
        self.assertEqual(json.loads(payload)["status"], "unavailable")
        self.assertNotIn("sensitive", payload.decode("utf-8"))

    def test_certificate_settings_api_accepts_routeros_ram_store(self) -> None:
        self.login()
        with mock.patch.object(
            self.server.context.router,
            "get_certificate_settings",
            return_value={"crl_store": "ram"},
        ):
            status, _, payload = self.request("GET", "/api/certificate-settings")

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["crl_store"], "ram")

    def test_policy_template_api_projects_storage_records_to_allowlisted_fields(self) -> None:
        self.login()
        template = {
            "id": "synthetic-template",
            "name": "Synthetic template",
            "description": "Synthetic description",
            "group_name": "Support",
            "controls": {
                "policy": "lan-only",
                "expires_at": None,
                "max_sessions": 2,
                "rate_limit_kbps": 1024,
                "dns_mode": "router",
                "notifications": True,
                "quota_mb": 5120,
                "schedule": "weekdays",
                "private_key": "SENSITIVE-TEMPLATE-CONTROL",
            },
            "protected": False,
            "created_at": 100,
            "updated_at": 200,
            "private_key": "SENSITIVE-TEMPLATE-RECORD",
        }
        assignment = {
            "vpn_user": "synthetic-user",
            "template_id": "synthetic-template",
            "overrides": ["rate_limit_kbps", "private_key"],
            "assigned_at": 300,
            "updated_at": 400,
            "private_key": "SENSITIVE-ASSIGNMENT-RECORD",
        }
        with (
            mock.patch.object(self.server.context.store, "list_policy_templates", return_value=[template]),
            mock.patch.object(
                self.server.context.store,
                "user_template_assignments",
                return_value={"synthetic-user": assignment},
            ),
        ):
            status, _, payload = self.request("GET", "/api/policy-templates")

        self.assertEqual(status, 200)
        response = json.loads(payload)
        self.assertEqual(set(response), {"templates", "assignments"})
        self.assertEqual(len(response["templates"]), 1)
        public_template = response["templates"][0]
        self.assertEqual(
            set(public_template),
            {"id", "name", "description", "group_name", "controls", "protected", "created_at", "updated_at"},
        )
        self.assertEqual(
            set(public_template["controls"]),
            {"policy", "expires_at", "max_sessions", "rate_limit_kbps", "dns_mode", "notifications", "quota_mb", "schedule"},
        )
        public_assignment = response["assignments"]["synthetic-user"]
        self.assertEqual(
            set(public_assignment),
            {"vpn_user", "template_id", "overrides", "assigned_at", "updated_at"},
        )
        self.assertEqual(public_assignment["overrides"], ["rate_limit_kbps"])
        self.assertNotIn("SENSITIVE-", payload.decode("utf-8"))

    def test_filtered_timeline_export_has_no_references_to_omitted_events(self) -> None:
        self.login()
        start_at = 1767312000  # 2026-01-02 00:00:00 UTC
        store = self.server.context.store
        store.record_health_snapshot(
            {"overall": "healthy", "checks": []}, now=start_at - 30,
        )
        store.observe_sessions(
            [{"id": "*timeline-session", "name": "timeline-user", "uptime": "1m"}],
            now=start_at + 90,
        )

        status, _, payload = self.request(
            "GET", "/api/operations-timeline.json?from=2026-01-02&to=2026-01-02"
        )
        self.assertEqual(status, 200)
        timeline = json.loads(payload)
        event_ids = {event["id"] for event in timeline["events"]}
        self.assertTrue(event_ids)
        self.assertTrue(all(event["type"] == "session" for event in timeline["events"]))
        for event in timeline["events"]:
            self.assertTrue(
                all(item["event_id"] in event_ids for item in event["related_events"])
            )

    def test_sensitive_route_matrix_fails_closed_for_anonymous_requests(self) -> None:
        """Cover route dispatch auth gates independently of individual handler tests."""
        read_routes = (
            "/api/telemetry", "/api/admin/sessions", "/api/admin/api-tokens",
            "/api/reports/compliance.zip", "/api/reports/diagnostics.zip",
            "/api/release/verify", "/api/policy-templates", "/api/users", "/api/certificate-settings",
            "/api/bulk/views", "/api/status", "/api/service-health",
            "/api/observability", "/api/setup-preflight", "/api/audit.csv",
            "/api/audit.json", "/api/operations-timeline.json", "/api/backups/metadata.zip", "/api/connections.csv",
            "/api/usage.csv", "/metrics", "/api/events",
        )
        write_routes = (
            "/api/auth/reauthenticate", "/api/users", "/api/users/preview", "/api/users/test-user/preview", "/api/bulk/preview",
            "/api/auth/sessions/revoke-others",
            "/api/bulk/apply", "/api/bulk/views", "/api/setup-plan",
            "/api/openvpn-foundation-plan", "/api/admin/api-tokens",
            "/api/admin/break-glass/plan", "/api/network/segment-plan",
            "/api/profile/diagnose", "/api/connection-doctor",
            "/api/security/exposure-doctor", "/api/backups/preflight",
            "/api/backups/validate", "/api/backups/restore-plan",
            "/api/policy-templates", "/api/policy-templates/test/preview",
            "/api/policy-templates/test/apply", "/api/users/test-user/suspend",
            "/api/users/test-user/delete/preview",
            "/api/sessions/test-session/preview",
            "/api/users/test-user/restore", "/api/users/test-user/restore/preview",
            "/api/users/test-user/suspend/preview",
            "/api/users/test-user/profiles", "/api/users/test-user/profiles/preview",
            "/api/profile-migrations/legacy-user-one-phone/steps/imported",
            "/api/profile-migrations/legacy-user-one-phone/revoke/preview",
            "/api/profile-migrations/legacy-user-one-phone/revoke",
            "/api/devices/test-device/revoke/preview", "/api/devices/test-device/revoke",
            "/api/users/test-user/duplicate", "/api/users/test-user/duplicate/preview", "/api/alerts/1/ack",
        )
        patch_routes = (
            "/api/policy-templates/test-template", "/api/users/test-user",
        )
        delete_routes = (
            "/api/admin/api-tokens/token-12345678", "/api/admin/sessions/session-1",
            "/api/bulk/views/view-1", "/api/sessions/session-1", "/api/users/test-user",
        )
        mutation_routes = {
            "POST": write_routes,
            "PATCH": patch_routes,
            "DELETE": delete_routes,
        }
        routes_by_method = {"GET": read_routes, **mutation_routes}

        def persistent_local_state() -> dict[str, Any]:
            store = self.server.context.store
            return {
                "audit": store.recent_audit(100),
                "alerts": store.recent_alerts(100, include_acknowledged=True),
                "views": store.saved_views(),
                "tokens": store.list_api_tokens(include_revoked=True),
            }

        self.cookie = ""
        self.csrf = ""
        before_mutations = list(self.mock.state.mutation_requests)
        before_anonymous_state = persistent_local_state()

        for path in read_routes:
            with self.subTest(method="GET", path=path):
                status, _, payload = self.request("GET", path)
                self.assertEqual(status, 401)
                self.assertNotIn(b"routerpass", payload)
                self.assertNotIn(b"user-one", payload)

        body = json.dumps({}).encode("utf-8")
        for method, paths in mutation_routes.items():
            for path in paths:
                with self.subTest(method=method, path=path):
                    status, _, payload = self.request(
                        method, path, body=body, headers={"Content-Type": "application/json"},
                    )
                    self.assertEqual(status, 401)
                    self.assertNotIn(b"routerpass", payload)
                    self.assertNotIn(b"user-one", payload)

        self.assertEqual(persistent_local_state(), before_anonymous_state)
        self.login()
        before_csrf_denials_state = persistent_local_state()
        for method, paths in mutation_routes.items():
            for path in paths:
                with self.subTest(method=f"{method} without CSRF", path=path):
                    status, _, payload = self.request(
                        method, path, body=body,
                        headers={"Content-Type": "application/json", "Cookie": self.cookie},
                    )
                    self.assertEqual(status, 403)
                    self.assertNotIn(b"routerpass", payload)
                    self.assertNotIn(b"user-one", payload)

        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(persistent_local_state(), before_csrf_denials_state)

        # Bind route inventory to the exact tuples exercised above. The current
        # dispatch forms are either a literal equality or a raw-regex fullmatch;
        # an alternate /api string form must update this guard explicitly.
        for method, examples in routes_by_method.items():
            source = inspect.getsource(getattr(DashboardHandler, f"do_{method}"))
            all_api_strings = set(re.findall(r'["\'](/api/[^"\']+)["\']', source))
            literal_routes = set(re.findall(r'path == "(/api/[^\"]+)"', source))
            patterns = re.findall(r're\.fullmatch\(r"(/api/[^\"]+)"\s*,\s*path\)', source)
            with self.subTest(method=method, route_inventory="dispatch forms"):
                self.assertEqual(all_api_strings, literal_routes | set(patterns))
            for path in literal_routes:
                with self.subTest(method=method, literal=path):
                    self.assertIn(path, examples)
            for pattern in patterns:
                with self.subTest(method=method, pattern=pattern):
                    self.assertTrue(
                        any(re.fullmatch(pattern, path) for path in examples),
                        f"route pattern {pattern!r} has no executed anonymous/CSRF case",
                    )

    def test_read_only_role_cannot_cross_audit_or_mutation_capability_boundaries(self) -> None:
        self.mock.state.admin_group = "read"
        self.login()
        self.server.context.store.audit(
            actor="admin", action="security.review", target="private-audit-marker",
            status="success", details="audit rows require audit.read",
        )
        cookie = self.cookie
        self.assertTrue(cookie)
        status, _, page = self.request("GET", "/dashboard", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        self.assertNotIn(b"private-audit-marker", page)
        self.assertNotIn(b'href="#audit-log"', page)
        status, _, payload = self.request("GET", "/api/observability", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        operations = json.loads(payload)["operations_timeline"]["events"]
        self.assertFalse(any(item["source"] == "dashboard audit" for item in operations))
        self.assertFalse(any(item.get("actor") for item in operations))
        status, _, payload = self.request("GET", "/api/telemetry", headers={"Cookie": cookie})
        self.assertEqual(status, 200)
        telemetry_status = json.loads(payload)
        self.assertIn("transport", telemetry_status)
        self.assertNotIn("sessions", telemetry_status)
        self.assertNotIn("router_password", payload.decode("utf-8").casefold())
        csrf_headers = {
            "Content-Type": "application/json",
            "Cookie": cookie,
            "X-CSRF-Token": self.csrf,
        }
        before_mutations = list(self.mock.state.mutation_requests)

        for path in (
            "/api/admin/api-tokens", "/api/audit.csv", "/api/audit.json", "/api/operations-timeline.json",
            "/api/reports/compliance.zip", "/api/backups/metadata.zip",
        ):
            with self.subTest(method="GET", path=path):
                status, _, payload = self.request("GET", path, headers={"Cookie": cookie})
                self.assertEqual(status, 403)
                self.assertNotIn(b"routerpass", payload)

        for path in (
            "/api/users", "/api/users/preview", "/api/policy-templates",
            "/api/policy-templates/test-template/preview", "/api/policy-templates/test-template/apply",
            "/api/users/test-user/profiles", "/api/users/test-user/profiles/preview",
            "/api/users/test-user/duplicate", "/api/users/test-user/duplicate/preview",
            "/api/users/test-user/suspend", "/api/users/test-user/restore",
            "/api/users/test-user/restore/preview",
            "/api/users/test-user/suspend/preview", "/api/devices/test-device/revoke/preview",
            "/api/devices/test-device/revoke", "/api/admin/api-tokens", "/api/alerts/1/ack",
            "/api/profile-migrations/legacy-user-one-phone/revoke/preview",
            "/api/profile-migrations/legacy-user-one-phone/revoke",
            "/api/openvpn-foundation-plan", "/api/admin/break-glass/plan",
            "/api/network/segment-plan", "/api/backups/preflight",
            "/api/backups/validate", "/api/backups/restore-plan",
        ):
            with self.subTest(method="POST", path=path):
                status, _, payload = self.request(
                    "POST", path, body=b"{}", headers=csrf_headers,
                )
                self.assertEqual(status, 403)
                self.assertNotIn(b"routerpass", payload)

        for action in ("suspend", "revoke", "tag"):
            for endpoint in ("preview", "apply"):
                path = f"/api/bulk/{endpoint}"
                body = json.dumps({"action": action, "user_ids": ["*1"], "tag": "reviewed"}).encode()
                with self.subTest(method="POST", path=path, action=action):
                    status, _, payload = self.request("POST", path, body=body, headers=csrf_headers)
                    self.assertEqual(status, 403)
                    self.assertNotIn(b"routerpass", payload)

        for path in ("/api/policy-templates/test-template", "/api/users/test-user"):
            with self.subTest(method="PATCH", path=path):
                status, _, payload = self.request("PATCH", path, body=b"{}", headers=csrf_headers)
                self.assertEqual(status, 403)
                self.assertNotIn(b"routerpass", payload)

        for path in (
            "/api/admin/api-tokens/token-12345678", "/api/admin/sessions/session-1",
            "/api/sessions/session-1", "/api/users/test-user",
        ):
            with self.subTest(method="DELETE", path=path):
                status, _, payload = self.request("DELETE", path, body=b"{}", headers=csrf_headers)
                self.assertEqual(status, 403)
                self.assertNotIn(b"routerpass", payload)

        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

    def test_role_capability_denials_precede_every_guarded_route_family(self) -> None:
        """Exercise each high-impact capability guard for every role denied it."""
        guarded_routes = {
            "audit.read": ("GET", "/api/audit.json", {"read"}),
            "security.manage": ("GET", "/api/admin/api-tokens", {"operator", "audit", "read"}),
            "backup.manage": ("GET", "/api/backups/metadata.zip", {"security-operator", "audit", "read"}),
            "users.manage": ("POST", "/api/users/preview", {"security-operator", "audit", "read"}),
            "profiles.manage": ("POST", "/api/users/test-user/profiles/preview", {"audit", "read"}),
            "policies.manage": ("POST", "/api/policy-templates/test/preview", {"security-operator", "audit", "read"}),
            "session.manage": ("DELETE", "/api/admin/sessions/session-999999", {"audit", "read"}),
            "device.manage": ("POST", "/api/devices/test-device/revoke/preview", {"operator", "audit", "read"}),
            "alert.manage": ("POST", "/api/alerts/999999/ack", {"security-operator", "audit", "read"}),
        }
        body = b"{}"
        before_mutations = list(self.mock.state.mutation_requests)
        denied_count = 0

        for group in ("security-operator", "operator", "audit", "read"):
            self.mock.state.admin_group = group
            self.cookie = ""
            self.csrf = ""
            self.login()
            headers = {"Content-Type": "application/json", "X-CSRF-Token": self.csrf}
            for capability, (method, path, denied_groups) in guarded_routes.items():
                if group not in denied_groups:
                    continue
                with self.subTest(group=group, capability=capability, path=path):
                    status, _, payload = self.request(method, path, body=body, headers=headers)
                    self.assertEqual(status, 403)
                    self.assertIn(capability.encode(), payload)
                    self.assertNotIn(b"routerpass", payload)
                    denied_count += 1

        self.assertEqual(denied_count, 23)
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

    def test_sensitive_management_route_matrix_denies_all_disallowed_role_variants(self) -> None:
        """Cover preview/apply/delete variants and action-selected bulk gates."""
        denied = {
            "audit.read": {"read"},
            "security.manage": {"operator", "audit", "read"},
            "backup.manage": {"security-operator", "audit", "read"},
            "users.manage": {"security-operator", "audit", "read"},
            "profiles.manage": {"audit", "read"},
            "policies.manage": {"security-operator", "audit", "read"},
            "session.manage": {"audit", "read"},
            "device.manage": {"operator", "audit", "read"},
            "alert.manage": {"security-operator", "audit", "read"},
        }
        route_cases = [
            ("audit.read", "GET", "/api/audit.csv", {}),
            ("audit.read", "GET", "/api/audit.json", {}),
            ("audit.read", "GET", "/api/operations-timeline.json", {}),
            ("audit.read", "GET", "/api/reports/compliance.zip", {}),
            ("security.manage", "GET", "/api/admin/api-tokens", {}),
            ("security.manage", "POST", "/api/admin/api-tokens", {}),
            ("security.manage", "DELETE", "/api/admin/api-tokens/token-12345678", {}),
            ("security.manage", "POST", "/api/admin/break-glass/plan", {}),
            ("security.manage", "POST", "/api/openvpn-foundation-plan", {}),
            ("backup.manage", "GET", "/api/backups/metadata.zip", {}),
            ("backup.manage", "POST", "/api/backups/preflight", {}),
            ("backup.manage", "POST", "/api/backups/validate", {}),
            ("backup.manage", "POST", "/api/backups/restore-plan", {}),
            ("users.manage", "POST", "/api/users", {}),
            ("users.manage", "POST", "/api/users/preview", {}),
            ("users.manage", "POST", "/api/users/test-user/preview", {}),
            ("users.manage", "POST", "/api/users/test-user/suspend", {}),
            ("users.manage", "POST", "/api/users/test-user/suspend/preview", {}),
            ("users.manage", "POST", "/api/users/test-user/restore", {}),
            ("users.manage", "POST", "/api/users/test-user/restore/preview", {}),
            ("users.manage", "POST", "/api/users/test-user/duplicate", {}),
            ("users.manage", "POST", "/api/users/test-user/duplicate/preview", {}),
            ("users.manage", "POST", "/api/users/test-user/delete/preview", {}),
            ("users.manage", "PATCH", "/api/users/test-user", {}),
            ("users.manage", "DELETE", "/api/users/test-user", {}),
            ("profiles.manage", "POST", "/api/users/test-user/profiles", {}),
            ("profiles.manage", "POST", "/api/users/test-user/profiles/preview", {}),
            ("profiles.manage", "POST", "/api/profile-migrations/legacy-user-one-phone/steps/imported", {}),
            ("policies.manage", "POST", "/api/policy-templates/test/preview", {}),
            ("policies.manage", "POST", "/api/policy-templates/test/apply", {}),
            ("policies.manage", "PATCH", "/api/policy-templates/test", {}),
            ("policies.manage", "POST", "/api/network/segment-plan", {}),
            ("session.manage", "POST", "/api/sessions/session-1/preview", {}),
            ("session.manage", "DELETE", "/api/admin/sessions/session-1", {}),
            ("session.manage", "DELETE", "/api/sessions/session-1", {}),
            ("device.manage", "POST", "/api/devices/device-1/revoke/preview", {}),
            ("device.manage", "POST", "/api/devices/device-1/revoke", {}),
            ("device.manage", "POST", "/api/profile-migrations/legacy-user-one-phone/revoke/preview", {}),
            ("device.manage", "POST", "/api/profile-migrations/legacy-user-one-phone/revoke", {}),
            ("alert.manage", "POST", "/api/alerts/999999/ack", {}),
            ("users.manage", "POST", "/api/bulk/preview", {"action": "suspend", "user_ids": ["*1"]}),
            ("users.manage", "POST", "/api/bulk/apply", {"action": "tag", "user_ids": ["*1"], "tag": "review"}),
            ("device.manage", "POST", "/api/bulk/preview", {"action": "revoke", "user_ids": ["*1"]}),
            ("device.manage", "POST", "/api/bulk/apply", {"action": "revoke", "user_ids": ["*1"]}),
        ]
        before_mutations = list(self.mock.state.mutation_requests)
        denied_cases = 0
        allowed_cases = 0
        role_groups = ("owner", "security-operator", "operator", "audit", "read")

        for group in role_groups:
            self.mock.state.admin_group = group
            self.cookie = ""
            self.csrf = ""
            self.login()
            headers = {"Content-Type": "application/json", "X-CSRF-Token": self.csrf}
            for capability, method, path, body in route_cases:
                with self.subTest(group=group, capability=capability, method=method, path=path):
                    status, _, payload = self.request(
                        method, path, body=json.dumps(body).encode(), headers=headers,
                    )
                    self.assertNotIn(b"routerpass", payload)
                    if group in denied[capability]:
                        self.assertEqual(status, 403)
                        self.assertIn(capability.encode(), payload)
                        denied_cases += 1
                    else:
                        self.assertTrue(
                            has_capability(group, capability),
                            f"{group} is missing the declared {capability} capability",
                        )
                        self.assertNotEqual(
                            status, 403,
                            f"{group} has {capability} but {method} {path} denied it: {payload!r}",
                        )
                        allowed_cases += 1

        self.assertEqual(denied_cases, 118)
        self.assertEqual(allowed_cases + denied_cases, len(role_groups) * len(route_cases))
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

    def test_api_dispatch_has_exhaustive_role_capability_inventory(self) -> None:
        """Bind every API dispatch branch to a role matrix and verify denial side effects."""
        def literal(path: str) -> str:
            return f"literal:{path}"

        def regex(pattern: str) -> str:
            return f"regex:{pattern}"

        # (method, source dispatch form, concrete request path, required
        # capabilities, request body). An empty capability tuple marks the
        # intentionally RouterOS-session/CSRF-only routes. Bulk action routes
        # have separate rows because their required capability is action-bound.
        route_cases = [
            ("POST", literal("/api/auth/reauthenticate"), "/api/auth/reauthenticate", (), {}),
            ("POST", literal("/api/auth/sessions/revoke-others"), "/api/auth/sessions/revoke-others", (), {}),
            ("GET", literal("/api/events"), "/api/events", ("sessions.read",), {}),
            ("GET", literal("/api/telemetry"), "/api/telemetry", (), {}),
            ("GET", literal("/api/admin/sessions"), "/api/admin/sessions", ("sessions.read",), {}),
            ("GET", literal("/api/admin/api-tokens"), "/api/admin/api-tokens", ("security.manage",), {}),
            ("GET", literal("/api/reports/compliance.zip"), "/api/reports/compliance.zip", ("audit.read", "sessions.read"), {}),
            ("GET", literal("/api/reports/diagnostics.zip"), "/api/reports/diagnostics.zip", ("health.read",), {}),
            ("GET", literal("/api/release/verify"), "/api/release/verify", ("health.read",), {}),
            ("GET", literal("/api/policy-templates"), "/api/policy-templates", ("policies.read",), {}),
            ("GET", literal("/api/users"), "/api/users", ("users.read",), {}),
            ("GET", literal("/api/certificate-settings"), "/api/certificate-settings", ("profiles.read",), {}),
            ("GET", literal("/api/bulk/views"), "/api/bulk/views", ("sessions.read",), {}),
            ("GET", literal("/api/status"), "/api/status", ("users.read", "sessions.read", "health.read"), {}),
            ("GET", literal("/api/service-health"), "/api/service-health", ("health.read",), {}),
            ("GET", literal("/api/observability"), "/api/observability", ("health.read",), {}),
            ("GET", literal("/api/setup-preflight"), "/api/setup-preflight", ("health.read",), {}),
            ("GET", literal("/api/audit.csv"), "/api/audit.csv", ("audit.read",), {}),
            ("GET", literal("/api/audit.json"), "/api/audit.json", ("audit.read",), {}),
            ("GET", literal("/api/operations-timeline.json"), "/api/operations-timeline.json", ("audit.read", "sessions.read"), {}),
            ("GET", literal("/api/backups/metadata.zip"), "/api/backups/metadata.zip", ("backup.manage",), {}),
            ("GET", literal("/api/connections.csv"), "/api/connections.csv", ("sessions.read",), {}),
            ("GET", literal("/api/usage.csv"), "/api/usage.csv", ("sessions.read",), {}),
            ("POST", literal("/api/users/preview"), "/api/users/preview", ("users.manage",), {}),
            ("POST", regex(r"/api/sessions/([^/]+)/preview"), "/api/sessions/session-1/preview", ("session.manage",), {"reason": "Review test session termination"}),
            ("POST", regex(r"/api/users/([^/]+)/duplicate/preview"), "/api/users/test-user/duplicate/preview", ("users.manage",), {}),
            ("POST", literal("/api/users"), "/api/users", ("users.manage",), {}),
            ("POST", regex(r"/api/users/([^/]+)/preview"), "/api/users/test-user/preview", ("users.manage",), {}),
            ("POST", literal("/api/bulk/preview"), "/api/bulk/preview", ("users.manage",), {"action": "suspend", "user_ids": ["*1"]}),
            ("POST", literal("/api/bulk/preview"), "/api/bulk/preview", ("users.manage",), {"action": "tag", "user_ids": ["*1"], "tag": "review"}),
            ("POST", literal("/api/bulk/preview"), "/api/bulk/preview", ("device.manage",), {"action": "revoke", "user_ids": ["*1"]}),
            ("POST", literal("/api/bulk/apply"), "/api/bulk/apply", ("users.manage",), {"action": "suspend", "user_ids": ["*1"]}),
            ("POST", literal("/api/bulk/apply"), "/api/bulk/apply", ("users.manage",), {"action": "tag", "user_ids": ["*1"], "tag": "review"}),
            ("POST", literal("/api/bulk/apply"), "/api/bulk/apply", ("device.manage",), {"action": "revoke", "user_ids": ["*1"]}),
            ("POST", literal("/api/bulk/views"), "/api/bulk/views", ("sessions.read",), {}),
            ("POST", literal("/api/setup-plan"), "/api/setup-plan", (), {}),
            ("POST", literal("/api/openvpn-foundation-plan"), "/api/openvpn-foundation-plan", ("security.manage",), {}),
            ("POST", literal("/api/admin/api-tokens"), "/api/admin/api-tokens", ("security.manage",), {}),
            ("POST", literal("/api/admin/break-glass/plan"), "/api/admin/break-glass/plan", ("security.manage",), {}),
            ("POST", literal("/api/network/segment-plan"), "/api/network/segment-plan", ("policies.manage",), {}),
            ("POST", literal("/api/profile/diagnose"), "/api/profile/diagnose", ("profiles.read",), {}),
            ("POST", literal("/api/connection-doctor"), "/api/connection-doctor", ("health.read",), {}),
            ("POST", literal("/api/security/exposure-doctor"), "/api/security/exposure-doctor", ("health.read",), {}),
            ("POST", literal("/api/backups/preflight"), "/api/backups/preflight", ("backup.manage",), {}),
            ("POST", literal("/api/backups/validate"), "/api/backups/validate", ("backup.manage",), {}),
            ("POST", literal("/api/backups/restore-plan"), "/api/backups/restore-plan", ("backup.manage",), {}),
            ("POST", literal("/api/policy-templates"), "/api/policy-templates", ("policies.manage",), {}),
            ("POST", regex(r"/api/policy-templates/([A-Za-z0-9_-]{1,64})/(preview|apply)"), "/api/policy-templates/test/preview", ("policies.manage",), {}),
            ("POST", regex(r"/api/policy-templates/([A-Za-z0-9_-]{1,64})/(preview|apply)"), "/api/policy-templates/test/apply", ("policies.manage",), {}),
            ("POST", regex(r"/api/users/([^/]+)/(suspend|restore)/preview"), "/api/users/test-user/suspend/preview", ("users.manage",), {}),
            ("POST", regex(r"/api/users/([^/]+)/(suspend|restore)/preview"), "/api/users/test-user/restore/preview", ("users.manage",), {}),
            ("POST", regex(r"/api/users/([^/]+)/delete/preview"), "/api/users/test-user/delete/preview", ("users.manage",), {}),
            ("POST", regex(r"/api/users/([^/]+)/(suspend|restore)"), "/api/users/test-user/suspend", ("users.manage",), {}),
            ("POST", regex(r"/api/users/([^/]+)/(suspend|restore)"), "/api/users/test-user/restore", ("users.manage",), {}),
            ("POST", regex(r"/api/users/([^/]+)/profiles/preview"), "/api/users/test-user/profiles/preview", ("profiles.manage",), {}),
            ("POST", regex(r"/api/profile-migrations/([^/]+)/steps/(imported|tested)"), "/api/profile-migrations/legacy-user-one-phone/steps/imported", ("profiles.manage",), {}),
            ("POST", regex(r"/api/profile-migrations/([^/]+)/steps/(imported|tested)"), "/api/profile-migrations/legacy-user-one-phone/steps/tested", ("profiles.manage",), {}),
            ("POST", regex(r"/api/users/([^/]+)/profiles"), "/api/users/test-user/profiles", ("profiles.manage",), {}),
            ("POST", regex(r"/api/devices/([^/]+)/revoke/preview"), "/api/devices/test-device/revoke/preview", ("device.manage",), {}),
            ("POST", regex(r"/api/devices/([^/]+)/revoke"), "/api/devices/test-device/revoke", ("device.manage",), {}),
            ("POST", regex(r"/api/profile-migrations/([^/]+)/revoke/preview"), "/api/profile-migrations/legacy-user-one-phone/revoke/preview", ("device.manage",), {}),
            ("POST", regex(r"/api/profile-migrations/([^/]+)/revoke"), "/api/profile-migrations/legacy-user-one-phone/revoke", ("device.manage",), {}),
            ("POST", regex(r"/api/users/([^/]+)/duplicate"), "/api/users/test-user/duplicate", ("users.manage",), {}),
            ("POST", regex(r"/api/alerts/(\d+)/ack"), "/api/alerts/1/ack", ("alert.manage",), {}),
            ("PATCH", regex(r"/api/policy-templates/([A-Za-z0-9_-]{1,64})"), "/api/policy-templates/test-template", ("policies.manage",), {}),
            ("PATCH", regex(r"/api/users/([^/]+)"), "/api/users/test-user", ("users.manage",), {}),
            ("DELETE", regex(r"/api/admin/api-tokens/([A-Za-z0-9_-]{8,96})"), "/api/admin/api-tokens/token-12345678", ("security.manage",), {}),
            ("DELETE", regex(r"/api/admin/sessions/([^/]+)"), "/api/admin/sessions/session-1", ("session.manage",), {}),
            ("DELETE", regex(r"/api/bulk/views/([A-Za-z0-9_-]{1,64})"), "/api/bulk/views/view-1", ("sessions.read",), {}),
            ("DELETE", regex(r"/api/sessions/([^/]+)"), "/api/sessions/session-1", ("session.manage",), {}),
            ("DELETE", regex(r"/api/users/([^/]+)"), "/api/users/test-user", ("users.manage",), {}),
        ]

        # The public /api dispatch surface is exhaustively classified: source
        # changes cannot introduce a new API equality/regex branch without
        # adding a role-matrix case here.
        declared_forms = {(method, form) for method, form, *_ in route_cases}
        dispatch_forms: set[tuple[str, str]] = set()
        for method in ("GET", "POST", "PATCH", "DELETE"):
            source = inspect.getsource(getattr(DashboardHandler, f"do_{method}"))
            literal_routes = re.findall(r'path == "(/api/[^"]+)"', source)
            patterns = re.findall(r're\.fullmatch\(r"(/api/[^"]+)"\s*,\s*path\)', source)
            dispatch_forms.update((method, literal(path)) for path in literal_routes)
            dispatch_forms.update((method, regex(pattern)) for pattern in patterns)
        self.assertEqual(dispatch_forms, declared_forms)
        for method, form, path, _, _ in route_cases:
            if form.startswith("regex:"):
                self.assertRegex(path, re.compile(form.removeprefix("regex:")))
            else:
                self.assertEqual(path, form.removeprefix("literal:"))

        store = self.server.context.store

        def non_audit_state() -> dict[str, Any]:
            with store._connection() as connection:
                tables = connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table' "
                    "AND name NOT LIKE 'sqlite_%' AND name != 'audit' ORDER BY name"
                ).fetchall()
                return {
                    table[0]: connection.execute(f'SELECT * FROM "{table[0]}" ORDER BY rowid').fetchall()
                    for table in tables
                }

        before_mutations = list(self.mock.state.mutation_requests)
        denied_count = 0
        allowed_count = 0
        role_groups = ("owner", "security-operator", "operator", "audit", "read")
        for group in role_groups:
            self.mock.state.admin_group = group
            self.cookie = ""
            self.csrf = ""
            self.login()
            headers = {
                "Content-Type": "application/json",
                "X-CSRF-Token": self.csrf,
                "Origin": self.config.public_origin,
            }
            for method, form, path, required, body in route_cases:
                missing = {capability for capability in required if not has_capability(group, capability)}
                # /api/events is an intentionally long-lived SSE response.
                # Its allowed streaming behavior is covered by focused SSE
                # tests; this inventory still exercises every denied role.
                if method == "GET" and path == "/api/events" and not missing:
                    continue
                before_denial_state = non_audit_state() if missing else None
                before_denial_mutations = len(self.mock.state.mutation_requests)
                with self.subTest(group=group, method=method, form=form, path=path, body=body):
                    status, _, payload = self.request(
                        method, path,
                        body=json.dumps(body).encode() if method != "GET" else b"",
                        headers=headers,
                    )
                    self.assertNotIn(b"routerpass", payload)
                    if missing:
                        self.assertEqual(status, 403)
                        self.assertNotIn(b"user-one", payload)
                        self.assertTrue(
                            any(capability.encode() in payload for capability in missing),
                            f"denial must name a missing capability from {sorted(missing)}",
                        )
                        self.assertEqual(non_audit_state(), before_denial_state)
                        self.assertEqual(
                            len(self.mock.state.mutation_requests), before_denial_mutations,
                            "capability denial must happen before any RouterOS mutation",
                        )
                        denied_count += 1
                    else:
                        self.assertNotEqual(
                            status, 403,
                            f"{group} has {sorted(required)} but {method} {path} denied it: {payload!r}",
                        )
                        allowed_count += 1

        self.assertGreater(denied_count, 0)
        self.assertGreater(allowed_count, 0)
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

        # A bearer token is intentionally not a browser session and has no
        # CSRF secret. Even a token carrying every read scope must fail closed
        # across every current write dispatch, including routes whose primary
        # guard is RouterOS-session-specific.
        viewer_token = "vpt_" + "w" * 48
        store.create_api_token(
            token_id="route-matrix-read-only",
            token_hash=hashlib.sha256(viewer_token.encode("utf-8")).hexdigest(),
            label="route matrix read-only principal",
            actor="route-matrix-test",
            capabilities=[
                "health.read", "users.read", "profiles.read", "sessions.read",
                "audit.read", "policies.read",
            ],
            expires_at=int(time.time()) + 3600,
        )
        bearer_headers = {
            "Authorization": f"Bearer {viewer_token}",
            "Content-Type": "application/json",
            "Cookie": "",
            "Origin": self.config.public_origin,
            "X-CSRF-Token": "attacker-supplied-token",
        }
        status, _, payload = self.request(
            "GET", "/api/service-health", headers=bearer_headers,
        )
        self.assertEqual(status, 200, payload.decode())

        def non_audit_state_ignoring_token_touch() -> dict[str, Any]:
            state = non_audit_state()
            token_rows = state.get("api_tokens", [])
            state["api_tokens"] = [
                tuple((key, value) for key, value in dict(row).items() if key != "last_used_at")
                for row in token_rows
            ]
            return state

        before_bearer_denials = non_audit_state_ignoring_token_touch()
        before_bearer_mutations = list(self.mock.state.mutation_requests)
        for method, form, path, _, body in route_cases:
            if method == "GET":
                continue
            with self.subTest(principal="read-only-api-token", method=method, form=form, path=path):
                status, _, payload = self.request(
                    method,
                    path,
                    body=json.dumps(body).encode(),
                    headers=bearer_headers,
                )
                self.assertIn(status, (401, 403), payload.decode())
                self.assertNotIn(b"routerpass", payload)
                self.assertNotIn(viewer_token.encode(), payload)
                self.assertEqual(non_audit_state_ignoring_token_touch(), before_bearer_denials)
                self.assertEqual(self.mock.state.mutation_requests, before_bearer_mutations)

        # A valid browser session still needs its unpredictable CSRF secret on
        # every current write dispatch. Exercise the complete same-origin
        # surface with a forged token so route additions cannot silently omit
        # anti-forgery validation.
        self.mock.state.admin_group = "owner"
        self.cookie = ""
        self.csrf = ""
        self.login()
        csrf_headers = {
            "Content-Type": "application/json",
            "Cookie": self.cookie,
            "Origin": self.config.public_origin,
            "X-CSRF-Token": "attacker-supplied-token",
        }
        before_csrf_denials = non_audit_state_ignoring_token_touch()
        before_csrf_mutations = list(self.mock.state.mutation_requests)
        for method, form, path, _, body in route_cases:
            if method == "GET":
                continue
            with self.subTest(principal="browser-session-with-forged-csrf", method=method, form=form, path=path):
                status, _, payload = self.request(
                    method,
                    path,
                    body=json.dumps(body).encode(),
                    headers=csrf_headers,
                )
                self.assertEqual(status, 403, payload.decode())
                self.assertIn(b"CSRF", payload)
                self.assertNotIn(b"routerpass", payload)
                self.assertEqual(non_audit_state_ignoring_token_touch(), before_csrf_denials)
                self.assertEqual(self.mock.state.mutation_requests, before_csrf_mutations)

        # A valid CSRF token does not authorize a browser write from a foreign
        # origin. Exercise the same complete route surface to keep Origin
        # enforcement from drifting between mutation handlers.
        foreign_origin_headers = {
            **csrf_headers,
            "Origin": "https://attacker.example",
            "X-CSRF-Token": self.csrf,
        }
        before_origin_denials = non_audit_state_ignoring_token_touch()
        before_origin_mutations = list(self.mock.state.mutation_requests)
        for method, form, path, _, body in route_cases:
            if method == "GET":
                continue
            with self.subTest(principal="browser-session-with-foreign-origin", method=method, form=form, path=path):
                status, _, payload = self.request(
                    method,
                    path,
                    body=json.dumps(body).encode(),
                    headers=foreign_origin_headers,
                )
                self.assertEqual(status, 403, payload.decode())
                self.assertIn(b"origin", payload.lower())
                self.assertNotIn(b"routerpass", payload)
                self.assertEqual(non_audit_state_ignoring_token_touch(), before_origin_denials)
                self.assertEqual(self.mock.state.mutation_requests, before_origin_mutations)

    def test_admin_session_response_fields_are_capability_gated_at_http_boundary(self) -> None:
        self.login()
        owner_cookie = self.cookie
        owner = self.server.context.sessions.get(owner_cookie.split("=", 1)[1], touch=False)
        self.assertIsNotNone(owner)
        # Use a scoped API token for a genuine sessions.read-only principal.
        # A synthetic RouterOS session would be force-revalidated against the
        # mock account and could not prove this response-field contract.
        viewer_token = "vpt_" + "v" * 48
        viewer_token_hash = hashlib.sha256(viewer_token.encode("utf-8")).hexdigest()
        self.server.context.store.create_api_token(
            token_id="session-read-field-contract",
            token_hash=viewer_token_hash,
            label="session inventory reader",
            actor="viewer",
            capabilities=["sessions.read"],
            expires_at=2_000_000_000,
        )

        # Query parameters cannot opt a sessions.read-only caller into
        # revocation references; that projection is server-side and requires
        # session.manage.
        status, _, payload = self.request(
            "GET",
            "/api/admin/sessions?include_revocation_refs=true",
            headers={"Authorization": f"Bearer {viewer_token}", "Cookie": ""},
        )
        self.assertEqual(status, 200)
        viewer_response = json.loads(payload)
        self.assertEqual(
            set(viewer_response),
            {"sessions", "idle_timeout_seconds", "absolute_timeout_seconds", "generated_at"},
        )
        expected_session_fields = {
            "id",
            "id_hash",
            "username",
            "role",
            "created_at",
            "last_seen",
            "idle_seconds",
            "idle_remaining",
            "absolute_remaining",
            "source_address",
            "user_agent",
            "auth_method",
            "current",
        }
        for item in viewer_response["sessions"]:
            self.assertEqual(set(item), expected_session_fields)
            self.assertEqual(item["id"], "")
        serialized_viewer = json.dumps(viewer_response)
        self.assertNotIn(owner.session_id, serialized_viewer)
        self.assertNotIn(viewer_token, serialized_viewer)
        self.assertNotIn(viewer_token_hash, serialized_viewer)

        status, _, payload = self.request(
            "GET",
            "/api/admin/sessions",
            headers={"Cookie": owner_cookie},
        )
        self.assertEqual(status, 200)
        owner_response = json.loads(payload)
        disclosed_refs = {item["id"] for item in owner_response["sessions"]}
        self.assertIn(owner.revocation_ref, disclosed_refs)
        self.assertNotIn(owner.session_id, json.dumps(owner_response))
        reference_cookie = f"{owner_cookie.split('=', 1)[0]}={owner.revocation_ref}"
        status, _, payload = self.request(
            "GET",
            "/api/admin/sessions",
            headers={"Cookie": reference_cookie},
        )
        self.assertEqual(status, 401, payload.decode("utf-8"))
        self.assertNotIn(owner.revocation_ref, payload.decode("utf-8"))

    def test_admin_session_revocation_reference_projection_matches_all_routeros_roles(self) -> None:
        role_groups = ("owner", "security-operator", "operator", "audit", "read")
        issued_session_refs: set[str] = set()
        issued_cookie_bearers: set[str] = set()

        for group in role_groups:
            with self.subTest(group=group):
                self.mock.state.admin_group = group
                self.cookie = ""
                self.csrf = ""
                self.login()
                issued_cookie_bearers.add(self.cookie.split("=", 1)[1])
                issued_session_refs.add(
                    self.server.context.sessions.get(
                        self.cookie.split("=", 1)[1], touch=False
                    ).revocation_ref
                )

                status, _, payload = self.request("GET", "/api/admin/sessions")
                self.assertEqual(status, 200, payload.decode("utf-8"))
                response = json.loads(payload)
                may_manage_sessions = has_capability(group, "session.manage")
                projected_ids = {
                    row["id"] for row in response["sessions"] if row["id"]
                }

                self.assertTrue(response["sessions"])
                self.assertEqual(
                    projected_ids,
                    issued_session_refs if may_manage_sessions else set(),
                )
                serialized = payload.decode("utf-8")
                for session_id in issued_cookie_bearers:
                    self.assertNotIn(session_id, serialized)

    def test_warm_role_downgrade_hides_admin_session_references_from_api_and_dashboard(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        self.assertEqual(session.role, "owner")
        other_session = self.server.context.sessions.create("admin", "routerpass", role="owner")

        status, _, owner_payload = self.request("GET", "/api/admin/sessions")
        self.assertEqual(status, 200)
        self.assertIn(session.revocation_ref.encode("ascii"), owner_payload)
        self.assertIn(other_session.revocation_ref.encode("ascii"), owner_payload)
        self.assertNotIn(session_id.encode("ascii"), owner_payload)
        self.assertNotIn(other_session.session_id.encode("ascii"), owner_payload)
        status, _, owner_dashboard = self.request(
            "GET", "/dashboard", headers={"Cookie": self.cookie},
        )
        self.assertEqual(status, 200)
        self.assertIn(session.revocation_ref.encode("ascii"), owner_dashboard)
        self.assertNotIn(session_id.encode("ascii"), owner_dashboard)
        self.assertNotIn(other_session.session_id.encode("ascii"), owner_dashboard)

        # The ordinary 15-second role cache remains warm. The read-only role
        # retains sessions.read, but must lose revocation references immediately.
        self.mock.state.admin_group = "read"
        status, _, payload = self.request("GET", "/api/admin/sessions")

        self.assertEqual(status, 200, payload.decode("utf-8"))
        self.assertEqual(session.role, "read_only")
        response = json.loads(payload)
        self.assertTrue(response["sessions"])
        self.assertTrue(all(row["id"] == "" for row in response["sessions"]))
        self.assertTrue(any(row["username"] == "admin" for row in response["sessions"]))
        self.assertNotIn(session_id.encode("ascii"), payload)
        self.assertNotIn(other_session.session_id.encode("ascii"), payload)
        status, _, downgraded_dashboard = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertNotIn(session.revocation_ref.encode("ascii"), downgraded_dashboard)
        self.assertNotIn(session_id.encode("ascii"), downgraded_dashboard)
        self.assertNotIn(other_session.session_id.encode("ascii"), downgraded_dashboard)

    def test_routeros_role_lookup_failure_revokes_session_before_admin_sessions_response(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        self.assertEqual(session.role, "owner")

        # An unavailable role source cannot prove even read-only access.
        self.mock.state.admin_user_read_error = 503
        self.server.context.sessions._role_checked_monotonic[session_id] = 0
        status, _, payload = self.request("GET", "/api/admin/sessions")

        self.assertEqual(status, 401, payload.decode("utf-8"))
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertEqual(json.loads(payload), {"error": "Authentication required"})
        self.assertNotIn(session_id.encode("ascii"), payload)

    def test_socketio_stream_revokes_session_when_routeros_role_lookup_fails(self) -> None:
        self.login()
        sid, cookie = self.connect_socketio_polling()
        session_id = cookie.split("=", 1)[1]
        self.mock.state.admin_user_read_error = 503
        self.server.context.sessions._role_checked_monotonic[session_id] = 0

        status, _, payload = self.request(
            "GET",
            f"/socket.io/?EIO=4&transport=polling&sid={urllib.parse.quote(sid, safe='')}",
            headers={"Cookie": cookie, "Origin": self.config.public_origin},
        )

        self.assertEqual(status, 401)
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertNotIn(sid, self.server.socketio_bridge._clients)
        self.assertEqual(self.server.socketio_bridge.gateway.client_count, 0)
        self.assertNotIn(b"telemetry", payload)

    def test_admin_api_token_response_uses_metadata_only_allowlist(self) -> None:
        self.login()
        plaintext = "vpt_" + "s" * 48
        token_hash = hashlib.sha256(plaintext.encode("utf-8")).hexdigest()
        self.server.context.store.create_api_token(
            token_id="token-field-contract",
            token_hash=token_hash,
            label="security-field-contract",
            actor="admin",
            capabilities=["health.read"],
            expires_at=2_000_000_000,
        )

        status, _, payload = self.request("GET", "/api/admin/api-tokens")
        self.assertEqual(status, 200, payload.decode("utf-8"))
        response = json.loads(payload)
        self.assertEqual(set(response), {"tokens"})
        self.assertEqual(len(response["tokens"]), 1)
        self.assertEqual(
            set(response["tokens"][0]),
            {
                "id",
                "label",
                "actor",
                "capabilities",
                "created_at",
                "expires_at",
                "last_used_at",
                "revoked_at",
            },
        )
        self.assertNotIn(plaintext, payload.decode("utf-8"))
        self.assertNotIn(token_hash, payload.decode("utf-8"))
        self.assertNotIn("token_hash", response["tokens"][0])

    def test_admin_session_revocation_is_csrf_protected_scoped_and_audited(self) -> None:
        self.login()
        current_session_id = self.cookie.split("=", 1)[1]
        other_session = self.server.context.sessions.create(
            "admin", "routerpass", role="owner",
        )
        unrelated_session = self.server.context.sessions.create(
            "admin", "routerpass", role="owner",
        )
        path = f"/api/admin/sessions/{urllib.parse.quote(other_session.revocation_ref, safe='')}"

        status, _, _ = self.json_request("DELETE", path, csrf=False)
        self.assertEqual(status, 403)
        self.assertIsNotNone(self.server.context.sessions.get(other_session.session_id, touch=False))

        current_session = self.server.context.sessions.get(current_session_id, touch=False)
        self.assertIsNotNone(current_session)
        current_path = f"/api/admin/sessions/{urllib.parse.quote(current_session.revocation_ref, safe='')}"
        status, _, payload = self.json_request("DELETE", current_path)
        self.assertEqual(status, 400)
        self.assertIn(b"current session cannot be revoked", payload)
        self.assertIsNotNone(self.server.context.sessions.get(current_session_id, touch=False))

        bearer_path = f"/api/admin/sessions/{urllib.parse.quote(current_session_id, safe='')}"
        status, _, payload = self.json_request(
            "DELETE", bearer_path, {"password": "routerpass"},
        )
        self.assertEqual(status, 404, payload.decode("utf-8"))
        self.assertIsNotNone(self.server.context.sessions.get(current_session_id, touch=False))

        status, _, payload = self.json_request("DELETE", path)
        self.assertEqual(status, 400, payload.decode("utf-8"))
        self.assertIn(b"Enter your RouterOS password", payload)
        self.assertIsNotNone(self.server.context.sessions.get(other_session.session_id, touch=False))

        status, _, payload = self.json_request("DELETE", path, {"password": "incorrect"})
        self.assertEqual(status, 401, payload.decode("utf-8"))
        self.assertNotIn(b"incorrect", payload)
        self.assertIsNotNone(self.server.context.sessions.get(other_session.session_id, touch=False))

        status, _, payload = self.json_request("DELETE", path, {"password": "routerpass"})
        self.assertEqual(status, 200, payload.decode("utf-8"))
        self.assertIsNone(self.server.context.sessions.get(other_session.session_id, touch=False))
        self.assertIsNotNone(self.server.context.sessions.get(current_session_id, touch=False))
        self.assertIsNotNone(self.server.context.sessions.get(unrelated_session.session_id, touch=False))
        audit = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(audit["action"], "admin-session.revoke")
        self.assertNotIn(other_session.session_id, audit["details"])
        reauth_events = self.server.context.store.recent_audit(10)
        self.assertTrue(any(item["action"] == "admin-session.reauth.failed" for item in reauth_events))
        self.assertTrue(any(item["action"] == "admin-session.reauth.success" for item in reauth_events))
        self.assertNotIn("routerpass", json.dumps(reauth_events))

    def test_admin_session_reauthentication_is_rate_limited(self) -> None:
        self.login()
        target = self.server.context.sessions.create("admin", "routerpass", role="owner")
        path = f"/api/admin/sessions/{urllib.parse.quote(target.revocation_ref, safe='')}"

        for _ in range(5):
            status, _, _ = self.json_request("DELETE", path, {"password": "wrong-password"})
            self.assertEqual(status, 401)
        status, _, payload = self.json_request("DELETE", path, {"password": "routerpass"})
        self.assertEqual(status, 429)
        self.assertNotIn(b"routerpass", payload)
        self.assertIsNotNone(self.server.context.sessions.get(target.session_id, touch=False))

    def test_own_other_session_revocation_is_account_scoped_csrf_protected_and_audited(self) -> None:
        self.login()
        current_session_id = self.cookie.split("=", 1)[1]
        other_same_account = self.server.context.sessions.create(
            "ADMIN", "routerpass", role="owner",
        )
        other_account = self.server.context.sessions.create(
            "auditor", "another-password", role="audit",
        )
        path = "/api/auth/sessions/revoke-others"
        def own_session_request(value: dict[str, Any], *, csrf: bool = True):
            headers = {
                "Content-Type": "application/json",
                "Origin": self.config.public_origin,
            }
            if csrf:
                headers["X-CSRF-Token"] = self.csrf
            return self.request("POST", path, body=json.dumps(value).encode(), headers=headers)

        status, _, _ = own_session_request(
            {"password": "routerpass", "confirmation": "SIGN OUT MY OTHER SESSIONS"},
            csrf=False,
        )
        self.assertEqual(status, 403)
        self.assertIsNotNone(self.server.context.sessions.get(other_same_account.session_id, touch=False))

        status, _, payload = own_session_request(
            {"password": "routerpass", "confirmation": "wrong"},
        )
        self.assertEqual(status, 400, payload.decode("utf-8"))
        self.assertIsNotNone(self.server.context.sessions.get(other_same_account.session_id, touch=False))

        status, _, payload = own_session_request(
            {"password": "incorrect", "confirmation": "SIGN OUT MY OTHER SESSIONS"},
        )
        self.assertEqual(status, 401, payload.decode("utf-8"))
        self.assertNotIn(b"incorrect", payload)
        self.assertIsNotNone(self.server.context.sessions.get(other_same_account.session_id, touch=False))

        status, _, payload = own_session_request(
            {"password": "routerpass", "confirmation": "SIGN OUT MY OTHER SESSIONS"},
        )
        self.assertEqual(status, 200, payload.decode("utf-8"))
        self.assertEqual(json.loads(payload)["revoked_count"], 1)
        self.assertIsNotNone(self.server.context.sessions.get(current_session_id, touch=False))
        self.assertIsNone(self.server.context.sessions.get(other_same_account.session_id, touch=False))
        self.assertIsNotNone(self.server.context.sessions.get(other_account.session_id, touch=False))
        audit = self.server.context.store.recent_audit(10)
        self.assertTrue(any(item["action"] == "session.revoke-others" for item in audit))
        self.assertNotIn(current_session_id, json.dumps(audit))
        self.assertNotIn(other_same_account.session_id, json.dumps(audit))
        self.assertNotIn("routerpass", json.dumps(audit))

    def test_own_other_session_revocation_reauthentication_is_rate_limited(self) -> None:
        self.login()
        other = self.server.context.sessions.create("admin", "routerpass", role="owner")
        path = "/api/auth/sessions/revoke-others"
        body = {"password": "wrong-password", "confirmation": "SIGN OUT MY OTHER SESSIONS"}
        headers = {
            "Content-Type": "application/json",
            "X-CSRF-Token": self.csrf,
            "Origin": self.config.public_origin,
        }

        for _ in range(5):
            status, _, _ = self.request("POST", path, body=json.dumps(body).encode(), headers=headers)
            self.assertEqual(status, 401)
        status, _, payload = self.request(
            "POST", path,
            body=json.dumps({"password": "routerpass", "confirmation": "SIGN OUT MY OTHER SESSIONS"}).encode(),
            headers=headers,
        )
        self.assertEqual(status, 429)
        self.assertNotIn(b"routerpass", payload)
        self.assertIsNotNone(self.server.context.sessions.get(other.session_id, touch=False))

    def test_own_other_session_revocation_does_not_revoke_a_concurrently_rotated_caller(self) -> None:
        self.login()
        current_session_id = self.cookie.split("=", 1)[1]
        peer_session = self.server.context.sessions.create("admin", "routerpass", role="owner")
        runtime = self.server.telemetry_runtime
        original_revalidate = runtime.revalidate_session
        rotated_sessions = []

        def rotate_after_revalidation(session_id: str, *, force_role_check: bool = False):
            result = original_revalidate(session_id, force_role_check=force_role_check)
            if result is not None and force_role_check:
                rotated = self.server.context.sessions.rotate(
                    session_id,
                    "routerpass",
                    role=result.role,
                )
                rotated_sessions.append(rotated)
            return result

        with mock.patch.object(runtime, "revalidate_session", side_effect=rotate_after_revalidation):
            status, _, payload = self.request(
                "POST",
                "/api/auth/sessions/revoke-others",
                body=json.dumps({
                    "password": "routerpass",
                    "confirmation": "SIGN OUT MY OTHER SESSIONS",
                }).encode(),
                headers={
                    "Content-Type": "application/json",
                    "X-CSRF-Token": self.csrf,
                    "Origin": self.config.public_origin,
                },
            )

        self.assertEqual(status, 409, payload.decode("utf-8"))
        self.assertIsNone(self.server.context.sessions.get(current_session_id, touch=False))
        self.assertEqual(len(rotated_sessions), 1)
        replacement = rotated_sessions[0]
        self.assertIsNotNone(replacement)
        self.assertIsNotNone(self.server.context.sessions.get(replacement.session_id, touch=False))
        self.assertIsNotNone(self.server.context.sessions.get(peer_session.session_id, touch=False))

    def test_enterprise_foundations_are_scoped_and_read_only_where_expected(self) -> None:
        self.login()
        status, _, payload = self.request("GET", "/api/admin/sessions")
        self.assertEqual(status, 200)
        sessions = json.loads(payload)
        self.assertEqual(len(sessions["sessions"]), 1)
        self.assertTrue(sessions["sessions"][0]["current"])
        self.assertNotIn(b"password", payload.lower())

        sensitive_target = "certificate-private-target-canary"
        self.server.context.store.add_alert(
            severity="warning", action="certificate.expiring", target=sensitive_target,
            title="Certificate expires soon", details="safe actionable detail",
        )
        status, _, payload = self.request("GET", "/metrics")
        self.assertEqual(status, 200)
        self.assertIn(b"vpn_dashboard_info", payload)
        self.assertRegex(
            payload.decode(),
            r"(?m)^vpn_dashboard_process_start_time_seconds [0-9]+(?:\.[0-9]+)?$",
        )
        self.assertIn(b"vpn_dashboard_integration_outbox_pending", payload)
        self.assertIn(b"vpn_dashboard_integration_outbox_dead_lettered", payload)
        self.assertIn(b"vpn_dashboard_integration_outbox_storage_failures_total 0", payload)
        self.assertIn(b"vpn_dashboard_redis_last_observed_available", payload)
        self.assertIn(b"vpn_dashboard_sqlite_file_bytes", payload)
        self.assertIn(b"vpn_dashboard_sqlite_volume_free_bytes", payload)
        self.assertIn(b'vpn_dashboard_telemetry_gateway_events_total{outcome="snapshot_recovery"}', payload)
        self.assertIn(b"vpn_dashboard_telemetry_gateway_rejected_clients_total", payload)
        self.assertIn(b"vpn_dashboard_telemetry_gateway_delivery_queue_age_seconds", payload)
        self.assertIn(b"vpn_dashboard_telemetry_gateway_delivery_queue_age_p95_seconds", payload)
        self.assertIn(b"vpn_dashboard_telemetry_session_event_age_seconds", payload)
        self.assertIn(b"vpn_dashboard_telemetry_traffic_sample_age_seconds", payload)
        self.assertIn(b"vpn_dashboard_telemetry_session_events_total", payload)
        self.assertIn(b"vpn_dashboard_telemetry_traffic_samples_total", payload)
        self.assertIn(b"vpn_dashboard_telemetry_traffic_sample_age_seconds -1", payload)
        self.assertIn(b"vpn_dashboard_telemetry_supervisor_status{state=\"disabled\"} 1", payload)
        self.assertIn(b"vpn_dashboard_telemetry_supervisor_reconnects_total 0", payload)
        self.assertIn(b"vpn_dashboard_telemetry_supervisor_last_snapshot_timestamp_seconds -1", payload)
        self.assertNotIn(b"routerpass", payload)
        self.assertNotIn(sensitive_target.encode(), payload)

        status, _, payload = self.json_request(
            "POST", "/api/admin/api-tokens",
            {"label": "metrics export", "scopes": ["health.read", "audit.read", "sessions.read", "policies.read"], "expires_in": "1h"},
        )
        self.assertEqual(status, 201)
        token_payload = json.loads(payload)
        self.assertTrue(token_payload["token"].startswith("vpt_"))
        token_id = token_payload["metadata"]["id"]
        self.assertNotIn(token_payload["token"], json.dumps(self.server.context.store.list_api_tokens()))

        status, _, payload = self.request(
            "GET", "/api/observability",
            headers={"Authorization": f"Bearer {token_payload['token']}", "Cookie": ""},
        )
        self.assertEqual(status, 200)
        self.assertIn(b"health_timeline", payload)

        status, _, payload = self.request(
            "GET", "/api/admin/sessions",
            headers={"Authorization": f"Bearer {token_payload['token']}", "Cookie": ""},
        )
        self.assertEqual(status, 200)
        self.assertIn(b"sessions", payload)

        # API tokens are not interactive RouterOS dashboard sessions, even
        # when they carry sessions.read for the separately scoped REST views.
        status, _, payload = self.request(
            "GET", "/api/events",
            headers={"Authorization": f"Bearer {token_payload['token']}", "Cookie": ""},
        )
        self.assertEqual(status, 403)

        for path in ("/api/policy-templates", "/api/bulk/views"):
            status, _, payload = self.request(
                "GET", path,
                headers={"Authorization": f"Bearer {token_payload['token']}", "Cookie": ""},
            )
            self.assertEqual(status, 200, path)

        for path in ("/api/connections.csv", "/api/usage.csv"):
            status, headers, payload = self.request(
                "GET", path,
                headers={"Authorization": f"Bearer {token_payload['token']}", "Cookie": ""},
            )
            self.assertEqual(status, 200, payload.decode("utf-8"))
            self.assertEqual(headers["content-type"], "text/csv; charset=utf-8")

        status, _, payload = self.json_request(
            "POST", "/api/admin/api-tokens",
            {"label": "health-only export attempt", "scopes": ["health.read"], "expires_in": "1h"},
        )
        self.assertEqual(status, 201)
        health_token = json.loads(payload)["token"]
        status, _, payload = self.json_request(
            "POST", "/api/admin/api-tokens",
            {"label": "policies-only export attempt", "scopes": ["policies.read"], "expires_in": "1h"},
        )
        self.assertEqual(status, 201)
        policies_token = json.loads(payload)["token"]
        status, _, payload = self.request(
            "GET", "/api/observability",
            headers={"Authorization": f"Bearer {policies_token}", "Cookie": ""},
        )
        self.assertEqual(status, 403)
        self.assertIn(b'"required_capability":"health.read"', payload)
        for path, capability in (
            ("/api/policy-templates", "policies.read"),
            ("/api/bulk/views", "sessions.read"),
            ("/api/admin/sessions", "sessions.read"),
        ):
            status, _, payload = self.request(
                "GET", path,
                headers={"Authorization": f"Bearer {health_token}", "Cookie": ""},
            )
            self.assertEqual(status, 403, path)
            self.assertIn(f'"required_capability":"{capability}"'.encode(), payload)
            self.assertNotIn(b"full-tunnel", payload)

        with mock.patch.object(
            self.server.context.router, "_request", wraps=self.server.context.router._request,
        ) as router_request:
            for path in ("/api/status", "/api/users", "/api/telemetry"):
                status, _, payload = self.request(
                    "GET", path,
                    headers={"Authorization": f"Bearer {health_token}", "Cookie": ""},
                )
                self.assertEqual(status, 403, path)
                self.assertIn(b"authenticated RouterOS dashboard session", payload)
            router_request.assert_not_called()
        for path in ("/api/connections.csv", "/api/usage.csv"):
            status, _, payload = self.request(
                "GET", path,
                headers={"Authorization": f"Bearer {health_token}", "Cookie": ""},
            )
            self.assertEqual(status, 403, path)
            self.assertIn(b'"required_capability":"sessions.read"', payload)
            self.assertNotIn(b"user-two", payload)

        for path in ("/metrics", "/api/reports/diagnostics.zip"):
            status, _, payload = self.request(
                "GET", path,
                headers={"Authorization": f"Bearer {health_token}", "Cookie": ""},
            )
            self.assertEqual(status, 200, path)
            self.assertNotIn(b"routerpass", payload)

        status, _, payload = self.request(
            "GET", "/api/reports/compliance.zip",
            headers={"Authorization": f"Bearer {token_payload['token']}", "Cookie": ""},
        )
        self.assertEqual(status, 200)

        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertEqual(set(archive.namelist()), {"summary.json", "audit.csv", "connections.csv"})
            self.assertNotIn(b"routerpass", archive.read("summary.json"))

        status, _, payload = self.json_request(
            "POST", "/api/admin/api-tokens",
            {"label": "audit-only export attempt", "scopes": ["audit.read"], "expires_in": "1h"},
        )
        self.assertEqual(status, 201)
        audit_token = json.loads(payload)["token"]
        for path, capability in (
            ("/api/reports/compliance.zip", "sessions.read"),
            ("/metrics", "health.read"),
            ("/api/reports/diagnostics.zip", "health.read"),
            ("/api/service-health", "health.read"),
            ("/api/setup-preflight", "health.read"),
        ):
            status, _, payload = self.request(
                "GET", path,
                headers={"Authorization": f"Bearer {audit_token}", "Cookie": ""},
            )
            self.assertEqual(status, 403, path)
            self.assertIn(f'"required_capability":"{capability}"'.encode(), payload)
        status, _, payload = self.request(
            "GET", "/api/operations-timeline.json",
            headers={"Authorization": f"Bearer {audit_token}", "Cookie": ""},
        )
        self.assertEqual(status, 403)
        self.assertIn(b'"required_capability":"sessions.read"', payload)

        self.server.context.store.record_health_snapshot({
            "overall": "healthy",
            "checks": [{"id": "routeros-rest", "status": "healthy", "remediation": "private-host-marker"},
                       {"id": "private-user-marker", "status": "healthy"}],
        })
        status, _, dashboard = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        for disclosure in (
            "Preview what the ZIP contains", "Dashboard version, source revision, and bundle creation time",
            "RouterOS credentials or tokens", "VPN profiles, certificates, private keys",
            "Raw RouterOS configuration or records, logs, event payloads",
            "without making a RouterOS request", "Download redacted diagnostic ZIP",
            'value="policies.read"',
        ):
            self.assertIn(disclosure.encode(), dashboard)

        with mock.patch.object(
            self.server.context.router, "_request",
            side_effect=AssertionError("diagnostic export must not query RouterOS"),
        ):
            status, headers, payload = self.request("GET", "/api/reports/diagnostics.zip")
        self.assertEqual(status, 200)
        self.assertIn("vpn-diagnostic-bundle.zip", headers["content-disposition"])
        self.assertLessEqual(len(payload), 32 * 1024)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertEqual(archive.namelist(), ["diagnostics.json"])
            diagnostics = archive.read("diagnostics.json")
        self.assertIn(b"routeros-rest", diagnostics)
        self.assertNotIn(b"private-host-marker", diagnostics)
        self.assertNotIn(b"private-user-marker", diagnostics)
        self.assertNotIn(b"admin", diagnostics)
        self.assertNotIn(b"routerpass", diagnostics)
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["action"], "report.diagnostics.export")

        self.cookie = ""
        status, _, payload = self.request("GET", "/api/reports/diagnostics.zip")
        self.assertEqual(status, 401)
        self.assertNotIn(b"diagnostics", payload)
        self.login()

        status, _, payload = self.request(
            "GET", "/api/release/verify?image=ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-0123456789abcdef0123456789abcdef01234567-arm64@sha256:" + "b" * 64 + "&revision=0123456789abcdef0123456789abcdef01234567",
        )
        self.assertEqual(status, 200)
        valid_reference = json.loads(payload)
        self.assertTrue(valid_reference["reference_valid"])
        self.assertFalse(valid_reference["verified"])
        self.assertEqual(valid_reference["verification_scope"], "reference_syntax_and_revision_match")
        self.assertEqual(valid_reference["checks"][2]["status"], "not_checked")
        self.assertEqual(valid_reference["checks"][3]["status"], "not_checked")
        status, _, payload = self.request(
            "GET", "/api/release/verify?image=ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-0123456789abcdef0123456789abcdef01234567-amd64@sha256:" + "c" * 64 + "&revision=0123456789abcdef0123456789abcdef01234567",
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["reference_valid"])

        status, _, payload = self.request(
            "GET", "/api/release/verify?image=ghcr.io/example/mikrotik-openvpn-gui:sha-0123456789abcdef0123456789abcdef01234567-arm64@sha256:" + "b" * 64 + "&revision=0123456789abcdef0123456789abcdef01234567",
        )
        self.assertEqual(status, 200)
        untrusted_repository = json.loads(payload)
        self.assertFalse(untrusted_repository["reference_valid"])
        self.assertFalse(untrusted_repository["verified"])
        self.assertEqual(untrusted_repository["checks"][0]["status"], "fail")

        status, _, payload = self.request(
            "GET", "/api/release/verify?image=ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-0123456789abcdef0123456789abcdef01234567-arm64&revision=0123456789abcdef0123456789abcdef01234567",
        )
        self.assertEqual(status, 200)
        unpinned = json.loads(payload)
        self.assertFalse(unpinned["reference_valid"])
        self.assertFalse(unpinned["verified"])
        self.assertEqual(unpinned["checks"][0]["status"], "fail")

        status, _, payload = self.request(
            "GET", "/api/release/verify?image=ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-0123456789abcdef0123456789abcdef01234567-arm64@sha256:" + "b" * 64 + "&revision=1123456789abcdef0123456789abcdef01234567",
        )
        self.assertEqual(status, 200)
        mismatched_revision = json.loads(payload)
        self.assertFalse(mismatched_revision["reference_valid"])
        self.assertEqual(mismatched_revision["checks"][1]["status"], "fail")

        profile = """client\nremote vpn.example.test 1194 udp\nproto udp\nauth-nocache\nverify-x509-name vpn.example.test name\n<ca>\nCERT\n</ca>\n<cert>\nCERT\n</cert>\n<key>\nKEY\n</key>\ncipher AES-256-GCM\n"""
        status, _, payload = self.json_request("POST", "/api/profile/diagnose", {"profile": profile})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["status"], "pass")

        status, _, payload = self.json_request("POST", "/api/connection-doctor", {"username": "user-two"})
        self.assertEqual(status, 200)
        doctor = json.loads(payload)
        doctor_checks = {item["id"]: item for item in doctor["checks"]}
        self.assertEqual(doctor_checks["server"]["status"], "pass")
        self.assertEqual(doctor_checks["session"]["status"], "pass")
        self.assertIn("source", doctor_checks["router"])
        self.assertIn("confidence", doctor_checks["compatibility"])
        self.assertNotIn(b"user-two", payload)
        self.assertNotIn(b"198.51.100.40", payload)
        self.assertNotIn(b"198.18.0.48", payload)

        status, _, payload = self.json_request("POST", "/api/connection-doctor", {"username": "invalid name"})
        self.assertEqual(status, 400)

        status, _, _ = self.json_request("POST", "/api/connection-doctor", {"username": "user-two"}, csrf=False)
        self.assertEqual(status, 403)

        before_mutations = list(self.mock.state.mutation_requests)
        status, _, payload = self.json_request("POST", "/api/security/exposure-doctor", {})
        self.assertEqual(status, 200)
        exposure = json.loads(payload)
        exposure_checks = {item["id"]: item for item in exposure["checks"]}
        self.assertTrue(exposure["read_only"])
        self.assertEqual(exposure_checks["service-www"]["status"], "verified")
        self.assertEqual(exposure_checks["service-www-ssl"]["status"], "verified")
        self.assertEqual(exposure_checks["service-ssh"]["status"], "warning")
        self.assertEqual(exposure_checks["account-source-match"]["status"], "warning")
        self.assertEqual(exposure_checks["management-service-source-match"]["status"], "warning")
        self.assertEqual(exposure_checks["firewall-boundary"]["status"], "unknown")
        self.assertNotIn(b"admin", payload)
        self.assertNotIn(b"routerpass", payload)
        self.assertNotIn(b"172.31.250.0/24", payload)
        self.assertNotIn(b"172.31.250.10", payload)
        self.assertNotIn(b"web-cert", payload)
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

        status, _, _ = self.json_request("POST", "/api/security/exposure-doctor", {}, csrf=False)
        self.assertEqual(status, 403)

        status, _, payload = self.json_request("POST", "/api/network/segment-plan", {"zone": "lan", "cidrs": ["192.0.2.0/24"]})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["mode"], "review-only")

        status, _, payload = self.json_request("POST", "/api/admin/break-glass/plan", {"reason": "RouterOS dashboard recovery drill"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["mode"], "review-only")

        status, _, _ = self.request(
            "DELETE", f"/api/admin/api-tokens/{urllib.parse.quote(token_id, safe='')}",
            headers={"X-CSRF-Token": self.csrf},
        )
        self.assertEqual(status, 200)

    def test_metrics_export_sqlite_outbox_storage_failure_counter_without_labels(self) -> None:
        self.login()
        dispatcher = mock.Mock()
        dispatcher.metrics.return_value = {
            "delivery_successes": 0,
            "delivery_failures": 0,
            "last_delivery_success": 0,
            "outbox_storage_failures": 7,
            "redis_configured": 0,
            "redis_available": -1,
            "redis_publish_successes": 0,
            "redis_publish_failures": 0,
            "redis_last_publish_success": 0,
        }
        self.server.context.integration_dispatcher = dispatcher

        status, _, payload = self.request("GET", "/metrics")

        self.assertEqual(status, 200)
        self.assertIn(b"# TYPE vpn_dashboard_integration_outbox_storage_failures_total counter", payload)
        self.assertIn(b"vpn_dashboard_integration_outbox_storage_failures_total 7", payload)

    def test_api_token_mutations_require_fresh_routeros_reauthentication(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        session.reauthenticated_at = time.time() - 301

        status, _, payload = self.json_request(
            "POST", "/api/admin/api-tokens",
            {"label": "step-up test", "scopes": ["health.read"], "expires_in": "1h"},
        )
        self.assertEqual(status, 428)
        self.assertTrue(json.loads(payload)["step_up_required"])
        self.assertEqual(self.server.context.store.list_api_tokens(include_revoked=True), [])

        def reauthenticate() -> None:
            nonlocal session_id
            status, headers, response = self.request(
                "POST", "/api/auth/reauthenticate",
                body=json.dumps({"password": "routerpass"}).encode(),
                headers={
                    "Content-Type": "application/json",
                    "X-CSRF-Token": self.csrf,
                    "Origin": self.config.public_origin,
                },
            )
            self.assertEqual(status, 200)
            self.cookie = headers["set-cookie"].split(";", 1)[0]
            session_id = self.cookie.split("=", 1)[1]
            self.csrf = json.loads(response)["csrf_token"]

        reauthenticate()
        status, _, payload = self.json_request(
            "POST", "/api/admin/api-tokens",
            {"label": "step-up test", "scopes": ["health.read"], "expires_in": "1h"},
        )
        self.assertEqual(status, 201, payload.decode())
        token_id = json.loads(payload)["metadata"]["id"]

        session = self.server.context.sessions.get(session_id, touch=False)
        session.reauthenticated_at = time.time() - 301
        status, _, payload = self.request(
            "DELETE", f"/api/admin/api-tokens/{token_id}",
            headers={"X-CSRF-Token": self.csrf},
        )
        self.assertEqual(status, 428)
        self.assertTrue(json.loads(payload)["step_up_required"])
        self.assertTrue(any(
            item["id"] == token_id and item["revoked_at"] is None
            for item in self.server.context.store.list_api_tokens(include_revoked=True)
        ))

        reauthenticate()
        status, _, payload = self.request(
            "DELETE", f"/api/admin/api-tokens/{token_id}",
            headers={"X-CSRF-Token": self.csrf},
        )
        self.assertEqual(status, 200, payload.decode())
        self.assertTrue(any(
            item["id"] == token_id and item["revoked_at"] is not None
            for item in self.server.context.store.list_api_tokens(include_revoked=True)
        ))

    def test_observability_api_tokens_filter_audit_and_session_rows(self) -> None:
        self.login()
        store = self.server.context.store
        now = int(time.time())
        audit_row = {
            "id": 901,
            "created_at": now - 2,
            "actor": "AUDIT-ACTOR-SENTINEL",
            "action": "audit.projection-sentinel",
            "target": "AUDIT-TARGET-SENTINEL",
            "status": "failed",
            "details": {"private": "SENSITIVE-AUDIT-DETAIL-SENTINEL"},
        }
        connection_row = {
            "id": 902,
            "vpn_user": "SESSION-USER-SENTINEL",
            "connected_at": now - 1,
            "disconnected_at": 0,
            "source_address": "SENSITIVE-PEER-ADDRESS-SENTINEL",
            "vpn_address": "SENSITIVE-VPN-ADDRESS-SENTINEL",
        }
        integration_row = {
            "source_id": 901,
            "event_type": "audit",
            "created_at": now - 2,
            "delivered_at": now - 1,
            "attempts": 2,
            "payload": "SENSITIVE-INTEGRATION-PAYLOAD-SENTINEL",
        }
        all_scopes = ("health.read", "audit.read", "sessions.read", "policies.read")
        query_variants = (
            "",
            "?include_audit=true&include_sessions=true",
            "?scopes=audit.read,sessions.read&fields=all&session_id=SENSITIVE-QUERY-SESSION-ID",
        )
        expected_root_fields = {
            "current", "deployments", "health_timeline", "operations_timeline",
            "rollback", "generated_at",
        }
        expected_event_fields = {
            "id", "occurred_at", "source", "type", "actor", "target", "outcome",
            "severity", "summary", "clock_skew_seconds", "age_seconds", "related_events",
            "relationship_summary",
        }

        with (
            mock.patch.object(store, "recent_audit", return_value=[audit_row]) as recent_audit,
            mock.patch.object(store, "recent_connection_timeline", return_value=[connection_row]) as recent_connections,
            mock.patch.object(
                store, "recent_integration_delivery_events", return_value=[integration_row],
            ) as recent_integrations,
            mock.patch.object(store, "recent_deployment_events", return_value=[]) as recent_deployments,
            mock.patch.object(store, "recent_health_snapshots", return_value=[]) as recent_health,
        ):
            for scope_mask in range(1, 1 << len(all_scopes)):
                scopes = [
                    scope for bit, scope in enumerate(all_scopes)
                    if scope_mask & (1 << bit)
                ]
                label = "+".join(scopes)
                status, _, token_payload = self.json_request(
                    "POST", "/api/admin/api-tokens",
                    {"label": f"observability projection {scope_mask}", "scopes": scopes, "expires_in": "1h"},
                )
                self.assertEqual(status, 201, token_payload.decode())
                token = json.loads(token_payload)["token"]
                for query in query_variants:
                    status, _, payload = self.request(
                        "GET", f"/api/observability{query}",
                        headers={"Authorization": f"Bearer {token}", "Cookie": ""},
                    )
                    with self.subTest(scope_case=label, query=query or "none"):
                        if "health.read" not in scopes:
                            self.assertEqual(status, 403, payload.decode())
                            denied = json.loads(payload)
                            self.assertEqual(set(denied), {"error", "role", "required_capability"})
                            self.assertTrue(denied["error"])
                            self.assertEqual(denied["required_capability"], "health.read")
                            continue

                        self.assertEqual(status, 200, payload.decode())
                        observability = json.loads(payload)
                        self.assertEqual(set(observability), expected_root_fields)
                        self.assertEqual(
                            set(observability["current"]), {"version", "revision", "status"},
                        )
                        self.assertEqual(
                            set(observability["rollback"]),
                            {"available", "revision", "version", "message", "data_preserved"},
                        )
                        timeline = observability["operations_timeline"]
                        self.assertEqual(set(timeline), {"events", "generated_at", "coverage"})
                        self.assertEqual(set(timeline["coverage"]), {"complete", "message"})

                        expected_types = set()
                        if "audit.read" in scopes:
                            expected_types.update({"change", "integration"})
                        if "sessions.read" in scopes:
                            expected_types.add("session")
                        self.assertEqual({event["type"] for event in timeline["events"]}, expected_types)
                        integration_events = [
                            event for event in timeline["events"] if event["type"] == "integration"
                        ]
                        if "audit.read" in scopes:
                            self.assertEqual(len(integration_events), 1)
                            self.assertEqual(integration_events[0]["source"], "integration delivery")
                            self.assertEqual(integration_events[0]["outcome"], "delivered")
                            self.assertEqual(integration_events[0]["summary"], "Audit delivery delivered · 2 attempts")
                        else:
                            self.assertEqual(integration_events, [])
                        for event in timeline["events"]:
                            expected_fields = expected_event_fields | (
                                {"timestamp_quality"} if event["type"] == "session" else set()
                            )
                            self.assertEqual(set(event), expected_fields, event["type"])
                            for relation in event["related_events"]:
                                self.assertEqual(
                                    set(relation), {"event_id", "source", "relation", "delta_seconds"},
                                )

                        response = payload.decode("utf-8")
                        visible = []
                        hidden = []
                        if "audit.read" in scopes:
                            visible.extend(("AUDIT-ACTOR-SENTINEL", "AUDIT-TARGET-SENTINEL"))
                        else:
                            hidden.extend(("AUDIT-ACTOR-SENTINEL", "AUDIT-TARGET-SENTINEL"))
                        if "sessions.read" in scopes:
                            visible.append("SESSION-USER-SENTINEL")
                        else:
                            hidden.append("SESSION-USER-SENTINEL")
                        for sentinel in visible:
                            self.assertIn(sentinel, response)
                        for sentinel in hidden + [
                            "SENSITIVE-AUDIT-DETAIL-SENTINEL",
                            "SENSITIVE-INTEGRATION-PAYLOAD-SENTINEL",
                            "SENSITIVE-PEER-ADDRESS-SENTINEL",
                            "SENSITIVE-VPN-ADDRESS-SENTINEL",
                            "SENSITIVE-QUERY-SESSION-ID",
                            "routerpass",
                        ]:
                            self.assertNotIn(sentinel, response)

            # Seven of the fifteen non-empty scope combinations lack health.read
            # and are denied before any observability-store access. Each scope
            # combination was requested with all three query variants.
            self.assertEqual(recent_deployments.call_count, 8 * len(query_variants))
            self.assertEqual(recent_health.call_count, 8 * len(query_variants))
            self.assertEqual(recent_audit.call_count, 4 * len(query_variants))
            self.assertEqual(recent_integrations.call_count, 4 * len(query_variants))
            self.assertEqual(recent_connections.call_count, 4 * len(query_variants))

    def test_setup_preflight_projects_allowlisted_schema_and_omits_inventory_secrets(self) -> None:
        self.login()
        router = self.server.context.router
        inventory = router.get_bootstrap_inventory(RouterOSCredentials("admin", "routerpass"))
        sentinel = "SENSITIVE-SETUP-PREFLIGHT-INVENTORY-SENTINEL"
        inventory["resource"]["private-key"] = sentinel
        for collection in ("ovpn_servers", "ppp_profiles", "certificates"):
            for item in inventory.get(collection) or []:
                item["sensitive-probe"] = sentinel

        with mock.patch.object(router, "get_bootstrap_inventory", return_value=inventory):
            status, _, payload = self.request("GET", "/api/setup-preflight")

        self.assertEqual(status, 200, payload.decode())
        response = json.loads(payload)
        self.assertEqual(set(response), {"router", "image_target", "openvpn", "checks"})
        self.assertEqual(set(response["router"]), {"architecture", "version", "free_storage"})
        self.assertEqual(
            set(response["openvpn"]),
            {"name", "enabled"},
        )
        self.assertEqual(
            response["image_target"],
            container_image_target(response["router"]["architecture"]),
        )
        self.assertEqual(len(response["checks"]), 9)
        self.assertTrue(all(set(item) == {"name", "status", "detail"} for item in response["checks"]))
        self.assertNotIn(sentinel, payload.decode("utf-8"))
        self.assertNotIn("routerpass", payload.decode("utf-8"))

    def test_scoped_api_tokens_follow_the_route_scope_matrix(self) -> None:
        """Verify every token-readable route against each standalone scope and all scopes."""
        self.login()
        revision = "0123456789abcdef0123456789abcdef01234567"
        release_verify = (
            "/api/release/verify?image=ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-"
            f"{revision}-arm64@sha256:{'d' * 64}&revision={revision}"
        )
        scoped_routes = {
            "/metrics": {"health.read"},
            "/api/service-health": {"health.read"},
            "/api/observability": {"health.read"},
            "/api/setup-preflight": {"health.read"},
            release_verify: {"health.read"},
            "/api/reports/diagnostics.zip": {"health.read"},
            "/api/audit.csv": {"audit.read"},
            "/api/audit.json": {"audit.read"},
            "/api/connections.csv": {"sessions.read"},
            "/api/usage.csv": {"sessions.read"},
            "/api/admin/sessions": {"sessions.read"},
            "/api/bulk/views": {"sessions.read"},
            "/api/policy-templates": {"policies.read"},
            "/api/operations-timeline.json": {"audit.read", "sessions.read"},
            "/api/reports/compliance.zip": {"audit.read", "sessions.read"},
        }
        routeros_session_routes = {
            "/api/events": b"Live router events require an authenticated RouterOS session",
            "/api/status": b"authenticated RouterOS dashboard session",
            "/api/certificate-settings": b"authenticated RouterOS dashboard session",
            "/api/users": b"authenticated RouterOS dashboard session",
            "/api/telemetry": b"authenticated RouterOS dashboard session",
        }
        ungrantable_routes = {
            "/api/admin/api-tokens": "security.manage",
            "/api/backups/metadata.zip": "backup.manage",
        }
        get_source = inspect.getsource(DashboardHandler.do_GET)
        get_dispatch_paths = set(re.findall(r'path == "(/api/[^"]+)"', get_source))
        get_dispatch_patterns = set(re.findall(r're\.fullmatch\(r"(/api/[^"]+)"\s*,\s*path\)', get_source))
        token_route_paths = {
            path
            for path in (
                {urllib.parse.urlsplit(path).path for path in scoped_routes}
                | set(routeros_session_routes)
                | set(ungrantable_routes)
            )
            if path.startswith("/api/")
        }
        self.assertEqual(
            get_dispatch_paths, token_route_paths,
            "every literal GET /api route must be classified for API-token access",
        )
        self.assertEqual(
            get_dispatch_patterns, set(),
            "classify any newly added regex GET /api route for API-token access",
        )
        all_scopes = {"health.read", "audit.read", "sessions.read", "policies.read"}
        scope_names = sorted(all_scopes)
        scope_sets = [
            {
                scope_names[index]
                for index in range(len(scope_names))
                if mask & (1 << index)
            }
            for mask in range(1, 1 << len(scope_names))
        ]
        self.assertEqual(len(scope_sets), (1 << len(scope_names)) - 1)
        before_mutations = list(self.mock.state.mutation_requests)

        for index, scopes in enumerate(scope_sets):
            status, _, payload = self.json_request(
                "POST", "/api/admin/api-tokens",
                {"label": f"route matrix {index}", "scopes": sorted(scopes), "expires_in": "1h"},
            )
            self.assertEqual(status, 201)
            token = json.loads(payload)["token"]
            headers = {"Authorization": f"Bearer {token}", "Cookie": ""}

            for path, required in scoped_routes.items():
                with self.subTest(scopes=sorted(scopes), path=path):
                    status, _, response = self.request("GET", path, headers=headers)
                    if required <= scopes:
                        self.assertIn(status, {200, 502}, path)
                        self.assertNotEqual(status, 403, path)
                        self.assertNotIn(b"routerpass", response)
                    else:
                        self.assertEqual(status, 403, path)
                        self.assertNotIn(b"user-one", response)
                        self.assertTrue(
                            any(scope.encode() in response for scope in required - scopes),
                            f"denial should name a missing scope for {path}",
                        )

            with mock.patch.object(
                self.server.context.router, "_request",
                side_effect=AssertionError("scoped API token reached RouterOS-only route"),
            ) as router_request:
                for path, denial in routeros_session_routes.items():
                    with self.subTest(scopes=sorted(scopes), path=path):
                        status, _, response = self.request("GET", path, headers=headers)
                        self.assertEqual(status, 403, path)
                        self.assertIn(denial, response)
                router_request.assert_not_called()

            for path, required in ungrantable_routes.items():
                with self.subTest(scopes=sorted(scopes), path=path):
                    status, _, response = self.request("GET", path, headers=headers)
                    self.assertEqual(status, 403, path)
                    self.assertIn(required.encode(), response)

        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

    def test_api_token_cannot_open_dashboard_or_reach_routeros(self) -> None:
        token = "vpt_" + "d" * 48
        self.server.context.store.create_api_token(
            token_id="dashboard-html-token",
            token_hash=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            label="dashboard route denial",
            actor="viewer",
            capabilities=["health.read"],
            expires_at=2_000_000_000,
        )
        before_router_reads = list(self.mock.state.rest_reads)

        with mock.patch.object(
            self.server.context.router,
            "verify_credentials",
            side_effect=AssertionError("API-token principal reached RouterOS verification"),
        ) as verify_credentials:
            status, _, payload = self.request(
                "GET",
                "/dashboard",
                headers={"Authorization": f"Bearer {token}", "Cookie": ""},
            )

        self.assertEqual(status, 403, payload.decode("utf-8"))
        self.assertEqual(
            json.loads(payload),
            {"error": "This endpoint requires an authenticated RouterOS dashboard session"},
        )
        verify_credentials.assert_not_called()
        self.assertEqual(self.mock.state.rest_reads, before_router_reads)

    def test_routeros_group_downgrade_takes_effect_on_existing_dashboard_session(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        self.server.context.store.audit(
            actor="admin", action="security.review", target="role-downgrade-marker",
            status="success", details="owner-only history",
        )

        self.mock.state.admin_group = "read"
        self.server.context.sessions._role_checked_monotonic[session_id] = 0
        status, _, payload = self.request("GET", "/api/observability", headers={"Cookie": self.cookie})

        self.assertEqual(status, 200)
        self.assertEqual(session.role, "read_only")
        self.assertNotIn(b"role-downgrade-marker", payload)
        principal = self.server.telemetry_runtime.principal_for_session(session_id)
        self.assertTrue(principal.may_stream, "read-only role retains the approved live-session capability")

        status, _, _ = self.request(
            "POST", "/api/admin/api-tokens",
            body=json.dumps({"label": "denied after downgrade"}).encode(),
            headers={"Cookie": self.cookie, "Content-Type": "application/json", "X-CSRF-Token": self.csrf},
        )
        self.assertEqual(status, 403)

    def test_routeros_role_downgrade_blocks_mutation_without_waiting_for_cache(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        self.assertEqual(session.role, "owner")
        before_mutations = self.mock.state.mutation_requests

        # Keep the ordinary 15-second session-role cache warm, then downgrade
        # the RouterOS account before its cached role expires.
        self.mock.state.admin_group = "read"
        status, _, _ = self.json_request("POST", "/api/users", {})

        self.assertEqual(status, 403)
        self.assertEqual(session.role, "read_only")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

    def test_warm_auditor_downgrade_stops_audit_disclosure_on_next_request(self) -> None:
        self.mock.state.admin_group = "audit"
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        self.assertEqual(session.role, "auditor")
        self.server.context.store.audit(
            actor="admin", action="security.review", target="warm-role-audit-marker",
            status="success", details="auditor-only history",
        )

        status, _, payload = self.request("GET", "/api/audit.json", headers={"Cookie": self.cookie})
        self.assertEqual(status, 200)
        self.assertIn(b"warm-role-audit-marker", payload)

        # The ordinary session-role cache is now warm. A downgrade must be
        # revalidated before optional audit data or a protected export is sent.
        self.mock.state.admin_group = "read"
        status, _, status_payload = self.request("GET", "/api/status", headers={"Cookie": self.cookie})

        self.assertEqual(status, 200)
        self.assertEqual(session.role, "read_only")
        self.assertNotIn(b"warm-role-audit-marker", status_payload)

        status, _, audit_payload = self.request("GET", "/api/audit.json", headers={"Cookie": self.cookie})
        self.assertEqual(status, 403)
        self.assertNotIn(b"warm-role-audit-marker", audit_payload)

    def test_warm_role_downgrade_hides_admin_session_references_from_dashboard(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        other_session = self.server.context.sessions.create("admin", "routerpass", role="owner")

        status, _, owner_page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(session.revocation_ref.encode("ascii"), owner_page)
        self.assertIn(other_session.revocation_ref.encode("ascii"), owner_page)
        self.assertNotIn(session_id.encode("ascii"), owner_page)
        self.assertNotIn(other_session.session_id.encode("ascii"), owner_page)

        self.mock.state.admin_group = "read"
        original_revalidate = self.server.telemetry_runtime.revalidate_session
        with mock.patch.object(
            self.server.telemetry_runtime,
            "revalidate_session",
            wraps=original_revalidate,
        ) as revalidate:
            status, _, page = self.request("GET", "/dashboard")

        self.assertEqual(status, 200)
        self.assertEqual(session.role, "read_only")
        self.assertIn(b"Active administrator sessions", page)
        self.assertNotIn(session.revocation_ref.encode("ascii"), page)
        self.assertNotIn(other_session.revocation_ref.encode("ascii"), page)
        self.assertNotIn(session_id.encode("ascii"), page)
        self.assertNotIn(other_session.session_id.encode("ascii"), page)
        forced_role_checks = [
            call for call in revalidate.call_args_list
            if call.kwargs.get("force_role_check") is True
        ]
        self.assertEqual(len(forced_role_checks), 1)

    def test_disabled_warm_auditor_does_not_reuse_stale_request_audit_allow(self) -> None:
        self.mock.state.admin_group = "audit"
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        self.assertIsNotNone(self.server.context.sessions.get(session_id, touch=False))
        self.server.context.store.audit(
            actor="admin", action="security.review", target="revoked-audit-marker",
            status="success", details="must not be disclosed after account disable",
        )

        # The initial session lookup remains inside its normal role-cache
        # interval. The dashboard's first audit check then discovers revocation;
        # subsequent checks in this same response must reuse a DENY, not stale
        # authorization from the detached session object.
        self.mock.state.admin_disabled = True
        status, _, payload = self.request("GET", "/dashboard", headers={"Cookie": self.cookie})

        self.assertEqual(status, 200)
        self.assertNotIn(b"revoked-audit-marker", payload)
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))

    def test_disabled_warm_routeros_account_cannot_read_admin_session_inventory(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        owner = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(owner)
        peer = self.server.context.sessions.create(
            owner.username,
            owner.password,
            role=owner.role,
            source_address="SENSITIVE-PEER-ADDRESS-SENTINEL",
            user_agent="SENSITIVE-PEER-AGENT-SENTINEL",
        )

        # The ordinary request authentication remains inside its role-cache
        # interval; the inventory route must force a fresh role check before
        # returning metadata about any session for this account.
        self.mock.state.admin_disabled = True
        status, _, payload = self.request(
            "GET", "/api/admin/sessions", headers={"Cookie": self.cookie}
        )

        self.assertEqual(status, 401)
        self.assertNotIn(b"SENSITIVE-PEER-ADDRESS-SENTINEL", payload)
        self.assertNotIn(b"SENSITIVE-PEER-AGENT-SENTINEL", payload)
        self.assertNotIn(peer.session_id.encode("ascii"), payload)
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertIsNone(self.server.context.sessions.get(peer.session_id, touch=False))
        self.assertEqual(owner.password, "")
        self.assertEqual(peer.password, "")

    def test_disabled_routeros_account_revokes_all_existing_live_sessions(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        peer = self.server.context.sessions.create(
            session.username, session.password, role=session.role
        )
        self.mock.state.admin_disabled = True
        self.server.context.sessions._role_checked_monotonic[session_id] = 0

        principal = self.server.telemetry_runtime.principal_for_session(session_id)

        self.assertIsNone(principal)
        self.assertIsNone(self.server.context.sessions.get(session_id, touch=False))
        self.assertIsNone(
            self.server.context.sessions.get(peer.session_id, touch=False)
        )
        self.assertEqual(session.password, "")
        self.assertEqual(peer.password, "")

    def test_auth_audit_events_are_detailed_but_secret_free(self) -> None:
        bad_login = urllib.parse.urlencode({"username": "admin", "password": "wrong"}).encode()
        self.request(
            "POST", "/login", body=bad_login,
            headers={
                "Content-Type": "application/x-www-form-urlencoded",
                "Origin": self.config.public_origin,
            },
        )
        failed = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(failed["action"], "login.failure")
        self.assertIn("auth_method", failed["details"])
        self.assertNotIn("wrong", failed["details"])

        self.login()
        actions = [item["action"] for item in self.server.context.store.recent_audit(10)]
        self.assertIn("routeros.login.credentials_verified", actions)
        self.assertIn("routeros.role.verified", actions)
        logout = urllib.parse.urlencode({"csrf": self.csrf}).encode()
        status, _, _ = self.request(
            "POST", "/logout", body=logout,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 303)
        revoked = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(revoked["action"], "session.revoked")
        self.assertNotIn(self.cookie, revoked["details"])

    def test_openvpn_foundation_plan_is_review_only_and_conflict_aware(self) -> None:
        self.login()
        payload = {
            "endpoint": "vpn.example.test",
            "lan": "192.0.2.0/24",
            "vpn_subnet": "10.254.0.0/24",
            "dns_server": "192.0.2.1",
            "port": "1194",
            "ca_name": "ovpn-bootstrap-ca",
            "server_certificate": "ovpn-bootstrap-server",
            "server_name": "ovpn-bootstrap",
            "ppp_profile": "ovpn-bootstrap",
            "pool_name": "ovpn-bootstrap-pool",
        }
        status, _, response = self.json_request("POST", "/api/openvpn-foundation-plan", payload)
        self.assertEqual(status, 409)
        self.assertIn("no existing OpenVPN server", json.loads(response)["error"])

        self.mock.state.ovpn_servers.clear()
        self.mock.state.profiles.clear()
        self.mock.state.certificates.clear()
        status, _, response = self.json_request("POST", "/api/openvpn-foundation-plan", payload)
        self.assertEqual(status, 200)
        plan = json.loads(response)["plan"]
        self.assertIn("REVIEW-ONLY OPENVPN FOUNDATION PLAN", plan)
        self.assertIn("/certificate/sign ovpn-bootstrap-ca", plan)
        self.assertIn("disabled=yes protocol=udp port=1194", plan)
        self.assertIn("disabled=yes comment", plan)
        self.assertNotIn("routerpass", plan)
        self.assertEqual(self.mock.state.ovpn_servers, [])
        self.assertEqual(self.mock.state.profiles, {})
        self.assertEqual(self.mock.state.certificates, {})

        payload["vpn_subnet"] = "192.0.2.0/24"
        status, _, _ = self.json_request("POST", "/api/openvpn-foundation-plan", payload)
        self.assertEqual(status, 400)

    def test_openvpn_foundation_plan_redacts_routeros_inventory_errors(self) -> None:
        self.login()
        payload = {
            "endpoint": "vpn.example.test",
            "lan": "192.0.2.0/24",
            "vpn_subnet": "10.254.0.0/24",
            "dns_server": "192.0.2.1",
            "port": "1194",
            "ca_name": "ovpn-bootstrap-ca",
            "server_certificate": "ovpn-bootstrap-server",
            "server_name": "ovpn-bootstrap",
            "ppp_profile": "ovpn-bootstrap",
            "pool_name": "ovpn-bootstrap-pool",
        }
        with mock.patch.object(
            self.server.context.router,
            "get_bootstrap_inventory",
            side_effect=RouterOSError("private RouterOS response marker", 503),
        ):
            status, _, payload_bytes = self.json_request(
                "POST", "/api/openvpn-foundation-plan", payload,
            )

        response = json.loads(payload_bytes)
        self.assertEqual(status, 502)
        self.assertEqual(response["code"], "routeros.request_failed")
        self.assertNotIn("private RouterOS response marker", payload_bytes.decode())

    def test_profile_creation_redacts_routeros_provisioning_errors(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-one"
        )
        review = self.preview_profile(user["id"], "Redaction test phone")
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/profiles"
        with mock.patch.object(
            self.server.context.router,
            "provision_profile",
            side_effect=RouterOSError("private RouterOS profile detail", 503),
        ):
            status, _, payload = self.json_request(
                "POST", path,
                {
                    "device_name": "Redaction test phone",
                    "reason": review["reason"],
                    "key_passphrase": "test-profile-passphrase",
                    "delivery": "zip",
                    "review_token": review["review_token"],
                },
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["code"], "routeros.request_failed")
        self.assertNotIn("private RouterOS profile detail", payload.decode())
        self.assertNotIn("test-profile-passphrase", payload.decode())

    def test_profile_issuance_and_recovery_logs_omit_sensitive_material(self) -> None:
        self.login()
        router = self.server.context.router
        user = next(
            item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/profiles"
        provision_profile = router.provision_profile

        def capture_profile(*args: Any, **kwargs: Any) -> Any:
            profile = provision_profile(*args, **kwargs)
            issued_profiles.append(profile)
            return profile

        issued_profiles = []
        success_device = "Log-redaction success phone"
        success_passphrase = "LOG-ONLY-success-passphrase"
        success_review = self.preview_profile(user["id"], success_device, delivery="zip")
        success_logs = io.StringIO()
        with (
            mock.patch.object(router, "provision_profile", side_effect=capture_profile),
            contextlib.redirect_stdout(success_logs),
        ):
            status, _, _ = self.json_request(
                "POST", path,
                {
                    "device_name": success_device,
                    "reason": success_review["reason"],
                    "key_passphrase": success_passphrase,
                    "delivery": "zip",
                    "review_token": success_review["review_token"],
                },
            )

        self.assertEqual(status, 200)
        self.assertEqual(len(issued_profiles), 1)
        success_log_text = success_logs.getvalue()
        self.assertIn("http method=POST status=200", success_log_text)
        for sensitive_value in (
            success_passphrase,
            success_device,
            issued_profiles[0].certificate_name,
            issued_profiles[0].profile.decode("utf-8"),
        ):
            self.assertNotIn(sensitive_value, success_log_text)

        recovery_device = "Log-redaction recovery phone"
        recovery_passphrase = "LOG-ONLY-recovery-passphrase"
        storage_error = "LOG-ONLY-private-storage-error"
        recovery_review = self.preview_profile(user["id"], recovery_device, delivery="zip")
        recovery_logs = io.StringIO()
        recovery_profiles = []

        def capture_recovery_profile(*args: Any, **kwargs: Any) -> Any:
            profile = provision_profile(*args, **kwargs)
            recovery_profiles.append(profile)
            return profile

        with (
            mock.patch.object(router, "provision_profile", side_effect=capture_recovery_profile),
            mock.patch.object(
                self.server.context.store,
                "add_device",
                side_effect=OSError(storage_error),
            ),
            contextlib.redirect_stdout(recovery_logs),
        ):
            status, _, payload = self.json_request(
                "POST", path,
                {
                    "device_name": recovery_device,
                    "reason": recovery_review["reason"],
                    "key_passphrase": recovery_passphrase,
                    "delivery": "zip",
                    "review_token": recovery_review["review_token"],
                },
            )

        self.assertEqual(status, 502)
        self.assertEqual(json.loads(payload)["recovery"], "verified")
        self.assertEqual(len(recovery_profiles), 1)
        recovery_log_text = recovery_logs.getvalue()
        self.assertIn("http method=POST status=502", recovery_log_text)
        for sensitive_value in (
            recovery_passphrase,
            recovery_device,
            storage_error,
            recovery_profiles[0].certificate_name,
            recovery_profiles[0].profile.decode("utf-8"),
        ):
            self.assertNotIn(sensitive_value, recovery_log_text)

    def test_user_provision_redacts_routeros_error_after_verified_cleanup(self) -> None:
        self.login()
        intent = {
            "username": "redacted-provision",
            "email": "redacted-provision@example.test",
            "device_name": "Test phone",
            "delivery": "ovpn",
            "policy": "full-tunnel",
            "reason": "Approved redaction regression test for profile creation",
        }
        review = self.preview_user_provision(intent)
        with mock.patch.object(
            self.server.context.router,
            "provision_profile",
            side_effect=RouterOSError("private RouterOS provision detail", 503),
        ):
            status, _, payload = self.json_request(
                "POST", "/api/users",
                {
                    **intent,
                    "password": "redacted-provision-password",
                    "key_passphrase": "redacted-provision-private-key",
                    "review_token": review["review_token"],
                },
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["code"], "routeros.request_failed")
        self.assertNotIn("private RouterOS provision detail", payload.decode())
        self.assertNotIn("redacted-provision-password", payload.decode())
        self.assertNotIn("redacted-provision-private-key", payload.decode())
        self.assertNotIn(
            "redacted-provision",
            [item["name"] for item in self.mock.state.users.values()],
        )

    def test_setup_plan_accepts_ipv6_without_materialising_the_network(self) -> None:
        self.login()
        payload = {
            "origin": "https://dashboard.example.test",
            "image": "ghcr.io/example/mikrotik-openvpn-gui:sha-" + "a" * 40 + "-arm64@sha256:" + "b" * 64,
            "storage": "/disk1/vpn-dashboard",
            "subnet": "2001:db8:1234:1::/120",
            "lan": "2001:db8:1234:2::/64",
        }
        status, _, response = self.json_request("POST", "/api/setup-plan", payload)
        self.assertEqual(status, 200)
        plan = json.loads(response)["plan"]
        self.assertIn("IPv6", plan)
        self.assertIn("address=2001:db8:1234:1::2/120", plan)
        self.assertIn("gateway=2001:db8:1234:1::1", plan)

        payload["lan"] = "192.0.2.0/24"
        status, _, response = self.json_request("POST", "/api/setup-plan", payload)
        self.assertEqual(status, 400)
        self.assertIn("same IPv4 or IPv6 family", json.loads(response)["error"])

    def test_readiness_failure_is_generic_and_non_successful(self) -> None:
        with mock.patch.object(
            self.server.context.store,
            "verify_readiness",
            side_effect=RuntimeError("sensitive database path"),
        ):
            status, _, payload = self.request("GET", "/readyz")

        self.assertEqual(status, 503)
        self.assertEqual(json.loads(payload), {"status": "unavailable"})
        self.assertNotIn(b"sensitive", payload)

    def test_health_snapshot_is_safe_when_router_is_unavailable(self) -> None:
        health = service_health_snapshot(
            router=None,
            ovpn_server=None,
            certificates=None,
            config=self.config,
            database_ready=False,
            unavailable_reason="router",
        )
        self.assertEqual(health["overall"], "unavailable")
        self.assertEqual(health["checks"][0]["id"], "routeros-rest")
        self.assertNotIn("routerpass", json.dumps(health))

    def test_certificate_health_does_not_interpret_router_local_absolute_dates(self) -> None:
        health = service_health_snapshot(
            router={},
            ovpn_server={"name": "vpn-server", "enabled": True},
            certificates=[{
                "name": "client-without-relative-expiry",
                "invalid_after": "Dec/04/2030 14:19:51",
                "revoked": False,
            }],
            config=self.config,
            database_ready=True,
        )

        inventory = next(check for check in health["checks"] if check["id"] == "certificate-inventory")
        self.assertEqual(inventory["status"], "warning")
        self.assertIn("Expiry could not be confirmed", inventory["impact"])

    def test_service_health_persists_certificate_expiry_alerts(self) -> None:
        """A soon-to-expire RouterOS certificate becomes a durable dashboard alert."""
        self.login()
        # Keep the fixture in the warning window regardless of when CI runs.
        self.mock.state.certificates["*CL1"]["expires-after"] = "1w"
        status, _, payload = self.request("GET", "/api/service-health")
        self.assertEqual(status, 200)
        self.assertIn("certificate-inventory", {item["id"] for item in json.loads(payload)["checks"]})
        alerts = self.server.context.store.recent_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["action"], "certificate.expiring")
        self.assertIn("ovpn-user-one-device-a", alerts[0]["details"])
        # Repeated five-second polls update the same incident rather than
        # spamming separate alerts.
        self.request("GET", "/api/service-health")
        repeated = self.server.context.store.recent_alerts()
        self.assertEqual(len(repeated), 1)
        self.assertEqual(repeated[0]["occurrence_count"], 2)
        self.assertGreaterEqual(repeated[0]["last_seen_at"], repeated[0]["created_at"])

    def test_service_health_response_projects_exact_allowlisted_fields(self) -> None:
        self.login()
        health = {
            "overall": "warning",
            "checked_at": 1_800_000_000,
            "router_password_sentinel": "must-not-escape",
            "checks": [{
                "id": "routeros-rest",
                "name": "RouterOS REST connection",
                "status": "warning",
                "impact": "Router health is delayed.",
                "remediation": "Check the connection.",
                "private_certificate_sentinel": "must-not-escape",
                "source_address": "198.51.100.77",
            }],
            "private_root_sentinel": "must-not-escape",
        }
        with mock.patch.object(DashboardHandler, "_service_health", return_value=health):
            status, _, payload = self.request("GET", "/api/service-health")

        self.assertEqual(status, 200, payload.decode("utf-8"))
        response = json.loads(payload)
        self.assertEqual(set(response), {"overall", "checked_at", "checks"})
        self.assertEqual(len(response["checks"]), 1)
        self.assertEqual(
            set(response["checks"][0]),
            {"id", "name", "status", "impact", "remediation"},
        )
        self.assertEqual(response["overall"], "warning")
        serialized = payload.decode("utf-8")
        for sentinel in (
            "must-not-escape",
            "router_password_sentinel",
            "private_certificate_sentinel",
            "source_address",
            "198.51.100.77",
            "private_root_sentinel",
        ):
            self.assertNotIn(sentinel, serialized)

    def test_favicon_variants_are_public_and_linked(self) -> None:
        status, headers, svg = self.request("GET", "/favicon.svg")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "image/svg+xml")
        self.assertIn(b"<svg", svg)

        status, headers, ico = self.request("GET", "/favicon.ico")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "image/x-icon")
        self.assertEqual(ico[:4], b"\x00\x00\x01\x00")
        self.assertEqual(ico[22:26], b"\x89PNG")

        status, _, login_page = self.request("GET", "/login")
        self.assertEqual(status, 200)
        self.assertIn(b'href="/favicon.svg?v=20260905"', login_page)
        self.assertIn(b'href="/favicon.ico?v=20260905"', login_page)

        status, headers, manifest = self.request("GET", "/static/manifest.webmanifest")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/manifest+json")
        self.assertEqual(json.loads(manifest)["display"], "standalone")

        status, headers, logo = self.request("GET", "/static/openvpn-logo.svg")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "image/svg+xml")
        self.assertIn(b"<svg", logo)
        self.assertNotIn(b"<script", logo.lower())

    def test_user_profile_lifecycle_and_csrf(self) -> None:
        self.login()

        status, _, _ = self.json_request(
            "POST",
            "/api/users",
            {"username": "maria", "password": "profile-pass", "device_name": "Tablet test"},
            csrf=False,
        )
        self.assertEqual(status, 403)

        status, _, payload = self.json_request(
            "POST",
            "/api/users",
            {"username": "missing-email", "password": "profile-pass", "device_name": "Test phone"},
        )
        self.assertEqual(status, 400)
        self.assertIn("valid email", json.loads(payload)["error"])
        self.assertNotIn("missing-email", [item["name"] for item in self.mock.state.users.values()])

        create_request = {
            "username": "maria", "email": "maria@example.com", "password": "profile-pass",
            "key_passphrase": "maria-key-passphrase", "device_name": "Tablet test",
            "comment": "integration test", "delivery": "ovpn",
            "reason": "Approved remote access for Maria",
        }
        preview = self.preview_user_provision({key: value for key, value in create_request.items() if key not in {"password", "key_passphrase"}})
        status, headers, profile = self.json_request(
            "POST",
            "/api/users",
            {**create_request, "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/x-openvpn-profile")
        self.assertIn('filename="maria-Tablet-test.ovpn"', headers["content-disposition"])
        self.assertIn(b"redirect-gateway def1", profile)
        self.assertIn(b"<key>", profile)
        self.assertNotIn(b"profile-pass", profile)
        create_audit = next(
            item for item in self.server.context.store.recent_audit()
            if item["action"] == "user.create" and item["target"] == "maria"
        )
        self.assertTrue(json.loads(create_audit["details"])["rationale_recorded"])

        users = {
            item["name"]: item
            for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            )
        }
        maria_id = users["maria"]["id"]

        edit = {
                "email": "maria.new@example.com", "comment": "changed", "disabled": True,
                "password": "new-profile-pass", "policy": "lan-only", "expiry": "1d",
                "max_sessions": "2", "rate_limit_kbps": "25600", "quota_mb": "10240",
                "schedule": "weekdays", "dns_mode": "cloudflare",
                "notifications": True, "reason": "Update Maria access settings",
            }
        edit_path = f"/api/users/{urllib.parse.quote(maria_id, safe='*')}"
        status, _, preview_payload = self.json_request("POST", edit_path + "/preview", edit)
        self.assertEqual(status, 200)
        preview = json.loads(preview_payload)
        self.assertTrue(preview["changes"]["password_changed"])
        self.assertNotIn("new-profile-pass", preview_payload.decode())
        edit["review_token"] = preview["review_token"]
        status, _, payload = self.json_request("PATCH", edit_path, edit)
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(payload),
            {
                "ok": True,
                "verified": False,
                "verification": "partial",
                "password_verified": False,
                "reconciled": False,
            },
        )
        self.assertEqual(self.server.context.store.user_emails()["maria"], "maria.new@example.com")
        controls = self.server.context.store.user_controls("maria")
        self.assertEqual(controls["policy"], "lan-only")
        self.assertEqual(controls["rate_limit_kbps"], 25600)
        self.assertEqual(controls["quota_mb"], 10240)
        self.assertEqual(controls["schedule"], "weekdays")
        self.assertEqual(self.mock.state.users[maria_id]["profile"], "vpn-ui-maria")

        preview = self.preview_profile(maria_id, "Tablet", delivery="ovpn")
        status, _, second_profile = self.json_request(
            "POST",
            f"/api/users/{urllib.parse.quote(maria_id, safe='*')}/profiles",
            {"device_name": "Tablet", "reason": preview["reason"], "key_passphrase": "tablet-passphrase", "delivery": "ovpn", "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 200)
        self.assertNotIn(b"tablet-passphrase", second_profile)
        self.assertNotIn(b"redirect-gateway def1", second_profile)
        self.assertIn(b"dhcp-option DNS 1.1.1.1", second_profile)
        self.assertEqual(len(self.server.context.store.devices_for_user("maria")), 2)
        profile_audit = self.server.context.store.recent_audit(1)[0]
        self.assertTrue(json.loads(profile_audit["details"])["rationale_recorded"])
        self.server.context.store.save_policy_template(
            template_id="template-reviewed", name="Reviewed", description="test",
            group_name="Test", controls={"policy": "full-tunnel"},
        )
        self.server.context.store.assign_policy_template("maria", "template-reviewed")
        self.server.context.store.add_user_tag("maria", "Remote")
        deletion_review = self.preview_user_delete(maria_id)
        self.assertEqual(deletion_review["managed_devices"], 2)

        status, _, payload = self.json_request(
            "DELETE", f"/api/users/{urllib.parse.quote(maria_id, safe='*')}",
            self.user_delete_apply(deletion_review, "not-maria"),
        )
        self.assertEqual(status, 400)
        self.assertIn("exact target name", json.loads(payload)["error"])
        self.assertIn("maria", [item["name"] for item in self.mock.state.users.values()])

        status, _, payload = self.json_request(
            "DELETE", f"/api/users/{urllib.parse.quote(maria_id, safe='*')}",
            self.user_delete_apply(deletion_review, "maria"),
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {
            "ok": True,
            "verified": True,
            "retired_devices": 2,
            "disconnected_sessions": 0,
        })
        self.assertNotIn("maria", [item["name"] for item in self.mock.state.users.values()])
        self.assertNotIn("maria", self.server.context.store.user_emails())
        self.assertNotIn("maria", self.server.context.store.all_user_controls())
        self.assertNotIn("maria", self.server.context.store.user_template_assignments())
        self.assertEqual(self.server.context.store.user_tags("maria"), [])
        self.assertEqual(set(self.mock.state.certificates), {"*CA", "*CL1", "*CL2", "*C1", "*C2"})
        self.assertTrue(self.mock.state.certificates["*CA"].get("revoked") in (None, "no"))
        self.assertTrue(all(self.mock.state.certificates[item]["revoked"] for item in ("*C1", "*C2")))
        self.assertTrue(all(item["revoked_at"] for item in self.server.context.store.devices_for_user("maria", include_revoked=True)))
        self.assertTrue(
            json.loads(self.server.context.store.recent_audit(1)[0]["details"])["rationale_recorded"]
        )

    def test_user_creation_review_excludes_secrets_and_rejects_taken_username(self) -> None:
        self.login()
        create_intent = {
            "username": "review-race", "email": "review-race@example.test",
            "device_name": "New phone", "delivery": "zip", "policy": "full-tunnel",
            "reason": "Approved remote access for review race",
        }
        before_mutations = list(self.mock.state.mutation_requests)
        before_certificates = set(self.mock.state.certificates)
        preview = self.preview_user_provision(create_intent)
        serialized = json.dumps(preview)
        self.assertEqual(preview["username"], "review-race")
        self.assertFalse(preview["secrets_included"])
        self.assertNotIn("password", serialized.lower())
        self.assertNotIn("private-key", serialized.lower())
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(set(self.mock.state.certificates), before_certificates)

        self.mock.state.users["*RACE"] = {
            ".id": "*RACE", "name": "review-race", "service": "ovpn",
            "profile": "vpn-full-tunnel", "comment": "Created by a concurrent administrator", "disabled": "no",
        }
        status, _, payload = self.json_request(
            "POST", "/api/users",
            {
                **create_intent, "password": "review-race-password",
                "key_passphrase": "review-race-key-passphrase", "review_token": preview["review_token"],
            },
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(set(self.mock.state.certificates), before_certificates)
        self.assertNotIn(b"review-race-password", payload)

    def test_user_creation_review_rejects_changed_access_intent_before_mutation(self) -> None:
        self.login()
        create_intent = {
            "username": "review-change", "email": "review-change@example.test",
            "device_name": "New phone", "delivery": "zip", "policy": "full-tunnel",
            "rate_limit_kbps": "10240", "comment": "Reviewed comment",
            "reason": "Approved remote access for review change",
        }
        before_mutations = list(self.mock.state.mutation_requests)
        before_certificates = set(self.mock.state.certificates)
        preview = self.preview_user_provision(create_intent)
        changed_intent = {
            **create_intent, "policy": "lan-only", "reason": "Different approved access purpose", "password": "changed-intent-password",
            "key_passphrase": "changed-intent-key-passphrase", "review_token": preview["review_token"],
        }
        status, _, payload = self.json_request("POST", "/api/users", changed_intent)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(set(self.mock.state.certificates), before_certificates)

    def test_user_creation_review_requires_reason_before_routeros_reads(self) -> None:
        self.login()
        status, _, payload = self.json_request("POST", "/api/users/preview", {
            "username": "reason-required", "email": "reason@example.test",
            "device_name": "Phone", "delivery": "zip",
        })
        self.assertEqual(status, 400)
        self.assertIn("reason", json.loads(payload)["error"])
        self.assertEqual(self.mock.state.mutation_requests, [])

    def test_user_creation_review_binds_and_displays_reason(self) -> None:
        self.login()
        intent = {
            "username": "review-reason", "email": "reason@example.test",
            "device_name": "Phone", "delivery": "zip",
            "reason": "Approved remote access for a contractor",
        }
        preview = self.preview_user_provision(intent)
        self.assertEqual(preview["reason"], intent["reason"])
        before_mutations = list(self.mock.state.mutation_requests)
        status, _, payload = self.json_request("POST", "/api/users", {
            **intent, "reason": "Different purpose for VPN access",
            "password": "reason-required-password",
            "key_passphrase": "reason-required-key-passphrase",
            "review_token": preview["review_token"],
        })
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

    def test_user_creation_review_binds_generated_rate_profile_state(self) -> None:
        self.login()
        intent = {
            "username": "review-rate-race", "email": "rate-race@example.test",
            "device_name": "New phone", "delivery": "zip", "policy": "full-tunnel",
            "rate_limit_kbps": "10240",
            "reason": "Approved rate-limited remote access",
        }
        before_mutations = list(self.mock.state.mutation_requests)
        before_certificates = set(self.mock.state.certificates)
        preview = self.preview_user_provision(intent)
        self.mock.state.profiles["*P9"] = {
            ".id": "*P9", "name": "vpn-ui-review-rate-race", "rate-limit": "512k/512k",
        }

        status, _, payload = self.json_request(
            "POST", "/api/users",
            {
                **intent, "password": "review-rate-password",
                "key_passphrase": "review-rate-key-passphrase", "review_token": preview["review_token"],
            },
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(set(self.mock.state.certificates), before_certificates)
        self.assertEqual(self.mock.state.profiles["*P9"]["rate-limit"], "512k/512k")

    def test_user_edit_relative_expiry_review_survives_second_boundary(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-two"
        )
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}"
        edit = {
            "email": "user.two@example.test", "comment": "Expiry boundary test",
            "policy": "full-tunnel", "expiry": "1d", "max_sessions": "2",
            "rate_limit_kbps": "0", "quota_mb": "0", "schedule": "always",
            "dns_mode": "router", "notifications": True,
            "reason": "Test expiry review stability",
        }
        status, _, payload = self.json_request("POST", f"{path}/preview", edit)
        self.assertEqual(status, 200, payload.decode("utf-8"))
        edit["review_token"] = json.loads(payload)["review_token"]

        parse_controls = DashboardHandler._parse_controls

        def simulate_next_second(data: dict[str, Any], current: dict[str, Any] | None = None) -> dict[str, Any]:
            controls = parse_controls(data, current)
            if data.get("expiry") == "1d" and controls["expires_at"] is not None:
                controls["expires_at"] += 1
            return controls

        with mock.patch.object(DashboardHandler, "_parse_controls", side_effect=simulate_next_second):
            status, _, payload = self.json_request("PATCH", path, edit)

        self.assertEqual(status, 200, payload.decode("utf-8"))
        self.assertTrue(json.loads(payload)["verified"])

    def test_user_provision_reports_incomplete_cleanup_when_router_still_has_account(self) -> None:
        self.login()
        intent = {
            "username": "provision-recovery", "email": "provision-recovery@example.test",
            "device_name": "Test laptop", "delivery": "ovpn", "policy": "full-tunnel",
            "reason": "Approved recovery scenario for VPN setup",
        }
        review = self.preview_user_provision(intent)
        router = self.server.context.router
        with mock.patch.object(
            router, "provision_profile", side_effect=RouterOSError("injected provisioning failure", 503),
        ), mock.patch.object(router, "delete_user"):
            status, _, payload = self.json_request(
                "POST", "/api/users",
                {
                    **intent, "password": "provision-recovery-password",
                    "key_passphrase": "provision-recovery-key", "review_token": review["review_token"],
                },
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["code"], "routeros.provision_recovery_incomplete")
        self.assertEqual(response["recovery"], "partial")
        self.assertIn("provision-recovery", [item["name"] for item in self.mock.state.users.values()])
        self.assertEqual(self.server.context.store.user_emails()["provision-recovery"], intent["email"])
        self.assertNotIn(b"provision-recovery-password", payload)
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "partial")

    def test_user_provision_reports_retained_generated_rate_profile(self) -> None:
        self.login()
        intent = {
            "username": "provision-rate-residue", "email": "rate-residue@example.test",
            "device_name": "Test laptop", "delivery": "ovpn", "policy": "full-tunnel",
            "rate_limit_kbps": "10240",
            "reason": "Approved rate-limited recovery scenario",
        }
        review = self.preview_user_provision(intent)
        router = self.server.context.router
        with mock.patch.object(
            router, "provision_profile", side_effect=RouterOSError("injected provisioning failure", 503),
        ):
            status, _, payload = self.json_request(
                "POST", "/api/users",
                {
                    **intent, "password": "rate-residue-password",
                    "key_passphrase": "rate-residue-key", "review_token": review["review_token"],
                },
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["recovery"], "partial")
        self.assertEqual(response["rate_profile_recovery"], "retained_or_changed")
        self.assertNotIn("provision-rate-residue", [item["name"] for item in self.mock.state.users.values()])
        self.assertTrue(any(
            item["name"] == "vpn-ui-provision-rate-residue"
            for item in self.mock.state.profiles.values()
        ))
        self.assertEqual(
            json.loads(self.server.context.store.recent_audit(1)[0]["details"])["rate_profile_recovery"],
            "retained_or_changed",
        )

    def test_profile_creation_revokes_new_certificate_when_local_recording_fails(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            )
            if item["name"] == "user-two"
        )
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/profiles"
        preview = self.preview_profile(user["id"], "Recovery phone")
        revoke_certificate = self.server.context.router.revoke_certificate

        def revoke_then_lose_response(credentials: Any, *, certificate_id: str) -> None:
            revoke_certificate(credentials, certificate_id=certificate_id)
            raise RouterOSError("private RouterOS response", 503)

        with mock.patch.object(
            self.server.context.store, "add_device", side_effect=OSError("injected disk full"),
        ), mock.patch.object(
            self.server.context.router, "revoke_certificate", side_effect=revoke_then_lose_response,
        ):
            status, _, payload = self.json_request(
                "POST", path,
                {"device_name": "Recovery phone", "reason": preview["reason"], "key_passphrase": "private-file-passphrase", "delivery": "zip", "review_token": preview["review_token"]},
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["recovery"], "verified")
        self.assertIn("certificate was revoked", response["error"])
        self.assertNotIn("injected disk full", response["error"])
        self.assertNotIn(b"private-file-passphrase", payload)
        certificates = self.server.context.router.list_ovpn_client_certificates(
            RouterOSCredentials("admin", "routerpass"), include_legacy=True,
        )
        generated = [
            item for item in certificates
            if item["name"].startswith("ovpn-ui-user-two-recovery-phone-")
        ]
        self.assertEqual(len(generated), 1)
        self.assertTrue(generated[0]["revoked"])
        self.assertIsNone(self.server.context.store.device_by_certificate(generated[0]["name"]))
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["action"], "profile.create.recovery")
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "verified")

    def test_profile_migration_revokes_replacement_when_migration_recording_fails(self) -> None:
        self.mock.state.certificates["*OLD"] = {
            ".id": "*OLD", "name": "legacy-user-one-phone", "common-name": "user-one-phone",
            "fingerprint": "OLD:FAKE", "issuer": "legacy-ca", "ca": "legacy-ca",
            "trusted": "yes", "revoked": "no", "key-usage": "tls-client",
            "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
        }
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-one"
        )
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/profiles"
        preview = self.preview_profile(
            user["id"], "Replacement phone", delivery="ovpn",
            legacy_certificate="legacy-user-one-phone",
        )

        with mock.patch.object(
            self.server.context.store,
            "record_profile_migration",
            side_effect=OSError("injected migration storage failure"),
        ):
            status, _, payload = self.json_request(
                "POST", path,
                {
                    "device_name": "Replacement phone",
                    "reason": preview["reason"],
                    "key_passphrase": "replacement-key-passphrase",
                    "legacy_certificate": "legacy-user-one-phone",
                    "delivery": "ovpn",
                    "review_token": preview["review_token"],
                },
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["recovery"], "verified")
        self.assertIn("new certificate was revoked", response["error"])
        self.assertNotIn("injected migration storage failure", response["error"])
        self.assertNotIn(b"replacement-key-passphrase", payload)
        certificates = self.server.context.router.list_ovpn_client_certificates(
            RouterOSCredentials("admin", "routerpass"), include_legacy=True,
        )
        replacement = next(
            item for item in certificates if item["name"].startswith("ovpn-ui-user-one-replacement-phone-")
        )
        self.assertTrue(replacement["revoked"])
        self.assertFalse(next(item for item in certificates if item["name"] == "legacy-user-one-phone")["revoked"])
        device = self.server.context.store.device_by_certificate(replacement["name"])
        self.assertIsNotNone(device)
        self.assertIsNotNone(device["revoked_at"])
        self.assertNotIn("legacy-user-one-phone", self.server.context.store.profile_migrations())
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["action"], "profile.create.recovery")
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "verified")

    def test_profile_creation_reports_unknown_if_cleanup_cannot_be_verified(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            )
            if item["name"] == "user-two"
        )
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/profiles"
        preview = self.preview_profile(user["id"], "Uncertain phone")
        with mock.patch.object(
            self.server.context.store, "add_device", side_effect=OSError("injected disk full"),
        ), mock.patch.object(self.server.context.router, "revoke_certificate"):
            status, _, payload = self.json_request(
                "POST", path,
                {"device_name": "Uncertain phone", "reason": preview["reason"], "key_passphrase": "private-file-passphrase", "delivery": "zip", "review_token": preview["review_token"]},
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["recovery"], "unknown")
        self.assertIn("before retrying", response["error"])
        self.assertNotIn(b"private-file-passphrase", payload)
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "unknown")
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["action"], "profile.create.recovery")

    def test_profile_migration_reports_unknown_when_replacement_cleanup_is_unverified(self) -> None:
        self.mock.state.certificates["*OLD"] = {
            ".id": "*OLD", "name": "legacy-user-one-phone", "common-name": "user-one-phone",
            "fingerprint": "OLD:FAKE", "issuer": "legacy-ca", "ca": "legacy-ca",
            "trusted": "yes", "revoked": "no", "key-usage": "tls-client",
            "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
        }
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-one"
        )
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/profiles"
        preview = self.preview_profile(
            user["id"], "Replacement phone", delivery="ovpn",
            legacy_certificate="legacy-user-one-phone",
        )

        with (
            mock.patch.object(
                self.server.context.store,
                "record_profile_migration",
                side_effect=OSError("injected migration storage failure"),
            ),
            mock.patch.object(self.server.context.router, "revoke_certificate"),
            mock.patch.object(DashboardHandler, "_deliver_profile") as deliver_profile,
        ):
            status, _, payload = self.json_request(
                "POST", path,
                {
                    "device_name": "Replacement phone",
                    "reason": preview["reason"],
                    "key_passphrase": "replacement-key-passphrase",
                    "legacy_certificate": "legacy-user-one-phone",
                    "delivery": "ovpn",
                    "review_token": preview["review_token"],
                },
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["recovery"], "unknown")
        self.assertIn("recovery is not fully verified", response["error"])
        self.assertNotIn("injected migration storage failure", response["error"])
        self.assertNotIn(b"replacement-key-passphrase", payload)
        deliver_profile.assert_not_called()
        certificates = self.server.context.router.list_ovpn_client_certificates(
            RouterOSCredentials("admin", "routerpass"), include_legacy=True,
        )
        replacement = next(
            item for item in certificates
            if item["name"].startswith("ovpn-ui-user-one-replacement-phone-")
        )
        self.assertFalse(replacement["revoked"])
        self.assertFalse(next(
            item for item in certificates if item["name"] == "legacy-user-one-phone"
        )["revoked"])
        device = self.server.context.store.device_by_certificate(replacement["name"])
        self.assertIsNotNone(device)
        self.assertIsNone(device["revoked_at"])
        self.assertNotIn("legacy-user-one-phone", self.server.context.store.profile_migrations())
        audit = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(audit["action"], "profile.create.recovery")
        self.assertEqual(audit["status"], "unknown")
        self.assertNotIn("replacement-key-passphrase", json.dumps(audit))

    def test_profile_review_is_secret_free_and_rejects_stale_policy_before_mutation(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        before_mutations = list(self.mock.state.mutation_requests)
        preview = self.preview_profile(user["id"], "Reviewed tablet")
        serialized_preview = json.dumps(preview)
        self.assertEqual(preview["user"], "user-two")
        self.assertEqual(preview["device"], "Reviewed tablet")
        self.assertEqual(preview["reason"], "Approved additional device access")
        self.assertNotIn("key_passphrase", serialized_preview)
        self.assertNotIn("private-file-passphrase", serialized_preview)
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

        self.server.context.store.set_user_controls(
            "user-two", policy="lan-only", expires_at=None, max_sessions=1,
            rate_limit_kbps=0, dns_mode="router", notifications=True,
        )
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/profiles",
            {
                "device_name": "Reviewed tablet", "reason": preview["reason"], "key_passphrase": "private-file-passphrase",
                "delivery": "zip", "review_token": preview["review_token"],
            },
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertNotIn(b"private-file-passphrase", payload)
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(set(self.mock.state.certificates), {"*CA", "*CL1", "*CL2"})

    def test_profile_issue_requires_reason_and_binds_it_to_review(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/profiles"
        before_mutations = list(self.mock.state.mutation_requests)
        status, _, payload = self.json_request(
            "POST", path + "/preview", {"device_name": "Reviewed phone", "delivery": "zip"},
        )
        self.assertEqual(status, 400)
        self.assertIn("Provide a reason", json.loads(payload)["error"])

        preview = self.preview_profile(user["id"], "Reviewed phone")
        changed_reason = {
            "device_name": "Reviewed phone", "reason": "Different profile issuance reason",
            "delivery": "zip", "key_passphrase": "private-file-passphrase",
            "review_token": preview["review_token"],
        }
        status, _, payload = self.json_request("POST", path, changed_reason)
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        audit = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(audit["status"], "failed")
        self.assertTrue(json.loads(audit["details"])["rationale_recorded"])

    def test_profile_checkpoint_failure_prevents_certificate_mutation_and_delivery(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass"),
            ) if item["name"] == "user-two"
        )
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/profiles"
        preview = self.preview_profile(user["id"], "Checkpoint phone", delivery="ovpn")
        mutations_before = list(self.mock.state.mutation_requests)
        certificates_before = {
            certificate_id: dict(certificate)
            for certificate_id, certificate in self.mock.state.certificates.items()
        }

        with (
            mock.patch.object(
                self.server.context.router,
                "create_configuration_export",
                side_effect=RouterOSError("private checkpoint detail", 503),
            ) as create_checkpoint,
            mock.patch.object(self.server.context.router, "provision_profile") as provision_profile,
            mock.patch.object(DashboardHandler, "_deliver_profile") as deliver_profile,
        ):
            status, _, payload = self.json_request(
                "POST",
                path,
                {
                    "device_name": "Checkpoint phone",
                    "reason": preview["reason"],
                    "key_passphrase": "private-checkpoint-passphrase",
                    "delivery": "ovpn",
                    "review_token": preview["review_token"],
                },
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(
            response["error"],
            "RouterOS configuration checkpoint failed; no change was applied.",
        )
        self.assertNotIn(b"private checkpoint detail", payload)
        self.assertNotIn(b"private-checkpoint-passphrase", payload)
        create_checkpoint.assert_called_once()
        provision_profile.assert_not_called()
        deliver_profile.assert_not_called()
        self.assertEqual(self.mock.state.mutation_requests, mutations_before)
        self.assertEqual(self.mock.state.certificates, certificates_before)
        self.assertEqual(self.server.context.store.devices_for_user("user-two"), [])
        audit = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(audit["action"], "checkpoint.create")
        self.assertEqual(audit["target"], "profile.create")
        self.assertEqual(audit["status"], "failed")
        self.assertEqual(json.loads(audit["details"]), {"reason": "RouterOSError"})

    def test_profile_review_receipt_is_atomically_single_use_for_concurrent_apply(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        preview = self.preview_profile(user["id"], "Single issue tablet")
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/profiles"
        request_data = {
            "device_name": "Single issue tablet", "reason": preview["reason"], "key_passphrase": "private-file-passphrase",
            "delivery": "zip", "review_token": preview["review_token"],
        }
        review_barrier = threading.Barrier(2)
        original_context = DashboardHandler._profile_review_context

        def synchronized_context(handler: DashboardHandler, *args: Any, **kwargs: Any) -> Any:
            result = original_context(handler, *args, **kwargs)
            review_barrier.wait(timeout=10)
            return result

        results: list[tuple[int, dict[str, str], bytes]] = []
        result_lock = threading.Lock()

        def apply_profile() -> None:
            response = self.json_request("POST", path, request_data)
            with result_lock:
                results.append(response)

        before_certificates = len(self.mock.state.certificates)
        before_devices = len(self.server.context.store.devices_for_user("user-two"))
        with mock.patch.object(
            DashboardHandler, "_profile_review_context", autospec=True, side_effect=synchronized_context,
        ):
            workers = [threading.Thread(target=apply_profile) for _ in range(2)]
            for worker in workers:
                worker.start()
            for worker in workers:
                worker.join(timeout=15)

        self.assertTrue(all(not worker.is_alive() for worker in workers))
        self.assertEqual(sorted(status for status, _, _ in results), [200, 409])
        self.assertEqual(len(self.mock.state.certificates), before_certificates + 1)
        self.assertEqual(len(self.server.context.store.devices_for_user("user-two")), before_devices + 1)

    def _review_user_edit(self, path: str, values: dict[str, Any]) -> dict[str, Any]:
        reviewed = {**values, "reason": "Unit-test reviewed account change"}
        status, _, payload = self.json_request("POST", path + "/preview", reviewed)
        if status != 200:
            raise AssertionError(f"user edit preview failed: {status} {payload!r}")
        reviewed["review_token"] = json.loads(payload)["review_token"]
        return reviewed

    def test_user_update_reconciles_lost_routeros_response_from_readback(self) -> None:
        self.login()
        router = self.server.context.router
        user = next(
            item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        update_user = router.update_user

        def update_then_lose_response(*args: Any, **kwargs: Any) -> None:
            update_user(*args, **kwargs)
            raise RouterOSError("private RouterOS response", 503)

        reviewed = self._review_user_edit(
            f"/api/users/{urllib.parse.quote(user['id'], safe='*')}",
            {"comment": "updated safely", "disabled": False, "policy": "full-tunnel"},
        )
        with mock.patch.object(router, "update_user", side_effect=update_then_lose_response):
            status, _, payload = self.json_request(
                "PATCH", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}",
                reviewed,
            )

        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["reconciled"])
        self.assertEqual(self.mock.state.users[user["id"]]["comment"], "updated safely")
        audit = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(audit["status"], "success")
        self.assertTrue(json.loads(audit["details"])["mutation_response_lost"])
        self.assertNotIn("private RouterOS response", payload.decode())

    def test_user_update_review_is_bound_to_generated_rate_profile_state(self) -> None:
        self.login()
        router = self.server.context.router
        user = next(
            item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-one"
        )
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}"
        edit = {
            "email": "user.one@example.test", "comment": "Reviewed bandwidth update",
            "disabled": False, "policy": "full-tunnel", "expiry": "",
            "max_sessions": "2", "rate_limit_kbps": "10240", "quota_mb": "0",
            "schedule": "always", "dns_mode": "router", "notifications": True,
            "reason": "Review the generated PPP bandwidth profile",
        }
        reviewed = self._review_user_edit(path, edit)
        self.mock.state.profiles["*P9"] = {
            ".id": "*P9", "name": "vpn-ui-user-one", "rate-limit": "512k/512k",
        }

        status, _, payload = self.json_request("PATCH", path, reviewed)

        self.assertEqual(status, 409)
        self.assertIn("state has changed", json.loads(payload)["error"])
        self.assertEqual(self.mock.state.profiles["*P9"]["rate-limit"], "512k/512k")
        self.assertNotIn("PATCH /ppp/profile/*P9", self.mock.state.mutation_requests)

    def test_user_update_retains_local_state_when_routeros_readback_is_unavailable(self) -> None:
        self.login()
        router = self.server.context.router
        self.server.context.store.set_user_controls(
            "user-two", policy="full-tunnel", expires_at=None, max_sessions=1,
            rate_limit_kbps=0, dns_mode="router", notifications=True,
        )
        self.server.context.store.set_enforcement_state("user-two", "quota")
        user = next(
            item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        initial_users = router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
        reviewed = {
            "comment": "update not yet confirmed", "disabled": True, "policy": "lan-only",
        }
        with mock.patch.object(
            router, "list_ovpn_users",
            side_effect=[initial_users, initial_users, RouterOSError("read-back unavailable")],
        ):
            reviewed = self._review_user_edit(
                f"/api/users/{urllib.parse.quote(user['id'], safe='*')}", reviewed,
            )
            status, _, payload = self.json_request(
                "PATCH", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}",
                reviewed,
            )

        self.assertEqual(status, 502)
        self.assertEqual(json.loads(payload)["verification"], "unknown")
        controls = self.server.context.store.user_controls("user-two")
        self.assertEqual(controls["policy"], "full-tunnel")
        self.assertEqual(controls["enforcement_state"], "quota")
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "unknown")

    def test_user_update_reports_mismatch_without_committing_local_metadata(self) -> None:
        self.login()
        router = self.server.context.router
        self.server.context.store.set_user_controls(
            "user-two", policy="full-tunnel", expires_at=None, max_sessions=1,
            rate_limit_kbps=0, dns_mode="router", notifications=True,
        )
        user = next(
            item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        with mock.patch.object(router, "update_user"):
            reviewed = self._review_user_edit(
                f"/api/users/{urllib.parse.quote(user['id'], safe='*')}",
                {"comment": "not applied", "disabled": True, "policy": "lan-only"},
            )
            status, _, payload = self.json_request(
                "PATCH", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}",
                reviewed,
            )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["verification"], "mismatch")
        self.assertEqual(self.server.context.store.user_controls("user-two")["policy"], "full-tunnel")
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "failed")

    def test_user_update_does_not_claim_lost_password_change_was_verified(self) -> None:
        self.login()
        router = self.server.context.router
        user = next(
            item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        update_user = router.update_user

        def update_then_lose_response(*args: Any, **kwargs: Any) -> None:
            update_user(*args, **kwargs)
            raise RouterOSError("private RouterOS response", 503)

        reviewed = self._review_user_edit(
            f"/api/users/{urllib.parse.quote(user['id'], safe='*')}",
            {
                "comment": "observable settings applied", "disabled": False,
                "password": "sensitive-password-value", "policy": "full-tunnel",
            },
        )
        with mock.patch.object(router, "update_user", side_effect=update_then_lose_response):
            status, _, payload = self.json_request(
                "PATCH", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}",
                reviewed,
            )

        self.assertEqual(status, 502)
        result = json.loads(payload)
        self.assertEqual(result["verification"], "unknown")
        self.assertNotIn("sensitive-password-value", payload.decode())
        self.assertNotIn("private RouterOS response", payload.decode())
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "unknown")
    def test_user_edit_receipt_rejects_tampering_staleness_and_other_session(self) -> None:
        self.login()
        user = next(item for item in self.server.context.router.list_ovpn_users(RouterOSCredentials("admin", "routerpass")) if item["name"] == "user-one")
        path = f"/api/users/{urllib.parse.quote(user['id'], safe='*')}"
        edit = {"email": "one@example.test", "comment": "reviewed", "disabled": False,
                "password": "secret-preview-value", "policy": "full-tunnel", "expiry": "never",
                "max_sessions": "5", "rate_limit_kbps": "0", "quota_mb": "0",
                "schedule": "always", "dns_mode": "router", "notifications": True,
                "reason": "Routine access review"}
        status, _, payload = self.json_request("POST", path + "/preview", edit)
        self.assertEqual(status, 200)
        preview = json.loads(payload)
        self.assertNotIn("secret-preview-value", payload.decode())

        tampered = dict(edit, password="different-secret", review_token=preview["review_token"])
        status, _, _ = self.json_request("PATCH", path, tampered)
        self.assertEqual(status, 409)
        self.assertNotEqual(self.mock.state.users[user["id"]].get("password"), "different-secret")

        stale = dict(edit, review_token=preview["review_token"])
        self.mock.state.users[user["id"]]["comment"] = "changed in RouterOS"
        status, _, _ = self.json_request("PATCH", path, stale)
        self.assertEqual(status, 409)
        self.mock.state.users[user["id"]]["comment"] = ""

        status, _, payload = self.json_request("POST", path + "/preview", edit)
        token = json.loads(payload)["review_token"]
        self.login()
        status, _, _ = self.json_request("PATCH", path, dict(edit, review_token=token))
        self.assertEqual(status, 409)
        audit = json.dumps(self.server.context.store.recent_audit(20))
        self.assertNotIn("secret-preview-value", audit)

    def test_qr_profile_share_is_a_bounded_zip_download(self) -> None:
        self.login()
        users = {
            item["name"]: item
            for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            )
        }
        user_one_id = users["user-one"]["id"]
        path = f"/api/users/{urllib.parse.quote(user_one_id, safe='*')}/profiles"
        preview = self.preview_profile(user_one_id, "QR phone", delivery="qr")
        status, headers, payload = self.json_request(
            "POST",
            path,
            {"device_name": "QR phone", "reason": preview["reason"], "key_passphrase": "qr-passphrase", "delivery": "qr", "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        response = json.loads(payload)
        self.assertTrue(response["download_url"].startswith("https://dashboard.example.test/share/"))
        self.assertIn("<svg", response["qr_svg"])
        mutation_count = len(self.mock.state.mutation_requests)
        certificate_count = len(self.mock.state.certificates)
        status, _, replay_payload = self.json_request(
            "POST", path,
            {
                "device_name": "QR phone", "reason": preview["reason"], "key_passphrase": "qr-passphrase", "delivery": "qr",
                "review_token": preview["review_token"],
            },
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(replay_payload)["code"], "routeros.review_stale")
        self.assertEqual(len(self.mock.state.mutation_requests), mutation_count)
        self.assertEqual(len(self.mock.state.certificates), certificate_count)
        share_path = urllib.parse.urlsplit(response["download_url"]).path

        for _ in range(3):
            status, headers, archive_payload = self.request("GET", share_path)
            self.assertEqual(status, 200)
            self.assertEqual(headers["content-type"], "application/zip")
            self.assertIn('filename="user-one-QR-phone.zip"', headers["content-disposition"])
            with zipfile.ZipFile(io.BytesIO(archive_payload)) as archive:
                self.assertEqual(archive.namelist(), ["user-one-QR-phone.ovpn"])
                profile = archive.read(archive.namelist()[0])
            self.assertIn(b"redirect-gateway def1", profile)
            self.assertNotIn(b"qr-passphrase", profile)
        status, _, _ = self.request("GET", share_path)
        self.assertEqual(status, 410)

    def test_profile_migration_issues_replacement_without_retiring_legacy_profile(self) -> None:
        self.mock.state.certificates["*OLD"] = {
            ".id": "*OLD", "name": "legacy-user-one-phone", "common-name": "user-one-phone",
            "fingerprint": "OLD:FAKE", "issuer": "legacy-ca", "ca": "legacy-ca",
            "trusted": "yes", "revoked": "no", "key-usage": "tls-client",
            "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
        }
        self.login()
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b"Certificate replacement", page)
        self.assertIn(b"legacy-user-one-phone", page)
        self.assertIn(b"Issue replacement", page)

        user_one_id = next(
            user["id"] for user in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if user["name"] == "user-one"
        )
        preview = self.preview_profile(
            user_one_id, "Replacement phone", delivery="ovpn",
            legacy_certificate="legacy-user-one-phone",
        )
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_one_id, safe='*')}/profiles",
            {
                "device_name": "Replacement phone", "reason": preview["reason"], "key_passphrase": "replacement-passphrase",
                "legacy_certificate": "legacy-user-one-phone", "delivery": "ovpn",
                "review_token": preview["review_token"],
            },
        )
        self.assertEqual(status, 200)
        self.assertIn(b"BEGIN CERTIFICATE", payload)
        migration = self.server.context.store.profile_migrations()["legacy-user-one-phone"]
        self.assertEqual(migration["vpn_user"], "user-one")
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(migration["replacement_certificate_name"].encode(), page)
        self.assertIn(b"Replacement issued; import pending", page)
        self.assertIn(b"Import it on the VPN device first", page)
        self.assertNotIn(b"Review old-certificate revocation", page)
        legacy = next(
            item for item in self.server.context.router.list_ovpn_client_certificates(
                RouterOSCredentials("admin", "routerpass"), include_legacy=True
            ) if item["name"] == "legacy-user-one-phone"
        )
        self.assertFalse(legacy["revoked"])

        status, _, payload = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/tested", {},
        )
        self.assertEqual(status, 409)
        self.assertIn("Confirm the replacement import", json.loads(payload)["error"])
        status, _, payload = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/imported", {},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["operator_attested"])
        migration = self.server.context.store.profile_migrations()["legacy-user-one-phone"]
        self.assertIsNotNone(migration["imported_at"])
        self.assertIsNone(migration["tested_at"])
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b"Confirm live replacement test", page)
        self.assertNotIn(b"Review old-certificate revocation", page)

        self.mock.state.active_sessions["*A2"] = {
            ".id": "*A2", "name": "user-one", "service": "ovpn",
            "caller-id": "198.51.100.41", "address": "198.18.0.49",
            "uptime": "1m", "encoding": "AES-256-GCM/[user-one-digest]",
        }

        status, _, payload = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/tested", {},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["step"], "tested")
        self.assertTrue(json.loads(payload)["active_user_session_observed"])
        self.assertFalse(json.loads(payload)["certificate_attribution_verified"])
        migration = self.server.context.store.profile_migrations()["legacy-user-one-phone"]
        self.assertTrue(migration["tested_with_active_session"])
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b"Replacement test confirmed by operator", page)
        self.assertIn(b"RouterOS cannot identify which client certificate", page)
        self.assertIn(b"Review old-certificate revocation", page)
        self.assertIn(b'data-revoke-kind="legacy"', page)

    def test_expiring_managed_certificate_supports_staged_same_ca_renewal(self) -> None:
        source_name = "ovpn-user-one-device-a"
        source_device_id = "managed-expiring-phone"
        source_device_name = "Managed phone"
        self.mock.state.certificates["*CL1"]["expires-after"] = "2w"
        self.server.context.store.add_device(
            device_id=source_device_id,
            vpn_user="user-one",
            device_name=source_device_name,
            certificate_name=source_name,
            certificate_id="*CL1",
            fingerprint="A1:EX:26",
        )
        self.login()

        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b"Renewal recommended", page)
        self.assertIn(b"Renew certificate", page)
        self.assertIn(b"data-replacement-type=\"renewal\"", page)

        user_id = next(
            user["id"] for user in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if user["name"] == "user-one"
        )
        preview = self.preview_profile(
            user_id, "Managed phone replacement", delivery="ovpn",
            legacy_certificate=source_name,
        )
        self.assertEqual(preview["replacement_type"], "renewal")
        self.assertTrue(preview["old_profile_remains_active"])

        passphrase = "renewal-passphrase-never-persisted"
        status, _, profile = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/profiles",
            {
                "device_name": "Managed phone replacement",
                "reason": preview["reason"],
                "key_passphrase": passphrase,
                "legacy_certificate": source_name,
                "delivery": "ovpn",
                "review_token": preview["review_token"],
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(profile)
        migration = self.server.context.store.profile_migrations()[source_name]
        replacement_name = migration["replacement_certificate_name"]
        persisted_state = json.dumps(migration, sort_keys=True)
        self.assertNotIn(passphrase, persisted_state)
        self.assertNotIn("PRIVATE KEY", persisted_state)
        self.assertFalse(self.mock.state.certificates["*CL1"]["revoked"] in {"yes", "true"})

        status, _, response = self.json_request(
            "POST", "/api/devices/managed-expiring-phone/revoke/preview",
            {"confirmation": source_device_name, "reason": "Staged replacement must be tested first."},
        )
        self.assertEqual(status, 400)
        self.assertIn("test", json.loads(response)["error"].lower())
        self.assertEqual(self.mock.state.certificates["*CL1"]["revoked"], "no")

        status, _, response = self.json_request(
            "POST", f"/api/profile-migrations/{urllib.parse.quote(source_name, safe='')}/steps/imported", {},
        )
        self.assertEqual(status, 200, response.decode("utf-8"))
        status, _, response = self.json_request(
            "POST", f"/api/profile-migrations/{urllib.parse.quote(source_name, safe='')}/steps/tested", {},
        )
        self.assertEqual(status, 409)
        self.assertIn("active session", json.loads(response)["error"])
        self.mock.state.active_sessions["*A2"] = {
            ".id": "*A2", "name": "user-one", "service": "ovpn",
            "caller-id": "198.51.100.41", "address": "198.18.0.49",
            "uptime": "1m", "encoding": "AES-256-GCM/[user-one-digest]",
        }
        status, _, response = self.json_request(
            "POST", f"/api/profile-migrations/{urllib.parse.quote(source_name, safe='')}/steps/tested", {},
        )
        self.assertEqual(status, 200, response.decode("utf-8"))
        self.assertFalse(json.loads(response)["certificate_attribution_verified"])
        self.assertEqual(self.mock.state.certificates["*CL1"]["revoked"], "no")
        self.assertEqual(
            self.server.context.store.profile_migrations()[source_name]["replacement_certificate_name"],
            replacement_name,
        )

        reason = "Replacement tested on the owner's phone."
        revoke_path = "/api/devices/managed-expiring-phone/revoke"
        status, _, response = self.json_request(
            "POST", f"{revoke_path}/preview",
            {"confirmation": source_device_name, "reason": reason},
        )
        self.assertEqual(status, 200, response.decode("utf-8"))
        review = json.loads(response)
        status, _, response = self.json_request(
            "POST", revoke_path,
            {
                "confirmation": source_device_name,
                "reason": reason,
                "review_token": review["review_token"],
            },
        )
        self.assertEqual(status, 200, response.decode("utf-8"))
        self.assertTrue(json.loads(response)["verified"])
        self.assertNotIn(self.mock.state.certificates["*CL1"]["revoked"], {"no", "false", ""})
        self.assertFalse(self.mock.state.certificates[next(
            key for key, item in self.mock.state.certificates.items()
            if item.get("name") == replacement_name
        )]["revoked"] in {"yes", "true"})
        self.assertEqual(
            self.server.context.store.profile_migrations()[source_name]["retirement_state"],
            "verified",
        )
        renewal_audits = [
            item for item in self.server.context.store.recent_audit(20)
            if item["action"] == "profile.renew"
        ]
        self.assertEqual(len(renewal_audits), 1)
        self.assertNotIn(passphrase, json.dumps(renewal_audits))

    def test_same_ca_renewal_review_rejects_changed_source_certificate_identity(self) -> None:
        source_name = "ovpn-user-one-device-a"
        user_id = next(
            user["id"] for user in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if user["name"] == "user-one"
        )
        self.server.context.store.add_device(
            device_id="managed-renewal-review-phone",
            vpn_user="user-one",
            device_name="Managed phone",
            certificate_name=source_name,
            certificate_id="*CL1",
            fingerprint="A1:EX:26",
        )
        self.login()
        preview = self.preview_profile(
            user_id, "Replacement phone", delivery="ovpn", legacy_certificate=source_name,
        )
        before_mutations = list(self.mock.state.mutation_requests)

        # RouterOS now reports a different issuer identity for the reviewed source.
        self.mock.state.certificates["*CL1"]["issuer"] = "rotated-vpn-ca"
        self.mock.state.certificates["*CL1"]["ca"] = "rotated-vpn-ca"
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/profiles",
            {
                "device_name": "Replacement phone",
                "reason": preview["reason"],
                "key_passphrase": "renewal-passphrase-never-persisted",
                "legacy_certificate": source_name,
                "delivery": "ovpn",
                "review_token": preview["review_token"],
            },
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertNotIn(b"renewal-passphrase-never-persisted", payload)
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(set(self.mock.state.certificates), {"*CA", "*CL1", "*CL2"})
        self.assertEqual(self.mock.state.certificates["*CL1"]["issuer"], "rotated-vpn-ca")

    def test_same_ca_renewal_rejects_changed_source_id_fingerprint_or_revocation(self) -> None:
        source_name = "ovpn-user-one-device-a"
        user_id = next(
            user["id"] for user in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if user["name"] == "user-one"
        )
        self.server.context.store.add_device(
            device_id="managed-renewal-identity-phone",
            vpn_user="user-one",
            device_name="Managed phone",
            certificate_name=source_name,
            certificate_id="*CL1",
            fingerprint="A1:EX:26",
        )
        self.login()
        source = self.mock.state.certificates["*CL1"]
        original = dict(source)

        # Each RouterOS identity change must stop issuance before any mutation.
        for field, value in ((".id", "*ROTATED"), ("fingerprint", "B2:CHANGED"), ("revoked", "yes")):
            with self.subTest(field=field):
                source.clear()
                source.update(original)
                device_name = f"Replacement {field.replace('.', 'id-')}"
                preview = self.preview_profile(
                    user_id, device_name, delivery="ovpn", legacy_certificate=source_name,
                )
                before_mutations = list(self.mock.state.mutation_requests)
                source[field] = value
                passphrase = "source-identity-change-passphrase"
                status, _, payload = self.json_request(
                    "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/profiles",
                    {
                        "device_name": device_name,
                        "reason": preview["reason"],
                        "key_passphrase": passphrase,
                        "legacy_certificate": source_name,
                        "delivery": "ovpn",
                        "review_token": preview["review_token"],
                    },
                )

                self.assertEqual(status, 400)
                self.assertNotIn(passphrase.encode(), payload)
                self.assertEqual(self.mock.state.mutation_requests, before_mutations)
                self.assertEqual(set(self.mock.state.certificates), {"*CA", "*CL1", "*CL2"})
                self.assertNotIn(passphrase, json.dumps(self.server.context.store.recent_audit(20)))

        source.clear()
        source.update(original)

    def test_same_ca_renewal_rejects_unmanaged_certificate(self) -> None:
        self.login()
        user_id = next(
            user["id"] for user in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if user["name"] == "user-one"
        )
        reason = "Approved certificate renewal request"
        status, _, response = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/profiles/preview",
            {
                "device_name": "Unmanaged replacement",
                "delivery": "zip",
                "legacy_certificate": "ovpn-user-one-device-a",
                "reason": reason,
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("dashboard-managed", json.loads(response)["error"])
        self.assertEqual(self.mock.state.mutation_requests, [])

        self.server.context.store.add_device(
            device_id="stale-managed-certificate-metadata",
            vpn_user="user-one",
            device_name="Managed phone with stale identity",
            certificate_name="ovpn-user-one-device-a",
            certificate_id="*STALE",
            fingerprint="STALE:FAKE",
        )
        status, _, response = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/profiles/preview",
            {
                "device_name": "Stale replacement",
                "delivery": "zip",
                "legacy_certificate": "ovpn-user-one-device-a",
                "reason": reason,
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("dashboard-managed", json.loads(response)["error"])
        self.assertEqual(self.mock.state.mutation_requests, [])

    def test_same_ca_renewal_button_requires_known_expiry(self) -> None:
        self.mock.state.certificates["*CL1"]["expires-after"] = ""
        self.server.context.store.add_device(
            device_id="managed-unknown-expiry-phone",
            vpn_user="user-one",
            device_name="Managed phone",
            certificate_name="ovpn-user-one-device-a",
            certificate_id="*CL1",
            fingerprint="A1:EX:26",
        )
        self.login()

        status, _, page = self.request("GET", "/dashboard")

        self.assertEqual(status, 200)
        self.assertIn(b"Expiry unknown", page)
        self.assertNotIn(b'data-replacement-type="renewal"', page)

    def test_expired_managed_certificate_renewal_does_not_promise_connectivity(self) -> None:
        self.mock.state.certificates["*CL1"]["expires-after"] = "0s"
        self.server.context.store.add_device(
            device_id="managed-expired-phone",
            vpn_user="user-one",
            device_name="Managed phone",
            certificate_name="ovpn-user-one-device-a",
            certificate_id="*CL1",
            fingerprint="A1:EX:26",
        )
        self.login()
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn("Expired · renewal recommended".encode(), page)
        self.assertIn(b"an expired certificate may already be unusable", page)
        self.assertIn(b'data-replacement-type="renewal"', page)

    def test_same_ca_renewal_requires_nonempty_identity_evidence(self) -> None:
        self.mock.state.certificates["*CL1"]["fingerprint"] = ""
        self.mock.state.certificates["*CL1"]["expires-after"] = "15d"
        self.server.context.store.add_device(
            device_id="managed-missing-fingerprint",
            vpn_user="user-one",
            device_name="Managed phone",
            certificate_name="ovpn-user-one-device-a",
            certificate_id="*CL1",
            fingerprint="",
        )
        self.login()
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertNotIn(b'data-replacement-type="renewal"', page)

        user_id = next(
            user["id"] for user in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if user["name"] == "user-one"
        )
        status, _, response = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/profiles/preview",
            {
                "device_name": "Replacement for missing fingerprint",
                "delivery": "zip",
                "legacy_certificate": "ovpn-user-one-device-a",
                "reason": "Approved certificate renewal request",
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("dashboard-managed", json.loads(response)["error"])
        self.assertEqual(self.mock.state.mutation_requests, [])

    def test_profile_migration_test_requires_a_live_user_session_and_fails_closed(self) -> None:
        self.mock.state.certificates["*OLD"] = {
            ".id": "*OLD", "name": "legacy-user-one-phone", "common-name": "user-one-phone",
            "fingerprint": "OLD:FAKE", "issuer": "legacy-ca", "ca": "legacy-ca",
            "trusted": "yes", "revoked": "no", "key-usage": "tls-client",
            "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
        }
        self.mock.state.certificates["*REPLACEMENT"] = {
            ".id": "*REPLACEMENT", "name": "user-one-phone-current", "common-name": "user-one-phone-current",
            "fingerprint": "NEW:FAKE", "issuer": "vpn-ca", "ca": "vpn-ca",
            "trusted": "yes", "revoked": "no", "key-usage": "tls-client",
            "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
        }
        self.server.context.store.record_profile_migration(
            legacy_certificate_name="legacy-user-one-phone", vpn_user="user-one",
            replacement_certificate_name="user-one-phone-current",
        )
        self.login()
        status, _, _ = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/imported", {},
        )
        self.assertEqual(status, 200)

        status, _, payload = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/tested", {},
        )
        self.assertEqual(status, 409)
        self.assertIn("active session for this VPN user", json.loads(payload)["error"])
        self.assertIsNone(
            self.server.context.store.profile_migrations()["legacy-user-one-phone"]["tested_at"]
        )

        with mock.patch.object(
            self.server.context.router,
            "list_active_ovpn_sessions",
            side_effect=RouterOSError("private session detail", 503),
        ):
            status, _, payload = self.json_request(
                "POST", "/api/profile-migrations/legacy-user-one-phone/steps/tested", {},
            )
        self.assertEqual(status, 502)
        self.assertIn("live-session state is unavailable", json.loads(payload)["error"])
        self.assertIsNone(
            self.server.context.store.profile_migrations()["legacy-user-one-phone"]["tested_at"]
        )

        self.mock.state.active_sessions["*A2"] = {
            ".id": "*A2", "name": "user-one", "service": "ovpn",
            "caller-id": "198.51.100.41", "address": "198.18.0.49",
            "uptime": "1m", "encoding": "AES-256-GCM/[user-one-digest]",
        }
        status, _, payload = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/tested", {},
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["active_user_session_observed"])

    def test_profile_migration_test_rejects_expired_replacement(self) -> None:
        self.mock.state.certificates["*OLD"] = {
            ".id": "*OLD", "name": "legacy-user-one-phone", "common-name": "user-one-phone",
            "fingerprint": "OLD:FAKE", "issuer": "legacy-ca", "ca": "legacy-ca",
            "trusted": "yes", "revoked": "no", "key-usage": "tls-client",
            "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
        }
        self.mock.state.certificates["*EXPIRED-REPLACEMENT"] = {
            ".id": "*EXPIRED-REPLACEMENT", "name": "user-one-phone-current",
            "common-name": "user-one-phone-current", "fingerprint": "EXPIRED:FAKE",
            "issuer": "vpn-ca", "ca": "vpn-ca", "trusted": "yes", "revoked": "no",
            "key-usage": "tls-client", "invalid-after": "2030-08-03 00:00:00",
            "expires-after": "0s",
        }
        store = self.server.context.store
        store.record_profile_migration(
            legacy_certificate_name="legacy-user-one-phone", vpn_user="user-one",
            replacement_certificate_name="user-one-phone-current",
        )
        store.record_profile_migration_step(
            legacy_certificate_name="legacy-user-one-phone", step="imported", actor="operator",
        )
        self.mock.state.active_sessions["*A2"] = {
            ".id": "*A2", "name": "user-one", "service": "ovpn",
            "caller-id": "198.51.100.41", "address": "198.18.0.49",
            "uptime": "1m", "encoding": "AES-256-GCM/[user-one-digest]",
        }
        self.login()

        status, _, payload = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/tested", {},
        )

        self.assertEqual(status, 409)
        self.assertIn("replacement validity could not be confirmed", json.loads(payload)["error"])
        self.assertIsNone(
            store.profile_migrations()["legacy-user-one-phone"]["tested_at"]
        )

    def test_profile_migration_test_requires_session_new_since_import_checkpoint(self) -> None:
        self.mock.state.certificates["*OLD"] = {
            ".id": "*OLD", "name": "legacy-user-one-phone", "common-name": "user-one-phone",
            "fingerprint": "OLD:FAKE", "issuer": "legacy-ca", "ca": "legacy-ca",
            "trusted": "yes", "revoked": "no", "key-usage": "tls-client",
            "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
        }
        self.mock.state.certificates["*REPLACEMENT"] = {
            ".id": "*REPLACEMENT", "name": "user-one-phone-current",
            "common-name": "user-one-phone-current", "fingerprint": "NEW:FAKE",
            "issuer": "vpn-ca", "ca": "vpn-ca", "trusted": "yes", "revoked": "no",
            "key-usage": "tls-client", "invalid-after": "2030-08-03 00:00:00",
            "expires-after": "208w",
        }
        self.mock.state.active_sessions["*A1"] = {
            ".id": "*A1", "name": "user-one", "service": "ovpn",
            "caller-id": "198.51.100.41", "address": "198.18.0.49",
            "uptime": "20m", "encoding": "AES-256-GCM/[user-one-digest]",
        }
        store = self.server.context.store
        store.record_profile_migration(
            legacy_certificate_name="legacy-user-one-phone", vpn_user="user-one",
            replacement_certificate_name="user-one-phone-current",
        )
        self.login()

        status, _, payload = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/imported", {},
        )
        self.assertEqual(status, 200)
        migration = store.profile_migrations()["legacy-user-one-phone"]
        self.assertEqual(json.loads(migration["imported_session_ids"]), ["*A1"])

        status, _, payload = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/tested", {},
        )
        self.assertEqual(status, 409)
        self.assertIn("Reconnect after confirming", json.loads(payload)["error"])
        self.assertIsNone(store.profile_migrations()["legacy-user-one-phone"]["tested_at"])

        self.mock.state.active_sessions.pop("*A1")
        self.mock.state.active_sessions["*A2"] = {
            ".id": "*A2", "name": "user-one", "service": "ovpn",
            "caller-id": "198.51.100.41", "address": "198.18.0.49",
            "uptime": "1m", "encoding": "AES-256-GCM/[user-one-digest]",
        }
        status, _, payload = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/tested", {},
        )
        self.assertEqual(status, 200, payload.decode("utf-8"))
        self.assertTrue(json.loads(payload)["active_user_session_observed"])
        self.assertFalse(json.loads(payload)["certificate_attribution_verified"])

    def test_reissuing_a_replacement_clears_prior_live_test_attestation(self) -> None:
        store = self.server.context.store
        store.record_profile_migration(
            legacy_certificate_name="legacy-user-one-phone", vpn_user="user-one",
            replacement_certificate_name="user-one-phone-old",
        )
        store.record_profile_migration_step(
            legacy_certificate_name="legacy-user-one-phone", step="imported", actor="operator",
        )
        store.record_profile_migration_step(
            legacy_certificate_name="legacy-user-one-phone", step="tested", actor="operator",
            active_session_observed=True, active_session_ids=["*TEST-SESSION"],
        )
        store.record_profile_migration_retirement(
            legacy_certificate_name="legacy-user-one-phone", state="verified",
        )
        with store._lock, store._connection() as connection:
            connection.execute(
                "UPDATE profile_migrations SET reconnect_tested_at=?, reconnect_tested_by=?, reconnect_result=? WHERE legacy_certificate_name=?",
                (123, "historical-operator", "rejected", "legacy-user-one-phone"),
            )
        store.record_profile_migration(
            legacy_certificate_name="legacy-user-one-phone", vpn_user="user-one",
            replacement_certificate_name="user-one-phone-new",
        )
        migration = store.profile_migrations()["legacy-user-one-phone"]
        self.assertEqual(migration["replacement_certificate_name"], "user-one-phone-new")
        self.assertIsNone(migration["tested_at"])
        self.assertFalse(migration["tested_with_active_session"])
        self.assertEqual(migration["retirement_state"], "")
        self.assertIsNone(migration["reconnect_tested_at"])
        self.assertEqual(migration["reconnect_tested_by"], "")
        self.assertEqual(migration["reconnect_result"], "")

    def test_profile_migration_reconnect_report_endpoint_is_removed(self) -> None:
        self.login()
        before_mutations = list(self.mock.state.mutation_requests)
        before_audit = self.server.context.store.recent_audit(20)

        status, _, payload = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/reconnect-test",
            {"result": "rejected"},
        )

        self.assertEqual(status, 404)
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(self.server.context.store.recent_audit(20), before_audit)
        self.assertNotIn(b"operator_attested", payload)

    def test_profile_migration_progress_requires_live_active_certificates_and_profile_capability(self) -> None:
        self.mock.state.certificates["*OLD"] = {
            ".id": "*OLD", "name": "legacy-user-one-phone", "common-name": "user-one-phone",
            "fingerprint": "OLD:FAKE", "issuer": "legacy-ca", "ca": "legacy-ca",
            "trusted": "yes", "revoked": "no", "key-usage": "tls-client",
            "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
        }
        self.server.context.store.record_profile_migration(
            legacy_certificate_name="legacy-user-one-phone",
            vpn_user="user-one",
            replacement_certificate_name="user-one-phone-20261004",
        )
        self.mock.state.certificates["*REPLACEMENT"] = {
            ".id": "*REPLACEMENT", "name": "user-one-phone-20261004", "common-name": "user-one-phone-20261004",
            "fingerprint": "NEW:FAKE", "issuer": "vpn-ca", "ca": "vpn-ca",
            "trusted": "yes", "revoked": "yes", "key-usage": "tls-client",
            "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
        }
        self.login()
        status, _, payload = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/imported", {},
        )
        self.assertEqual(status, 409)
        self.assertIn("no progress was recorded", json.loads(payload)["error"])
        self.assertIsNone(
            self.server.context.store.profile_migrations()["legacy-user-one-phone"]["imported_at"]
        )

        self.mock.state.certificates["*REPLACEMENT"]["revoked"] = "no"
        self.mock.state.admin_group = "read"
        self.cookie = ""
        self.csrf = ""
        self.login()
        status, _, _ = self.json_request(
            "POST", "/api/profile-migrations/legacy-user-one-phone/steps/imported", {},
        )
        self.assertEqual(status, 403)
        self.assertIsNone(
            self.server.context.store.profile_migrations()["legacy-user-one-phone"]["imported_at"]
        )

    def test_incomplete_instance_topology_fails_before_profile_mutation(self) -> None:
        self.login()
        self.server.context.config = RuntimeConfig.from_environ(
            {
                "PUBLIC_ORIGIN": "https://dashboard.example.test",
                "ROUTEROS_REST_URL": "https://router.example.test:8443/rest",
            }
        )
        user_one_id = next(
            user["id"]
            for user in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            )
            if user["name"] == "user-one"
        )
        status, _, payload = self.json_request(
            "POST",
            f"/api/users/{urllib.parse.quote(user_one_id, safe='*')}/profiles/preview",
            {"device_name": "Blocked device", "delivery": "ovpn", "reason": "Approved replacement access"},
        )
        self.assertEqual(status, 400)
        self.assertIn("OpenVPN profile issuing is not configured", json.loads(payload)["error"])
        self.assertEqual(set(self.mock.state.certificates), {"*CA", "*CL1", "*CL2"})
        self.assertFalse(any(name.startswith("vpn-dashboard-before-") for name in self.mock.state.files))

        status, _, payload = self.json_request(
            "POST",
            "/api/users",
            {
                "username": "blocked-user",
                "email": "blocked@example.test",
                "password": "blocked-passphrase",
                "device_name": "Blocked phone",
            },
        )
        self.assertEqual(status, 400)
        self.assertIn("OpenVPN profile issuing is not configured", json.loads(payload)["error"])
        self.assertNotIn("blocked-user", [item["name"] for item in self.mock.state.users.values()])

    def test_read_only_router_role_cannot_mutate(self) -> None:
        self.mock.state.admin_group = "read"
        self.login()
        users = {
            item["name"]: item
            for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            )
        }
        self.assertIn("user-one", users)
        status, _, _ = self.json_request(
            "POST", "/api/users", {
                "username": "blocked", "email": "blocked@example.com",
                "password": "blocked-pass", "device_name": "Phone",
            },
        )
        self.assertEqual(status, 403)
        self.assertNotIn("blocked", [item["name"] for item in self.mock.state.users.values()])
        denied = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(denied["action"], "role.denied")
        self.assertIn("users.manage", denied["details"])
        status, _, _ = self.request("GET", "/api/audit.csv")
        self.assertEqual(status, 403)

    def test_security_operator_role_is_scoped_to_security_workflows(self) -> None:
        self.mock.state.admin_group = "security-operator"
        self.login()
        status, _, payload = self.request("GET", "/api/status")
        self.assertEqual(status, 200)
        snapshot = json.loads(payload)
        self.assertEqual(snapshot["role"], "security_operator")
        self.assertIn("device.manage", snapshot["capabilities"])
        self.assertNotIn("users.manage", snapshot["capabilities"])
        status, _, _ = self.json_request(
            "POST", "/api/users", {
                "username": "blocked", "email": "blocked@example.com",
                "password": "blocked-pass", "device_name": "Phone",
            },
        )
        self.assertEqual(status, 403)

    def test_schedule_presets_and_quota_validation(self) -> None:
        monday_morning = 1785747600  # 2026-08-03 10:00 local in the test environment
        saturday_morning = monday_morning + 5 * 86400
        self.assertTrue(DashboardServer._schedule_allows("weekdays", monday_morning))
        self.assertFalse(DashboardServer._schedule_allows("weekdays", saturday_morning))
        controls = DashboardHandler._parse_controls(
            {"quota_mb": "10240", "schedule": "daytime"}
        )
        self.assertEqual(controls["quota_mb"], 10240)
        self.assertEqual(controls["schedule"], "daytime")
        self.assertEqual(controls["max_sessions"], 5)
        self.assertEqual(DashboardHandler._parse_controls({"max_sessions": "4"})["max_sessions"], 4)
        with self.assertRaises(ValueError):
            DashboardHandler._parse_controls({"max_sessions": "0"})
        with self.assertRaises(ValueError):
            DashboardHandler._parse_controls({"max_sessions": "6"})
        with self.assertRaises(ValueError):
            DashboardHandler._parse_controls({"quota_mb": "123"})

    def test_live_refresh_does_not_discard_open_forms(self) -> None:
        script = (Path(__file__).resolve().parents[1] / "static" / "app.js").read_text()
        mobile_css = (Path(__file__).resolve().parents[1] / "static" / "app.css").read_text()
        self.assertIn("function hasOpenDialog()", script)
        self.assertIn("function renderConnectionHistory(connections = [])", script)
        self.assertIn("function reconcileConnectionHistory(sessions = [])", script)
        self.assertIn("reconcileConnectionHistory(sessions)", script)
        self.assertIn("session.counter_complete !== false", script)
        template = (Path(__file__).resolve().parents[1] / "templates.py").read_text()
        update_block = script.split("function updateDashboard(payload", 1)[1].split("async function pollStatus(", 1)[0]
        self.assertIn("preserveIncompleteSessionCounters(", update_block)
        self.assertIn("queueIfInFlight: true", script)
        self.assertIn('data-router-session-id="{session_id}"', template)
        self.assertIn("function renderAlerts(alerts = [])", script)
        self.assertIn("function rememberOperatorViewState()", script)
        self.assertIn("function restoreOperatorViewState()", script)
        self.assertIn("function syncUserConnectionStatuses(sessions)", script)
        self.assertIn("function setUserConnectionStatusesStale(stale)", script)
        self.assertIn("liveSnapshotVersion > liveVersionAtRequest", update_block)
        self.assertIn("syncUserConnectionStatuses(sessions);", update_block)
        live_block = script.split("function updateLiveSnapshot(payload)", 1)[1].split("function reconcileTerminationAttempt", 1)[0]
        self.assertIn("syncUserConnectionStatuses(sessions);", live_block)
        self.assertIn("data-connection-status-filter", script)
        self.assertIn("data-bulk-action-controls", template)
        self.assertIn('class="saved-view-tools"', template)
        self.assertIn("history.dataset.renderKey", script)
        self.assertIn("panel.dataset.renderKey", script)
        self.assertIn("deploymentBody.dataset.renderKey", script)
        self.assertIn("timeline.dataset.renderKey", script)
        self.assertIn("scheduleAutomaticPageSync()", update_block)
        self.assertNotIn("function deferFreshData(reason)", script)
        self.assertNotIn("data-full-refresh", script)
        self.assertNotIn("Refresh to apply changes", script)
        self.assertIn("Mobile administrator ergonomics", mobile_css)
        self.assertIn("Mobile UX polish", mobile_css)
        self.assertIn("env(safe-area-inset-bottom)", mobile_css)
        self.assertIn("max-width: 520px", mobile_css)
        self.assertIn("scroll-snap-type: x proximity", mobile_css)
        self.assertIn("backdrop-filter: blur(4px)", mobile_css)
        self.assertIn("scrollIntoView", script)
        self.assertIn("THEME_STORAGE_KEY", script)
        self.assertIn("themeResolved", script)
        self.assertIn("data-theme-choice", script)

    def test_live_socketio_asset_is_packaged_and_allowlisted(self) -> None:
        root = Path(__file__).resolve().parents[1]
        asset = root / "static" / "socket.io.min.js"
        source = (root / "app.py").read_text()
        self.assertGreater(asset.stat().st_size, 1000)
        self.assertIn('"socket.io.min.js"', source)

    def test_dashboard_exposes_persistent_theme_choices(self) -> None:
        self.login()
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b"Choose appearance", page)
        for mode in (b"standard", b"dark", b"light", b"system"):
            self.assertIn(b'data-theme-choice="' + mode + b'"', page)
        self.assertIn(b"vpn-dashboard-theme", page)
        self.assertIn(b'data-theme=\"standard\"', page)

    def test_dashboard_uses_contextual_navigation_icons_and_readable_metadata(self) -> None:
        self.login()
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b'href="#policy-templates"', page)
        self.assertIn(b'<use href="#i-template"></use>', page)
        self.assertIn(b'<use href="#i-health"></use>', page)
        self.assertIn(b'<use href="#i-plan"></use>', page)
        self.assertIn(b'<use href="#i-appearance"></use>', page)
        self.assertIn(b'title="Service Health"', page)
        self.assertIn(b'title="Setup Planner"', page)
        css = (Path(__file__).resolve().parents[1] / "static" / "app.css").read_text()
        self.assertIn("Unified visual hierarchy", css)
        self.assertIn(".user-activity span { color: var(--muted); font-size: 11px", css)
        self.assertIn(".user-activity strong { font-size: 13px", css)

    def test_optional_certificate_failure_does_not_cancel_valid_login(self) -> None:
        self.mock.state.fail_certificate_inventory = True
        self.login()

        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b"You are connected", page)
        self.assertIn(b"Certificate inventory is temporarily unavailable", page)

        status, _, payload = self.request("GET", "/api/users")
        self.assertEqual(status, 200)
        self.assertEqual(
            [item["name"] for item in json.loads(payload)["users"]],
            ["user-one", "user-two"],
        )

    def test_duplicate_user_and_terminate_live_session(self) -> None:
        self.login()
        users = {
            item["name"]: item
            for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            )
        }
        user_one_id = users["user-one"]["id"]

        duplicate_request = {
            "username": "user-one-copy", "email": "user.one.copy@example.test",
            "password": "duplicate-pass", "key_passphrase": "duplicate-key-passphrase",
            "device_name": "Backup phone", "comment": "Copied access", "delivery": "ovpn",
            "reason": "Approved additional access for backup phone",
        }
        preview = self.preview_user_provision(
            {key: value for key, value in duplicate_request.items() if key not in {"password", "key_passphrase"}},
            source_id=user_one_id,
        )
        status, headers, profile = self.json_request(
            "POST",
            f"/api/users/{urllib.parse.quote(user_one_id, safe='*')}/duplicate",
            {**duplicate_request, "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 200)
        self.assertIn('filename="user-one-copy-Backup-phone.ovpn"', headers["content-disposition"])
        self.assertIn(b"<cert>", profile)
        self.assertIn("user-one-copy", [item["name"] for item in self.mock.state.users.values()])
        self.assertEqual(
            self.server.context.store.user_emails()["user-one-copy"],
            "user.one.copy@example.test",
        )
        duplicate_audit = next(
            item for item in self.server.context.store.recent_audit()
            if item["action"] == "user.duplicate" and item["target"] == "user-one-copy"
        )
        self.assertTrue(json.loads(duplicate_audit["details"])["rationale_recorded"])

        session_id = next(iter(self.mock.state.active_sessions))
        termination_review = self.preview_session_termination(session_id)
        status, _, _ = self.json_request(
            "DELETE", f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}", csrf=False
        )
        self.assertEqual(status, 403)
        self.assertIn(session_id, self.mock.state.active_sessions)

        status, _, payload = self.json_request(
            "DELETE", f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}",
            {"confirmation": "user-two", "reason": termination_review["reason"], "review_token": termination_review["review_token"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"ok": True, "verified": True})
        self.assertNotIn(session_id, self.mock.state.active_sessions)
        termination_audit = next(
            item for item in self.server.context.store.recent_audit()
            if item["action"] == "session.terminate"
        )
        self.assertTrue(json.loads(termination_audit["details"])["rationale_recorded"])

    def test_session_termination_reason_is_bound_to_review_and_audited(self) -> None:
        self.login()
        session_id = next(iter(self.mock.state.active_sessions))
        review = self.preview_session_termination(session_id)
        before_mutations = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request(
            "DELETE", f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}",
            {"confirmation": "user-two", "reason": "Different operator rationale", "review_token": review["review_token"]},
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertIn(session_id, self.mock.state.active_sessions)

    def test_session_termination_review_receipt_is_bound_to_issuing_session(self) -> None:
        self.login()
        target_id = next(iter(self.mock.state.active_sessions))
        review = self.preview_session_termination(target_id)
        owner_cookie = self.cookie
        owner_csrf = self.csrf
        before_mutations = list(self.mock.state.mutation_requests)

        # A second equally privileged browser session must not be able to use
        # a receipt issued to the first session, even for the same target and
        # unchanged RouterOS state.
        self.login()
        status, _, payload = self.json_request(
            "DELETE",
            f"/api/sessions/{urllib.parse.quote(target_id, safe='*')}",
            {
                "confirmation": "user-two",
                "reason": review["reason"],
                "review_token": review["review_token"],
            },
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertIn(target_id, self.mock.state.active_sessions)

        # A failed cross-session attempt must not consume the owner's receipt.
        self.cookie = owner_cookie
        self.csrf = owner_csrf
        status, _, payload = self.json_request(
            "DELETE",
            f"/api/sessions/{urllib.parse.quote(target_id, safe='*')}",
            {
                "confirmation": "user-two",
                "reason": review["reason"],
                "review_token": review["review_token"],
            },
        )
        self.assertEqual(status, 200, payload.decode("utf-8"))
        self.assertNotIn(target_id, self.mock.state.active_sessions)

    def test_session_termination_rejects_missing_rationale_before_routeros_read(self) -> None:
        self.login()
        session_id = next(iter(self.mock.state.active_sessions))

        status, _, payload = self.json_request(
            "POST", f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}/preview", {},
        )

        self.assertEqual(status, 400)
        self.assertEqual(self.mock.state.mutation_requests, [])
        self.assertIn("reason", json.loads(payload)["error"])

    def test_duplicate_user_review_rejects_changed_copied_settings_before_mutation(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-one"
        )
        request_data = {
            "username": "user-one-stale-copy", "email": "stale-copy@example.test",
            "password": "stale-copy-password", "key_passphrase": "stale-copy-passphrase",
            "device_name": "Backup phone", "comment": "Copied access", "delivery": "ovpn",
            "policy": "full-tunnel",
            "reason": "Approved additional access for review race",
        }
        preview = self.preview_user_provision(
            {key: value for key, value in request_data.items() if key not in {"password", "key_passphrase"}},
            source_id=user["id"],
        )
        before_mutations = list(self.mock.state.mutation_requests)
        before_certificates = set(self.mock.state.certificates)
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/duplicate",
            {**request_data, "policy": "lan-only", "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(set(self.mock.state.certificates), before_certificates)
        self.assertNotIn("user-one-stale-copy", [item["name"] for item in self.mock.state.users.values()])

    def test_session_termination_is_not_reported_successful_while_router_still_shows_it(self) -> None:
        self.login()
        session_id = next(iter(self.mock.state.active_sessions))
        review = self.preview_session_termination(session_id)
        clock = [0.0]

        def advance_clock(seconds: float) -> None:
            clock[0] += seconds

        def monotonic() -> float:
            return clock[0]

        with mock.patch.object(self.server.context.router, "terminate_session"):
            with (
                mock.patch("app.time.monotonic", side_effect=monotonic),
                mock.patch("app.time.sleep", side_effect=advance_clock),
            ):
                status, _, payload = self.json_request(
                    "DELETE",
                    f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}",
                    {"confirmation": "user-two", "reason": review["reason"], "review_token": review["review_token"]},
                )

        self.assertEqual(status, 409)
        response = json.loads(payload)
        self.assertEqual(response["code"], "routeros.mutation_verification_failed")
        self.assertFalse(response["verified"])
        self.assertIn(session_id, self.mock.state.active_sessions)
        latest = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(latest["action"], "session.terminate")
        self.assertEqual(latest["status"], "failed")

    def test_session_termination_waits_for_routeros_readback_after_one_second(self) -> None:
        self.login()
        session_id = next(iter(self.mock.state.active_sessions))
        review = self.preview_session_termination(session_id)
        router = self.server.context.router
        active = router.list_active_ovpn_sessions(RouterOSCredentials("admin", "routerpass"))
        clock = [0.0]

        def monotonic() -> float:
            value = clock[0]
            clock[0] += 0.1
            return value

        def advance_clock(seconds: float) -> None:
            clock[0] += seconds

        with (
            mock.patch.object(router, "list_active_ovpn_sessions", side_effect=[active] * 12 + [[]]) as readback,
            mock.patch("app.time.monotonic", side_effect=monotonic),
            mock.patch("app.time.sleep", side_effect=advance_clock),
        ):
            status, _, payload = self.json_request(
                "DELETE",
                f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}",
                {
                    "confirmation": "user-two",
                    "reason": review["reason"],
                    "review_token": review["review_token"],
                },
            )

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"ok": True, "verified": True})
        self.assertEqual(readback.call_count, 13)
        self.assertNotIn(session_id, self.mock.state.active_sessions)

    def test_session_termination_retries_transient_active_readback(self) -> None:
        self.login()
        session_id = next(iter(self.mock.state.active_sessions))
        review = self.preview_session_termination(session_id)
        router = self.server.context.router
        active = router.list_active_ovpn_sessions(RouterOSCredentials("admin", "routerpass"))

        with (
            mock.patch.object(router, "list_active_ovpn_sessions", side_effect=[active, active, []]) as readback,
            mock.patch("app.time.sleep"),
        ):
            status, _, payload = self.json_request(
                "DELETE",
                f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}",
                {
                    "confirmation": "user-two",
                    "reason": review["reason"],
                    "review_token": review["review_token"],
                },
            )

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"ok": True, "verified": True})
        self.assertEqual(readback.call_count, 3)
        self.assertNotIn(session_id, self.mock.state.active_sessions)
        latest = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(latest["status"], "success")
        self.assertEqual(json.loads(latest["details"])["verification"], "session_absent")

    def test_session_termination_accepts_lost_response_when_readback_confirms_disconnect(self) -> None:
        self.login()
        session_id = next(iter(self.mock.state.active_sessions))
        review = self.preview_session_termination(session_id)
        router = self.server.context.router
        terminate = router.terminate_session

        def commit_then_lose_response(*args: Any, **kwargs: Any) -> None:
            terminate(*args, **kwargs)
            raise RouterOSError("private router detail", 503)

        with mock.patch.object(router, "terminate_session", side_effect=commit_then_lose_response):
            status, _, payload = self.json_request(
                "DELETE", f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}",
                {"confirmation": "user-two", "reason": review["reason"], "review_token": review["review_token"]},
            )

        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"ok": True, "verified": True})
        self.assertNotIn(session_id, self.mock.state.active_sessions)
        latest = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(latest["status"], "success")
        details = json.loads(latest["details"])
        self.assertEqual(details["verification"], "session_absent")
        self.assertNotIn("source_address", details)
        self.assertNotIn("vpn_address", details)
        self.assertEqual(details["mutation_response"], "lost")
        self.assertNotIn("private router detail", payload.decode("utf-8"))

    def test_session_termination_lost_response_and_failed_readback_is_unknown(self) -> None:
        self.login()
        session_id = next(iter(self.mock.state.active_sessions))
        review = self.preview_session_termination(session_id)
        credentials = RouterOSCredentials("admin", "routerpass")
        router = self.server.context.router
        active_sessions = router.list_active_ovpn_sessions(credentials)
        terminate = router.terminate_session

        def commit_then_lose_response(*args: Any, **kwargs: Any) -> None:
            terminate(*args, **kwargs)
            raise RouterOSError("private mutation detail", 503)

        with (
            mock.patch.object(
                router, "list_active_ovpn_sessions",
                side_effect=[active_sessions, RouterOSError("private readback detail", 503)],
            ),
            mock.patch.object(router, "terminate_session", side_effect=commit_then_lose_response),
        ):
            status, _, payload = self.json_request(
                "DELETE", f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}",
                {"confirmation": "user-two", "reason": review["reason"], "review_token": review["review_token"]},
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["code"], "routeros.mutation_verification_unavailable")
        self.assertFalse(response["verified"])
        self.assertIn("outcome could not be verified", response["error"])
        self.assertNotIn("received the termination request", response["error"])
        self.assertNotIn("private mutation detail", payload.decode("utf-8"))
        self.assertNotIn("private readback detail", payload.decode("utf-8"))
        self.assertNotIn(session_id, self.mock.state.active_sessions)
        latest = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(latest["status"], "unknown")
        details = json.loads(latest["details"])
        self.assertEqual(details["mutation_response"], "unknown")

    def test_device_revoke_marks_local_state_only_after_routeros_readback(self) -> None:
        path, device_id = self._managed_device_revoke_request()
        reviewed = self._review_device_revoke(path)
        status, _, payload = self.json_request("POST", path, reviewed)

        response = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertTrue(response["verified"])
        self.assertEqual(response["verification"], "routeros_revoked")
        self.assertFalse(response["active_session_termination_verified"])
        self.assertFalse(response["client_rejection_verified"])
        self.assertIsNotNone(self.server.context.store.device_by_id(device_id)["revoked_at"])
        self.assertTrue(self.mock.state.certificates["*CL1"]["revoked"])
        self.assertIn("POST /certificate/issued-revoke", self.mock.state.mutation_requests)

    def test_device_revoke_checkpoint_failure_prevents_routeros_mutation(self) -> None:
        path, device_id = self._managed_device_revoke_request()
        reviewed = self._review_device_revoke(path)
        with mock.patch.object(
            self.server.context.router,
            "create_configuration_export",
            side_effect=RouterOSError("private checkpoint detail", 503),
        ) as create_checkpoint:
            status, _, payload = self.json_request("POST", path, reviewed)

        create_checkpoint.assert_called_once()
        response_text = payload.decode("utf-8")
        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(
            response["error"],
            "RouterOS configuration checkpoint failed; no change was applied.",
        )
        self.assertNotIn("private checkpoint detail", response_text)
        self.assertNotIn("POST /certificate/issued-revoke", self.mock.state.mutation_requests)
        self.assertEqual(self.mock.state.certificates["*CL1"]["revoked"], "no")
        self.assertIsNone(self.server.context.store.device_by_id(device_id)["revoked_at"])
        audit = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(audit["action"], "checkpoint.create")
        self.assertEqual(audit["target"], "device.revoke")
        self.assertEqual(audit["status"], "failed")
        self.assertEqual(json.loads(audit["details"]), {"reason": "RouterOSError"})
        self.assertNotIn("private checkpoint detail", audit["details"])

    def test_tested_unmanaged_legacy_migration_can_be_reviewed_and_revoked_safely(self) -> None:
        path, legacy_name = self._legacy_migration_revoke_request()
        request = {"confirmation": legacy_name, "reason": "Replacement tested; retire old phone identity."}
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b'data-revoke-kind="legacy"', page)
        self.assertIn(b"Review old-certificate revocation", page)
        before = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request("POST", f"{path}/preview", request)

        preview = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertEqual(preview["certificate"], legacy_name)
        self.assertEqual(preview["vpn_user"], "user-one")
        self.assertEqual(self.mock.state.mutation_requests, before)
        status, _, payload = self.json_request("POST", path, {**request, "review_token": preview["review_token"]})

        result = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertTrue(result["verified"])
        self.assertTrue(self.mock.state.certificates["*OLD"]["revoked"])
        self.assertEqual(self.mock.state.certificates["*REPLACEMENT"]["revoked"], "no")
        with self.server.context.store._lock, self.server.context.store._connection() as connection:
            connection.execute(
                "UPDATE profile_migrations SET reconnect_tested_at=?, reconnect_tested_by=?, reconnect_result=? WHERE legacy_certificate_name=?",
                (123, "historical-operator", "rejected", legacy_name),
            )
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b"Old profile rejected on reported fresh reconnect", page)
        self.assertNotIn(b"No managed device record to revoke here", page)
        self.assertNotIn(b"Report: rejected", page)
        self.assertNotIn(b"Report: connected", page)
        self.assertIn(b"Reconnect outcome not verifiable here", page)
        self.assertIn(b"not independently verified", page)
        self.assertIn(b"RouterOS cannot attribute a session to a certificate", page)

    def test_unmanaged_legacy_revoke_reconciles_lost_response_from_readback(self) -> None:
        path, legacy_name = self._legacy_migration_revoke_request()
        request = {
            "confirmation": legacy_name,
            "reason": "Replacement tested; retire old phone identity.",
        }
        status, _, payload = self.json_request("POST", f"{path}/preview", request)
        self.assertEqual(status, 200, payload.decode("utf-8"))
        reviewed = {**request, "review_token": json.loads(payload)["review_token"]}
        revoke = self.server.context.router.revoke_certificate

        def commit_then_lose_response(credentials: Any, *, certificate_id: str) -> None:
            revoke(credentials, certificate_id=certificate_id)
            # A same-name certificate must not satisfy read-back for the
            # reviewed RouterOS id if the actual mutation response is lost.
            self.mock.state.certificates["*OLD-DECOY"] = {
                ".id": "*OLD-DECOY", "name": legacy_name, "common-name": "user-one-phone",
                "fingerprint": "DECOY:FAKE", "issuer": "legacy-ca", "ca": "legacy-ca",
                "trusted": "yes", "revoked": "no", "key-usage": "tls-client",
                "invalid-after": "2030-08-03 00:00:00", "expires-after": "208w",
            }
            # A transport timeout has no HTTP status: the mutation may have
            # committed even though its response never reached the client.
            raise RouterOSError("private simulated response loss", failure_kind="timeout")

        with mock.patch.object(
            self.server.context.router,
            "revoke_certificate",
            side_effect=commit_then_lose_response,
        ):
            status, _, payload = self.json_request("POST", path, reviewed)

        result = json.loads(payload)
        self.assertEqual(status, 200, payload.decode("utf-8"))
        self.assertTrue(result["verified"])
        self.assertTrue(self.mock.state.certificates["*OLD"]["revoked"])
        self.assertEqual(self.mock.state.certificates["*OLD-DECOY"]["revoked"], "no")
        self.assertEqual(self.mock.state.certificates["*REPLACEMENT"]["revoked"], "no")
        self.assertEqual(
            self.server.context.store.profile_migrations()[legacy_name]["retirement_state"],
            "verified",
        )
        audit = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(audit["status"], "success")
        details = json.loads(audit["details"])
        self.assertEqual(details["verification"], "routeros_revoked")
        self.assertEqual(details["mutation_response"], "lost")
        self.assertNotIn("private simulated response loss", payload.decode("utf-8"))

    def test_unmanaged_legacy_revoke_rejects_changed_replacement_after_review(self) -> None:
        path, _ = self._legacy_migration_revoke_request()
        request = {"confirmation": "legacy-user-one-phone", "reason": "Replacement tested; retire old identity."}
        status, _, payload = self.json_request("POST", f"{path}/preview", request)
        self.assertEqual(status, 200)
        review = json.loads(payload)
        self.mock.state.certificates["*REPLACEMENT"]["fingerprint"] = "CHANGED:FAKE"
        before = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request(
            "POST", path, {**request, "review_token": review["review_token"]},
        )

        self.assertEqual(status, 409)
        self.assertIn("Review this revocation again", json.loads(payload)["error"])
        self.assertEqual(self.mock.state.mutation_requests, before)
        self.assertEqual(self.mock.state.certificates["*OLD"]["revoked"], "no")

    def test_unmanaged_legacy_migration_revoke_requires_tested_current_ca_replacement(self) -> None:
        path, _ = self._legacy_migration_revoke_request()
        self.server.context.store.record_profile_migration_step(
            legacy_certificate_name="legacy-user-one-phone", step="imported", actor="operator",
        )
        migration = self.server.context.store.profile_migrations()["legacy-user-one-phone"]
        self.server.context.store.record_profile_migration(
            legacy_certificate_name="legacy-user-one-phone", vpn_user="user-one",
            replacement_certificate_name=migration["replacement_certificate_name"],
        )
        before = list(self.mock.state.mutation_requests)
        status, _, payload = self.json_request(
            "POST", f"{path}/preview",
            {"confirmation": "legacy-user-one-phone", "reason": "Retire after replacement test."},
        )
        self.assertEqual(status, 400)
        self.assertIn("active VPN-user session", json.loads(payload)["error"])
        self.assertEqual(self.mock.state.mutation_requests, before)

    def test_managed_certificate_retirement_requires_replacement_import_and_live_test(self) -> None:
        path, device_id = self._managed_device_revoke_request()
        old_certificate_name = "ovpn-user-one-device-a"
        replacement_name = "user-one-managed-replacement"
        self.mock.state.certificates["*MANAGED-REPLACEMENT"] = {
            ".id": "*MANAGED-REPLACEMENT", "name": replacement_name,
            "common-name": "user-one-managed-replacement", "fingerprint": "NEW:MANAGED",
            "issuer": "vpn-ca", "ca": "vpn-ca", "trusted": "yes", "revoked": "no",
            "key-usage": "tls-client", "invalid-after": "2030-08-03 00:00:00",
            "expires-after": "208w",
        }
        store = self.server.context.store
        store.record_profile_migration(
            legacy_certificate_name=old_certificate_name,
            vpn_user="user-one",
            replacement_certificate_name=replacement_name,
        )
        store.record_profile_migration_step(
            legacy_certificate_name=old_certificate_name, step="imported", actor="operator",
        )
        before = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request(
            "POST", f"{path}/preview",
            {"confirmation": "Managed test phone", "reason": "Replace this phone certificate after renewal."},
        )

        self.assertEqual(status, 400)
        self.assertIn("live connection test", json.loads(payload)["error"])
        self.assertEqual(self.mock.state.mutation_requests, before)
        self.assertEqual(self.mock.state.certificates["*CL1"]["revoked"], "no")
        self.assertIsNone(store.device_by_id(device_id)["revoked_at"])

    def test_managed_certificate_retirement_rejects_expired_replacement(self) -> None:
        path, device_id = self._managed_device_revoke_request()
        old_certificate_name = "ovpn-user-one-device-a"
        replacement_name = "user-one-managed-replacement"
        self.mock.state.certificates["*MANAGED-REPLACEMENT"] = {
            ".id": "*MANAGED-REPLACEMENT", "name": replacement_name,
            "common-name": "user-one-managed-replacement", "fingerprint": "NEW:MANAGED",
            "issuer": "vpn-ca", "ca": "vpn-ca", "trusted": "yes", "revoked": "no",
            "key-usage": "tls-client", "invalid-after": "2030-08-03 00:00:00",
            "expires-after": "0s",
        }
        store = self.server.context.store
        store.record_profile_migration(
            legacy_certificate_name=old_certificate_name, vpn_user="user-one",
            replacement_certificate_name=replacement_name,
        )
        store.record_profile_migration_step(
            legacy_certificate_name=old_certificate_name, step="imported", actor="operator",
        )
        store.record_profile_migration_step(
            legacy_certificate_name=old_certificate_name, step="tested", actor="operator",
            active_session_observed=True, active_session_ids=["*TEST-SESSION"],
        )

        status, _, payload = self.json_request(
            "POST", f"{path}/preview",
            {"confirmation": "Managed test phone", "reason": "Replace this phone certificate after renewal."},
        )

        self.assertEqual(status, 400)
        self.assertIn("unexpired active replacement", json.loads(payload)["error"])
        self.assertEqual(self.mock.state.mutation_requests, [])
        self.assertEqual(self.mock.state.certificates["*CL1"]["revoked"], "no")
        self.assertIsNone(store.device_by_id(device_id)["revoked_at"])

    def test_managed_certificate_retires_only_after_verified_replacement_test(self) -> None:
        path, device_id = self._managed_device_revoke_request()
        old_certificate_name = "ovpn-user-one-device-a"
        replacement_name = "user-one-managed-replacement"
        self.mock.state.certificates["*MANAGED-REPLACEMENT"] = {
            ".id": "*MANAGED-REPLACEMENT", "name": replacement_name,
            "common-name": "user-one-managed-replacement", "fingerprint": "NEW:MANAGED",
            "issuer": "vpn-ca", "ca": "vpn-ca", "trusted": "yes", "revoked": "no",
            "key-usage": "tls-client", "invalid-after": "2030-08-03 00:00:00",
            "expires-after": "208w",
        }
        store = self.server.context.store
        store.record_profile_migration(
            legacy_certificate_name=old_certificate_name,
            vpn_user="user-one",
            replacement_certificate_name=replacement_name,
        )
        store.record_profile_migration_step(
            legacy_certificate_name=old_certificate_name, step="imported", actor="operator",
        )
        store.record_profile_migration_step(
            legacy_certificate_name=old_certificate_name, step="tested", actor="operator",
            active_session_observed=True, active_session_ids=["*TEST-SESSION"],
        )
        request = {
            "confirmation": "Managed test phone",
            "reason": "Replacement imported and tested; retire old identity.",
        }

        status, _, payload = self.json_request("POST", f"{path}/preview", request)
        self.assertEqual(status, 200, payload.decode("utf-8"))
        before = list(self.mock.state.mutation_requests)
        self.assertNotIn("POST /certificate/issued-revoke", before)
        status, _, payload = self.json_request(
            "POST", path, {**request, "review_token": json.loads(payload)["review_token"]},
        )

        result = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertTrue(result["verified"])
        self.assertTrue(self.mock.state.certificates["*CL1"]["revoked"])
        self.assertEqual(self.mock.state.certificates["*MANAGED-REPLACEMENT"]["revoked"], "no")
        self.assertIsNotNone(store.device_by_id(device_id)["revoked_at"])

    def test_device_revoke_reports_partial_when_replacement_changes_during_retirement(self) -> None:
        path, legacy_name = self._legacy_migration_revoke_request()
        store = self.server.context.store
        request = {
            "confirmation": legacy_name,
            "reason": "Replacement imported and tested; retire old identity.",
        }
        status, _, payload = self.json_request("POST", f"{path}/preview", request)
        self.assertEqual(status, 200, payload.decode("utf-8"))
        reviewed = {**request, "review_token": json.loads(payload)["review_token"]}
        revoke = self.server.context.router.revoke_certificate

        def revoke_old_and_change_replacement(credentials: Any, *, certificate_id: str) -> None:
            revoke(credentials, certificate_id=certificate_id)
            self.mock.state.certificates["*REPLACEMENT"]["revoked"] = "yes"

        with mock.patch.object(
            self.server.context.router,
            "revoke_certificate",
            side_effect=revoke_old_and_change_replacement,
        ):
            status, _, payload = self.json_request("POST", path, reviewed)

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertFalse(response["verified"])
        self.assertEqual(response["verification"], "partial")
        self.assertTrue(response["old_certificate_revoked"])
        self.assertFalse(response["replacement_verified"])
        self.assertTrue(self.mock.state.certificates["*OLD"]["revoked"])
        self.assertEqual(
            store.profile_migrations()[legacy_name]["retirement_state"], "partial",
        )
        self.assertEqual(store.recent_audit(1)[0]["status"], "partial")
        status, _, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn(b"Old identity revoked; replacement needs review", page)
        self.assertIn("Partial \u00b7 review required".encode("utf-8"), page)

    def test_device_revoke_preview_is_read_only_and_stale_review_is_rejected(self) -> None:
        path, device_id = self._managed_device_revoke_request()
        reviewed = self._review_device_revoke(path)
        self.assertEqual(self.mock.state.mutation_requests, [])
        reviewed["reason"] = "A different reason was substituted after review."

        status, _, payload = self.json_request("POST", path, reviewed)

        self.assertEqual(status, 409)
        self.assertIn("Review this revocation again", json.loads(payload)["error"])
        self.assertEqual(self.mock.state.mutation_requests, [])
        self.assertIsNone(self.server.context.store.device_by_id(device_id)["revoked_at"])
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "failed")

    def test_device_revoke_accepts_lost_mutation_response_when_readback_confirms_commit(self) -> None:
        path, device_id = self._managed_device_revoke_request()
        reviewed = self._review_device_revoke(path)
        revoke = self.server.context.router.revoke_certificate

        def commit_then_lose_response(*args: Any, **kwargs: Any) -> None:
            revoke(*args, **kwargs)
            raise RouterOSError("response lost after commit", 503)

        with mock.patch.object(
            self.server.context.router,
            "revoke_certificate",
            side_effect=commit_then_lose_response,
        ):
            status, _, payload = self.json_request("POST", path, reviewed)

        response = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertTrue(response["verified"])
        self.assertIsNotNone(self.server.context.store.device_by_id(device_id)["revoked_at"])
        latest = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(latest["status"], "success")
        self.assertEqual(json.loads(latest["details"])["mutation_response"], "error")

    def test_device_revoke_does_not_mark_local_state_when_routeros_readback_mismatches(self) -> None:
        path, device_id = self._managed_device_revoke_request()
        reviewed = self._review_device_revoke(path)
        with mock.patch.object(self.server.context.router, "revoke_certificate"):
            status, _, payload = self.json_request("POST", path, reviewed)

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["verification"], "mismatch")
        self.assertFalse(response["verified"])
        self.assertIsNone(self.server.context.store.device_by_id(device_id)["revoked_at"])
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "failed")

    def test_device_revoke_reports_unknown_when_routeros_readback_is_unavailable(self) -> None:
        path, device_id = self._managed_device_revoke_request()
        reviewed = self._review_device_revoke(path)
        current_certificates = self.server.context.router.list_ovpn_client_certificates(
            RouterOSCredentials("admin", "routerpass"), include_legacy=True,
        )
        with mock.patch.object(
            self.server.context.router,
            "list_ovpn_client_certificates",
            side_effect=[current_certificates, RouterOSError("private router detail", 503)],
        ):
            status, _, payload = self.json_request("POST", path, reviewed)

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["verification"], "unknown")
        self.assertFalse(response["verified"])
        self.assertNotIn("private router detail", payload.decode("utf-8"))
        self.assertIsNone(self.server.context.store.device_by_id(device_id)["revoked_at"])
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "unknown")

    def test_user_delete_does_not_delete_account_when_certificate_revocation_fails(self) -> None:
        self._managed_device_revoke_request()
        review = self.preview_user_delete("*1")
        router = self.server.context.router
        with mock.patch.object(
            router, "revoke_certificate", side_effect=RouterOSError("private detail", 503)
        ):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", self.user_delete_apply(review, "user-one")
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertFalse(response["user_deleted"])
        self.assertIn("*1", self.mock.state.users)
        self.assertEqual(self.mock.state.certificates["*CL1"].get("revoked"), "no")
        self.assertIsNone(self.server.context.store.device_by_id("managed-device-revoke-test")["revoked_at"])
        self.assertFalse(
            any(item.startswith("DELETE /ppp/secret") for item in self.mock.state.mutation_requests)
        )
        self.assertNotIn("private detail", payload.decode("utf-8"))

    def test_user_delete_disables_account_and_terminates_active_sessions_before_revocation(self) -> None:
        self._managed_device_revoke_request()
        self.mock.state.active_sessions["*A2"] = {
            ".id": "*A2",
            "name": "user-one",
            "service": "ovpn",
            "caller-id": "198.51.100.41",
            "address": "198.18.0.49",
            "uptime": "2m",
            "encoding": "AES-256-GCM/[test-digest]",
            "session-id": "0x81E0000C",
            "comment": "Disposable test device",
        }
        review = self.preview_user_delete("*1")
        self.assertEqual(review["active_sessions"], 1)

        status, _, payload = self.json_request(
            "DELETE", "/api/users/%2A1", self.user_delete_apply(review, "user-one")
        )

        self.assertEqual(status, 200, payload.decode("utf-8"))
        response = json.loads(payload)
        self.assertEqual(response["disconnected_sessions"], 1)
        self.assertNotIn("*A2", self.mock.state.active_sessions)
        self.assertNotIn("*1", self.mock.state.users)
        mutations = self.mock.state.mutation_requests
        disable_index = next(i for i, item in enumerate(mutations) if item.startswith("PATCH /ppp/secret/"))
        terminate_index = next(i for i, item in enumerate(mutations) if item.startswith("DELETE /ppp/active/"))
        revoke_index = next(i for i, item in enumerate(mutations) if item.startswith("POST /certificate/issued-revoke"))
        delete_index = next(i for i, item in enumerate(mutations) if item.startswith("DELETE /ppp/secret/"))
        self.assertLess(disable_index, terminate_index)
        self.assertLess(terminate_index, revoke_index)
        self.assertLess(revoke_index, delete_index)

    def test_user_delete_keeps_disabled_account_when_active_session_termination_fails(self) -> None:
        self._managed_device_revoke_request()
        self.mock.state.active_sessions["*A2"] = {
            ".id": "*A2",
            "name": "user-one",
            "service": "ovpn",
            "address": "198.18.0.49",
        }
        review = self.preview_user_delete("*1")
        router = self.server.context.router
        with mock.patch.object(router, "terminate_session", side_effect=RouterOSError("private detail", 503)):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", self.user_delete_apply(review, "user-one")
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertFalse(response["user_deleted"])
        self.assertIn("*1", self.mock.state.users)
        self.assertEqual(self.mock.state.users["*1"].get("disabled"), "yes")
        self.assertEqual(self.mock.state.certificates["*CL1"].get("revoked"), "no")
        self.assertNotIn("DELETE /ppp/secret/*1", self.mock.state.mutation_requests)
        self.assertNotIn("private detail", payload.decode("utf-8"))

    def test_user_delete_requires_reason_and_binds_it_to_review(self) -> None:
        self.login()
        before_mutations = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request("POST", "/api/users/%2A1/delete/preview", {})
        self.assertEqual(status, 400)
        self.assertIn("Provide a reason", json.loads(payload)["error"])
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

        review = self.preview_user_delete("*1")
        self.assertEqual(review["reason"], "Remove access after owner request")
        changed_intent = self.user_delete_apply(review, "user-one")
        changed_intent["reason"] = "Different administrator rationale"
        status, _, payload = self.json_request("DELETE", "/api/users/%2A1", changed_intent)

        self.assertEqual(status, 409)
        self.assertIn("Preview the deletion again", json.loads(payload)["error"])
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertIn("*1", self.mock.state.users)
        audit = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(audit["status"], "failed")
        self.assertTrue(json.loads(audit["details"])["rationale_recorded"])

    def test_user_delete_rejects_stale_managed_certificate_set(self) -> None:
        self._managed_device_revoke_request()
        review = self.preview_user_delete("*1")
        self.server.context.store.add_device(
            device_id="managed-device-delete-added-after-review",
            vpn_user="user-one",
            device_name="Added test laptop",
            certificate_name="ovpn-user-one-added-after-review",
            certificate_id="*CL3",
            fingerprint="D4:EX:59",
        )
        self.mock.state.certificates["*CL3"] = {
            **self.mock.state.certificates["*CL1"],
            ".id": "*CL3", "name": "ovpn-user-one-added-after-review",
            "fingerprint": "D4:EX:59", "revoked": "no",
        }
        before_mutations = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request(
            "DELETE", "/api/users/%2A1",
            self.user_delete_apply(review, "user-one"),
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertIn("*1", self.mock.state.users)
        self.assertEqual(self.mock.state.certificates["*CL1"]["revoked"], "no")
        self.assertEqual(self.mock.state.certificates["*CL3"]["revoked"], "no")

    def test_user_delete_rejects_changed_local_metadata_after_review(self) -> None:
        self.login()
        review = self.preview_user_delete("*1")
        mutations_before = list(self.mock.state.mutation_requests)
        self.server.context.store.add_user_tag("user-one", "changed after review")

        status, _, payload = self.json_request(
            "DELETE", "/api/users/%2A1",
            self.user_delete_apply(review, "user-one"),
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertIn("*1", self.mock.state.users)
        self.assertEqual(self.mock.state.mutation_requests, mutations_before)

    def test_user_delete_reconciles_lost_certificate_revocation_response(self) -> None:
        self._managed_device_revoke_request()
        review = self.preview_user_delete("*1")
        router = self.server.context.router
        revoke_certificate = router.revoke_certificate

        def revoke_then_lose_response(credentials: Any, *, certificate_id: str) -> None:
            revoke_certificate(credentials, certificate_id=certificate_id)
            raise RouterOSError("private detail", 503)

        with mock.patch.object(router, "revoke_certificate", side_effect=revoke_then_lose_response):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", self.user_delete_apply(review, "user-one")
            )

        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["verified"])
        self.assertNotIn("*1", self.mock.state.users)
        self.assertTrue(self.mock.state.certificates["*CL1"]["revoked"])

    def test_user_delete_retains_local_metadata_when_routeros_user_remains(self) -> None:
        self._managed_device_revoke_request()
        review = self.preview_user_delete("*1")
        router = self.server.context.router
        with mock.patch.object(router, "delete_user"):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", self.user_delete_apply(review, "user-one")
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["verification"], "mismatch")
        self.assertIn("*1", self.mock.state.users)
        self.assertIsNotNone(
            self.server.context.store.device_by_id("managed-device-revoke-test")["revoked_at"]
        )
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "failed")

    def test_user_delete_response_loss_is_reconciled_by_routeros_readback(self) -> None:
        self._managed_device_revoke_request()
        review = self.preview_user_delete("*1")
        router = self.server.context.router
        delete_user = router.delete_user

        def delete_then_lose_response(credentials: Any, *, user_id: str) -> None:
            delete_user(credentials, user_id=user_id)
            raise RouterOSError("private detail", 503)

        with mock.patch.object(router, "delete_user", side_effect=delete_then_lose_response):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", self.user_delete_apply(review, "user-one")
            )

        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["verified"])
        self.assertNotIn("*1", self.mock.state.users)

    def test_user_delete_preserves_account_when_certificate_readback_is_unavailable(self) -> None:
        self._managed_device_revoke_request()
        review = self.preview_user_delete("*1")
        router = self.server.context.router

        def unavailable_readback(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            raise RouterOSError("private router detail", 503)

        with mock.patch.object(
            router, "list_ovpn_client_certificates", side_effect=unavailable_readback
        ):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", self.user_delete_apply(review, "user-one")
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["verification"], "unknown")
        self.assertTrue(response["user_deleted"] is False)
        self.assertIn("*1", self.mock.state.users)
        self.assertIsNone(self.server.context.store.device_by_id("managed-device-revoke-test")["revoked_at"])

    def test_user_delete_preserves_local_metadata_when_account_readback_is_unavailable(self) -> None:
        self._managed_device_revoke_request()
        self.server.context.store.set_user_email("user-one", "user-one@example.invalid")
        review = self.preview_user_delete("*1")
        router = self.server.context.router
        list_users = router.list_ovpn_users

        def fail_only_after_delete(credentials: Any) -> list[dict[str, Any]]:
            if "*1" not in self.mock.state.users:
                raise RouterOSError("private router detail", 503)
            return list_users(credentials)

        with mock.patch.object(router, "list_ovpn_users", side_effect=fail_only_after_delete):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", self.user_delete_apply(review, "user-one")
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["verification"], "unknown")
        self.assertNotIn("*1", self.mock.state.users)
        self.assertEqual(
            self.server.context.store.user_emails()["user-one"],
            "user-one@example.invalid",
        )
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "unknown")

    def test_session_termination_reports_unknown_when_router_readback_fails(self) -> None:
        self.login()
        session_id = next(iter(self.mock.state.active_sessions))
        review = self.preview_session_termination(session_id)
        credentials = RouterOSCredentials("admin", "routerpass")
        router = self.server.context.router
        active_sessions = router.list_active_ovpn_sessions(credentials)
        with mock.patch.object(
            router,
            "list_active_ovpn_sessions",
            side_effect=[active_sessions, RouterOSError("private router detail", 503)],
        ):
            status, _, payload = self.json_request(
                "DELETE",
                f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}",
                {"confirmation": "user-two", "reason": review["reason"], "review_token": review["review_token"]},
            )

        self.assertEqual(status, 502)
        response = json.loads(payload)
        self.assertEqual(response["code"], "routeros.mutation_verification_unavailable")
        self.assertFalse(response["verified"])
        self.assertNotIn("private router detail", payload.decode("utf-8"))
        self.assertNotIn(session_id, self.mock.state.active_sessions)
        latest = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(latest["action"], "session.terminate")
        self.assertEqual(latest["status"], "unknown")

    def test_session_termination_rejects_changed_live_session_after_review(self) -> None:
        self.login()
        session_id = next(iter(self.mock.state.active_sessions))
        review = self.preview_session_termination(session_id)
        self.mock.state.active_sessions[session_id]["session-id"] = "changed-session-id"
        mutations_before = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request(
            "DELETE", f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}",
            {"confirmation": "user-two", "reason": review["reason"], "review_token": review["review_token"]},
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertIn(session_id, self.mock.state.active_sessions)
        self.assertEqual(self.mock.state.mutation_requests, mutations_before)

    def test_suspend_disconnects_all_sessions_and_restore_reenables_access(self) -> None:
        self.login()
        users = {
            item["name"]: item
            for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            )
        }
        user_two_id = users["user-two"]["id"]

        status, _, _ = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_two_id, safe='*')}/suspend", csrf=False
        )
        self.assertEqual(status, 403)
        self.assertTrue(self.mock.state.active_sessions)

        preview = self.preview_user_suspend(user_two_id)
        self.assertEqual(preview["active_sessions"], 1)
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_two_id, safe='*')}/suspend",
            self.user_suspend_apply(preview, "user-two"),
        )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertTrue(result["disabled"])
        self.assertEqual(result["disconnected"], 1)
        self.assertEqual(result["remaining"], 0)
        self.assertTrue(
            json.loads(self.server.context.store.recent_audit(1)[0]["details"])["rationale_recorded"]
        )
        self.assertFalse(self.mock.state.active_sessions)
        disabled = next(item for item in self.mock.state.users.values() if item["name"] == "user-two")
        self.assertEqual(disabled["disabled"], "yes")
        self.assertIsNotNone(self.server.context.store.recent_connections(1)[0]["disconnected_at"])

        restore_review = self.preview_user_restore(user_two_id)
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_two_id, safe='*')}/restore",
            {"review_token": restore_review["review_token"]},
        )
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(payload)["disabled"])
        restored = next(item for item in self.mock.state.users.values() if item["name"] == "user-two")
        self.assertEqual(restored["disabled"], "no")
        actions = [item["action"] for item in self.server.context.store.recent_audit(10)]
        self.assertIn("user.suspend", actions)
        self.assertIn("user.restore", actions)

    def test_restore_rejects_account_state_changed_after_review(self) -> None:
        self.login()
        user = next(item for item in self.mock.state.users.values() if item["name"] == "user-two")
        user["disabled"] = "yes"
        review = self.preview_user_restore("*2")
        user["disabled"] = "no"
        mutations_before = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request(
            "POST", "/api/users/%2A2/restore", {"review_token": review["review_token"]},
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, mutations_before)

    def test_user_suspend_preview_is_read_only_and_stale_session_set_blocks_apply(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        before_mutations = list(self.mock.state.mutation_requests)
        preview = self.preview_user_suspend(user["id"])

        self.assertEqual(preview["active_sessions"], 1)
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertNotIn("198.51.100.40", json.dumps(preview))
        self.assertNotIn("0x81E0000B", json.dumps(preview))

        self.mock.state.active_sessions["*A2"] = {
            **self.mock.state.active_sessions["*A1"], ".id": "*A2", "session-id": "0x81E0000C",
        }
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/suspend",
            self.user_suspend_apply(preview, "user-two"),
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(self.mock.state.users[user["id"]]["disabled"], "no")

    def test_user_suspend_requires_reason_and_binds_it_to_review(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        before_mutations = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/suspend/preview", {},
        )
        self.assertEqual(status, 400)
        self.assertIn("Provide a reason", json.loads(payload)["error"])

        review = self.preview_user_suspend(user["id"])
        changed_intent = self.user_suspend_apply(review, "user-two")
        changed_intent["reason"] = "Different administrator rationale"
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/suspend", changed_intent,
        )
        self.assertEqual(status, 409)
        self.assertIn("state changed", json.loads(payload)["error"])
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        audit = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(audit["status"], "failed")
        self.assertTrue(json.loads(audit["details"])["rationale_recorded"])

    def test_user_suspend_reconciles_lost_patch_response_from_routeros_readback(self) -> None:
        self.login()
        router = self.server.context.router
        user = next(
            item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        preview = self.preview_user_suspend(user["id"])
        update_user = router.update_user

        def update_then_lose_response(*args: Any, **kwargs: Any) -> None:
            update_user(*args, **kwargs)
            raise RouterOSError("private router detail", 503)

        with mock.patch.object(router, "update_user", side_effect=update_then_lose_response):
            status, _, payload = self.json_request(
                "POST", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/suspend",
                self.user_suspend_apply(preview, "user-two"),
            )

        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertTrue(result["verified"])
        self.assertTrue(result["reconciled"])
        self.assertTrue(result["disabled"])
        disabled = next(item for item in self.mock.state.users.values() if item["name"] == "user-two")
        self.assertEqual(disabled["disabled"], "yes")
        audit = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(audit["status"], "success")
        self.assertTrue(json.loads(audit["details"])["mutation_response_lost"])
        self.assertNotIn("private router detail", payload.decode("utf-8"))

    def test_user_suspend_reports_mismatch_without_claiming_success(self) -> None:
        self.login()
        router = self.server.context.router
        user = next(
            item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        preview = self.preview_user_suspend(user["id"])

        with mock.patch.object(router, "update_user"):
            status, _, payload = self.json_request(
                "POST", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/suspend",
                self.user_suspend_apply(preview, "user-two"),
            )

        self.assertEqual(status, 409)
        result = json.loads(payload)
        self.assertEqual(result["code"], "routeros.mutation_verification_failed")
        self.assertFalse(result["verified"])
        unchanged = next(item for item in self.mock.state.users.values() if item["name"] == "user-two")
        self.assertEqual(unchanged["disabled"], "no")
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "failed")

    def test_user_access_reports_unknown_when_routeros_readback_is_unavailable(self) -> None:
        self.login()
        router = self.server.context.router
        self.server.context.store.set_user_controls(
            "user-two", policy="full-tunnel", expires_at=None, max_sessions=1,
            rate_limit_kbps=0, dns_mode="router", notifications=True,
        )
        self.server.context.store.set_enforcement_state("user-two", "quota")
        user = next(
            item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        preview = self.preview_user_suspend(user["id"])
        update_user = router.update_user
        list_users = router.list_ovpn_users

        def update_then_readback_fails(*args: Any, **kwargs: Any) -> None:
            update_user(*args, **kwargs)

        def list_with_failed_verification(credentials: RouterOSCredentials) -> list[dict[str, Any]]:
            # The handler's initial lookup succeeds; only the post-mutation
            # verification read is unavailable.
            if list_with_failed_verification.calls == 0:
                list_with_failed_verification.calls += 1
                return list_users(credentials)
            raise RouterOSError("private router detail", 503)

        list_with_failed_verification.calls = 0  # type: ignore[attr-defined]
        with (
            mock.patch.object(router, "update_user", side_effect=update_then_readback_fails),
            mock.patch.object(router, "list_ovpn_users", side_effect=list_with_failed_verification),
        ):
            status, _, payload = self.json_request(
                "POST", f"/api/users/{urllib.parse.quote(user['id'], safe='*')}/suspend",
                self.user_suspend_apply(preview, "user-two"),
            )

        self.assertEqual(status, 502)
        result = json.loads(payload)
        self.assertEqual(result["verification"], "unknown")
        self.assertFalse(result["verified"])
        self.assertNotIn("private router detail", payload.decode("utf-8"))
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "unknown")
        self.assertEqual(self.server.context.store.user_controls("user-two")["enforcement_state"], "quota")

    def test_bulk_tag_is_reviewed_idempotent_and_supports_saved_views(self) -> None:
        self.login()
        users = {
            item["name"]: item
            for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            )
        }
        selected = [users["user-one"]["id"], users["user-two"]["id"]]

        status, _, payload = self.json_request(
            "POST", "/api/bulk/preview",
            {"action": "tag", "user_ids": selected, "tag": "Field Team"},
        )
        self.assertEqual(status, 200)
        preview = json.loads(payload)
        self.assertEqual(preview["confirmation"], "APPLY TAG TO 2 USERS")
        self.assertEqual({item["state"] for item in preview["users"]}, {"will_tag"})

        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {"action": "tag", "user_ids": selected, "tag": "Field Team", "confirmation": "wrong", "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 400)
        self.assertIn("exact target name", json.loads(payload)["error"])

        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {"action": "tag", "user_ids": selected, "tag": "Field Team", "confirmation": "APPLY TAG TO 2 USERS", "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertEqual(result["status"], "success")
        self.assertEqual({self.server.context.store.user_tags(name)[0] for name in users}, {"Field Team"})

        preview = self.preview_bulk_action("tag", selected, tag="Field Team")
        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {"action": "tag", "user_ids": selected, "tag": "Field Team", "confirmation": "APPLY TAG TO 2 USERS", "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 200)
        self.assertEqual({item["status"] for item in json.loads(payload)["outcomes"]}, {"skipped"})

        status, _, payload = self.json_request("GET", "/api/bulk/views")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["views"], [])
        status, _, payload = self.json_request(
            "POST", "/api/bulk/views",
            {"name": "Field team users", "filters": {"query": "field", "status": "all", "tag": "Field Team"}},
        )
        self.assertEqual(status, 200)
        view = json.loads(payload)["view"]
        self.assertEqual(view["filters"]["tag"], "Field Team")
        self.assertNotIn("user-one", json.dumps(view))
        status, _, payload = self.json_request("GET", "/api/bulk/views")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["views"][0]["name"], "Field team users")
        status, _, _ = self.json_request("DELETE", f"/api/bulk/views/{view['id']}")
        self.assertEqual(status, 200)
        self.assertIn("bulk.tag", [item["action"] for item in self.server.context.store.recent_audit(20)])
        self.assertIn("bulk.view.save", [item["action"] for item in self.server.context.store.recent_audit(20)])

    def test_saved_view_mutations_require_sessions_read(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        session = self.server.context.sessions.get(session_id, touch=False)
        self.assertIsNotNone(session)
        session.capabilities = frozenset({"health.read"})
        headers = {
            "Cookie": self.cookie,
            "Content-Type": "application/json",
            "X-CSRF-Token": self.csrf,
        }

        status, _, payload = self.json_request(
            "POST", "/api/bulk/views",
            {"name": "unauthorized view", "filters": {"status": "online"}},
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["required_capability"], "sessions.read")
        self.assertEqual(self.server.context.store.saved_views(), [])

        existing = self.server.context.store.save_view(name="protected view", filters={"status": "offline"})
        status, _, payload = self.request(
            "DELETE", f"/api/bulk/views/{existing['id']}", headers=headers,
        )
        self.assertEqual(status, 403)
        self.assertEqual(json.loads(payload)["required_capability"], "sessions.read")
        self.assertEqual(self.server.context.store.saved_views(), [existing])

    def test_bulk_suspend_previews_and_disconnects_selected_users(self) -> None:
        self.login()
        users = {
            item["name"]: item
            for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            )
        }
        selected = [users["user-one"]["id"], users["user-two"]["id"]]
        status, _, payload = self.json_request(
            "POST", "/api/bulk/preview", {"action": "suspend", "user_ids": selected, "reason": "Quarterly VPN access review"},
        )
        self.assertEqual(status, 200)
        preview = json.loads(payload)
        self.assertEqual({item["state"] for item in preview["users"]}, {"will_suspend"})
        self.assertEqual(next(item for item in preview["users"] if item["username"] == "user-two")["active_sessions"], 1)

        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {"action": "suspend", "user_ids": selected, "reason": preview["reason"], "confirmation": "APPLY SUSPEND TO 2 USERS", "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertEqual(result["status"], "success")
        self.assertEqual(next(item for item in result["outcomes"] if item["username"] == "user-two")["disconnected"], 1)
        self.assertEqual({item["status"] for item in result["outcomes"]}, {"verified"})
        self.assertFalse(self.mock.state.active_sessions)
        self.assertTrue(all(item["disabled"] == "yes" for item in self.mock.state.users.values()))
        bulk_audit = next(item for item in self.server.context.store.recent_audit(10) if item["action"] == "bulk.suspend")
        self.assertTrue(json.loads(bulk_audit["details"])["rationale_recorded"])

    def test_bulk_destructive_action_binds_rationale_before_routeros_mutation(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-two"
        )
        preview = self.preview_bulk_action("suspend", [user["id"]])
        before_mutations = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {
                "action": "suspend", "user_ids": [user["id"]],
                "reason": "Different operator rationale", "confirmation": preview["confirmation"],
                "review_token": preview["review_token"],
            },
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(self.mock.state.users[user["id"]]["disabled"], "no")

    def test_bulk_destructive_preview_rejects_missing_reason(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-two"
        )

        status, _, payload = self.json_request(
            "POST", "/api/bulk/preview", {"action": "suspend", "user_ids": [user["id"]]},
        )

        self.assertEqual(status, 400)
        self.assertEqual(self.mock.state.mutation_requests, [])
        self.assertIn("reason", json.loads(payload)["error"])

    def test_bulk_review_binds_exact_live_state_and_is_single_use(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-two"
        )
        review = self.preview_bulk_action("suspend", [user["id"]])
        old_session_id = next(iter(self.mock.state.active_sessions))
        active = self.mock.state.active_sessions.pop(old_session_id)
        changed_session_id = f"{old_session_id}-changed"
        self.mock.state.active_sessions[changed_session_id] = {
            **active, ".id": changed_session_id, "session-id": "0x81E0000C",
        }
        before_mutations = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {
                "action": "suspend", "user_ids": [user["id"]],
                "reason": review["reason"], "confirmation": "APPLY SUSPEND TO 1 USERS", "review_token": review["review_token"],
            },
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(self.mock.state.users[user["id"]]["disabled"], "no")

        refreshed = self.preview_bulk_action("suspend", [user["id"]])
        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {
                "action": "suspend", "user_ids": [user["id"]],
                "reason": refreshed["reason"], "confirmation": "APPLY SUSPEND TO 1 USERS", "review_token": refreshed["review_token"],
            },
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["ok"])
        before_replay = list(self.mock.state.mutation_requests)
        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {
                "action": "suspend", "user_ids": [user["id"]],
                "reason": refreshed["reason"], "confirmation": "APPLY SUSPEND TO 1 USERS", "review_token": refreshed["review_token"],
            },
        )
        self.assertEqual(status, 409)
        self.assertEqual(self.mock.state.mutation_requests, before_replay)

    def test_bulk_suspend_review_detects_routeros_disabled_string_change(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-two"
        )
        review = self.preview_bulk_action("suspend", [user["id"]])
        before_mutations = list(self.mock.state.mutation_requests)
        self.mock.state.users[user["id"]]["disabled"] = "yes"

        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {
                "action": "suspend", "user_ids": [user["id"]],
                "reason": review["reason"], "confirmation": "APPLY SUSPEND TO 1 USERS", "review_token": review["review_token"],
            },
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

    def test_bulk_tag_review_detects_changed_tag_set(self) -> None:
        self.login()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-two"
        )
        review = self.preview_bulk_action("tag", [user["id"]], tag="Field Team")
        self.server.context.store.add_user_tag(user["name"], "External label")

        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {
                "action": "tag", "tag": "Field Team", "user_ids": [user["id"]],
                "confirmation": "APPLY TAG TO 1 USERS", "review_token": review["review_token"],
            },
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.server.context.store.user_tags(user["name"]), ["External label"])

    def test_bulk_revoke_review_detects_changed_certificate_set(self) -> None:
        _, _ = self._managed_device_revoke_request()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-one"
        )
        review = self.preview_bulk_action("revoke", [user["id"]])
        self.server.context.store.add_device(
            device_id="managed-device-added-after-preview",
            vpn_user="user-one",
            device_name="Managed test laptop",
            certificate_name="ovpn-user-one-added-after-preview",
            certificate_id="*CL3",
            fingerprint="C3:EX:48",
        )
        self.mock.state.certificates["*CL3"] = {
            **self.mock.state.certificates["*CL1"],
            ".id": "*CL3", "name": "ovpn-user-one-added-after-preview",
            "fingerprint": "C3:EX:48", "revoked": "no",
        }
        before_mutations = list(self.mock.state.mutation_requests)

        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {
                "action": "revoke", "user_ids": [user["id"]],
                "reason": review["reason"], "confirmation": "APPLY REVOKE TO 1 USERS", "review_token": review["review_token"],
            },
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(self.mock.state.certificates["*CL1"]["revoked"], "no")
        self.assertEqual(self.mock.state.certificates["*CL3"]["revoked"], "no")

    def test_bulk_suspend_reconciles_lost_mutation_response_by_user_readback(self) -> None:
        self.login()
        router = self.server.context.router
        user = next(
            item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        review = self.preview_bulk_action("suspend", [user["id"]])
        update_user = router.update_user

        def update_then_lose_response(*args: Any, **kwargs: Any) -> None:
            update_user(*args, **kwargs)
            raise RouterOSError("private RouterOS response", 503)

        with mock.patch.object(router, "update_user", side_effect=update_then_lose_response):
            status, _, payload = self.json_request(
                "POST", "/api/bulk/apply",
                {
                    "action": "suspend", "user_ids": [user["id"]],
                    "confirmation": "APPLY SUSPEND TO 1 USERS",
                    "reason": review["reason"],
                    "review_token": review["review_token"],
                },
            )

        result = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["outcomes"][0]["status"], "verified")
        self.assertTrue(result["outcomes"][0]["reconciled"])
        self.assertTrue(next(item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass")) if item["id"] == user["id"])["disabled"])
        self.assertNotIn("private RouterOS response", payload.decode())

    def test_bulk_suspend_readback_unavailable_does_not_clear_local_enforcement(self) -> None:
        self.login()
        router = self.server.context.router
        user = next(
            item for item in router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
            if item["name"] == "user-two"
        )
        self.server.context.store.set_user_controls(
            user["name"], policy="full-tunnel", expires_at="", max_sessions=1,
            rate_limit_kbps=0, dns_mode="router", notifications=False,
        )
        self.server.context.store.set_enforcement_state(user["name"], "quota")
        current_users = router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
        review = self.preview_bulk_action("suspend", [user["id"]])
        with mock.patch.object(
            router,
            "list_ovpn_users",
            side_effect=[current_users, RouterOSError("private read-back detail", 503)],
        ):
            status, _, payload = self.json_request(
                "POST", "/api/bulk/apply",
                {
                    "action": "suspend", "user_ids": [user["id"]],
                    "confirmation": "APPLY SUSPEND TO 1 USERS",
                    "reason": review["reason"],
                    "review_token": review["review_token"],
                },
            )

        result = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["outcomes"][0]["status"], "unknown")
        self.assertEqual(self.server.context.store.user_controls(user["name"])["enforcement_state"], "quota")

    def test_bulk_revoke_marks_local_devices_only_after_certificate_readback(self) -> None:
        _, device_id = self._managed_device_revoke_request()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-one"
        )
        review = self.preview_bulk_action("revoke", [user["id"]])
        revoke = self.server.context.router.revoke_certificate

        def revoke_then_lose_response(*args: Any, **kwargs: Any) -> None:
            revoke(*args, **kwargs)
            raise RouterOSError("private RouterOS response", 503)

        with mock.patch.object(self.server.context.router, "revoke_certificate", side_effect=revoke_then_lose_response):
            status, _, payload = self.json_request(
                "POST", "/api/bulk/apply",
                {
                    "action": "revoke", "user_ids": [user["id"]],
                    "confirmation": "APPLY REVOKE TO 1 USERS",
                    "reason": review["reason"],
                    "review_token": review["review_token"],
                },
            )

        result = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["outcomes"][0]["status"], "verified")
        self.assertIsNotNone(self.server.context.store.device_by_id(device_id)["revoked_at"])
        self.assertTrue(self.mock.state.certificates["*CL1"]["revoked"])
        self.assertNotIn("private RouterOS response", payload.decode())

    def test_bulk_revoke_readback_failure_leaves_local_device_state_unknown(self) -> None:
        _, device_id = self._managed_device_revoke_request()
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-one"
        )
        review = self.preview_bulk_action("revoke", [user["id"]])
        with mock.patch.object(
            self.server.context.router,
            "list_ovpn_client_certificates",
            side_effect=RouterOSError("private read-back detail", 503),
        ):
            status, _, payload = self.json_request(
                "POST", "/api/bulk/apply",
                {
                    "action": "revoke", "user_ids": [user["id"]],
                    "confirmation": "APPLY REVOKE TO 1 USERS",
                    "reason": review["reason"],
                    "review_token": review["review_token"],
                },
            )

        result = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["outcomes"][0]["status"], "unknown")
        self.assertIsNone(self.server.context.store.device_by_id(device_id)["revoked_at"])
        self.assertTrue(self.mock.state.certificates["*CL1"]["revoked"])
        self.assertNotIn("private read-back detail", payload.decode())

    def test_bulk_revoke_reports_verified_partial_progress_before_later_readback_loss(self) -> None:
        self._managed_device_revoke_request()
        second_device_id = "managed-device-revoke-second-test"
        self.server.context.store.add_device(
            device_id=second_device_id,
            vpn_user="user-one",
            device_name="Managed test laptop",
            certificate_name="ovpn-user-one-device-b",
            certificate_id="*CL3",
            fingerprint="B2:EX:37",
        )
        self.mock.state.certificates["*CL3"] = {
            **self.mock.state.certificates["*CL1"],
            ".id": "*CL3",
            "name": "ovpn-user-one-device-b",
            "fingerprint": "B2:EX:37",
            "common-name": "user-one-managed-test-laptop",
            "revoked": "no",
        }
        device_order = self.server.context.store.devices_for_user("user-one")
        first_device_id = str(device_order[0]["id"])
        second_device_id = str(device_order[1]["id"])
        user = next(
            item for item in self.server.context.router.list_ovpn_users(
                RouterOSCredentials("admin", "routerpass")
            ) if item["name"] == "user-one"
        )
        review = self.preview_bulk_action("revoke", [user["id"]])
        list_certificates = self.server.context.router.list_ovpn_client_certificates
        readbacks = 0

        def lose_second_readback(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            nonlocal readbacks
            readbacks += 1
            if readbacks == 2:
                raise RouterOSError("private read-back detail", 503)
            return list_certificates(*args, **kwargs)

        with mock.patch.object(
            self.server.context.router,
            "list_ovpn_client_certificates",
            side_effect=lose_second_readback,
        ):
            status, _, payload = self.json_request(
                "POST", "/api/bulk/apply",
                {
                    "action": "revoke", "user_ids": [user["id"]],
                    "confirmation": "APPLY REVOKE TO 1 USERS",
                    "reason": review["reason"],
                    "review_token": review["review_token"],
                },
            )

        result = json.loads(payload)
        self.assertEqual(status, 200)
        self.assertEqual(result["status"], "partial")
        outcome = result["outcomes"][0]
        self.assertEqual(outcome["status"], "unknown")
        self.assertEqual(outcome["revoked"], 1)
        self.assertEqual(outcome["unknown"], 1)
        self.assertIsNotNone(self.server.context.store.device_by_id(first_device_id)["revoked_at"])
        self.assertIsNone(self.server.context.store.device_by_id(second_device_id)["revoked_at"])
        self.assertTrue(self.mock.state.certificates["*CL1"]["revoked"])
        self.assertTrue(self.mock.state.certificates["*CL3"]["revoked"])
        self.assertNotIn("private read-back detail", payload.decode())
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "partial")


    def test_policy_template_preview_and_explicit_apply(self) -> None:
        self.login()
        status, _, payload = self.request("GET", "/api/policy-templates")
        self.assertEqual(status, 200)
        templates = json.loads(payload)["templates"]
        self.assertEqual({item["id"] for item in templates}, {"standard", "contractor", "admin"})

        status, _, payload = self.json_request(
            "POST", "/api/policy-templates",
            {"name": "Field team", "description": "Limited field support access.", "group_name": "Field",
             "policy": "lan-only", "max_sessions": 2, "rate_limit_kbps": 10240,
             "quota_mb": 5120, "schedule": "weekdays", "dns_mode": "router", "notifications": True},
        )
        self.assertEqual(status, 201)
        template = json.loads(payload)["template"]
        users = self.server.context.router.list_ovpn_users(RouterOSCredentials("admin", "routerpass"))
        target = next(item for item in users if item["name"] == "user-one")
        rationale = "Approved field-team network restrictions"
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/preview",
            {"user_ids": [target["id"]], "reason": rationale},
        )
        self.assertEqual(status, 200)
        preview = json.loads(payload)
        self.assertEqual(preview["reason"], rationale)
        self.assertIn("rate_limit_kbps", preview["users"][0]["changes"])
        self.assertTrue(preview["review_token"])

        # Direct apply without a server-issued preview receipt is rejected.
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/apply",
            {"user_ids": [target["id"]], "reason": rationale},
        )
        self.assertEqual(status, 409)
        self.assertIn("Preview the selected users again", json.loads(payload)["error"])

        # A live RouterOS profile edit between review and apply also invalidates it.
        original_profile = self.mock.state.users[target["id"]]["profile"]
        self.mock.state.users[target["id"]]["profile"] = "manual-router-change"
        status, _, _ = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/apply",
            {"user_ids": [target["id"]], "reason": rationale,
             "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 409)
        self.mock.state.users[target["id"]]["profile"] = original_profile
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/preview",
            {"user_ids": [target["id"]], "reason": rationale},
        )
        self.assertEqual(status, 200)
        preview = json.loads(payload)

        # Reusing the receipt with a different selection cannot apply an unreviewed user.
        other = next(item for item in users if item["id"] != target["id"])
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/apply",
            {"user_ids": [target["id"], other["id"]], "reason": rationale,
             "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 409)
        self.assertNotIn("user-one", self.server.context.store.user_template_assignments())
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/preview",
            {"user_ids": [target["id"]], "reason": rationale},
        )
        self.assertEqual(status, 200)
        preview = json.loads(payload)

        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/apply",
            {"user_ids": [target["id"]], "reason": rationale,
             "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["applied"], ["user-one"])
        self.assertEqual(result["outcomes"], [{"username": "user-one", "status": "verified"}])
        self.assertEqual(self.server.context.store.user_controls("user-one")["rate_limit_kbps"], 10240)
        self.assertEqual(self.server.context.store.user_template_assignments()["user-one"]["template_id"], template["id"])
        self.assertIn("policy_template.apply", [item["action"] for item in self.server.context.store.recent_audit(10)])
        apply_audit = next(item for item in self.server.context.store.recent_audit(10)
                           if item["action"] == "policy_template.apply")
        self.assertTrue(json.loads(apply_audit["details"])["rationale_recorded"])
        status, _, _ = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/apply",
            {"user_ids": [target["id"]], "reason": rationale,
             "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 409)

        # A state change after preview invalidates that review before checkpoint/apply.
        current = self.server.context.store.user_controls("user-one")
        self.server.context.store.set_user_controls(
            "user-one", policy=current["policy"], expires_at=current["expires_at"],
            max_sessions=current["max_sessions"], rate_limit_kbps=2048,
            dns_mode=current["dns_mode"], notifications=current["notifications"],
            quota_mb=current["quota_mb"], schedule=current["schedule"],
        )
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/preview",
            {"user_ids": [target["id"]], "reason": rationale},
        )
        self.assertEqual(status, 200)
        stale_review = json.loads(payload)["review_token"]
        current = self.server.context.store.user_controls("user-one")
        self.server.context.store.set_user_controls(
            "user-one", policy=current["policy"], expires_at=current["expires_at"],
            max_sessions=current["max_sessions"], rate_limit_kbps=4096,
            dns_mode=current["dns_mode"], notifications=current["notifications"],
            quota_mb=current["quota_mb"], schedule=current["schedule"],
        )
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/apply",
            {"user_ids": [target["id"]], "reason": rationale,
             "review_token": stale_review},
        )
        self.assertEqual(status, 409)
        self.assertEqual(self.server.context.store.user_controls("user-one")["rate_limit_kbps"], 4096)

    def test_policy_template_review_binds_rationale(self) -> None:
        self.login()
        path, user_id, preview = self._policy_template_review()
        status, _, payload = self.json_request(
            "POST", path,
            {"user_ids": [user_id], "reason": "Different approved policy purpose",
             "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 409)
        self.assertNotIn("PATCH /ppp/secret/", self.mock.state.mutation_requests)

    def test_policy_template_review_binds_generated_rate_profile_state(self) -> None:
        self.login()
        path, user_id, preview = self._policy_template_review()
        self.mock.state.profiles["*P9"] = {
            ".id": "*P9", "name": "vpn-ui-user-one", "rate-limit": "512k/512k",
        }

        status, _, payload = self.json_request(
            "POST", path, {"user_ids": [user_id], "reason": preview["reason"],
                           "review_token": preview["review_token"]},
        )

        self.assertEqual(status, 409)
        self.assertIn("state has changed", json.loads(payload)["error"])
        self.assertEqual(self.mock.state.profiles["*P9"]["rate-limit"], "512k/512k")
        self.assertNotIn("PATCH /ppp/profile/*P9", self.mock.state.mutation_requests)

    def test_policy_template_apply_reports_router_failure_and_readback_unknown(self) -> None:
        self.login()
        path, user_id, preview = self._policy_template_review()
        with mock.patch.object(self.server.context.router, "update_user", side_effect=RouterOSError("router rejected update")):
            status, _, payload = self.json_request(
                "POST", path, {"user_ids": [user_id], "reason": preview["reason"],
                               "review_token": preview["review_token"]},
            )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["outcomes"], [{
            "username": "user-one", "status": "failed", "reason": "RouterOSError",
        }])
        self.assertEqual(self.server.context.store.user_controls("user-one")["rate_limit_kbps"], 0)

    def test_policy_template_apply_verifies_commit_after_routeros_response_loss(self) -> None:
        self.login()
        path, user_id, preview = self._policy_template_review()
        router = self.server.context.router
        update_user = router.update_user

        def commit_then_lose_response(*args: Any, **kwargs: Any) -> None:
            update_user(*args, **kwargs)
            raise RouterOSError("response lost after commit")

        with mock.patch.object(router, "update_user", side_effect=commit_then_lose_response):
            status, _, payload = self.json_request(
                "POST", path, {"user_ids": [user_id], "reason": preview["reason"],
                               "review_token": preview["review_token"]},
            )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["outcomes"], [{"username": "user-one", "status": "verified"}])
        self.assertEqual(self.server.context.store.user_controls("user-one")["rate_limit_kbps"], 10240)


    def test_policy_template_apply_reports_unknown_when_readback_is_unavailable(self) -> None:
        self.login()
        path, user_id, preview = self._policy_template_review()
        credentials = RouterOSCredentials("admin", "routerpass")
        initial_users = self.server.context.router.list_ovpn_users(credentials)
        with mock.patch.object(
            self.server.context.router,
            "list_ovpn_users",
            side_effect=[initial_users, RouterOSError("read-back unavailable")],
        ):
            status, _, payload = self.json_request(
                "POST", path, {"user_ids": [user_id], "reason": preview["reason"],
                               "review_token": preview["review_token"]},
            )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["outcomes"], [{"username": "user-one", "status": "unknown"}])
        self.assertEqual(self.server.context.store.user_controls("user-one")["rate_limit_kbps"], 0)


class RedirectTests(unittest.TestCase):
    def test_http_redirect_drops_query_and_preserves_path(self) -> None:
        RedirectHandler.public_origin = "https://dashboard.example.test"
        server = ThreadingHTTPServer(("127.0.0.1", 0), RedirectHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            connection = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            connection.request("GET", "/dashboard?token=must-not-leak")
            response = connection.getresponse()
            response.read()
            self.assertEqual(response.status, 308)
            self.assertEqual(response.getheader("Location"), "https://dashboard.example.test/dashboard")
            connection.close()

            malicious = RedirectHandler.__new__(RedirectHandler)
            malicious.path = "/dashboard\r\nX-Injected: yes"
            malicious.send_error = mock.Mock()
            malicious.do_GET()
            malicious.send_error.assert_called_once_with(400)

            encoded = http.client.HTTPConnection("127.0.0.1", server.server_port, timeout=5)
            encoded.request("GET", "/dashboard%0d%0aX-Injected%3a%20yes")
            response = encoded.getresponse()
            response.read()
            self.assertEqual(response.status, 308)
            self.assertEqual(
                response.getheader("Location"),
                "https://dashboard.example.test/dashboard%0d%0aX-Injected%3a%20yes",
            )
            self.assertEqual(
                sum(1 for name, _ in response.getheaders() if name.lower() == "location"),
                1,
            )
            self.assertNotIn("X-Injected", {name for name, _ in response.getheaders()})
            encoded.close()
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
class ProxyTrustTests(unittest.TestCase):
    def test_handler_combines_duplicate_forwarded_headers_before_proxy_resolution(self) -> None:
        handler = DashboardHandler.__new__(DashboardHandler)
        handler.client_address = ("192.0.2.10", 12345)
        handler.server = mock.Mock()
        handler.server.context.config.trusted_proxy_header = "X-Forwarded-For"
        handler.server.context.config.trusted_proxy_sources = ("192.0.2.10",)
        handler.headers = http.client.HTTPMessage()
        handler.headers.add_header("X-Forwarded-For", "198.51.100.77")
        handler.headers.add_header("X-Forwarded-For", "203.0.113.25")

        self.assertEqual(handler._client_ip(), "203.0.113.25")

    def test_cloudflare_header_requires_the_expected_reverse_proxy(self) -> None:
        expected = resolve_client_ip(
            "192.0.2.1",
            "2001:db8::1",
            trusted_proxy_header="CF-Connecting-IP",
            trusted_proxy_sources=("192.0.2.1",),
        )
        spoofed = resolve_client_ip(
            "198.51.100.50",
            "203.0.113.90",
            trusted_proxy_header="CF-Connecting-IP",
            trusted_proxy_sources=("192.0.2.1",),
        )
        invalid = resolve_client_ip(
            "192.0.2.1",
            "not-an-ip",
            trusted_proxy_header="CF-Connecting-IP",
            trusted_proxy_sources=("192.0.2.1",),
        )
        chained = resolve_client_ip(
            "192.0.2.1",
            "2001:db8::1, 2001:db8::2",
            trusted_proxy_header="CF-Connecting-IP",
            trusted_proxy_sources=("192.0.2.1",),
        )
        self.assertEqual(expected, "2001:db8::1")
        self.assertEqual(spoofed, "198.51.100.50")
        self.assertEqual(invalid, "192.0.2.1")
        self.assertEqual(chained, "192.0.2.1")

    def test_direct_proxy_resolves_x_forwarded_for_from_exact_peer(self) -> None:
        expected = resolve_client_ip(
            "192.0.2.10",
            "198.51.100.99, 203.0.113.50",
            trusted_proxy_header="X-Forwarded-For",
            trusted_proxy_sources=("192.0.2.10",),
        )
        single_hop = resolve_client_ip(
            "192.0.2.10",
            "203.0.113.50",
            trusted_proxy_header="X-Forwarded-For",
            trusted_proxy_sources=("192.0.2.10",),
        )
        malformed = resolve_client_ip(
            "192.0.2.10",
            "198.51.100.99, not-an-ip",
            trusted_proxy_header="X-Forwarded-For",
            trusted_proxy_sources=("192.0.2.10",),
        )
        trusted_chain = resolve_client_ip(
            "192.0.2.10",
            "198.51.100.25, 192.0.2.20",
            trusted_proxy_header="X-Forwarded-For",
            trusted_proxy_sources=("192.0.2.10", "192.0.2.20"),
        )
        all_trusted = resolve_client_ip(
            "192.0.2.10",
            "192.0.2.20",
            trusted_proxy_header="X-Forwarded-For",
            trusted_proxy_sources=("192.0.2.10", "192.0.2.20"),
        )
        spoofed = resolve_client_ip(
            "192.0.2.99",
            "198.51.100.99, 203.0.113.50",
            trusted_proxy_header="X-Forwarded-For",
            trusted_proxy_sources=("192.0.2.10",),
        )
        self.assertEqual(expected, "203.0.113.50")
        self.assertEqual(single_hop, "203.0.113.50")
        self.assertEqual(malformed, "192.0.2.10")
        self.assertEqual(trusted_chain, "198.51.100.25")
        self.assertEqual(all_trusted, "192.0.2.10")
        self.assertEqual(spoofed, "192.0.2.99")


if __name__ == "__main__":
    unittest.main()
