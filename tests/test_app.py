from __future__ import annotations

import http.client
import hashlib
import io
import inspect
import json
import re
import tempfile
import threading
import time
import unittest
import urllib.parse
import zipfile
import base64
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from app import AppContext, DashboardHandler, DashboardServer, RedirectHandler, container_image_target, resolve_client_ip, service_health_snapshot
from config import RuntimeConfig
from routeros import RouterOSClient, RouterOSCredentials, RouterOSError
from security import LoginRateLimiter, SessionStore
from store import MetadataStore
from templates import evaluate_device_posture
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


class DevicePostureTests(unittest.TestCase):
    def test_posture_requires_present_non_revoked_certificate_from_current_ca(self) -> None:
        devices = [
            {"id": "approved", "certificate_name": "client-current"},
            {"id": "missing", "certificate_name": "client-missing"},
            {"id": "revoked", "certificate_name": "client-revoked"},
            {"id": "legacy", "certificate_name": "client-legacy"},
            {"id": "unknown-issuer", "certificate_name": "client-unknown"},
        ]
        certificates = [
            {"name": "client-current", "certificate_authority": "vpn-ca", "revoked": False, "invalid_after": "2035-08-03 00:00:00"},
            {"name": "client-revoked", "certificate_authority": "vpn-ca", "revoked": True},
            {"name": "client-legacy", "certificate_authority": "old-ca", "revoked": False},
            {"name": "client-unknown", "revoked": False},
        ]

        result = evaluate_device_posture(devices, certificates, "vpn-ca")

        self.assertEqual([item["state"] for item in result], ["approved", "warning", "revoked", "warning", "warning"])
        self.assertEqual(result[0]["label"], "Inventory match")
        self.assertIn("not present", result[1]["reason"])
        self.assertIn("revoked", result[2]["reason"])
        self.assertIn("old-ca", result[3]["reason"])
        self.assertIn("unknown CA", result[4]["reason"])

    def test_posture_marks_expired_expiring_and_unknown_certificates_for_review(self) -> None:
        now = int(time.mktime(time.strptime("2030-01-01 00:00:00", "%Y-%m-%d %H:%M:%S")))
        devices = [
            {"id": "expired", "certificate_name": "expired-cert"},
            {"id": "soon", "certificate_name": "soon-cert"},
            {"id": "unknown", "certificate_name": "unknown-cert"},
            {"id": "valid", "certificate_name": "valid-cert"},
        ]
        certificates = [
            {"name": "expired-cert", "certificate_authority": "vpn-ca", "revoked": False, "invalid_after": "2029-12-31 23:59:59"},
            {"name": "soon-cert", "certificate_authority": "vpn-ca", "revoked": False, "invalid_after": "2030-01-15 00:00:00"},
            {"name": "unknown-cert", "certificate_authority": "vpn-ca", "revoked": False},
            {"name": "valid-cert", "certificate_authority": "vpn-ca", "revoked": False, "invalid_after": "2031-01-01 00:00:00"},
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

    def login(self) -> None:
        body = urllib.parse.urlencode({"username": "admin", "password": "routerpass"}).encode()
        status, headers, _ = self.request(
            "POST",
            "/login",
            body=body,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        self.assertEqual(status, 303)
        self.assertEqual(headers["location"], "/dashboard")
        set_cookie = headers["set-cookie"]
        self.assertIn("Secure", set_cookie)
        self.assertIn("HttpOnly", set_cookie)
        self.assertIn("SameSite=Strict", set_cookie)
        self.cookie = set_cookie.split(";", 1)[0]

        status, headers, page = self.request("GET", "/dashboard")
        self.assertEqual(status, 200)
        self.assertIn("default-src 'self'", headers["content-security-policy"])
        self.assertEqual(headers["x-content-type-options"], "nosniff")
        match = re.search(rb'<meta name="csrf-token" content="([^"]+)">', page)
        self.assertIsNotNone(match)
        self.csrf = match.group(1).decode("ascii")

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
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/suspend/preview",
        )
        self.assertEqual(status, 200)
        return json.loads(payload)

    def preview_profile(
        self, user_id: str, device_name: str, *, delivery: str = "zip", legacy_certificate: str = "",
    ) -> dict[str, Any]:
        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_id, safe='*')}/profiles/preview",
            {"device_name": device_name, "delivery": delivery, "legacy_certificate": legacy_certificate},
        )
        self.assertEqual(status, 200, payload.decode("utf-8"))
        return json.loads(payload)

    def test_sse_stops_emitting_when_server_session_is_revoked(self) -> None:
        self.login()
        session_id = self.cookie.split("=", 1)[1]
        connection = http.client.HTTPConnection("127.0.0.1", self.server.server_port, timeout=5)

        def revoke_after_first_event(_seconds: float) -> None:
            self.server.context.sessions.destroy(session_id)

        with mock.patch("app.time.sleep", side_effect=revoke_after_first_event):
            connection.request("GET", "/api/events", headers={"Cookie": self.cookie})
            response = connection.getresponse()
            self.assertEqual(response.status, 200)
            body = response.read()
        connection.close()

        self.assertEqual(body.count(b"event: status"), 1)

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
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/preview", {"user_ids": [target["id"]]},
        )
        self.assertEqual(status, 200)
        return path, target["id"], json.loads(payload)

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
            headers={"Content-Type": "application/x-www-form-urlencoded"},
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

        self.assertIn(b"not a complete RouterOS telemetry timeline", page)
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
        self.assertIn(b"Per-device revocation needs CA migration", page)

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
        self.assertEqual(health["overall"], "warning")
        self.assertEqual(
            {item["id"] for item in health["checks"]},
            {"routeros-rest", "dashboard-storage", "openvpn-service", "profile-issuing", "certificate-revocation", "certificate-inventory", "router-capacity"},
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
                "image": "ghcr.io/example/mikrotik-openvpn-gui:sha-" + "a" * 40 + "-arm64",
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
                "image": "ghcr.io/example/mikrotik-openvpn-gui:sha-" + "a" * 40 + "-arm64",
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
        self.assertIn(b"user-two", payload)

        status, headers, payload = self.request("GET", "/api/usage.csv")
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "text/csv; charset=utf-8")
        self.assertIn("vpn-monthly-usage.csv", headers["content-disposition"])
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

    def test_sensitive_route_matrix_fails_closed_for_anonymous_requests(self) -> None:
        """Cover route dispatch auth gates independently of individual handler tests."""
        read_routes = (
            "/api/telemetry", "/api/admin/sessions", "/api/admin/api-tokens",
            "/api/reports/compliance.zip", "/api/reports/diagnostics.zip",
            "/api/release/verify", "/api/policy-templates", "/api/users",
            "/api/bulk/views", "/api/status", "/api/service-health",
            "/api/observability", "/api/setup-preflight", "/api/audit.csv",
            "/api/audit.json", "/api/backups/metadata.zip", "/api/connections.csv",
            "/api/usage.csv", "/metrics", "/api/events",
        )
        write_routes = (
            "/api/users", "/api/users/test-user/preview", "/api/bulk/preview",
            "/api/bulk/apply", "/api/bulk/views", "/api/setup-plan",
            "/api/openvpn-foundation-plan", "/api/admin/api-tokens",
            "/api/admin/break-glass/plan", "/api/network/segment-plan",
            "/api/profile/diagnose", "/api/connection-doctor",
            "/api/security/exposure-doctor", "/api/backups/preflight",
            "/api/backups/validate", "/api/backups/restore-plan",
            "/api/policy-templates", "/api/policy-templates/test/preview",
            "/api/policy-templates/test/apply", "/api/users/test-user/suspend",
            "/api/users/test-user/restore", "/api/users/test-user/suspend/preview",
            "/api/users/test-user/profiles", "/api/users/test-user/profiles/preview",
            "/api/devices/test-device/revoke/preview", "/api/devices/test-device/revoke",
            "/api/users/test-user/duplicate", "/api/alerts/1/ack",
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
        session = self.server.context.sessions.create(
            "viewer", "routerpass", role="read_only", source_address="127.0.0.1",
        )
        cookie = f"vpn_session={session.session_id}"
        csrf_headers = {
            "Content-Type": "application/json",
            "Cookie": cookie,
            "X-CSRF-Token": session.csrf_token,
        }
        before_mutations = list(self.mock.state.mutation_requests)

        for path in ("/api/admin/api-tokens", "/api/audit.csv", "/api/audit.json"):
            with self.subTest(method="GET", path=path):
                status, _, payload = self.request("GET", path, headers={"Cookie": cookie})
                self.assertEqual(status, 403)
                self.assertNotIn(b"routerpass", payload)

        for path in (
            "/api/users", "/api/policy-templates", "/api/users/test-user/profiles",
            "/api/users/test-user/profiles/preview",
            "/api/devices/test-device/revoke/preview", "/api/admin/api-tokens",
        ):
            with self.subTest(method="POST", path=path):
                status, _, payload = self.request(
                    "POST", path, body=b"{}", headers=csrf_headers,
                )
                self.assertEqual(status, 403)
                self.assertNotIn(b"routerpass", payload)

        self.assertEqual(self.mock.state.mutation_requests, before_mutations)

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
        self.assertIn(b"vpn_dashboard_integration_outbox_pending", payload)
        self.assertIn(b"vpn_dashboard_integration_outbox_dead_lettered", payload)
        self.assertIn(b"vpn_dashboard_redis_last_observed_available", payload)
        self.assertIn(b"vpn_dashboard_sqlite_file_bytes", payload)
        self.assertIn(b"vpn_dashboard_sqlite_volume_free_bytes", payload)
        self.assertIn(b'vpn_dashboard_telemetry_gateway_events_total{outcome="snapshot_recovery"}', payload)
        self.assertIn(b"vpn_dashboard_telemetry_gateway_rejected_clients_total", payload)
        self.assertIn(b"vpn_dashboard_telemetry_session_event_age_seconds", payload)
        self.assertIn(b"vpn_dashboard_telemetry_traffic_sample_age_seconds", payload)
        self.assertIn(b"vpn_dashboard_telemetry_session_events_total", payload)
        self.assertIn(b"vpn_dashboard_telemetry_traffic_samples_total", payload)
        self.assertIn(b"vpn_dashboard_telemetry_traffic_sample_age_seconds -1", payload)
        self.assertNotIn(b"routerpass", payload)
        self.assertNotIn(sensitive_target.encode(), payload)

        status, _, payload = self.json_request(
            "POST", "/api/admin/api-tokens",
            {"label": "metrics export", "scopes": ["health.read", "audit.read", "sessions.read"], "expires_in": "1h"},
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

        status, _, payload = self.request("GET", "/api/reports/compliance.zip")
        self.assertEqual(status, 200)
        with zipfile.ZipFile(io.BytesIO(payload)) as archive:
            self.assertEqual(set(archive.namelist()), {"summary.json", "audit.csv", "connections.csv"})
            self.assertNotIn(b"routerpass", archive.read("summary.json"))

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
            "GET", "/api/release/verify?image=ghcr.io/example/mikrotik-openvpn-gui:sha-0123456789abcdef0123456789abcdef01234567&revision=0123456789abcdef0123456789abcdef01234567",
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["verified"])
        status, _, payload = self.request(
            "GET", "/api/release/verify?image=ghcr.io/example/mikrotik-openvpn-gui:sha-0123456789abcdef0123456789abcdef012345670123456789abcdef01234567&revision=0123456789abcdef0123456789abcdef01234567",
        )
        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["verified"])

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
        self.assertEqual(exposure_checks["firewall-boundary"]["status"], "unknown")
        self.assertNotIn(b"admin", payload)
        self.assertNotIn(b"routerpass", payload)
        self.assertNotIn(b"172.31.250.0/24", payload)
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

    def test_auth_audit_events_are_detailed_but_secret_free(self) -> None:
        bad_login = urllib.parse.urlencode({"username": "admin", "password": "wrong"}).encode()
        self.request(
            "POST", "/login", body=bad_login,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        failed = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(failed["action"], "login.failure")
        self.assertIn("auth_method", failed["details"])
        self.assertNotIn("wrong", failed["details"])

        self.login()
        actions = [item["action"] for item in self.server.context.store.recent_audit(10)]
        self.assertIn("login", actions)
        self.assertIn("role.assigned", actions)
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

    def test_setup_plan_accepts_ipv6_without_materialising_the_network(self) -> None:
        self.login()
        payload = {
            "origin": "https://dashboard.example.test",
            "image": "ghcr.io/example/mikrotik-openvpn-gui:sha-" + "a" * 40 + "-arm64",
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
            certificate_settings=None,
            certificates=None,
            config=self.config,
            database_ready=False,
            unavailable_reason="router",
        )
        self.assertEqual(health["overall"], "unavailable")
        self.assertEqual(health["checks"][0]["id"], "routeros-rest")
        self.assertNotIn("routerpass", json.dumps(health))

    def test_service_health_persists_certificate_expiry_alerts(self) -> None:
        """A soon-to-expire RouterOS certificate becomes a durable dashboard alert."""
        self.login()
        # Keep the fixture in the warning window regardless of when CI runs.
        self.mock.state.certificates["*CL1"]["invalid-after"] = time.strftime(
            "%Y-%m-%d %H:%M:%S", time.localtime(time.time() + (7 * 86400))
        )
        status, _, payload = self.request("GET", "/api/service-health")
        self.assertEqual(status, 200)
        self.assertIn("certificate-inventory", {item["id"] for item in json.loads(payload)["checks"]})
        alerts = self.server.context.store.recent_alerts()
        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0]["action"], "certificate.expiring")
        self.assertIn("ovpn-user-one-device-a", alerts[0]["details"])
        # Repeated five-second polls are deduplicated by the metadata store.
        self.request("GET", "/api/service-health")
        self.assertEqual(len(self.server.context.store.recent_alerts()), 1)

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

        status, headers, profile = self.json_request(
            "POST",
            "/api/users",
            {
                "username": "maria",
                "email": "maria@example.com",
                "password": "profile-pass",
                "device_name": "Tablet test",
                "comment": "integration test",
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/x-openvpn-profile")
        self.assertIn('filename="maria-Tablet-test.ovpn"', headers["content-disposition"])
        self.assertIn(b"redirect-gateway def1", profile)
        self.assertIn(b"<key>", profile)
        self.assertNotIn(b"profile-pass", profile)

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
            {"device_name": "Tablet", "key_passphrase": "tablet-passphrase", "delivery": "ovpn", "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 200)
        self.assertNotIn(b"tablet-passphrase", second_profile)
        self.assertNotIn(b"redirect-gateway def1", second_profile)
        self.assertIn(b"dhcp-option DNS 1.1.1.1", second_profile)
        self.assertEqual(len(self.server.context.store.devices_for_user("maria")), 2)

        status, _, payload = self.json_request(
            "DELETE", f"/api/users/{urllib.parse.quote(maria_id, safe='*')}",
            {"confirmation": "not-maria"},
        )
        self.assertEqual(status, 400)
        self.assertIn("exact target name", json.loads(payload)["error"])
        self.assertIn("maria", [item["name"] for item in self.mock.state.users.values()])

        status, _, payload = self.json_request(
            "DELETE", f"/api/users/{urllib.parse.quote(maria_id, safe='*')}",
            {"confirmation": "maria"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(
            json.loads(payload),
            {"ok": True, "verified": True, "retired_devices": 2},
        )
        self.assertNotIn("maria", [item["name"] for item in self.mock.state.users.values()])
        self.assertNotIn("maria", self.server.context.store.user_emails())
        self.assertEqual(
            set(self.mock.state.certificates), {"*CA", "*CL1", "*CL2", "*C1", "*C2"}
        )
        self.assertTrue(self.mock.state.certificates["*CA"].get("revoked") in (None, "no"))
        self.assertTrue(all(self.mock.state.certificates[item]["revoked"] for item in ("*C1", "*C2")))
        self.assertTrue(all(item["revoked_at"] for item in self.server.context.store.devices_for_user("maria", include_revoked=True)))

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
                {"device_name": "Recovery phone", "key_passphrase": "private-file-passphrase", "delivery": "zip", "review_token": preview["review_token"]},
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
                {"device_name": "Uncertain phone", "key_passphrase": "private-file-passphrase", "delivery": "zip", "review_token": preview["review_token"]},
            )

        response = json.loads(payload)
        self.assertEqual(status, 502)
        self.assertEqual(response["recovery"], "unknown")
        self.assertIn("before retrying", response["error"])
        self.assertNotIn(b"private-file-passphrase", payload)
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "unknown")
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["action"], "profile.create.recovery")

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
                "device_name": "Reviewed tablet", "key_passphrase": "private-file-passphrase",
                "delivery": "zip", "review_token": preview["review_token"],
            },
        )
        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertNotIn(b"private-file-passphrase", payload)
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(set(self.mock.state.certificates), {"*CA", "*CL1", "*CL2"})

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
            {"device_name": "QR phone", "key_passphrase": "qr-passphrase", "delivery": "qr", "review_token": preview["review_token"]},
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
                "device_name": "QR phone", "key_passphrase": "qr-passphrase", "delivery": "qr",
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
        self.assertIn(b"Certificate migration", page)
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
                "device_name": "Replacement phone", "key_passphrase": "replacement-passphrase",
                "legacy_certificate": "legacy-user-one-phone", "delivery": "ovpn",
                "review_token": preview["review_token"],
            },
        )
        self.assertEqual(status, 200)
        self.assertIn(b"BEGIN CERTIFICATE", payload)
        migration = self.server.context.store.profile_migrations()["legacy-user-one-phone"]
        self.assertEqual(migration["vpn_user"], "user-one")
        self.assertIn("legacy-user-one-phone", [
            item["name"] for item in self.server.context.router.list_ovpn_client_certificates(
                RouterOSCredentials("admin", "routerpass"), include_legacy=True
            )
        ])

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
            {"device_name": "Blocked device", "delivery": "ovpn"},
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
        self.assertIn("function renderAlerts(alerts = [])", script)
        self.assertIn("history.dataset.renderKey", script)
        self.assertIn("panel.dataset.renderKey", script)
        self.assertIn("deploymentBody.dataset.renderKey", script)
        self.assertIn("timeline.dataset.renderKey", script)
        update_block = script.split("function updateDashboard(payload)", 1)[1].split("async function pollStatus()", 1)[0]
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

        status, headers, profile = self.json_request(
            "POST",
            f"/api/users/{urllib.parse.quote(user_one_id, safe='*')}/duplicate",
            {
                "username": "user-one-copy",
                "email": "user.one.copy@example.test",
                "password": "duplicate-pass",
                "device_name": "Backup phone",
                "comment": "Copied access",
            },
        )
        self.assertEqual(status, 200)
        self.assertIn('filename="user-one-copy-Backup-phone.ovpn"', headers["content-disposition"])
        self.assertIn(b"<cert>", profile)
        self.assertIn("user-one-copy", [item["name"] for item in self.mock.state.users.values()])
        self.assertEqual(
            self.server.context.store.user_emails()["user-one-copy"],
            "user.one.copy@example.test",
        )

        session_id = next(iter(self.mock.state.active_sessions))
        status, _, _ = self.json_request(
            "DELETE", f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}", csrf=False
        )
        self.assertEqual(status, 403)
        self.assertIn(session_id, self.mock.state.active_sessions)

        status, _, payload = self.json_request(
            "DELETE", f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}",
            {"confirmation": "user-two"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"ok": True, "verified": True})
        self.assertNotIn(session_id, self.mock.state.active_sessions)
        self.assertIn(
            "session.terminate",
            [item["action"] for item in self.server.context.store.recent_audit()],
        )

    def test_session_termination_is_not_reported_successful_while_router_still_shows_it(self) -> None:
        self.login()
        session_id = next(iter(self.mock.state.active_sessions))
        with mock.patch.object(self.server.context.router, "terminate_session"):
            status, _, payload = self.json_request(
                "DELETE",
                f"/api/sessions/{urllib.parse.quote(session_id, safe='*')}",
                {"confirmation": "user-two"},
            )

        self.assertEqual(status, 409)
        response = json.loads(payload)
        self.assertEqual(response["code"], "routeros.mutation_verification_failed")
        self.assertFalse(response["verified"])
        self.assertIn(session_id, self.mock.state.active_sessions)
        latest = self.server.context.store.recent_audit(1)[0]
        self.assertEqual(latest["action"], "session.terminate")
        self.assertEqual(latest["status"], "failed")

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
        self.assertEqual(self.server.context.store.recent_audit(1)[0]["status"], "success")

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
        router = self.server.context.router
        with mock.patch.object(
            router, "revoke_certificate", side_effect=RouterOSError("private detail", 503)
        ):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", {"confirmation": "user-one"}
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

    def test_user_delete_reconciles_lost_certificate_revocation_response(self) -> None:
        self._managed_device_revoke_request()
        router = self.server.context.router
        revoke_certificate = router.revoke_certificate

        def revoke_then_lose_response(credentials: Any, *, certificate_id: str) -> None:
            revoke_certificate(credentials, certificate_id=certificate_id)
            raise RouterOSError("private detail", 503)

        with mock.patch.object(router, "revoke_certificate", side_effect=revoke_then_lose_response):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", {"confirmation": "user-one"}
            )

        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["verified"])
        self.assertNotIn("*1", self.mock.state.users)
        self.assertTrue(self.mock.state.certificates["*CL1"]["revoked"])

    def test_user_delete_retains_local_metadata_when_routeros_user_remains(self) -> None:
        self._managed_device_revoke_request()
        router = self.server.context.router
        with mock.patch.object(router, "delete_user"):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", {"confirmation": "user-one"}
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
        router = self.server.context.router
        delete_user = router.delete_user

        def delete_then_lose_response(credentials: Any, *, user_id: str) -> None:
            delete_user(credentials, user_id=user_id)
            raise RouterOSError("private detail", 503)

        with mock.patch.object(router, "delete_user", side_effect=delete_then_lose_response):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", {"confirmation": "user-one"}
            )

        self.assertEqual(status, 200)
        self.assertTrue(json.loads(payload)["verified"])
        self.assertNotIn("*1", self.mock.state.users)

    def test_user_delete_preserves_account_when_certificate_readback_is_unavailable(self) -> None:
        self._managed_device_revoke_request()
        router = self.server.context.router

        def unavailable_readback(*args: Any, **kwargs: Any) -> list[dict[str, Any]]:
            raise RouterOSError("private router detail", 503)

        with mock.patch.object(
            router, "list_ovpn_client_certificates", side_effect=unavailable_readback
        ):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", {"confirmation": "user-one"}
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
        router = self.server.context.router
        list_users = router.list_ovpn_users

        def fail_only_after_delete(credentials: Any) -> list[dict[str, Any]]:
            if "*1" not in self.mock.state.users:
                raise RouterOSError("private router detail", 503)
            return list_users(credentials)

        with mock.patch.object(router, "list_ovpn_users", side_effect=fail_only_after_delete):
            status, _, payload = self.json_request(
                "DELETE", "/api/users/%2A1", {"confirmation": "user-one"}
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
                {"confirmation": "user-two"},
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
            {"confirmation": "user-two", "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertTrue(result["disabled"])
        self.assertEqual(result["disconnected"], 1)
        self.assertEqual(result["remaining"], 0)
        self.assertFalse(self.mock.state.active_sessions)
        disabled = next(item for item in self.mock.state.users.values() if item["name"] == "user-two")
        self.assertEqual(disabled["disabled"], "yes")
        self.assertIsNotNone(self.server.context.store.recent_connections(1)[0]["disconnected_at"])

        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_two_id, safe='*')}/restore"
        )
        self.assertEqual(status, 200)
        self.assertFalse(json.loads(payload)["disabled"])
        restored = next(item for item in self.mock.state.users.values() if item["name"] == "user-two")
        self.assertEqual(restored["disabled"], "no")
        actions = [item["action"] for item in self.server.context.store.recent_audit(10)]
        self.assertIn("user.suspend", actions)
        self.assertIn("user.restore", actions)

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
            {"confirmation": "user-two", "review_token": preview["review_token"]},
        )

        self.assertEqual(status, 409)
        self.assertEqual(json.loads(payload)["code"], "routeros.review_stale")
        self.assertEqual(self.mock.state.mutation_requests, before_mutations)
        self.assertEqual(self.mock.state.users[user["id"]]["disabled"], "no")

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
                {"confirmation": "user-two", "review_token": preview["review_token"]},
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
                {"confirmation": "user-two", "review_token": preview["review_token"]},
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
                {"confirmation": "user-two", "review_token": preview["review_token"]},
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
            {"action": "tag", "user_ids": selected, "tag": "Field Team", "confirmation": "wrong"},
        )
        self.assertEqual(status, 400)
        self.assertIn("exact target name", json.loads(payload)["error"])

        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {"action": "tag", "user_ids": selected, "tag": "Field Team", "confirmation": "APPLY TAG TO 2 USERS"},
        )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertEqual(result["status"], "success")
        self.assertEqual({self.server.context.store.user_tags(name)[0] for name in users}, {"Field Team"})

        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {"action": "tag", "user_ids": selected, "tag": "Field Team", "confirmation": "APPLY TAG TO 2 USERS"},
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
            "POST", "/api/bulk/preview", {"action": "suspend", "user_ids": selected},
        )
        self.assertEqual(status, 200)
        preview = json.loads(payload)
        self.assertEqual({item["state"] for item in preview["users"]}, {"will_suspend"})
        self.assertEqual(next(item for item in preview["users"] if item["username"] == "user-two")["active_sessions"], 1)

        status, _, payload = self.json_request(
            "POST", "/api/bulk/apply",
            {"action": "suspend", "user_ids": selected, "confirmation": "APPLY SUSPEND TO 2 USERS"},
        )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertEqual(result["status"], "success")
        self.assertEqual(next(item for item in result["outcomes"] if item["username"] == "user-two")["disconnected"], 1)
        self.assertEqual({item["status"] for item in result["outcomes"]}, {"verified"})
        self.assertFalse(self.mock.state.active_sessions)
        self.assertTrue(all(item["disabled"] == "yes" for item in self.mock.state.users.values()))

    def test_bulk_suspend_reconciles_lost_mutation_response_by_user_readback(self) -> None:
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

        with mock.patch.object(router, "update_user", side_effect=update_then_lose_response):
            status, _, payload = self.json_request(
                "POST", "/api/bulk/apply",
                {
                    "action": "suspend", "user_ids": [user["id"]],
                    "confirmation": "APPLY SUSPEND TO 1 USERS",
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
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/preview", {"user_ids": [target["id"]]},
        )
        self.assertEqual(status, 200)
        preview = json.loads(payload)
        self.assertIn("rate_limit_kbps", preview["users"][0]["changes"])
        self.assertTrue(preview["review_token"])

        # Direct apply without a server-issued preview receipt is rejected.
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/apply", {"user_ids": [target["id"]]},
        )
        self.assertEqual(status, 409)
        self.assertIn("Preview the selected users again", json.loads(payload)["error"])

        # A live RouterOS profile edit between review and apply also invalidates it.
        original_profile = self.mock.state.users[target["id"]]["profile"]
        self.mock.state.users[target["id"]]["profile"] = "manual-router-change"
        status, _, _ = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/apply",
            {"user_ids": [target["id"]], "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 409)
        self.mock.state.users[target["id"]]["profile"] = original_profile

        # Reusing the receipt with a different selection cannot apply an unreviewed user.
        other = next(item for item in users if item["id"] != target["id"])
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/apply",
            {"user_ids": [target["id"], other["id"]], "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 409)
        self.assertNotIn("user-one", self.server.context.store.user_template_assignments())

        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/apply",
            {"user_ids": [target["id"]], "review_token": preview["review_token"]},
        )
        self.assertEqual(status, 200)
        result = json.loads(payload)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(result["applied"], ["user-one"])
        self.assertEqual(result["outcomes"], [{"username": "user-one", "status": "verified"}])
        self.assertEqual(self.server.context.store.user_controls("user-one")["rate_limit_kbps"], 10240)
        self.assertEqual(self.server.context.store.user_template_assignments()["user-one"]["template_id"], template["id"])
        self.assertIn("policy_template.apply", [item["action"] for item in self.server.context.store.recent_audit(10)])

        # A state change after preview invalidates that review before checkpoint/apply.
        current = self.server.context.store.user_controls("user-one")
        self.server.context.store.set_user_controls(
            "user-one", policy=current["policy"], expires_at=current["expires_at"],
            max_sessions=current["max_sessions"], rate_limit_kbps=2048,
            dns_mode=current["dns_mode"], notifications=current["notifications"],
            quota_mb=current["quota_mb"], schedule=current["schedule"],
        )
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/preview", {"user_ids": [target["id"]]},
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
            {"user_ids": [target["id"]], "review_token": stale_review},
        )
        self.assertEqual(status, 409)
        self.assertEqual(self.server.context.store.user_controls("user-one")["rate_limit_kbps"], 4096)

    def test_policy_template_apply_reports_router_failure_and_readback_unknown(self) -> None:
        self.login()
        path, user_id, preview = self._policy_template_review()
        with mock.patch.object(self.server.context.router, "update_user", side_effect=RouterOSError("router rejected update")):
            status, _, payload = self.json_request(
                "POST", path, {"user_ids": [user_id], "review_token": preview["review_token"]},
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
                "POST", path, {"user_ids": [user_id], "review_token": preview["review_token"]},
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
                "POST", path, {"user_ids": [user_id], "review_token": preview["review_token"]},
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
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2)
class ProxyTrustTests(unittest.TestCase):
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
        self.assertEqual(expected, "2001:db8::1")
        self.assertEqual(spoofed, "198.51.100.50")
        self.assertEqual(invalid, "192.0.2.1")

    def test_direct_proxy_honors_only_first_x_forwarded_for_from_exact_peer(self) -> None:
        expected = resolve_client_ip(
            "192.0.2.10",
            "203.0.113.50, 192.0.2.200",
            trusted_proxy_header="X-Forwarded-For",
            trusted_proxy_sources=("192.0.2.10",),
        )
        spoofed = resolve_client_ip(
            "192.0.2.99",
            "203.0.113.50",
            trusted_proxy_header="X-Forwarded-For",
            trusted_proxy_sources=("192.0.2.10",),
        )
        self.assertEqual(expected, "203.0.113.50")
        self.assertEqual(spoofed, "192.0.2.99")


if __name__ == "__main__":
    unittest.main()
