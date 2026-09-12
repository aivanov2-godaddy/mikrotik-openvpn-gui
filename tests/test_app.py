from __future__ import annotations

import http.client
import base64
import hashlib
import io
import json
import re
import tempfile
import threading
import unittest
import urllib.parse
import zipfile
from http.server import ThreadingHTTPServer
from pathlib import Path
from typing import Any
from unittest import mock

from app import AppContext, DashboardHandler, DashboardServer, RedirectHandler, container_image_target, resolve_client_ip, service_health_snapshot
from config import RuntimeConfig
from routeros import RouterOSClient, RouterOSCredentials
from security import LoginRateLimiter, SessionStore
from store import MetadataStore
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
        self.assertIn(b"data-rx-packets=\"387\"", page)
        self.assertIn(b"router.example.test", page)
        self.assertNotIn(b">Session</span>", page)
        self.assertNotIn(b"New Terminal", page)
        self.assertNotIn(b"Workspace:", page)
        self.assertIn(b'data-view="vpn-users"', page)
        self.assertIn(b'data-view="live-sessions"', page)
        self.assertIn(b'data-view="profile-security"', page)
        self.assertIn(b'data-view="service-health"', page)
        self.assertIn(b'data-view="audit-log"', page)
        self.assertIn(b"Change History", page)
        self.assertIn(b"What changed", page)
        self.assertIn(b"Service health", page)
        self.assertIn(b"Profile issuing prerequisites", page)
        self.assertIn(b"1d 06:12:00s", page)
        self.assertIn(b"Security posture", page)
        self.assertIn(b"Connection history", page)
        self.assertIn(b"RouterOS certificate inventory", page)
        self.assertIn(b"Per-device revocation needs CA migration", page)
        self.assertIn(b"ovpn-user-one-device-a", page)
        self.assertIn(b"What happens under the hood", page)
        self.assertIn(b"OpenVPN foundations", page)
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
        self.assertEqual(snapshot["sessions"][0]["tx_packets"], 825)
        self.assertEqual(snapshot["router"]["cpu-load"], "7")

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
        self.assertIn("REVIEW ONLY", json.loads(payload)["plan"])

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
            "POST", "/api/backups/preflight",
            {"manifest": manifest, "metadata_sha256": "0" * 64},
        )
        self.assertEqual(status, 400)
        self.assertFalse(json.loads(payload)["compatible"])

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

        status, _, payload = self.json_request(
            "PATCH",
            f"/api/users/{urllib.parse.quote(maria_id, safe='*')}",
            {
                "email": "maria.new@example.com", "comment": "changed", "disabled": True,
                "password": "new-profile-pass", "policy": "lan-only", "expiry": "1d",
                "max_sessions": "2", "rate_limit_kbps": "25600", "quota_mb": "10240",
                "schedule": "weekdays", "dns_mode": "cloudflare",
                "notifications": True,
            },
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload), {"ok": True})
        self.assertEqual(self.server.context.store.user_emails()["maria"], "maria.new@example.com")
        controls = self.server.context.store.user_controls("maria")
        self.assertEqual(controls["policy"], "lan-only")
        self.assertEqual(controls["rate_limit_kbps"], 25600)
        self.assertEqual(controls["quota_mb"], 10240)
        self.assertEqual(controls["schedule"], "weekdays")
        self.assertEqual(self.mock.state.users[maria_id]["profile"], "vpn-ui-maria")

        status, _, second_profile = self.json_request(
            "POST",
            f"/api/users/{urllib.parse.quote(maria_id, safe='*')}/profiles",
            {"device_name": "Tablet", "key_passphrase": "tablet-passphrase"},
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
        self.assertEqual(json.loads(payload), {"ok": True})
        self.assertNotIn("maria", [item["name"] for item in self.mock.state.users.values()])
        self.assertNotIn("maria", self.server.context.store.user_emails())
        self.assertEqual(set(self.mock.state.certificates), {"*CA", "*CL1", "*CL2"})
        self.assertTrue(all(item["revoked_at"] for item in self.server.context.store.devices_for_user("maria", include_revoked=True)))

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
        status, headers, payload = self.json_request(
            "POST",
            path,
            {"device_name": "QR phone", "key_passphrase": "qr-passphrase", "delivery": "qr"},
        )
        self.assertEqual(status, 200)
        self.assertEqual(headers["content-type"], "application/json; charset=utf-8")
        response = json.loads(payload)
        self.assertTrue(response["download_url"].startswith("https://dashboard.example.test/share/"))
        self.assertIn("<svg", response["qr_svg"])
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
            f"/api/users/{urllib.parse.quote(user_one_id, safe='*')}/profiles",
            {"device_name": "Blocked device", "key_passphrase": "blocked-passphrase"},
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
        self.assertIn("function hasOpenDialog()", script)
        self.assertIn("function deferFreshData(reason)", script)
        update_block = script.split("function updateDashboard(payload)", 1)[1].split("async function pollStatus()", 1)[0]
        self.assertNotIn("location.reload()", update_block)
        self.assertEqual(update_block.count("deferFreshData("), 3)
        self.assertIn("data-full-refresh", script)

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
        self.assertEqual(json.loads(payload), {"ok": True})
        self.assertNotIn(session_id, self.mock.state.active_sessions)
        self.assertIn(
            "session.terminate",
            [item["action"] for item in self.server.context.store.recent_audit()],
        )

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

        status, _, payload = self.json_request(
            "POST", f"/api/users/{urllib.parse.quote(user_two_id, safe='*')}/suspend",
            {"confirmation": "user-two"},
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
        self.assertIn("rate_limit_kbps", json.loads(payload)["users"][0]["changes"])
        status, _, payload = self.json_request(
            "POST", f"/api/policy-templates/{template['id']}/apply", {"user_ids": [target["id"]]},
        )
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(payload)["applied"], ["user-one"])
        self.assertEqual(self.server.context.store.user_controls("user-one")["rate_limit_kbps"], 10240)
        self.assertEqual(self.server.context.store.user_template_assignments()["user-one"]["template_id"], template["id"])
        self.assertIn("policy_template.apply", [item["action"] for item in self.server.context.store.recent_audit(10)])


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
