from __future__ import annotations

import json
import unittest
from unittest.mock import patch

from config import OpenVPNTopology
from routeros import RouterOSClient, RouterOSCredentials, RouterOSError, harden_profile
from tests.mock_routeros import MockRouterOS


TEST_TOPOLOGY = OpenVPNTopology(
    ppp_profile="vpn-full-tunnel",
    server_name="vpn-server",
    ca_name="vpn-ca",
    host="vpn.example.test",
    server_identity="vpn.example.test",
    lan_cidr="192.0.2.0/24",
    router_dns="192.0.2.1",
)


class RouterOSClientTests(unittest.TestCase):
    def test_admin_role_lookup_fails_closed_for_unknown_disabled_or_unreadable_accounts(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            credentials = RouterOSCredentials("admin", "routerpass")
            self.assertEqual(client.get_admin_role(credentials), "owner")

            mock.state.admin_group = "read"
            self.assertEqual(client.get_admin_role(credentials), "read_only")
            self.assertIsNone(client.get_admin_role(RouterOSCredentials("missing", "routerpass")))

            mock.state.admin_group = "full"
            mock.state.admin_disabled = True
            self.assertIsNone(client.get_admin_role(credentials))

            mock.state.admin_disabled = False
            mock.state.admin_user_read_error = 403
            self.assertEqual(client.get_admin_role(credentials), "read_only")

    def test_admin_role_lookup_fails_closed_when_group_is_missing_or_empty(self) -> None:
        client = RouterOSClient("http://router.example.test", topology=TEST_TOPOLOGY)
        credentials = RouterOSCredentials("admin", "routerpass")
        for record in (
            {"name": "admin", "disabled": "no"},
            {"name": "admin", "group": "", "disabled": "no"},
            {"name": "admin", "group": None, "disabled": "no"},
        ):
            with self.subTest(record=record), patch.object(client, "_request", return_value=[record]):
                self.assertEqual(client.get_admin_role(credentials), "read_only")

    def test_rate_profile_change_requires_reviewed_state_and_exact_readback(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            credentials = RouterOSCredentials("admin", "routerpass")
            reviewed = client.rate_profile_snapshot(credentials, username="user-one")
            self.assertEqual(reviewed, {"exists": False})

            profile = client.ensure_rate_profile(
                credentials, username="user-one", rate_limit_kbps=10240,
                expected_state=reviewed,
            )
            self.assertEqual(profile, "vpn-ui-user-one")
            self.assertEqual(
                client.rate_profile_snapshot(credentials, username="user-one")["rate_limit"],
                "10240k/10240k",
            )

    def test_rate_profile_refuses_stale_state_before_mutation(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            credentials = RouterOSCredentials("admin", "routerpass")
            expected = {"exists": True, "id": "*P9", "rate_limit": "1k/1k"}
            with self.assertRaisesRegex(RouterOSError, "changed since it was reviewed"):
                client.ensure_rate_profile(
                    credentials, username="user-one", rate_limit_kbps=10240,
                    expected_state=expected,
                )
            self.assertFalse(mock.state.mutation_requests)

    def test_rate_profile_mismatch_after_write_is_not_reported_as_success(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            credentials = RouterOSCredentials("admin", "routerpass")
            with patch.object(
                client, "rate_profile_snapshot",
                side_effect=[
                    {"exists": False},
                    {"exists": True, "id": "*P1", "rate_limit": "1k/1k"},
                ],
            ):
                with self.assertRaisesRegex(RouterOSError, "could not be verified"):
                    client.ensure_rate_profile(
                        credentials, username="user-one", rate_limit_kbps=10240,
                        expected_state={"exists": False},
                    )

    def test_rate_profile_reconciles_lost_write_response_by_exact_readback(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            credentials = RouterOSCredentials("admin", "routerpass")
            request = client._request

            def commit_then_lose_response(method, path, *args, **kwargs):
                result = request(method, path, *args, **kwargs)
                if method == "PUT" and path == "/ppp/profile":
                    raise RouterOSError("private response-loss detail")
                return result

            with patch.object(client, "_request", side_effect=commit_then_lose_response):
                profile = client.ensure_rate_profile(
                    credentials, username="user-one", rate_limit_kbps=10240,
                    expected_state={"exists": False},
                )

            self.assertEqual(profile, "vpn-ui-user-one")
            self.assertEqual(
                client.rate_profile_snapshot(credentials, username="user-one")["rate_limit"],
                "10240k/10240k",
            )

    def test_management_exposure_uses_only_allowlisted_read_probes(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            snapshot = client.get_management_exposure(RouterOSCredentials("admin", "routerpass"))

        self.assertEqual(snapshot["account"]["name"], "admin")
        self.assertNotIn("password", snapshot["account"])
        self.assertEqual(set(snapshot["group"]), {"name", "policy"})
        self.assertTrue(all(set(service) <= {"name", "disabled", "address", "available-from", "certificate"} for service in snapshot["services"]))
        self.assertEqual({path for path, _ in mock.state.rest_reads}, {"/user", "/user/group", "/ip/service", "/user/active"})
        self.assertEqual(
            {path: query.get(".proplist") for path, query in mock.state.rest_reads},
            {"/user": ["name,group,disabled,address"], "/user/group": ["name,policy"],
             "/ip/service": ["name,disabled,available-from,address,certificate"],
             "/user/active": ["name,via,address"]},
        )
        self.assertEqual(snapshot["active_source"], "172.31.250.10")
        self.assertEqual(snapshot["rest_service"], "www")
        self.assertEqual(mock.state.mutation_requests, [])

    def test_management_exposure_falls_back_for_legacy_routeros_service_property(self) -> None:
        with MockRouterOS() as mock:
            mock.state.reject_available_from_service_property = True
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            snapshot = client.get_management_exposure(RouterOSCredentials("admin", "routerpass"))

        service_queries = [query[".proplist"][0] for path, query in mock.state.rest_reads if path == "/ip/service"]
        self.assertEqual(service_queries, [
            "name,disabled,available-from,address,certificate",
            "name,disabled,address,certificate",
        ])
        self.assertEqual(snapshot["source_status"]["services"], "verified")
        self.assertEqual(mock.state.mutation_requests, [])

    def test_management_exposure_keeps_current_service_property_allowlisted(self) -> None:
        with MockRouterOS() as mock:
            mock.state.ip_services = [
                {"name": "api-ssl", "disabled": "no", "available-from": "192.0.2.0/24", "certificate": "private-cert"},
            ]
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            snapshot = client.get_management_exposure(RouterOSCredentials("admin", "routerpass"))

        self.assertEqual(snapshot["services"], [
            {"name": "api-ssl", "disabled": "no", "available-from": "192.0.2.0/24", "certificate": "private-cert"},
        ])
        self.assertEqual(mock.state.mutation_requests, [])

    def test_management_exposure_marks_ambiguous_or_unsupported_active_source_unknown(self) -> None:
        with MockRouterOS() as mock:
            mock.state.active_router_users.append({
                "name": "admin", "via": "rest-api", "address": "203.0.113.77",
            })
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            ambiguous = client.get_management_exposure(RouterOSCredentials("admin", "routerpass"))
            self.assertIsNone(ambiguous["active_source"])
            self.assertEqual(ambiguous["active_source_status"], "unknown")

            mock.state.unsupported_active_router_users = True
            unsupported = client.get_management_exposure(RouterOSCredentials("admin", "routerpass"))

        self.assertIsNone(unsupported["active_source"])
        self.assertEqual(unsupported["active_source_status"], "unsupported")
        self.assertEqual(mock.state.mutation_requests, [])

    def test_management_exposure_rejects_non_ip_active_source(self) -> None:
        with MockRouterOS() as mock:
            mock.state.active_router_users = [{
                "name": "admin", "via": "rest-api", "address": "private-hostname",
            }]
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            snapshot = client.get_management_exposure(RouterOSCredentials("admin", "routerpass"))

        self.assertIsNone(snapshot["active_source"])
        self.assertEqual(snapshot["active_source_status"], "unknown")

    def test_missing_routeros_group_is_unknown_not_verified(self) -> None:
        with MockRouterOS() as mock:
            mock.state.user_groups = []
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            snapshot = client.get_management_exposure(RouterOSCredentials("admin", "routerpass"))

        self.assertIsNone(snapshot["group"])
        self.assertEqual(snapshot["source_status"]["group"], "unknown")
        self.assertEqual(mock.state.mutation_requests, [])

    def test_unsupported_management_service_endpoint_is_not_misreported(self) -> None:
        with MockRouterOS() as mock:
            mock.state.unsupported_management_services = True
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            snapshot = client.get_management_exposure(RouterOSCredentials("admin", "routerpass"))

        self.assertIsNone(snapshot["services"])
        self.assertEqual(snapshot["source_status"]["services"], "unsupported")
        self.assertEqual(mock.state.mutation_requests, [])

    def test_certificate_inventory_treats_revocation_timestamp_as_revoked(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            credentials = RouterOSCredentials("admin", "routerpass")
            mock.state.certificates["*CL1"]["revoked"] = "2026-09-15 12:34:56"

            certificates = client.list_ovpn_client_certificates(credentials)

        by_name = {item["name"]: item for item in certificates}
        self.assertTrue(by_name["ovpn-user-one-device-a"]["revoked"])
        self.assertFalse(by_name["ovpn-user-two-device-b"]["revoked"])

    def test_certificate_inventory_normalizes_revocation_forms_without_leaking_secrets(self) -> None:
        missing = object()
        cases = (
            ("timestamp", "2026-09-15 12:34:56", True),
            ("empty", "", False),
            ("no", "no", False),
            ("false string", "false", False),
            ("false boolean", False, False),
            ("null", None, False),
            ("zero string", "0", False),
            ("omitted", missing, False),
        )
        secret_markers = (
            "SYNTHETIC-PASSWORD-DO-NOT-LEAK",
            "SYNTHETIC-PRIVATE-KEY-DO-NOT-LEAK",
            "SYNTHETIC-PROFILE-DO-NOT-LEAK",
            "SYNTHETIC-TOKEN-DO-NOT-LEAK",
        )

        with MockRouterOS() as mock:
            template = mock.state.certificates["*CL1"]
            for index, (label, revoked, _) in enumerate(cases, start=1):
                record = dict(template)
                record[".id"] = f"*SYNTH{index}"
                record["name"] = f"synthetic-{label.replace(' ', '-')}"
                if revoked is missing:
                    record.pop("revoked", None)
                else:
                    record["revoked"] = revoked
                record.update({
                    "password": secret_markers[0],
                    "private-key": secret_markers[1],
                    "profile": secret_markers[2],
                    "token": secret_markers[3],
                })
                mock.state.certificates[record[".id"]] = record

            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            inventory = client.list_ovpn_client_certificates(
                RouterOSCredentials("admin", "routerpass")
            )

        by_name = {item["name"]: item for item in inventory}
        for label, _, expected in cases:
            with self.subTest(revoked_form=label):
                self.assertEqual(by_name[f"synthetic-{label.replace(' ', '-')}"]["revoked"], expected)

        serialized_inventory = json.dumps(inventory, sort_keys=True)
        for marker in secret_markers:
            self.assertNotIn(marker, serialized_inventory)
        self.assertTrue(all(
            set(item) == {
                "id", "name", "common_name", "fingerprint", "issuer",
                "certificate_authority", "invalid_after", "expires_after",
                "revoked", "trusted",
            }
            for item in inventory
        ))
        self.assertEqual(mock.state.mutation_requests, [])
        self.assertEqual(
            mock.state.rest_reads,
            [("/certificate", {
                ".proplist": [
                    ".id,name,common-name,fingerprint,issuer,invalid-after,"
                    "expires-after,revoked,key-usage,trusted,ca"
                ],
                "ca": ["vpn-ca"],
            })],
        )

    def test_certificate_inventory_handles_missing_identity_and_expiry_fields(self) -> None:
        with MockRouterOS() as mock:
            incomplete = dict(mock.state.certificates["*CL1"])
            for field in (
                ".id", "name", "common-name", "fingerprint", "issuer",
                "invalid-after", "expires-after", "ca",
            ):
                incomplete.pop(field, None)
            mock.state.certificates["*MISSING-FIELDS"] = incomplete

            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            inventory = client.list_ovpn_client_certificates(
                RouterOSCredentials("admin", "routerpass"), include_legacy=True
            )

        missing_fields = next(item for item in inventory if item["id"] == "")
        self.assertEqual(missing_fields["name"], "")
        self.assertEqual(missing_fields["common_name"], "")
        self.assertEqual(missing_fields["fingerprint"], "")
        self.assertEqual(missing_fields["issuer"], "")
        self.assertEqual(missing_fields["certificate_authority"], "")
        self.assertEqual(missing_fields["invalid_after"], "")
        self.assertEqual(missing_fields["expires_after"], "")
        self.assertEqual(mock.state.mutation_requests, [])

    def test_certificate_inventory_filters_ca_and_excludes_non_client_certificates(self) -> None:
        with MockRouterOS() as mock:
            legacy = dict(mock.state.certificates["*CL1"])
            legacy.update({".id": "*LEGACY", "name": "legacy-client", "ca": "old-ca"})
            mock.state.certificates[legacy[".id"]] = legacy

            server = dict(mock.state.certificates["*CL2"])
            server.update({".id": "*SERVER", "name": "server-certificate", "key-usage": "tls-server"})
            mock.state.certificates[server[".id"]] = server

            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            credentials = RouterOSCredentials("admin", "routerpass")
            current_only = client.list_ovpn_client_certificates(credentials)
            include_legacy = client.list_ovpn_client_certificates(credentials, include_legacy=True)

        self.assertEqual(
            [item["name"] for item in current_only],
            ["ovpn-user-one-device-a", "ovpn-user-two-device-b"],
        )
        self.assertEqual(
            [item["name"] for item in include_legacy],
            ["legacy-client", "ovpn-user-one-device-a", "ovpn-user-two-device-b"],
        )
        self.assertNotIn("server-certificate", {item["name"] for item in include_legacy})
        self.assertEqual(mock.state.certificate_queries[0].get("ca"), ["vpn-ca"])
        self.assertNotIn("ca", mock.state.certificate_queries[1])
        self.assertEqual(mock.state.mutation_requests, [])

    def test_certificate_inventory_errors_do_not_echo_routeros_error_details(self) -> None:
        secret_marker = "SYNTHETIC-PRIVATE-KEY-ERROR-DO-NOT-LEAK"
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            with patch.object(
                client,
                "_request",
                side_effect=RouterOSError(
                    f"RouterOS echoed {secret_marker}", 500, failure_kind="timeout",
                ),
            ):
                with self.assertRaises(RouterOSError) as raised:
                    client.list_ovpn_client_certificates(
                        RouterOSCredentials("admin", "routerpass")
                    )

        self.assertNotIn(secret_marker, str(raised.exception))
        self.assertNotIn("PRIVATE KEY", str(raised.exception))
        self.assertEqual(str(raised.exception), "RouterOS certificate inventory could not be read")
        self.assertEqual(raised.exception.status, 500)
        self.assertEqual(raised.exception.failure_kind, "timeout")
        self.assertEqual(mock.state.mutation_requests, [])

    def test_authentication_and_crud(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            credentials = RouterOSCredentials("admin", "routerpass")
            resource = client.verify_credentials(credentials)
            self.assertEqual(resource["architecture-name"], "arm64")
            inventory = client.get_bootstrap_inventory(credentials)
            self.assertEqual(inventory["resource"]["version"], "7.23.3")
            self.assertEqual(inventory["packages"][0]["name"], "container")
            self.assertEqual(inventory["ovpn_servers"][0]["name"], "vpn-server")
            self.assertEqual(inventory["ppp_profiles"][0]["name"], "vpn-full-tunnel")
            self.assertEqual(inventory["dns"][0]["servers"], "192.0.2.1")
            self.assertEqual(inventory["firewall"][0]["dst-port"], "1194")
            self.assertEqual(
                [user["name"] for user in client.list_ovpn_users(credentials)],
                ["user-one", "user-two"],
            )
            server = client.get_ovpn_server_status(credentials)
            self.assertTrue(server["enabled"])
            self.assertTrue(server["require_client_certificate"])
            self.assertEqual(server["cipher"], "aes256-gcm")
            self.assertEqual(server["redirect_gateway"], "def1")
            certificate_settings = client.get_certificate_settings(credentials)
            self.assertFalse(certificate_settings["crl_use"])
            self.assertFalse(certificate_settings["crl_ready"])
            mock.state.certificate_settings[0]["crl-use"] = "true"
            mock.state.certificates["*CA"]["ca-crl-host"] = "crl.router.example.test"
            self.assertTrue(client.get_certificate_settings(credentials)["router_hosted_ovpn_ca_crl"])
            self.assertTrue(client.get_certificate_settings(credentials)["crl_ready"])
            mock.state.certificates["*CA"].pop("ca-crl-host")
            mock.state.certificate_crls = [{
                "cert": "vpn-ca",
                "revoked": "0",
                "last-update": "2026-09-11 12:00:00",
                # Keep the fixture safely in the future so the test remains
                # deterministic when the suite runs on or after today's date.
                "next-update": "2036-08-03 00:00:00",
            }]
            self.assertTrue(client.get_certificate_settings(credentials)["crl_ready"])
            certificates = client.list_ovpn_client_certificates(credentials)
            self.assertEqual(
                [item["name"] for item in certificates],
                ["ovpn-user-one-device-a", "ovpn-user-two-device-b"],
            )
            self.assertTrue(all(not item["revoked"] for item in certificates))
            self.assertEqual(mock.state.certificate_queries[-1].get("ca"), ["vpn-ca"])
            self.assertEqual(client.get_admin_role(credentials), "owner")
            checkpoint = client.create_configuration_export(
                credentials, name="vpn-dashboard-test-checkpoint"
            )
            self.assertEqual(checkpoint, "vpn-dashboard-test-checkpoint.rsc")
            self.assertIn(checkpoint, mock.state.files)

            created = client.create_user(
                credentials,
                username="newuser",
                password="long-password",
                comment="test",
            )
            client.update_user(credentials, user_id=created[".id"], comment="updated", disabled=True)
            changed = next(user for user in client.list_ovpn_users(credentials) if user["name"] == "newuser")
            self.assertTrue(changed["disabled"])
            client.delete_user(credentials, user_id=created[".id"])
            self.assertNotIn("newuser", [user["name"] for user in client.list_ovpn_users(credentials)])

    def test_profile_provisioning_and_cleanup(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            credentials = RouterOSCredentials("admin", "routerpass")
            profile = client.provision_profile(
                credentials,
                vpn_user="user-one",
                device_name="Test Phone",
                key_passphrase="private-passphrase",
            )
            text = profile.profile.decode("utf-8")
            self.assertIn("redirect-gateway def1", text)
            self.assertIn("route 192.0.2.0 255.255.255.0", text)
            self.assertIn("dhcp-option DNS 192.0.2.1", text)
            self.assertIn("verify-x509-name vpn.example.test name", text)
            self.assertNotIn("private-passphrase", text)
            self.assertIn(profile.certificate_id, mock.state.certificates)
            self.assertEqual(
                sorted(mock.state.files),
                ["vpn-ca.crt"],
                "temporary certificate/key/profile files must be removed",
            )

    def test_failed_profile_cleanup_reports_unremoved_certificate(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            credentials = RouterOSCredentials("admin", "routerpass")
            request = client._request

            def fail_certificate_delete(method, path, *args, **kwargs):
                if method == "DELETE" and path.startswith("/certificate/"):
                    raise RouterOSError("injected certificate cleanup failure")
                return request(method, path, *args, **kwargs)

            with (
                patch.object(client, "_ensure_ca_export", side_effect=RouterOSError("injected export failure")),
                patch.object(client, "_request", side_effect=fail_certificate_delete),
            ):
                with self.assertRaisesRegex(RouterOSError, "partial RouterOS certificate remains"):
                    client.provision_profile(
                        credentials,
                        vpn_user="user-one",
                        device_name="Cleanup test",
                        key_passphrase="private-passphrase",
                    )

            partial = [
                item for item in mock.state.certificates.values()
                if item.get("name", "").startswith("ovpn-ui-user-one-cleanup-test-")
            ]
            self.assertEqual(len(partial), 1, "failed cleanup must remain visible for operator recovery")

    def test_live_session_telemetry_and_termination(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url, topology=TEST_TOPOLOGY)
            credentials = RouterOSCredentials("admin", "routerpass")
            sessions = client.list_active_ovpn_sessions(credentials)
            self.assertEqual(len(sessions), 1)
            active = sessions[0]
            self.assertEqual(active["name"], "user-two")
            self.assertEqual(active["source_address"], "198.51.100.40")
            self.assertEqual(active["vpn_address"], "198.18.0.48")
            self.assertEqual(active["interface"], "<ovpn-user-two>")
            self.assertEqual(active["rx_bytes"], 69988)
            self.assertEqual(active["tx_bytes"], 192455)
            self.assertEqual(active["rx_packets"], 387)
            self.assertEqual(active["tx_packets"], 825)

            client.terminate_session(credentials, session_id=active["id"])
            self.assertEqual(client.list_active_ovpn_sessions(credentials), [])

    def test_bad_credentials(self) -> None:
        with MockRouterOS() as mock:
            client = RouterOSClient(mock.url)
            with self.assertRaises(RouterOSError):
                client.verify_credentials(RouterOSCredentials("admin", "wrong"))

    def test_profile_requires_inline_credentials(self) -> None:
        with self.assertRaises(RouterOSError):
            harden_profile(
                "client\nremote example 1194 udp\n",
                server_identity="vpn.example.test",
                lan_cidr="192.0.2.0/24",
                router_dns="192.0.2.1",
            )

    def test_profile_policy_and_dns_presets(self) -> None:
        profile = "client\nredirect-gateway def1\nroute 192.0.2.0 255.255.255.0\ndhcp-option DNS 192.0.2.1\n<ca>\nca\n</ca>\n<cert>\ncert\n</cert>\n<key>\nkey\n</key>\n"
        lan_only = harden_profile(
            profile,
            server_identity="vpn.example.test",
            lan_cidr="192.0.2.0/24",
            router_dns="192.0.2.1",
            policy="lan-only",
            dns_mode="cloudflare",
        )
        self.assertNotIn("redirect-gateway def1", lan_only)
        self.assertIn("route 192.0.2.0 255.255.255.0", lan_only)
        self.assertIn("dhcp-option DNS 1.1.1.1", lan_only)
        internet_only = harden_profile(
            profile,
            server_identity="vpn.example.test",
            lan_cidr="192.0.2.0/24",
            router_dns="192.0.2.1",
            policy="internet-only",
        )
        self.assertIn("redirect-gateway def1", internet_only)
        self.assertNotIn("route 192.0.2.0 255.255.255.0", internet_only)


if __name__ == "__main__":
    unittest.main()
