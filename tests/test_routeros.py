from __future__ import annotations

import unittest

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
            mock.state.certificate_crls = [{
                "cert": "vpn-ca",
                "revoked": "0",
                "last-update": "2026-09-11 12:00:00",
                "next-update": "2026-09-12 12:00:00",
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
