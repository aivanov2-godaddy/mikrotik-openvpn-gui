import unittest

from config import ConfigurationError, OpenVPNTopology, RuntimeConfig


class RuntimeConfigTests(unittest.TestCase):
    def test_safe_defaults_are_local_and_do_not_identify_an_instance(self) -> None:
        config = RuntimeConfig.from_environ({})
        self.assertEqual(config.public_origin, "http://localhost")
        self.assertEqual(config.routeros_rest_url, "https://127.0.0.1:8443/rest")
        self.assertEqual(config.dashboard_name, "MikroTik OpenVPN GUI")
        self.assertEqual(config.router_display_name, "RouterOS")
        self.assertEqual(config.topology, OpenVPNTopology())

    def test_explicit_topology_is_normalized_and_complete_for_profiles(self) -> None:
        config = RuntimeConfig.from_environ(
            {
                "PUBLIC_ORIGIN": "https://vpn.example.com/",
                "ROUTEROS_REST_URL": "https://router.example.com:8443/rest",
                "OVPN_PPP_PROFILE": "vpn-full-tunnel",
                "OVPN_SERVER_NAME": "vpn-server",
                "OVPN_CA_NAME": "vpn-ca",
                "OVPN_HOST": "VPN.Example.COM.",
                "VPN_LAN_CIDR": "192.0.2.0/24",
                "VPN_ROUTER_DNS": "192.0.2.1",
            }
        )
        self.assertEqual(config.public_origin, "https://vpn.example.com")
        self.assertEqual(config.topology.host, "vpn.example.com")
        self.assertEqual(config.topology.server_identity, "vpn.example.com")
        config.topology.require_profile_generation(policy="full-tunnel", dns_mode="router")

    def test_invalid_public_or_rest_settings_fail_before_a_router_request(self) -> None:
        with self.assertRaisesRegex(ConfigurationError, "HTTPS"):
            RuntimeConfig.from_environ({"PUBLIC_ORIGIN": "http://vpn.example.com"})
        with self.assertRaisesRegex(ConfigurationError, "ending in /rest"):
            RuntimeConfig.from_environ({"ROUTEROS_REST_URL": "https://router.example.com/api"})
        with self.assertRaisesRegex(ConfigurationError, "TRUSTED_PROXY_SOURCES"):
            RuntimeConfig.from_environ({"TRUST_CLOUDFLARE": "true"})

    def test_incomplete_topology_fails_closed_for_profile_issuing(self) -> None:
        topology = OpenVPNTopology.from_values(
            {
                "OVPN_PPP_PROFILE": "vpn-profile",
                "OVPN_SERVER_NAME": "vpn-server",
                "OVPN_CA_NAME": "vpn-ca",
                "OVPN_HOST": "vpn.example.com",
            }
        )
        with self.assertRaisesRegex(ConfigurationError, "VPN_LAN_CIDR, VPN_ROUTER_DNS"):
            topology.require_profile_generation(policy="full-tunnel", dns_mode="router")
        with self.assertRaisesRegex(ConfigurationError, "VPN_LAN_CIDR"):
            topology.require_profile_generation(policy="lan-only", dns_mode="cloudflare")


if __name__ == "__main__":
    unittest.main()
