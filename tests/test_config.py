import unittest

from config import ConfigurationError, OpenVPNTopology, RuntimeConfig


class RuntimeConfigTests(unittest.TestCase):
    def test_safe_defaults_are_local_and_do_not_identify_an_instance(self) -> None:
        config = RuntimeConfig.from_environ({})
        self.assertEqual(config.public_origin, "http://localhost")
        self.assertEqual(config.routeros_rest_url, "https://127.0.0.1:8443/rest")
        self.assertEqual(config.dashboard_name, "MikroTik OpenVPN GUI")
        self.assertEqual(config.router_display_name, "RouterOS")
        self.assertEqual(config.history_retention_days, 365)
        self.assertEqual(config.topology, OpenVPNTopology())

    def test_history_retention_has_safe_bounds(self) -> None:
        self.assertEqual(RuntimeConfig.from_environ({"HISTORY_RETENTION_DAYS": "30"}).history_retention_days, 30)
        with self.assertRaisesRegex(ConfigurationError, "between 30 and 3650"):
            RuntimeConfig.from_environ({"HISTORY_RETENTION_DAYS": "29"})

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
        with self.assertRaisesRegex(ConfigurationError, "TRUSTED_PROXY_HEADER"):
            RuntimeConfig.from_environ({"TRUSTED_PROXY_SOURCES": "192.0.2.10"})
        with self.assertRaisesRegex(ConfigurationError, "must be one of"):
            RuntimeConfig.from_environ(
                {
                    "TRUSTED_PROXY_SOURCES": "192.0.2.10",
                    "TRUSTED_PROXY_HEADER": "Forwarded",
                }
            )

    def test_direct_https_proxy_and_legacy_cloudflare_modes_are_explicit(self) -> None:
        direct = RuntimeConfig.from_environ(
            {
                "TRUSTED_PROXY_SOURCES": "192.0.2.10",
                "TRUSTED_PROXY_HEADER": "x-forwarded-for",
                "ACCESS_LAYER_LABEL": "Direct HTTPS via Caddy",
            }
        )
        cloudflare = RuntimeConfig.from_environ(
            {"TRUST_CLOUDFLARE": "true", "TRUSTED_PROXY_SOURCES": "192.0.2.11"}
        )
        self.assertFalse(direct.trust_cloudflare)
        self.assertEqual(direct.trusted_proxy_header, "X-Forwarded-For")
        self.assertEqual(direct.access_layer_label, "Direct HTTPS via Caddy")
        self.assertEqual(cloudflare.trusted_proxy_header, "CF-Connecting-IP")
        self.assertEqual(cloudflare.access_layer_label, "Cloudflare Access")

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
