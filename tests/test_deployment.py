from __future__ import annotations

import io
import ipaddress
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path

from deployment import (
    CLOUDFLARE_ADDRESS_LIST,
    CLOUDFLARE_IPV4_RANGES,
    CLOUDFLARE_IPV6_RANGES,
    cloudflare_country_allowlist_rule,
    routeros_origin_acl_script,
)
from deploy_routeros_canary import CanarySettings, main as render_canary_main, render_canary_plan
from cloudflare import (
    CONFIG_PHASE,
    CONFIG_REF,
    WAF_PHASE,
    WAF_REF,
    plan_tls_operation,
    plan_waf_operation,
)
from update_routeros_app import main as retired_source_update


TEST_ZONE_ID = "example-zone-id"
TEST_HOSTNAME = "vpn.example.test"
TEST_CONTAINER_ADDRESS = "192.0.2.10"


class DeploymentPolicyTests(unittest.TestCase):
    def test_cloudflare_networks_are_valid_and_unique(self) -> None:
        networks = [ipaddress.ip_network(value) for value in (*CLOUDFLARE_IPV4_RANGES, *CLOUDFLARE_IPV6_RANGES)]
        self.assertEqual(len(networks), len(set(networks)))
        self.assertEqual(sum(network.version == 4 for network in networks), 15)
        self.assertEqual(sum(network.version == 6 for network in networks), 7)

    def test_origin_acl_is_cloudflare_only_for_both_web_paths(self) -> None:
        script = routeros_origin_acl_script(TEST_CONTAINER_ADDRESS)
        lines = script.splitlines()
        for network in CLOUDFLARE_IPV4_RANGES:
            self.assertIn(f'list="{CLOUDFLARE_ADDRESS_LIST}" address={network}', script)

        https_allow = next(index for index, line in enumerate(lines) if 'comment="VPN Dashboard: origin allow Cloudflare HTTPS"' in line)
        https_drop = next(index for index, line in enumerate(lines) if 'comment="VPN Dashboard: origin drop non-Cloudflare HTTPS"' in line)
        http_allow = next(index for index, line in enumerate(lines) if 'comment="VPN Dashboard: origin allow Cloudflare HTTP"' in line)
        direct_drop = next(index for index, line in enumerate(lines) if 'comment="VPN Dashboard: origin block direct container"' in line)
        # Each command uses place-before=0, so later commands become earlier rules.
        self.assertLess(https_drop, https_allow)
        self.assertLess(direct_drop, http_allow)
        self.assertIn("chain=input action=drop protocol=tcp dst-port=443", lines[https_drop])
        self.assertIn(
            f"dst-address={TEST_CONTAINER_ADDRESS} dst-port=8080,8081", lines[direct_drop]
        )
        self.assertIn(
            f"dst-port=80 to-addresses={TEST_CONTAINER_ADDRESS} to-ports=8081", script
        )

    def test_country_allowlist_rule_is_host_scoped_and_blocking(self) -> None:
        rule = cloudflare_country_allowlist_rule(TEST_HOSTNAME, ("bg", "DE", "BG"))
        self.assertEqual(rule["action"], "block")
        self.assertTrue(rule["enabled"])
        self.assertEqual(rule["ref"], "vpn_dashboard_bulgaria_only")
        self.assertIn(f'http.host eq "{TEST_HOSTNAME}"', rule["expression"])
        self.assertIn('not ip.src.country in {"BG", "DE"}', rule["expression"])
        self.assertEqual(rule["position"], {"index": 1})

    def test_edge_tooling_rejects_implicit_or_invalid_targets(self) -> None:
        with self.assertRaisesRegex(ValueError, "hostname"):
            cloudflare_country_allowlist_rule("", ("BG",))
        with self.assertRaisesRegex(ValueError, "country code"):
            cloudflare_country_allowlist_rule(TEST_HOSTNAME, ("BGR",))
        with self.assertRaisesRegex(ValueError, "container_address"):
            routeros_origin_acl_script("not-an-ip")
        with self.assertRaisesRegex(ValueError, "container_address"):
            routeros_origin_acl_script("2001:db8::10")

    @staticmethod
    def canary_settings() -> CanarySettings:
        return CanarySettings(
            owner="example-owner",
            commit="a" * 40,
            public_origin="https://vpn.example.com",
            routeros_rest_url="https://router.example.internal:8443/rest",
            routeros_rest_san="router.example.internal",
            external_root="disk1/vpn-gui",
            bridge="br-containers",
            canary_address="192.0.2.6/30",
            gateway="192.0.2.5",
            ovpn_ppp_profile="vpn-full-tunnel",
            ovpn_server_name="vpn-server",
            ovpn_ca_name="vpn-ca",
            ovpn_host="ovpn.example.com",
            vpn_lan_cidr="198.18.10.0/24",
            vpn_router_dns="198.18.10.1",
            trust_cloudflare=True,
            trusted_proxy_sources="192.0.2.1,2001:db8::1",
        )

    def test_canary_plan_uses_an_immutable_ghcr_image_and_separate_state(self) -> None:
        plan = render_canary_plan(self.canary_settings())
        self.assertIn(
            f'remote-image="example-owner/mikrotik-openvpn-gui:sha-{"a" * 40}"',
            plan,
        )
        self.assertIn('mountlists="vpn-gui-canary-aaaaaaaaaaaa-mounts"', plan)
        self.assertIn('envlists="vpn-gui-canary-aaaaaaaaaaaa-env"', plan)
        self.assertIn('src="disk1/vpn-gui/canary/aaaaaaaaaaaa/data" dst=/data', plan)
        self.assertIn('src="disk1/vpn-gui/config" dst=/config', plan)
        self.assertIn("memory-high=134217728", plan)
        self.assertIn("memory-max=201326592", plan)
        self.assertIn('key=ROUTEROS_INSECURE_TLS value="false"', plan)
        self.assertIn('key=OVPN_PPP_PROFILE value="vpn-full-tunnel"', plan)
        self.assertIn('key=OVPN_SERVER_NAME value="vpn-server"', plan)
        self.assertIn('key=OVPN_CA_NAME value="vpn-ca"', plan)
        self.assertIn('key=OVPN_HOST value="ovpn.example.com"', plan)
        self.assertIn('key=VPN_LAN_CIDR value="198.18.10.0/24"', plan)
        self.assertIn('key=VPN_ROUTER_DNS value="198.18.10.1"', plan)
        self.assertNotIn("key=OVPN_SERVER_IDENTITY", plan)
        self.assertIn("start-on-boot=no", plan)
        self.assertNotIn("dst=/app", plan)
        self.assertNotIn("remote-image=python", plan)
        self.assertNotIn("password", plan.casefold())

    def test_canary_plan_renders_an_explicit_openvpn_server_identity(self) -> None:
        plan = render_canary_plan(
            replace(self.canary_settings(), ovpn_server_identity="vpn-server.example.com")
        )
        self.assertIn('key=OVPN_SERVER_IDENTITY value="vpn-server.example.com"', plan)

    def test_canary_cli_passes_the_openvpn_topology_to_the_plan(self) -> None:
        settings = self.canary_settings()
        output = io.StringIO()
        with redirect_stdout(output):
            status = render_canary_main(
                [
                    "--owner",
                    settings.owner,
                    "--commit",
                    settings.commit,
                    "--public-origin",
                    settings.public_origin,
                    "--routeros-rest-url",
                    settings.routeros_rest_url,
                    "--routeros-rest-san",
                    settings.routeros_rest_san,
                    "--external-root",
                    settings.external_root,
                    "--bridge",
                    settings.bridge,
                    "--canary-address",
                    settings.canary_address,
                    "--gateway",
                    settings.gateway,
                    "--ovpn-ppp-profile",
                    settings.ovpn_ppp_profile,
                    "--ovpn-server-name",
                    settings.ovpn_server_name,
                    "--ovpn-ca-name",
                    settings.ovpn_ca_name,
                    "--ovpn-host",
                    settings.ovpn_host,
                    "--vpn-lan-cidr",
                    settings.vpn_lan_cidr,
                    "--vpn-router-dns",
                    settings.vpn_router_dns,
                ]
            )
        self.assertEqual(status, 0)
        self.assertIn('key=OVPN_HOST value="ovpn.example.com"', output.getvalue())

    def test_canary_plan_rejects_unsafe_or_unverified_inputs(self) -> None:
        settings = self.canary_settings()
        with self.assertRaisesRegex(ValueError, "full 40-character"):
            render_canary_plan(replace(settings, commit="abc123"))
        with self.assertRaisesRegex(ValueError, "exactly match"):
            render_canary_plan(replace(settings, routeros_rest_san="other.example.internal"))
        with self.assertRaisesRegex(ValueError, "HTTPS"):
            render_canary_plan(replace(settings, routeros_rest_url="http://router.example.internal/rest"))
        with self.assertRaisesRegex(ValueError, "unsafe"):
            render_canary_plan(replace(settings, bridge='bad";remove'))
        with self.assertRaisesRegex(ValueError, "require --trust-cloudflare"):
            render_canary_plan(
                replace(settings, trust_cloudflare=False, trusted_proxy_sources="192.0.2.1")
            )
        with self.assertRaisesRegex(ValueError, "individual IP address"):
            render_canary_plan(replace(settings, trusted_proxy_sources="192.0.2.0/24"))
        with self.assertRaisesRegex(ValueError, "network or broadcast"):
            render_canary_plan(replace(settings, canary_address="192.0.2.4/30"))
        with self.assertRaisesRegex(ValueError, "RouterOS-safe"):
            render_canary_plan(replace(settings, ovpn_ppp_profile="unsafe profile"))
        with self.assertRaisesRegex(ValueError, "canonical IPv4"):
            render_canary_plan(replace(settings, vpn_lan_cidr="198.18.10.7/24"))

    def test_direct_source_updater_is_retired_and_fails_closed(self) -> None:
        output = io.StringIO()
        with redirect_stderr(output):
            status = retired_source_update()
        self.assertEqual(status, 64)
        self.assertIn("Direct source-file deployment is retired", output.getvalue())
        self.assertIn("no changes were made", output.getvalue())

    def test_image_leaves_routeros_runtime_identity_files_absent(self) -> None:
        containerfile = (Path(__file__).resolve().parents[1] / "Containerfile").read_text(encoding="utf-8")
        self.assertIn("FROM scratch", containerfile)
        for runtime_file in ("etc/hostname", "etc/hosts", "etc/resolv.conf"):
            self.assertIn(f"--exclude={runtime_file}", containerfile)

    def test_image_bakes_release_identity_and_checks_readiness(self) -> None:
        containerfile = (Path(__file__).resolve().parents[1] / "Containerfile").read_text(encoding="utf-8")
        self.assertIn('"$VERSION" > /app/VERSION', containerfile)
        self.assertIn('"$REVISION" > /app/REVISION', containerfile)
        self.assertIn("http://127.0.0.1:8080/readyz", containerfile)
        self.assertNotIn("http://127.0.0.1:8080/healthz", containerfile)

    def test_waf_plan_creates_updates_and_is_idempotent(self) -> None:
        self.assertIsNone(
            plan_waf_operation(
                None, zone_id=TEST_ZONE_ID, hostname=TEST_HOSTNAME, countries=()
            )
        )
        create = plan_waf_operation(
            None, zone_id=TEST_ZONE_ID, hostname=TEST_HOSTNAME, countries=("BG",)
        )
        self.assertEqual(create.method, "PUT")
        self.assertIn(f"/zones/{TEST_ZONE_ID}/rulesets/phases/{WAF_PHASE}/entrypoint", create.path)

        add = plan_waf_operation(
            {"id": "ruleset-1", "rules": []},
            zone_id=TEST_ZONE_ID, hostname=TEST_HOSTNAME, countries=("BG",),
        )
        self.assertEqual(add.method, "POST")
        self.assertEqual(add.body["ref"], WAF_REF)

        matching_rule = dict(add.body)
        matching_rule.pop("position")
        matching_rule["id"] = "rule-1"
        self.assertIsNone(
            plan_waf_operation(
                {"id": "ruleset-1", "rules": [matching_rule]}, zone_id=TEST_ZONE_ID,
                hostname=TEST_HOSTNAME, countries=("BG",),
            )
        )

        matching_rule["expression"] = "false"
        update = plan_waf_operation(
            {"id": "ruleset-1", "rules": [matching_rule]}, zone_id=TEST_ZONE_ID,
            hostname=TEST_HOSTNAME, countries=("BG",),
        )
        self.assertEqual(update.method, "PATCH")
        self.assertTrue(update.path.endswith("/rules/rule-1"))

    def test_tls_plan_is_host_scoped_and_does_not_change_zone_default(self) -> None:
        create = plan_tls_operation(None, zone_id=TEST_ZONE_ID, hostname=TEST_HOSTNAME)
        self.assertEqual(create.method, "PUT")
        self.assertIn(f"/zones/{TEST_ZONE_ID}/rulesets/phases/{CONFIG_PHASE}/entrypoint", create.path)
        rule = create.body["rules"][0]
        self.assertEqual(rule["ref"], CONFIG_REF)
        self.assertEqual(rule["action_parameters"], {"ssl": "strict"})
        self.assertEqual(rule["expression"], f'(http.host eq "{TEST_HOSTNAME}")')

        current = dict(rule, id="tls-rule-1")
        self.assertIsNone(
            plan_tls_operation(
                {"id": "config-ruleset", "rules": [current]},
                zone_id=TEST_ZONE_ID, hostname=TEST_HOSTNAME,
            )
        )


if __name__ == "__main__":
    unittest.main()
