from __future__ import annotations

import ipaddress
import unittest

from deployment import (
    CLOUDFLARE_ADDRESS_LIST,
    CLOUDFLARE_IPV4_RANGES,
    CLOUDFLARE_IPV6_RANGES,
    cloudflare_bulgaria_rule,
    routeros_container_add_command,
    routeros_container_script,
    routeros_origin_acl_script,
)
from cloudflare import (
    CONFIG_PHASE,
    CONFIG_REF,
    WAF_PHASE,
    WAF_REF,
    plan_tls_operation,
    plan_waf_operation,
)


TEST_ZONE_ID = "example-zone-id"


class DeploymentPolicyTests(unittest.TestCase):
    def test_cloudflare_networks_are_valid_and_unique(self) -> None:
        networks = [ipaddress.ip_network(value) for value in (*CLOUDFLARE_IPV4_RANGES, *CLOUDFLARE_IPV6_RANGES)]
        self.assertEqual(len(networks), len(set(networks)))
        self.assertEqual(sum(network.version == 4 for network in networks), 15)
        self.assertEqual(sum(network.version == 6 for network in networks), 7)

    def test_origin_acl_is_cloudflare_only_for_both_web_paths(self) -> None:
        script = routeros_origin_acl_script()
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
        self.assertIn("dst-address=172.31.255.2 dst-port=8080,8081", lines[direct_drop])
        self.assertIn("dst-port=80 to-addresses=172.31.255.2 to-ports=8081", script)

    def test_bulgaria_rule_is_host_scoped_and_blocking(self) -> None:
        rule = cloudflare_bulgaria_rule()
        self.assertEqual(rule["action"], "block")
        self.assertTrue(rule["enabled"])
        self.assertEqual(rule["ref"], "vpn_dashboard_bulgaria_only")
        self.assertIn('http.host eq "vpn.wanted.sx"', rule["expression"])
        self.assertIn('not ip.src.country in {"BG"}', rule["expression"])
        self.assertEqual(rule["position"], {"index": 1})

    def test_container_is_bounded_and_has_no_embedded_credentials(self) -> None:
        infrastructure = routeros_container_script()
        add = routeros_container_add_command()
        self.assertIn("python:3.14-alpine", add)
        self.assertIn("memory-high=134217728", add)
        self.assertIn("memory-max=201326592", add)
        self.assertIn("DROP_PRIVILEGES value=true", infrastructure)
        self.assertIn("TRUSTED_PROXY_SOURCES value=172.31.255.1", infrastructure)
        combined = (infrastructure + add).casefold()
        self.assertNotIn("example-password", combined)
        self.assertNotIn("example-api-token", combined)

    def test_waf_plan_creates_updates_and_is_idempotent(self) -> None:
        create = plan_waf_operation(None, zone_id=TEST_ZONE_ID)
        self.assertEqual(create.method, "PUT")
        self.assertIn(f"/zones/{TEST_ZONE_ID}/rulesets/phases/{WAF_PHASE}/entrypoint", create.path)

        add = plan_waf_operation(
            {"id": "ruleset-1", "rules": []}, zone_id=TEST_ZONE_ID
        )
        self.assertEqual(add.method, "POST")
        self.assertEqual(add.body["ref"], WAF_REF)

        matching_rule = dict(add.body)
        matching_rule.pop("position")
        matching_rule["id"] = "rule-1"
        self.assertIsNone(
            plan_waf_operation(
                {"id": "ruleset-1", "rules": [matching_rule]},
                zone_id=TEST_ZONE_ID,
            )
        )

        matching_rule["expression"] = "false"
        update = plan_waf_operation(
            {"id": "ruleset-1", "rules": [matching_rule]},
            zone_id=TEST_ZONE_ID,
        )
        self.assertEqual(update.method, "PATCH")
        self.assertTrue(update.path.endswith("/rules/rule-1"))

    def test_tls_plan_is_host_scoped_and_does_not_change_zone_default(self) -> None:
        create = plan_tls_operation(None, zone_id=TEST_ZONE_ID)
        self.assertEqual(create.method, "PUT")
        self.assertIn(f"/zones/{TEST_ZONE_ID}/rulesets/phases/{CONFIG_PHASE}/entrypoint", create.path)
        rule = create.body["rules"][0]
        self.assertEqual(rule["ref"], CONFIG_REF)
        self.assertEqual(rule["action_parameters"], {"ssl": "strict"})
        self.assertEqual(rule["expression"], '(http.host eq "vpn.wanted.sx")')

        current = dict(rule, id="tls-rule-1")
        self.assertIsNone(
            plan_tls_operation(
                {"id": "config-ruleset", "rules": [current]},
                zone_id=TEST_ZONE_ID,
            )
        )


if __name__ == "__main__":
    unittest.main()
