"""Safety and output tests for the offline first-time install wizard."""

from __future__ import annotations

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

from install_routeros import InstallationSettings, main as render_install_main, render_install_plan


def settings(**changes: str) -> InstallationSettings:
    values = {
        "owner": "example-owner",
        "commit": "a" * 40,
        "architecture": "arm64",
        "public_origin": "https://vpn.example.com",
        "routeros_rest_url": "https://router.example.com:8443/rest",
        "routeros_rest_san": "router.example.com",
        "external_root": "disk1/vpn-dashboard",
        "bridge": "containers",
        "veth": "veth-vpn-dashboard",
        "container_address": "172.31.250.2/24",
        "gateway": "172.31.250.1",
        "ovpn_ppp_profile": "vpn-full-tunnel",
        "ovpn_server_name": "vpn-server",
        "ovpn_ca_name": "vpn-ca",
        "ovpn_host": "ovpn.example.com",
        "vpn_lan_cidr": "192.168.88.0/24",
        "vpn_router_dns": "192.168.88.1",
    }
    values.update(changes)
    return InstallationSettings(**values)


class InstallationWizardTests(unittest.TestCase):
    def test_cli_writes_operational_plan_only_to_explicit_file(self) -> None:
        values = settings()
        with tempfile.TemporaryDirectory() as directory:
            output_path = Path(directory) / "install-plan.rsc"
            stdout = io.StringIO()
            stderr = io.StringIO()
            arguments = [
                "--owner", values.owner,
                "--commit", values.commit,
                "--architecture", values.architecture,
                "--public-origin", values.public_origin,
                "--routeros-rest-url", values.routeros_rest_url,
                "--routeros-rest-san", values.routeros_rest_san,
                "--external-root", values.external_root,
                "--bridge", values.bridge,
                "--veth", values.veth,
                "--container-address", values.container_address,
                "--gateway", values.gateway,
                "--ovpn-ppp-profile", values.ovpn_ppp_profile,
                "--ovpn-server-name", values.ovpn_server_name,
                "--ovpn-ca-name", values.ovpn_ca_name,
                "--ovpn-host", values.ovpn_host,
                "--vpn-lan-cidr", values.vpn_lan_cidr,
                "--vpn-router-dns", values.vpn_router_dns,
                "--output", str(output_path),
            ]
            with redirect_stdout(stdout), redirect_stderr(stderr):
                status = render_install_main(arguments)

            self.assertEqual(status, 0)
            self.assertNotIn("router.example.com", stdout.getvalue())
            self.assertNotIn("172.31.250.2", stdout.getvalue())
            self.assertNotIn(str(output_path), stdout.getvalue())
            self.assertEqual(stderr.getvalue(), "")
            plan = output_path.read_text(encoding="utf-8")
            self.assertIn("router.example.com", plan)
            self.assertIn("172.31.250.2", plan)
            self.assertIn("/container/add", plan)

    def test_cli_requires_an_explicit_output_file(self) -> None:
        stderr = io.StringIO()
        with redirect_stderr(stderr), self.assertRaises(SystemExit) as error:
            render_install_main([])
        self.assertEqual(error.exception.code, 2)

    def test_plan_is_explicit_immutable_and_never_applies(self) -> None:
        plan = render_install_plan(settings())
        self.assertIn("example-owner/mikrotik-openvpn-gui:sha-" + "a" * 40 + "-arm64", plan)
        self.assertIn("dst=/data", plan)
        self.assertIn("dst=/config", plan)
        self.assertIn("ROUTEROS_INSECURE_TLS", plan)
        self.assertIn('value="false"', plan)
        self.assertIn("/container/add", plan)
        self.assertNotIn("\n/container/start ", plan)
        self.assertIn("start manually", plan)
        self.assertNotIn("ROUTER_PASSWORD", plan)
        self.assertNotIn("read:packages", plan)
        self.assertNotIn("private-key", plan.casefold())

    def test_amd64_is_explicit_and_arm_is_rejected(self) -> None:
        self.assertIn("-amd64", render_install_plan(settings(architecture="amd64")))
        with self.assertRaisesRegex(ValueError, "architecture"):
            settings(architecture="arm").validated()

    def test_unsafe_values_and_networks_fail_closed(self) -> None:
        invalid = (
            {"external_root": "disk1/../escape"},
            {"external_root": "disk1;remove"},
            {"bridge": "container;remove"},
            {"public_origin": "https://vpn.example.com/path"},
            {"public_origin": "https://canary.invalid"},
            {"routeros_rest_url": "http://router.example.com/rest"},
            {"routeros_rest_san": "other.example.com"},
            {"container_address": "172.31.250.0/24"},
            {"gateway": "172.31.251.1"},
            {"commit": "a" * 39},
        )
        for changes in invalid:
            with self.subTest(changes=changes):
                with self.assertRaises(ValueError):
                    settings(**changes).validated()

    def test_topology_and_proxy_are_validated(self) -> None:
        with self.assertRaisesRegex(ValueError, "OpenVPN profile issuing"):
            settings(ovpn_ca_name="").validated()
        plan = render_install_plan(settings(trusted_proxy_sources="10.0.0.2"))
        self.assertIn("TRUSTED_PROXY_SOURCES", plan)
        with self.assertRaises(ValueError):
            settings(trusted_proxy_sources="10.0.0.2", trusted_proxy_header="CF-Connecting-IP").validated()
        secret_sentinel = "secret-proxy-value-do-not-echo"
        with self.assertRaisesRegex(ValueError, "individual IP address") as error:
            settings(trusted_proxy_sources=secret_sentinel).validated()
        self.assertNotIn(secret_sentinel, str(error.exception))


if __name__ == "__main__":
    unittest.main()
