"""Create a review-only, first-time RouterOS installation plan.

This offline wizard deliberately has no RouterOS client and never accepts a
password, token, private key, or configuration export. It validates non-secret
installation choices and renders commands for an operator to review in WinBox.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit

from config import ConfigurationError, OpenVPNTopology
from deploy_routeros_canary import (
    _FULL_COMMIT,
    _GHCR_OWNER,
    _https_url,
    _proxy_sources,
    _quoted,
    _validated_host,
    _validated_name,
    _validated_path,
)


_REPOSITORY = re.compile(r"^[a-z0-9][a-z0-9._-]{0,98}$")
_ARCHITECTURES = {"arm64", "amd64"}


@dataclass(frozen=True)
class InstallationSettings:
    owner: str
    commit: str
    architecture: str
    public_origin: str
    routeros_rest_url: str
    routeros_rest_san: str
    external_root: str
    bridge: str
    veth: str
    container_address: str
    gateway: str
    ovpn_ppp_profile: str
    ovpn_server_name: str
    ovpn_ca_name: str
    ovpn_host: str
    vpn_lan_cidr: str
    vpn_router_dns: str
    repository: str = "mikrotik-openvpn-gui-public"
    ovpn_server_identity: str = ""
    trusted_proxy_sources: str = ""
    trusted_proxy_header: str = "X-Forwarded-For"

    def validated(self) -> "ValidatedInstallationSettings":
        owner = self.owner.casefold()
        repository = self.repository.casefold()
        if self.owner != owner or not _GHCR_OWNER.fullmatch(owner):
            raise ValueError("owner must be a lowercase GitHub user or organization name")
        if self.repository != repository or not _REPOSITORY.fullmatch(repository):
            raise ValueError("repository must be a lowercase container repository name")
        if not _FULL_COMMIT.fullmatch(self.commit):
            raise ValueError("commit must be the full 40-character lowercase Git commit SHA")
        if self.architecture not in _ARCHITECTURES:
            raise ValueError("architecture must be arm64 or amd64; RouterOS arm is not supported")

        origin, _ = _https_url(self.public_origin, "public origin")
        if urlsplit(origin).path not in {"", "/"}:
            raise ValueError("public origin must not include a path")
        origin = origin.rstrip("/")
        rest_url, rest_host = _https_url(
            self.routeros_rest_url, "RouterOS REST URL", required_path="/rest"
        )
        if rest_host != _validated_host(self.routeros_rest_san, "RouterOS REST SAN"):
            raise ValueError("RouterOS REST hostname must exactly match the confirmed certificate SAN")

        try:
            address = ipaddress.ip_interface(self.container_address)
            gateway = ipaddress.ip_address(self.gateway)
        except ValueError as error:
            raise ValueError("container address and gateway must be valid IPv4 values") from error
        if address.version != 4 or gateway.version != 4:
            raise ValueError("container address and gateway must be IPv4 values")
        if gateway not in address.network or gateway == address.ip:
            raise ValueError("gateway must be a different address in the container subnet")
        if address.ip in {address.network.network_address, address.network.broadcast_address}:
            raise ValueError("container address cannot be the network or broadcast address")

        try:
            topology = OpenVPNTopology.from_values(
                {
                    "OVPN_PPP_PROFILE": self.ovpn_ppp_profile,
                    "OVPN_SERVER_NAME": self.ovpn_server_name,
                    "OVPN_CA_NAME": self.ovpn_ca_name,
                    "OVPN_HOST": self.ovpn_host,
                    "OVPN_SERVER_IDENTITY": self.ovpn_server_identity,
                    "VPN_LAN_CIDR": self.vpn_lan_cidr,
                    "VPN_ROUTER_DNS": self.vpn_router_dns,
                }
            )
            topology.require_profile_generation(policy="full-tunnel", dns_mode="router")
        except ConfigurationError as error:
            raise ValueError(str(error)) from None

        sources = _proxy_sources(self.trusted_proxy_sources) if self.trusted_proxy_sources.strip() else ""
        if sources and self.trusted_proxy_header != "X-Forwarded-For":
            raise ValueError("trusted proxy header must be X-Forwarded-For for this installation plan")

        return ValidatedInstallationSettings(
            owner=owner,
            repository=repository,
            commit=self.commit,
            architecture=self.architecture,
            public_origin=origin,
            routeros_rest_url=rest_url,
            external_root=_validated_path(self.external_root),
            bridge=_validated_name(self.bridge, "bridge"),
            veth=_validated_name(self.veth, "VETH name"),
            address=address,
            gateway=gateway,
            topology=topology,
            trusted_proxy_sources=sources,
        )


@dataclass(frozen=True)
class ValidatedInstallationSettings:
    owner: str
    repository: str
    commit: str
    architecture: str
    public_origin: str
    routeros_rest_url: str
    external_root: str
    bridge: str
    veth: str
    address: ipaddress.IPv4Interface
    gateway: ipaddress.IPv4Address
    topology: OpenVPNTopology
    trusted_proxy_sources: str

    @property
    def image(self) -> str:
        return f"{self.owner}/{self.repository}:sha-{self.commit}-{self.architecture}"


def render_install_plan(settings: InstallationSettings) -> str:
    values = settings.validated()
    root = values.external_root
    envs = "vpn-dashboard-env"
    mounts = "vpn-dashboard-mounts"
    commands = [
        "# REVIEW-ONLY FIRST-TIME INSTALL PLAN. It contains no credentials or private keys.",
        "# Before applying: back up the router; install the matching Container package; confirm device-mode physically; prepare external storage; and verify address/path availability.",
        "# Configure registry-url=https://ghcr.io separately. A public package needs no registry token.",
        f"/interface/veth/add name={_quoted(values.veth)} address={_quoted(str(values.address))} gateway={_quoted(str(values.gateway))}",
        f"/interface/bridge/port/add bridge={_quoted(values.bridge)} interface={_quoted(values.veth)}",
        f"/ip/address/add address={_quoted(f'{values.gateway}/{values.address.network.prefixlen}')} interface={_quoted(values.bridge)} comment={_quoted('VPN dashboard gateway')}",
        f"/container/mounts/add list={_quoted(mounts)} src={_quoted(f'{root}/data')} dst=/data",
        f"/container/mounts/add list={_quoted(mounts)} src={_quoted(f'{root}/config')} dst=/config",
    ]
    environment = {
        "PUBLIC_ORIGIN": values.public_origin,
        "ROUTEROS_REST_URL": values.routeros_rest_url,
        "ROUTEROS_CA_FILE": "/config/routeros-ca.crt",
        "ROUTEROS_INSECURE_TLS": "false",
        "DATABASE_PATH": "/data/dashboard.sqlite",
        "DROP_PRIVILEGES": "true",
        "OVPN_PPP_PROFILE": values.topology.ppp_profile,
        "OVPN_SERVER_NAME": values.topology.server_name,
        "OVPN_CA_NAME": values.topology.ca_name,
        "OVPN_HOST": values.topology.host,
        "OVPN_SERVER_IDENTITY": values.topology.server_identity,
        "VPN_LAN_CIDR": values.topology.lan_cidr,
        "VPN_ROUTER_DNS": values.topology.router_dns,
        "TRUST_CLOUDFLARE": "false",
    }
    if values.trusted_proxy_sources:
        environment["TRUSTED_PROXY_SOURCES"] = values.trusted_proxy_sources
        environment["TRUSTED_PROXY_HEADER"] = "X-Forwarded-For"
    commands.extend(
        f"/container/envs/add list={_quoted(envs)} key={key} value={_quoted(value)}"
        for key, value in environment.items()
    )
    commands.extend(
        [
            f"/container/add name=vpn-dashboard remote-image={_quoted(values.image)} interface={_quoted(values.veth)} root-dir={_quoted(f'{root}/root')} mountlists={_quoted(mounts)} envlists={_quoted(envs)} start-on-boot=yes logging=yes",
            "# Copy the verified RouterOS REST CA certificate to <external-root>/config/routeros-ca.crt.",
            "# After extraction, inspect Container logs and start manually: /container/start vpn-dashboard",
            "# Then verify /healthz, /readyz, HTTPS login, and a disposable VPN profile before production use.",
        ]
    )
    return "\n".join(commands) + "\n"


def parser() -> argparse.ArgumentParser:
    command = argparse.ArgumentParser(description="Render a review-only RouterOS installation plan.")
    command.add_argument("--interactive", action="store_true", help="Prompt for non-secret settings")
    command.add_argument("--owner")
    command.add_argument("--commit")
    command.add_argument("--architecture", choices=sorted(_ARCHITECTURES))
    command.add_argument("--public-origin")
    command.add_argument("--routeros-rest-url")
    command.add_argument("--routeros-rest-san")
    command.add_argument("--external-root")
    command.add_argument("--bridge")
    command.add_argument("--veth", default="veth-vpn-dashboard")
    command.add_argument("--container-address")
    command.add_argument("--gateway")
    command.add_argument("--ovpn-ppp-profile")
    command.add_argument("--ovpn-server-name")
    command.add_argument("--ovpn-ca-name")
    command.add_argument("--ovpn-host")
    command.add_argument("--ovpn-server-identity", default="")
    command.add_argument("--vpn-lan-cidr")
    command.add_argument("--vpn-router-dns")
    command.add_argument("--repository", default="mikrotik-openvpn-gui-public")
    command.add_argument("--trusted-proxy-sources", default="")
    command.add_argument("--output", type=Path, help="Write the review-only .rsc plan to this path")
    return command


def _prompt(values: dict[str, object]) -> None:
    print("MikroTik OpenVPN GUI installation wizard (review-only; never enter secrets).")
    fields = (
        ("owner", "GitHub owner", ""),
        ("commit", "Published 40-character commit SHA", ""),
        ("architecture", "Architecture (arm64 or amd64)", "arm64"),
        ("public_origin", "Dashboard HTTPS origin", "https://vpn.example.com"),
        ("routeros_rest_url", "RouterOS REST URL", "https://router.example.com:8443/rest"),
        ("routeros_rest_san", "RouterOS REST certificate SAN", "router.example.com"),
        ("external_root", "External storage root", "disk1/vpn-dashboard"),
        ("bridge", "Existing container bridge", "containers"),
        ("veth", "New VETH name", "veth-vpn-dashboard"),
        ("container_address", "Container IPv4/prefix", "172.31.250.2/24"),
        ("gateway", "Bridge gateway IPv4", "172.31.250.1"),
        ("ovpn_ppp_profile", "Existing OpenVPN PPP profile", "vpn-full-tunnel"),
        ("ovpn_server_name", "Existing OpenVPN server", "vpn-server"),
        ("ovpn_ca_name", "Existing OpenVPN CA", "vpn-ca"),
        ("ovpn_host", "Public OpenVPN hostname or IP", "ovpn.example.com"),
        ("vpn_lan_cidr", "LAN CIDR for VPN clients", "192.168.88.0/24"),
        ("vpn_router_dns", "Router DNS IPv4", "192.168.88.1"),
    )
    for name, label, default in fields:
        current = str(values.get(name) or default)
        answer = input(f"{label} [{current}]: ").strip()
        values[name] = answer or current


def _require(values: dict[str, object], command: argparse.ArgumentParser) -> None:
    required = (
        "owner", "commit", "architecture", "public_origin", "routeros_rest_url", "routeros_rest_san",
        "external_root", "bridge", "veth", "container_address", "gateway", "ovpn_ppp_profile",
        "ovpn_server_name", "ovpn_ca_name", "ovpn_host", "vpn_lan_cidr", "vpn_router_dns",
    )
    missing = [name.replace("_", "-") for name in required if not values.get(name)]
    if missing:
        command.error("missing required settings: " + ", ".join(missing))


def main(argv: list[str] | None = None) -> int:
    command = parser()
    values = vars(command.parse_args(argv))
    output = values.pop("output")
    interactive = bool(values.pop("interactive"))
    if interactive:
        _prompt(values)
    _require(values, command)
    try:
        plan = render_install_plan(InstallationSettings(**values))
    except ValueError as error:
        parser().error(str(error))
    if output:
        output.write_text(plan, encoding="utf-8", newline="\n")
        print(f"Wrote review-only plan to {output}")
    else:
        print(plan, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
