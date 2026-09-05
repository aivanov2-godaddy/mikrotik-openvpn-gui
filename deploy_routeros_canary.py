"""Render a fail-safe RouterOS GHCR canary plan without contacting a router.

This module deliberately has no apply mode. Review the rendered commands, compare
all addresses and paths with live RouterOS state, and follow docs/DEPLOYMENT.md.
"""

from __future__ import annotations

import argparse
import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit


_FULL_COMMIT = re.compile(r"^[0-9a-f]{40}$")
_GHCR_OWNER = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,37}[a-z0-9])?$")
_ROUTER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_ROUTER_PATH = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/-]*$")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")


def _quoted(value: str) -> str:
    if not value or any(character in '"\\$' or ord(character) < 32 for character in value):
        raise ValueError(
            "RouterOS values must be non-empty and cannot contain quotes, escapes, variables, or control characters"
        )
    return f'"{value}"'


def _validated_name(value: str, label: str) -> str:
    if not _ROUTER_NAME.fullmatch(value):
        raise ValueError(f"{label} contains characters unsafe for a generated RouterOS plan")
    return value


def _validated_path(value: str) -> str:
    if not _ROUTER_PATH.fullmatch(value) or ".." in value.split("/"):
        raise ValueError("external root must be a relative RouterOS path without spaces or parent traversal")
    return value.rstrip("/")


def _validated_host(value: str, label: str) -> str:
    candidate = value.rstrip(".")
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        if (
            not candidate
            or len(candidate) > 253
            or any(not _DNS_LABEL.fullmatch(part) for part in candidate.split("."))
        ):
            raise ValueError(f"{label} contains an invalid DNS name") from None
        return candidate.casefold()


def _https_url(value: str, label: str, *, required_path: str | None = None) -> tuple[str, str]:
    parsed = urlsplit(value)
    try:
        parsed.port
    except ValueError as error:
        raise ValueError(f"{label} contains an invalid port") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
    ):
        raise ValueError(f"{label} must be a credential-free HTTPS URL without query or fragment")
    normalized_path = parsed.path.rstrip("/") or "/"
    if required_path is not None and normalized_path != required_path:
        raise ValueError(f"{label} path must be {required_path}")
    return value.rstrip("/"), _validated_host(parsed.hostname, f"{label} hostname")


def _proxy_sources(value: str) -> str:
    sources = [item.strip() for item in value.split(",") if item.strip()]
    if not sources:
        raise ValueError("at least one trusted proxy source is required when Cloudflare trust is enabled")
    for source in sources:
        try:
            ipaddress.ip_address(source)
        except ValueError as error:
            raise ValueError(f"trusted proxy source must be an individual IP address: {source}") from error
    return ",".join(ipaddress.ip_address(source).compressed for source in sources)


@dataclass(frozen=True)
class CanarySettings:
    owner: str
    commit: str
    public_origin: str
    routeros_rest_url: str
    routeros_rest_san: str
    external_root: str
    bridge: str
    canary_address: str
    gateway: str
    trust_cloudflare: bool = False
    trusted_proxy_sources: str = ""

    def validated(self) -> "ValidatedCanarySettings":
        owner = self.owner.casefold()
        if self.owner != owner or not _GHCR_OWNER.fullmatch(owner):
            raise ValueError("owner must be a lowercase GitHub user or organization name")
        if not _FULL_COMMIT.fullmatch(self.commit):
            raise ValueError("commit must be the full 40-character lowercase Git commit SHA")

        public_origin, _ = _https_url(self.public_origin, "public origin")
        if urlsplit(public_origin).path not in {"", "/"}:
            raise ValueError("public origin must not contain a path")
        routeros_rest_url, rest_hostname = _https_url(
            self.routeros_rest_url,
            "RouterOS REST URL",
            required_path="/rest",
        )
        confirmed_san = _validated_host(self.routeros_rest_san, "RouterOS REST SAN")
        if rest_hostname != confirmed_san:
            raise ValueError("RouterOS REST hostname must exactly match the confirmed certificate SAN")

        try:
            canary = ipaddress.ip_interface(self.canary_address)
            gateway = ipaddress.ip_address(self.gateway)
        except ValueError as error:
            raise ValueError("canary address and gateway must be valid IP values") from error
        if gateway.version != canary.version or gateway not in canary.network or gateway == canary.ip:
            raise ValueError("gateway must be a different usable address in the canary subnet")
        if canary.ip in {canary.network.network_address, canary.network.broadcast_address}:
            raise ValueError("canary address cannot be the network or broadcast address")
        if gateway in {canary.network.network_address, canary.network.broadcast_address}:
            raise ValueError("gateway cannot be the network or broadcast address")

        proxy_sources = ""
        if self.trust_cloudflare:
            proxy_sources = _proxy_sources(self.trusted_proxy_sources)
        elif self.trusted_proxy_sources.strip():
            raise ValueError("trusted proxy sources require --trust-cloudflare")

        return ValidatedCanarySettings(
            owner=owner,
            commit=self.commit,
            public_origin=public_origin,
            routeros_rest_url=routeros_rest_url,
            external_root=_validated_path(self.external_root),
            bridge=_validated_name(self.bridge, "bridge"),
            canary=canary,
            gateway=gateway,
            trust_cloudflare=self.trust_cloudflare,
            trusted_proxy_sources=proxy_sources,
        )


@dataclass(frozen=True)
class ValidatedCanarySettings:
    owner: str
    commit: str
    public_origin: str
    routeros_rest_url: str
    external_root: str
    bridge: str
    canary: ipaddress.IPv4Interface | ipaddress.IPv6Interface
    gateway: ipaddress.IPv4Address | ipaddress.IPv6Address
    trust_cloudflare: bool
    trusted_proxy_sources: str


def render_canary_plan(settings: CanarySettings) -> str:
    values = settings.validated()
    short = values.commit[:12]
    slug = f"vpn-gui-canary-{short}"
    veth = _validated_name(f"veth-{slug}", "VETH name")
    mounts = _validated_name(f"{slug}-mounts", "mount list")
    envs = _validated_name(f"{slug}-env", "environment list")
    comment = f"VPN GUI canary {short}"
    root = values.external_root
    image = f"{values.owner}/mikrotik-openvpn-gui:sha-{values.commit}"

    environment = {
        "PUBLIC_ORIGIN": values.public_origin,
        "ROUTEROS_REST_URL": values.routeros_rest_url,
        "ROUTEROS_CA_FILE": "/config/routeros-ca.crt",
        "ROUTEROS_INSECURE_TLS": "false",
        "DATABASE_PATH": "/data/dashboard.sqlite",
        "DROP_PRIVILEGES": "true",
        "TRUST_CLOUDFLARE": str(values.trust_cloudflare).lower(),
    }
    if values.trust_cloudflare:
        environment["TRUSTED_PROXY_SOURCES"] = values.trusted_proxy_sources

    commands = [
        "# REVIEW-ONLY CANARY PLAN: this file does not contain registry credentials.",
        "# Confirm every name, address, route, path, and free-space requirement against live RouterOS state.",
        "# Configure registry-url=https://ghcr.io and an expiring read:packages credential in a private session.",
        "# The image is relative to that registry. Do not use a mutable tag.",
        f"/interface/veth/add name={_quoted(veth)} address={_quoted(str(values.canary))} gateway={_quoted(str(values.gateway))}",
        f"/interface/bridge/port/add bridge={_quoted(values.bridge)} interface={_quoted(veth)}",
        f"/ip/address/add address={_quoted(f'{values.gateway}/{values.canary.network.prefixlen}')} interface={_quoted(values.bridge)} comment={_quoted(comment + ' gateway')}",
        f"/container/mounts/add list={_quoted(mounts)} src={_quoted(f'{root}/canary/{short}/data')} dst=/data",
        f"/container/mounts/add list={_quoted(mounts)} src={_quoted(f'{root}/config')} dst=/config",
    ]
    commands.extend(
        f"/container/envs/add list={_quoted(envs)} key={key} value={_quoted(value)}"
        for key, value in environment.items()
    )
    commands.extend(
        [
            f"/container/add remote-image={_quoted(image)} interface={_quoted(veth)} root-dir={_quoted(f'{root}/containers/{slug}')} mountlists={_quoted(mounts)} envlists={_quoted(envs)} logging=yes memory-high=134217728 memory-max=201326592 start-on-boot=no comment={_quoted(comment)}",
            "# Stop here. Inspect extraction, logs, certificate validation, and private health before manually starting or exposing the canary.",
            f"# Manual start after review: /container/start [find where comment={_quoted(comment)}]",
        ]
    )
    return "\n".join(commands) + "\n"


def argument_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Render an offline RouterOS plan for an immutable private-GHCR canary."
    )
    parser.add_argument("--owner", required=True, help="Lowercase GitHub owner with package read access")
    parser.add_argument("--commit", required=True, help="Full 40-character lowercase commit SHA")
    parser.add_argument("--public-origin", required=True, help="Credential-free HTTPS dashboard origin")
    parser.add_argument("--routeros-rest-url", required=True, help="Verified HTTPS RouterOS URL ending in /rest")
    parser.add_argument("--routeros-rest-san", required=True, help="Confirmed DNS or IP SAN used by the REST URL")
    parser.add_argument("--external-root", required=True, help="Relative RouterOS external-storage root")
    parser.add_argument("--bridge", required=True, help="Existing private container bridge")
    parser.add_argument("--canary-address", required=True, help="Unused canary address with prefix")
    parser.add_argument("--gateway", required=True, help="Unused router gateway in the canary subnet")
    parser.add_argument("--trust-cloudflare", action="store_true")
    parser.add_argument("--trusted-proxy-source", action="append", default=[])
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = argument_parser()
    arguments = parser.parse_args(argv)
    try:
        plan = render_canary_plan(
            CanarySettings(
                owner=arguments.owner,
                commit=arguments.commit,
                public_origin=arguments.public_origin,
                routeros_rest_url=arguments.routeros_rest_url,
                routeros_rest_san=arguments.routeros_rest_san,
                external_root=arguments.external_root,
                bridge=arguments.bridge,
                canary_address=arguments.canary_address,
                gateway=arguments.gateway,
                trust_cloudflare=arguments.trust_cloudflare,
                trusted_proxy_sources=",".join(arguments.trusted_proxy_source),
            )
        )
    except ValueError as error:
        parser.error(str(error))
    print(plan, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
