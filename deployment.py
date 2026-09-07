"""Render non-secret Cloudflare and RouterOS origin-perimeter policy.

Container deployment intentionally lives in the offline GHCR canary-plan renderer
(`deploy_routeros_canary.py`). Direct host-mounted source deployment is retired.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Any


CLOUDFLARE_ADDRESS_LIST = "vpn-dashboard-cloudflare"
HOSTNAME_PATTERN = re.compile(
    r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
)

# Published at https://www.cloudflare.com/ips-v4 and /ips-v6 on 2026-08-04.
CLOUDFLARE_IPV4_RANGES = (
    "173.245.48.0/20",
    "103.21.244.0/22",
    "103.22.200.0/22",
    "103.31.4.0/22",
    "141.101.64.0/18",
    "108.162.192.0/18",
    "190.93.240.0/20",
    "188.114.96.0/20",
    "197.234.240.0/22",
    "198.41.128.0/17",
    "162.158.0.0/15",
    "104.16.0.0/13",
    "104.24.0.0/14",
    "172.64.0.0/13",
    "131.0.72.0/22",
)

CLOUDFLARE_IPV6_RANGES = (
    "2400:cb00::/32",
    "2606:4700::/32",
    "2803:f800::/32",
    "2405:b500::/32",
    "2405:8100::/32",
    "2a06:98c0::/29",
    "2c0f:f248::/32",
)


def normalize_cloudflare_hostname(hostname: str) -> str:
    """Return a safe canonical DNS name for a Cloudflare host-scoped rule."""
    normalized_host = hostname.strip().rstrip(".").lower()
    if not HOSTNAME_PATTERN.fullmatch(normalized_host):
        raise ValueError("hostname must be a non-empty DNS name")
    return normalized_host


def cloudflare_country_allowlist_rule(
    hostname: str, countries: tuple[str, ...], *, include_position: bool = True
) -> dict[str, Any]:
    """Create a host-scoped Cloudflare country allowlist rule.

    This optional edge policy is intentionally input-driven: a public clone
    must never inherit a hostname or geography policy from another deployment.
    """
    normalized_host = normalize_cloudflare_hostname(hostname)
    normalized_countries = tuple(country.strip().upper() for country in countries)
    if not normalized_countries or any(
        not re.fullmatch(r"[A-Z]{2}", country) for country in normalized_countries
    ):
        raise ValueError("at least one two-letter country code is required")
    allowed = ", ".join(f'"{country}"' for country in dict.fromkeys(normalized_countries))
    rule = {
        "action": "block",
        "expression": (
            f'(http.host eq "{normalized_host}" and not ip.src.country in {{{allowed}}})'
        ),
        "description": "VPN Dashboard: country allowlist",
        "enabled": True,
        "ref": "vpn_dashboard_bulgaria_only",
    }
    if include_position:
        rule["position"] = {"index": 1}
    return rule


def routeros_origin_acl_script(container_address: str) -> str:
    """Return an idempotent RouterOS script for the web-origin perimeter."""
    try:
        target = str(ipaddress.ip_address(container_address))
    except ValueError as error:
        raise ValueError("container_address must be an IPv4 address") from error
    if ipaddress.ip_address(target).version != 4:
        raise ValueError("container_address must be an IPv4 address")
    commands = [
        f'/ip/firewall/address-list/remove [find where list="{CLOUDFLARE_ADDRESS_LIST}"]',
        '/ip/firewall/filter/remove [find where comment~"^VPN Dashboard: origin"]',
        '/ip/firewall/nat/remove [find where comment="VPN Dashboard: HTTP redirect"]',
    ]
    commands.extend(
        f'/ip/firewall/address-list/add list="{CLOUDFLARE_ADDRESS_LIST}" address={network} '
        f'comment="VPN Dashboard: Cloudflare {network}"'
        for network in CLOUDFLARE_IPV4_RANGES
    )
    # Add drop first, then place allow before it. Both land before permissive legacy rules.
    commands.extend(
        [
            '/ip/firewall/filter/add chain=input action=drop protocol=tcp dst-port=443 '
            'comment="VPN Dashboard: origin drop non-Cloudflare HTTPS" place-before=0',
            f'/ip/firewall/filter/add chain=input action=accept protocol=tcp dst-port=443 '
            f'src-address-list="{CLOUDFLARE_ADDRESS_LIST}" '
            'comment="VPN Dashboard: origin allow Cloudflare HTTPS" place-before=0',
            f'/ip/firewall/filter/add chain=forward action=drop protocol=tcp '
            f'dst-address={target} dst-port=8080,8081 '
            'comment="VPN Dashboard: origin block direct container" place-before=0',
            f'/ip/firewall/filter/add chain=forward action=accept protocol=tcp '
            f'src-address-list="{CLOUDFLARE_ADDRESS_LIST}" dst-address={target} dst-port=8081 '
            'comment="VPN Dashboard: origin allow Cloudflare HTTP" place-before=0',
            f'/ip/firewall/nat/add chain=dstnat action=dst-nat protocol=tcp in-interface-list=WAN '
            f'dst-port=80 to-addresses={target} to-ports=8081 '
            'comment="VPN Dashboard: HTTP redirect"',
        ]
    )
    return "\n".join(commands) + "\n"
