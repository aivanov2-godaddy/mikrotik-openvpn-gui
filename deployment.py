from __future__ import annotations

from typing import Any


PUBLIC_HOST = "vpn.wanted.sx"
CONTAINER_ADDRESS = "172.31.255.2"
CLOUDFLARE_ADDRESS_LIST = "vpn-dashboard-cloudflare"

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


def cloudflare_bulgaria_rule(hostname: str = PUBLIC_HOST) -> dict[str, Any]:
    return {
        "action": "block",
        "expression": f'(http.host eq "{hostname}" and not ip.src.country in {{"BG"}})',
        "description": "VPN Dashboard: allow Bulgaria only",
        "enabled": True,
        "ref": "vpn_dashboard_bulgaria_only",
        "position": {"index": 1},
    }


def routeros_origin_acl_script() -> str:
    """Return an idempotent RouterOS script for the web-origin perimeter."""
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
            f'dst-address={CONTAINER_ADDRESS} dst-port=8080,8081 '
            'comment="VPN Dashboard: origin block direct container" place-before=0',
            f'/ip/firewall/filter/add chain=forward action=accept protocol=tcp '
            f'src-address-list="{CLOUDFLARE_ADDRESS_LIST}" dst-address={CONTAINER_ADDRESS} dst-port=8081 '
            'comment="VPN Dashboard: origin allow Cloudflare HTTP" place-before=0',
            f'/ip/firewall/nat/add chain=dstnat action=dst-nat protocol=tcp in-interface-list=WAN '
            f'dst-port=80 to-addresses={CONTAINER_ADDRESS} to-ports=8081 '
            'comment="VPN Dashboard: HTTP redirect"',
        ]
    )
    return "\n".join(commands) + "\n"


def routeros_container_script() -> str:
    """Render the non-secret infrastructure configuration; adding the image is a separate step."""
    return "\n".join(
        [
            ':if ([:len [/interface/bridge/find where name="br-vpn-dashboard"]] = 0) do={ '
            '/interface/bridge/add name=br-vpn-dashboard comment="VPN Dashboard" }',
            ':if ([:len [/interface/veth/find where name="veth-vpn-dashboard"]] = 0) do={ '
            '/interface/veth/add name=veth-vpn-dashboard address=172.31.255.2/30 gateway=172.31.255.1 }',
            ':if ([:len [/interface/bridge/port/find where interface="veth-vpn-dashboard"]] = 0) do={ '
            '/interface/bridge/port/add bridge=br-vpn-dashboard interface=veth-vpn-dashboard }',
            ':if ([:len [/ip/address/find where address="172.31.255.1/30"]] = 0) do={ '
            '/ip/address/add address=172.31.255.1/30 interface=br-vpn-dashboard comment="VPN Dashboard" }',
            '/container/mounts/remove [find where list="vpn-dashboard-mounts"]',
            '/container/envs/remove [find where list="vpn-dashboard-env"]',
            '/container/mounts/add list=vpn-dashboard-mounts src=vpn-dashboard/app dst=/app',
            '/container/mounts/add list=vpn-dashboard-mounts src=vpn-dashboard/data dst=/data',
            '/container/envs/add list=vpn-dashboard-env key=PUBLIC_ORIGIN value=https://vpn.wanted.sx',
            '/container/envs/add list=vpn-dashboard-env key=ROUTEROS_REST_URL value=https://172.31.255.1:8443/rest',
            '/container/envs/add list=vpn-dashboard-env key=ROUTEROS_CA_FILE value=/app/ovpn-ca-2026.crt',
            '/container/envs/add list=vpn-dashboard-env key=ROUTEROS_INSECURE_TLS value=false',
            '/container/envs/add list=vpn-dashboard-env key=DATABASE_PATH value=/data/dashboard.sqlite',
            '/container/envs/add list=vpn-dashboard-env key=TRUST_CLOUDFLARE value=true',
            '/container/envs/add list=vpn-dashboard-env key=TRUSTED_PROXY_SOURCES value=172.31.255.1',
            '/container/envs/add list=vpn-dashboard-env key=DROP_PRIVILEGES value=true',
        ]
    ) + "\n"


def routeros_container_add_command() -> str:
    return (
        '/container/add remote-image=python:3.14-alpine name=vpn-dashboard '
        'interface=veth-vpn-dashboard root-dir=vpn-dashboard/root '
        'mountlists=vpn-dashboard-mounts envlists=vpn-dashboard-env '
        'entrypoint=python3 cmd="-B /app/app.py" workdir=/app logging=yes '
        'memory-high=134217728 memory-max=201326592 '
        'start-on-boot=yes comment="VPN Dashboard"'
    )
