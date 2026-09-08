"""Validated, non-secret runtime configuration for the VPN dashboard.

The container image is deliberately portable.  Values that identify a specific
router, public site, or OpenVPN topology belong in the RouterOS container
environment list, never in source control or the image itself.
"""

from __future__ import annotations

import ipaddress
import os
import re
from dataclasses import dataclass
from typing import Mapping
from urllib.parse import urlsplit


class ConfigurationError(ValueError):
    """Raised when an instance setting is missing or unsafe to use."""


_ROUTEROS_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_DNS_LABEL = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_TRUSTED_PROXY_HEADERS = {"cf-connecting-ip": "CF-Connecting-IP", "x-forwarded-for": "X-Forwarded-For"}


def _value(values: Mapping[str, str], name: str, default: str = "") -> str:
    return str(values.get(name, default)).strip()


def _boolean(values: Mapping[str, str], name: str, default: bool = False) -> bool:
    raw = _value(values, name)
    if not raw:
        return default
    if raw.casefold() in {"1", "true", "yes", "on"}:
        return True
    if raw.casefold() in {"0", "false", "no", "off"}:
        return False
    raise ConfigurationError(f"{name} must be true or false")


def _retention_days(values: Mapping[str, str]) -> int:
    """Return a deliberately bounded retention period for non-secret history."""
    raw = _value(values, "HISTORY_RETENTION_DAYS", "365")
    try:
        days = int(raw)
    except ValueError as error:
        raise ConfigurationError("HISTORY_RETENTION_DAYS must be a whole number") from error
    if not 30 <= days <= 3650:
        raise ConfigurationError("HISTORY_RETENTION_DAYS must be between 30 and 3650")
    return days


def _hostname_or_ip(value: str, name: str) -> str:
    candidate = value.rstrip(".")
    try:
        return ipaddress.ip_address(candidate).compressed
    except ValueError:
        if (
            not candidate
            or len(candidate) > 253
            or any(not _DNS_LABEL.fullmatch(label) for label in candidate.split("."))
        ):
            raise ConfigurationError(f"{name} must be a DNS name or IP address") from None
        return candidate.casefold()


def _routeros_name(value: str, name: str) -> str:
    if not _ROUTEROS_NAME.fullmatch(value):
        raise ConfigurationError(f"{name} must be a RouterOS-safe name")
    return value


def _origin(value: str) -> str:
    parsed = urlsplit(value)
    try:
        parsed.port
    except ValueError as error:
        raise ConfigurationError("PUBLIC_ORIGIN contains an invalid port") from error
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ConfigurationError(
            "PUBLIC_ORIGIN must be a credential-free HTTP(S) origin without a path"
        )
    host = _hostname_or_ip(parsed.hostname, "PUBLIC_ORIGIN hostname")
    if parsed.scheme == "http" and host not in {"localhost", "127.0.0.1", "::1"}:
        raise ConfigurationError("PUBLIC_ORIGIN must use HTTPS except for a loopback development origin")
    return value.rstrip("/")


def _rest_url(value: str) -> str:
    parsed = urlsplit(value)
    try:
        parsed.port
    except ValueError as error:
        raise ConfigurationError("ROUTEROS_REST_URL contains an invalid port") from error
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") != "/rest"
    ):
        raise ConfigurationError(
            "ROUTEROS_REST_URL must be a credential-free HTTPS URL ending in /rest"
        )
    _hostname_or_ip(parsed.hostname, "ROUTEROS_REST_URL hostname")
    return value.rstrip("/")


def _webhook_url(value: str) -> str | None:
    if not value:
        return None
    parsed = urlsplit(value)
    try:
        parsed.port
    except ValueError as error:
        raise ConfigurationError("WEBHOOK_URL contains an invalid port") from error
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise ConfigurationError("WEBHOOK_URL must be a credential-free HTTPS URL")
    _hostname_or_ip(parsed.hostname, "WEBHOOK_URL hostname")
    return value


def _proxy_source(value: str) -> str:
    try:
        return ipaddress.ip_address(value).compressed
    except ValueError as error:
        raise ConfigurationError("TRUSTED_PROXY_SOURCES must contain individual IP addresses") from error


def _trusted_proxy_header(value: str) -> str:
    header = _TRUSTED_PROXY_HEADERS.get(value.casefold())
    if header is None:
        allowed = ", ".join(_TRUSTED_PROXY_HEADERS.values())
        raise ConfigurationError(f"TRUSTED_PROXY_HEADER must be one of: {allowed}")
    return header


def _access_layer_label(value: str, *, default: str) -> str:
    label = value or default
    if len(label) > 80 or any(ord(character) < 32 for character in label):
        raise ConfigurationError("ACCESS_LAYER_LABEL must be a short, printable label")
    return label


@dataclass(frozen=True, slots=True)
class OpenVPNTopology:
    """The RouterOS objects and network values needed to issue a client profile."""

    ppp_profile: str = ""
    server_name: str = ""
    ca_name: str = ""
    host: str = ""
    server_identity: str = ""
    lan_cidr: str = ""
    router_dns: str = ""

    @classmethod
    def from_values(cls, values: Mapping[str, str]) -> "OpenVPNTopology":
        profile = _value(values, "OVPN_PPP_PROFILE")
        server = _value(values, "OVPN_SERVER_NAME")
        ca = _value(values, "OVPN_CA_NAME")
        host = _value(values, "OVPN_HOST")
        identity = _value(values, "OVPN_SERVER_IDENTITY")
        lan_cidr = _value(values, "VPN_LAN_CIDR")
        router_dns = _value(values, "VPN_ROUTER_DNS")

        if profile:
            profile = _routeros_name(profile, "OVPN_PPP_PROFILE")
        if server:
            server = _routeros_name(server, "OVPN_SERVER_NAME")
        if ca:
            ca = _routeros_name(ca, "OVPN_CA_NAME")
        if host:
            host = _hostname_or_ip(host, "OVPN_HOST")
        if identity:
            identity = _hostname_or_ip(identity, "OVPN_SERVER_IDENTITY")
        elif host:
            identity = host
        if lan_cidr:
            try:
                network = ipaddress.ip_network(lan_cidr, strict=True)
            except ValueError as error:
                raise ConfigurationError("VPN_LAN_CIDR must be a canonical IPv4 network") from error
            if network.version != 4:
                raise ConfigurationError("VPN_LAN_CIDR must be an IPv4 network")
            lan_cidr = str(network)
        if router_dns:
            try:
                router_dns = ipaddress.ip_address(router_dns).compressed
            except ValueError as error:
                raise ConfigurationError("VPN_ROUTER_DNS must be an IP address") from error
        return cls(profile, server, ca, host, identity, lan_cidr, router_dns)

    def require_profile_generation(self, *, policy: str, dns_mode: str) -> None:
        missing = [
            name
            for name, value in (
                ("OVPN_PPP_PROFILE", self.ppp_profile),
                ("OVPN_SERVER_NAME", self.server_name),
                ("OVPN_CA_NAME", self.ca_name),
                ("OVPN_HOST", self.host),
                ("OVPN_SERVER_IDENTITY", self.server_identity),
            )
            if not value
        ]
        if policy in {"full-tunnel", "lan-only"} and not self.lan_cidr:
            missing.append("VPN_LAN_CIDR")
        if dns_mode == "router" and not self.router_dns:
            missing.append("VPN_ROUTER_DNS")
        if missing:
            joined = ", ".join(missing)
            raise ConfigurationError(
                f"OpenVPN profile issuing is not configured. Set {joined} in the container environment."
            )


@dataclass(frozen=True, slots=True)
class RuntimeConfig:
    public_origin: str
    routeros_rest_url: str
    routeros_ca_file: str | None
    routeros_insecure_tls: bool
    database_path: str
    trust_cloudflare: bool
    trusted_proxy_sources: tuple[str, ...]
    trusted_proxy_header: str | None
    access_layer_label: str
    dashboard_name: str
    router_display_name: str
    history_retention_days: int
    webhook_url: str | None
    webhook_secret: str | None
    topology: OpenVPNTopology

    @classmethod
    def from_environ(cls, values: Mapping[str, str] | None = None) -> "RuntimeConfig":
        source = os.environ if values is None else values
        public_origin = _origin(_value(source, "PUBLIC_ORIGIN", "http://localhost"))
        routeros_rest_url = _rest_url(
            _value(source, "ROUTEROS_REST_URL", "https://127.0.0.1:8443/rest")
        )
        trust_cloudflare = _boolean(source, "TRUST_CLOUDFLARE")
        sources = tuple(
            _proxy_source(item.strip())
            for item in _value(source, "TRUSTED_PROXY_SOURCES").split(",")
            if item.strip()
        )
        configured_header = _value(source, "TRUSTED_PROXY_HEADER")
        trusted_proxy_header = (
            _trusted_proxy_header(configured_header) if configured_header else None
        )
        if trust_cloudflare and not sources:
            raise ConfigurationError(
                "TRUSTED_PROXY_SOURCES is required when TRUST_CLOUDFLARE is true"
            )
        if trust_cloudflare:
            if trusted_proxy_header is None:
                trusted_proxy_header = "CF-Connecting-IP"
            elif trusted_proxy_header != "CF-Connecting-IP":
                raise ConfigurationError(
                    "TRUST_CLOUDFLARE requires TRUSTED_PROXY_HEADER=CF-Connecting-IP"
                )
        elif sources and trusted_proxy_header is None:
            raise ConfigurationError(
                "TRUSTED_PROXY_HEADER is required when TRUSTED_PROXY_SOURCES is set"
            )
        elif trusted_proxy_header and not sources:
            raise ConfigurationError(
                "TRUSTED_PROXY_SOURCES is required when TRUSTED_PROXY_HEADER is set"
            )
        webhook_url = _webhook_url(_value(source, "WEBHOOK_URL"))
        webhook_secret = _value(source, "WEBHOOK_SIGNING_SECRET") or None
        if bool(webhook_url) != bool(webhook_secret):
            raise ConfigurationError("WEBHOOK_URL and WEBHOOK_SIGNING_SECRET must be set together")
        if webhook_secret and len(webhook_secret) < 32:
            raise ConfigurationError("WEBHOOK_SIGNING_SECRET must be at least 32 characters")
        return cls(
            public_origin=public_origin,
            routeros_rest_url=routeros_rest_url,
            routeros_ca_file=_value(source, "ROUTEROS_CA_FILE") or None,
            routeros_insecure_tls=_boolean(source, "ROUTEROS_INSECURE_TLS"),
            database_path=_value(source, "DATABASE_PATH", "/data/dashboard.sqlite"),
            trust_cloudflare=trust_cloudflare,
            trusted_proxy_sources=sources,
            trusted_proxy_header=trusted_proxy_header,
            access_layer_label=_access_layer_label(
                _value(source, "ACCESS_LAYER_LABEL"),
                default="Cloudflare Access" if trust_cloudflare else "Direct HTTPS",
            ),
            dashboard_name=_value(source, "DASHBOARD_NAME", "MikroTik OpenVPN GUI"),
            router_display_name=_value(source, "ROUTER_DISPLAY_NAME", "RouterOS"),
            history_retention_days=_retention_days(source),
            webhook_url=webhook_url,
            webhook_secret=webhook_secret,
            topology=OpenVPNTopology.from_values(source),
        )
