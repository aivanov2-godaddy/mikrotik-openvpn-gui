from __future__ import annotations

import base64
import binascii
import hashlib
import ipaddress
import json
import re
import secrets
import socket
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from config import ConfigurationError, OpenVPNTopology


class RouterOSError(RuntimeError):
    def __init__(
        self,
        message: str,
        status: int | None = None,
        *,
        failure_kind: str | None = None,
    ) -> None:
        super().__init__(message)
        self.status = status
        self.failure_kind = failure_kind


@dataclass(frozen=True, slots=True)
class RouterOSCredentials:
    username: str
    password: str


@dataclass(frozen=True, slots=True)
class ProvisionedProfile:
    profile: bytes
    certificate_id: str | None
    certificate_name: str
    fingerprint: str | None


def _records(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    raise RouterOSError("RouterOS returned an unexpected JSON shape", failure_kind="invalid_response")


def _yes(value: Any) -> bool:
    return str(value).lower() in {"yes", "true", "1"}


def _certificate_is_revoked(value: Any) -> bool:
    """RouterOS exposes ``revoked`` as a timestamp, not a yes/no flag."""
    if isinstance(value, bool):
        return value
    return str(value or "").strip().casefold() not in {"", "no", "false", "0", "none"}


def _integer(value: Any) -> int:
    try:
        return max(0, int(str(value or "0")))
    except (TypeError, ValueError):
        return 0


def _crl_is_current(value: Any) -> bool:
    """Treat missing or malformed CRL expiry data as unsafe."""
    try:
        return datetime.strptime(str(value), "%Y-%m-%d %H:%M:%S") > datetime.now()
    except (TypeError, ValueError):
        return False


def _slug(value: str, maximum: int = 42) -> str:
    normalized = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (normalized or "device")[:maximum].rstrip("-")


def harden_profile(
    profile: str,
    *,
    server_identity: str,
    lan_cidr: str | None,
    router_dns: str | None,
    policy: str = "full-tunnel",
    dns_mode: str = "router",
) -> str:
    normalized_policy = policy if policy in {"full-tunnel", "lan-only", "internet-only"} else "full-tunnel"
    normalized_dns = dns_mode if dns_mode in {"router", "cloudflare"} else "router"
    if not server_identity:
        raise RouterOSError("OpenVPN server identity is not configured")
    network: ipaddress.IPv4Network | None = None
    if lan_cidr:
        try:
            candidate = ipaddress.ip_network(lan_cidr, strict=True)
        except ValueError as error:
            raise RouterOSError("VPN_LAN_CIDR is invalid") from error
        if candidate.version != 4:
            raise RouterOSError("VPN_LAN_CIDR must be IPv4")
        network = candidate
    if normalized_policy in {"full-tunnel", "lan-only"} and network is None:
        raise RouterOSError("VPN_LAN_CIDR is required for this traffic policy")
    if normalized_dns == "router" and not router_dns:
        raise RouterOSError("VPN_ROUTER_DNS is required when RouterOS DNS is selected")
    required = [
        "auth-nocache",
        f"verify-x509-name {server_identity} name",
    ]
    normalized = profile.replace("\r\n", "\n").replace("\r", "\n")
    ca_index = normalized.find("<ca>")
    if ca_index < 0:
        raise RouterOSError("Generated RouterOS profile does not contain an inline CA")
    header = normalized[:ca_index].rstrip("\n")
    payload = normalized[ca_index:].lstrip("\n")
    lines = [line.strip() for line in header.splitlines()]
    lines = [
        line for line in lines
        if not line.startswith("redirect-gateway")
        and not (
            network is not None
            and line == f"route {network.network_address} {network.netmask}"
        )
        and not line.startswith("dhcp-option DNS ")
        and not line.startswith("verify-x509-name ")
    ]
    header = "\n".join(lines)
    existing = set(lines)
    for directive in required:
        if directive not in existing:
            header += "\n" + directive
    if normalized_policy in {"full-tunnel", "internet-only"}:
        header += "\nredirect-gateway def1"
    if normalized_policy in {"full-tunnel", "lan-only"} and network is not None:
        header += f"\nroute {network.network_address} {network.netmask}"
    dns_server = "1.1.1.1" if normalized_dns == "cloudflare" else router_dns
    if not dns_server:
        raise RouterOSError("VPN DNS is not configured")
    header += f"\ndhcp-option DNS {dns_server}"
    hardened = header + "\n" + payload
    if not all(tag in hardened for tag in ("<ca>", "<cert>", "<key>")):
        raise RouterOSError("Generated RouterOS profile is missing inline credentials")
    return hardened.rstrip("\n") + "\n"


class RouterOSClient:
    def __init__(
        self,
        base_url: str,
        *,
        ca_file: str | None = None,
        timeout: float = 15,
        insecure_tls: bool = False,
        topology: OpenVPNTopology | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.topology = topology or OpenVPNTopology()
        self.ovpn_profile = self.topology.ppp_profile
        self.ovpn_server = self.topology.server_name
        self.ovpn_ca = self.topology.ca_name
        self.ovpn_host = self.topology.host
        if self.base_url.startswith("https://"):
            if insecure_tls:
                self.ssl_context = ssl._create_unverified_context()  # noqa: SLF001 - explicit test option
            else:
                self.ssl_context = ssl.create_default_context(cafile=ca_file)
        else:
            self.ssl_context = None

    def _request(
        self,
        method: str,
        path: str,
        credentials: RouterOSCredentials,
        *,
        body: dict[str, Any] | None = None,
        query: dict[str, Any] | None = None,
    ) -> Any:
        target = self.base_url + "/" + path.lstrip("/")
        if query:
            target += "?" + urllib.parse.urlencode(query, doseq=True, safe=".,*")
        encoded_body = None
        headers = {"Accept": "application/json"}
        if body is not None:
            encoded_body = json.dumps(body, separators=(",", ":")).encode("utf-8")
            headers["Content-Type"] = "application/json"
        basic = base64.b64encode(
            f"{credentials.username}:{credentials.password}".encode("utf-8")
        ).decode("ascii")
        headers["Authorization"] = f"Basic {basic}"
        request = urllib.request.Request(
            target,
            data=encoded_body,
            headers=headers,
            method=method,
        )
        try:
            with urllib.request.urlopen(
                request,
                timeout=self.timeout,
                context=self.ssl_context,
            ) as response:
                payload = response.read()
        except urllib.error.HTTPError as error:
            if error.code in {401, 403}:
                error.close()
                raise RouterOSError("RouterOS rejected the supplied credentials", error.code) from None
            detail = ""
            try:
                error_payload = json.loads(error.read().decode("utf-8"))
                if isinstance(error_payload, dict):
                    detail = str(
                        error_payload.get("detail")
                        or error_payload.get("message")
                        or ""
                    ).strip()
            except (UnicodeDecodeError, json.JSONDecodeError, OSError):
                pass
            error.close()
            suffix = f": {detail}" if detail else ""
            raise RouterOSError(
                f"RouterOS request failed with HTTP {error.code}{suffix}", error.code
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            reason = error.reason if isinstance(error, urllib.error.URLError) else error
            if isinstance(reason, ssl.SSLError):
                failure_kind = "tls"
            elif isinstance(reason, (TimeoutError, socket.timeout)):
                failure_kind = "timeout"
            else:
                failure_kind = None
            raise RouterOSError(f"RouterOS is unavailable: {error}", failure_kind=failure_kind) from None
        if not payload:
            return None
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RouterOSError(
                "RouterOS returned an invalid JSON response",
                failure_kind="invalid_response",
            ) from None

    def verify_credentials(self, credentials: RouterOSCredentials) -> dict[str, Any]:
        records = _records(self._request("GET", "/system/resource", credentials))
        if not records:
            raise RouterOSError("RouterOS returned no system resource record")
        return records[0]

    def get_bootstrap_inventory(self, credentials: RouterOSCredentials) -> dict[str, Any]:
        """Read the non-secret RouterOS objects needed by the bootstrap wizard.

        Every optional probe is isolated so restricted RouterOS accounts or older
        builds produce an ``unavailable`` result instead of turning the whole
        review into a write-capable operation.  This method never mutates state.
        """
        resource = self.verify_credentials(credentials)

        def optional(path: str, *, proplist: str) -> list[dict[str, Any]] | None:
            try:
                return _records(self._request("GET", path, credentials, query={".proplist": proplist}))
            except RouterOSError:
                return None

        return {
            "resource": resource,
            "packages": optional("/system/package", proplist="name,version,disabled") ,
            "ovpn_servers": optional(
                "/interface/ovpn-server/server",
                proplist="name,disabled,protocol,port,certificate,require-client-certificate,tls-version",
            ),
            "ppp_profiles": optional("/ppp/profile", proplist="name,local-address,remote-address"),
            "certificates": optional(
                "/certificate",
                proplist="name,common-name,ca,issuer,key-usage,private-key,invalid-after,revoked",
            ),
            "dns": optional("/ip/dns", proplist="servers,allow-remote-requests"),
            "firewall": optional(
                "/ip/firewall/filter",
                proplist="chain,action,protocol,dst-port,disabled,comment",
            ),
        }

    def get_admin_role(self, credentials: RouterOSCredentials) -> str | None:
        try:
            records = _records(
                self._request(
                    "GET",
                    "/user",
                    credentials,
                    query={"name": credentials.username, ".proplist": "name,group,disabled"},
                )
            )
        except RouterOSError as error:
            # A failed or unsupported privilege lookup must never grant Owner.
            # Invalid credentials/account disablement revokes; other lookup
            # failures retain only the least-privileged dashboard role.
            return None if error.status == 401 else "read_only"
        record = next(
            (item for item in records if str(item.get("name", "")) == credentials.username),
            None,
        )
        if record is None or str(record.get("disabled", "no")).strip().casefold() in {"yes", "true", "1"}:
            return None
        group = str(record.get("group", "full")).strip().lower()
        # RouterOS groups are the identity source.  The additional named
        # groups are optional custom groups; unknown groups fail closed in the
        # dashboard's role normalizer rather than inheriting owner access.
        if group in {"read", "readonly", "read-only"}:
            return "read_only"
        if group in {"audit", "auditor"}:
            return "auditor"
        if group in {"security", "security-operator", "security_operator"}:
            return "security_operator"
        if group in {"write", "operator", "policy", "administrator", "admin"}:
            return "administrator"
        if group in {"full", "owner"}:
            return "owner"
        return "read_only"

    def get_management_exposure(self, credentials: RouterOSCredentials) -> dict[str, Any]:
        """Read a tightly allowlisted RouterOS access snapshot; never mutate state."""

        states: dict[str, str] = {}

        def read(path: str, source: str, proplist: str, *, name: str | None = None) -> list[dict[str, Any]] | None:
            query: dict[str, Any] = {".proplist": proplist}
            if name is not None:
                query["name"] = name
            try:
                records = _records(self._request("GET", path, credentials, query=query))
            except RouterOSError as error:
                states[source] = "unsupported" if error.status == 404 else "unknown"
                return None
            states[source] = "verified"
            # Some RouterOS versions and test doubles may disregard .proplist.
            # Keep unrequested values, including passwords and addresses other than
            # the derived scope flag, from ever crossing this boundary.
            allowed = set(proplist.split(","))
            return [{key: value for key, value in record.items() if key in allowed} for record in records]

        account_records = read("/user", "account", "name,group,disabled,address", name=credentials.username)
        account = next(
            (record for record in account_records or [] if str(record.get("name", "")) == credentials.username),
            None,
        )
        if account is None and states.get("account") == "verified":
            states["account"] = "unknown"
        group_name = str(account.get("group", "")).strip() if account else ""
        group_records = read("/user/group", "group", "name,policy", name=group_name) if group_name else None
        group = next(
            (record for record in group_records or [] if str(record.get("name", "")).casefold() == group_name.casefold()),
            None,
        )
        if group_name and group is None and states.get("group") == "verified":
            states["group"] = "unknown"
        services = read(
            "/ip/service", "services", "name,disabled,available-from,address,certificate",
        )
        # RouterOS currently documents `available-from`; `address` is its
        # deprecated alias. Older releases may reject the newer property in a
        # .proplist, so retry with the legacy spelling without widening reads.
        if services is None and states.get("services") == "unknown":
            services = read("/ip/service", "services", "name,disabled,address,certificate")
        active_records = read("/user/active", "active-source", "name,via,address", name=credentials.username)
        matching_sessions = [
            record for record in active_records or []
            if str(record.get("name", "")) == credentials.username
            and str(record.get("via", "")).casefold() == "rest-api"
            and str(record.get("address", "")).strip()
        ]
        active_source = matching_sessions[0].get("address") if len(matching_sessions) == 1 else None
        if active_source is not None:
            try:
                ipaddress.ip_address(str(active_source).strip().strip("[]").split("%", 1)[0])
            except ValueError:
                active_source = None
        active_source_status = states.get("active-source", "unknown")
        if active_source is not None:
            active_source_status = "verified"
        elif active_source_status == "verified":
            active_source_status = "unknown"
        states["active-source"] = active_source_status
        rest_service = "www-ssl" if self.base_url.startswith("https://") else "www"
        return {
            "account": account,
            "group": group,
            "services": services,
            "active_source": active_source,
            "active_source_status": active_source_status,
            "rest_service": rest_service,
            "source_status": states,
        }

    def create_configuration_export(
        self, credentials: RouterOSCredentials, *, name: str
    ) -> str:
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", name).strip("-") or "vpn-dashboard-checkpoint"
        if not safe_name.endswith(".rsc"):
            safe_name += ".rsc"
        self._request("POST", "/export", credentials, body={"file": safe_name, "compact": ""})
        return safe_name

    def get_ovpn_server_status(self, credentials: RouterOSCredentials) -> dict[str, Any]:
        records = _records(
            self._request(
                "GET",
                "/interface/ovpn-server/server",
                credentials,
                query={
                    ".proplist": (
                        ".id,name,disabled,protocol,port,require-client-certificate,"
                        "tls-version,auth,cipher,redirect-gateway,user-auth-method,"
                        "reneg-sec,certificate"
                    )
                },
            )
        )
        record = (
            next(
                (item for item in records if str(item.get("name", "")) == self.ovpn_server),
                None,
            )
            if self.ovpn_server
            else (records[0] if records else None)
        )
        if not record:
            raise RouterOSError("Configured OpenVPN server was not found")
        return {
            "name": str(record.get("name", self.ovpn_server)),
            "enabled": not _yes(record.get("disabled", "no")),
            "protocol": str(record.get("protocol", "")),
            "port": _integer(record.get("port")),
            "require_client_certificate": _yes(record.get("require-client-certificate", "no")),
            "tls_version": str(record.get("tls-version", "")),
            "auth": str(record.get("auth", "")),
            "cipher": str(record.get("cipher", "")),
            "redirect_gateway": str(record.get("redirect-gateway", "")),
            "user_auth_method": str(record.get("user-auth-method", "")),
            "reneg_sec": _integer(record.get("reneg-sec")),
            "certificate": str(record.get("certificate", "")),
        }

    def get_certificate_settings(self, credentials: RouterOSCredentials) -> dict[str, Any]:
        records = _records(self._request("GET", "/certificate/settings", credentials))
        record = records[0] if records else {}
        ca_records = _records(
            self._request(
                "GET",
                "/certificate",
                credentials,
                query={
                    "name": self.ovpn_ca,
                    ".proplist": "name,ca-crl-host,trusted",
                },
            )
        )
        active_ca = ca_records[0] if ca_records else {}
        crl_records = _records(
            self._request(
                "GET",
                "/certificate/crl",
                credentials,
                query={".proplist": "cert,revoked,next-update,last-update"},
            )
        )
        downloaded_ca_crl = any(
            str(item.get("cert", "")) == self.ovpn_ca
            and str(item.get("revoked", "")).casefold() != "unknown"
            and _crl_is_current(item.get("next-update"))
            for item in crl_records
        )
        # RouterOS does not put a CRL generated by its own signing CA in
        # /certificate/crl; that endpoint lists downloaded CRLs. A signed,
        # trusted authority with ca-crl-host has RouterOS' local CRL enabled
        # (shown as the L flag in the terminal / WinBox certificate view).
        router_hosted_ca_crl = (
            _yes(active_ca.get("trusted", "no"))
            and bool(str(active_ca.get("ca-crl-host", "")).strip())
        )
        active_ca_crl = downloaded_ca_crl or router_hosted_ca_crl
        crl_download = _yes(record.get("crl-download", "no"))
        crl_use = _yes(record.get("crl-use", "no"))
        crl_store = str(record.get("crl-store", ""))
        return {
            "crl_download": crl_download,
            "crl_use": crl_use,
            "crl_store": crl_store,
            "active_ovpn_ca_crl": active_ca_crl,
            "router_hosted_ovpn_ca_crl": router_hosted_ca_crl,
            "crl_ready": crl_download and crl_use and crl_store == "system" and active_ca_crl,
        }

    def get_public_endpoint(self, credentials: RouterOSCredentials) -> dict[str, str]:
        """Read the public address reported by RouterOS Cloud."""
        records = _records(
            self._request(
                "GET",
                "/ip/cloud",
                credentials,
                query={".proplist": "public-address"},
            )
        )
        record = records[0] if records else {}
        return {
            "public_ip": str(record.get("public-address", "")),
        }

    def list_ovpn_client_certificates(
        self, credentials: RouterOSCredentials, *, include_legacy: bool = False
    ) -> list[dict[str, Any]]:
        """List OpenVPN client identities.

        The normal inventory is deliberately limited to the configured CA.
        During a CA migration the dashboard must also discover identities
        issued by the previous CA, so the caller can opt into the broader,
        still TLS-client-only, inventory.
        """
        query: dict[str, Any] = {
            ".proplist": (
                ".id,name,common-name,fingerprint,issuer,invalid-after,"
                "expires-after,revoked,key-usage,trusted,ca"
            )
        }
        if self.ovpn_ca and not include_legacy:
            query["ca"] = self.ovpn_ca
        records = _records(
            self._request(
                "GET",
                "/certificate",
                credentials,
                query=query,
            )
        )
        clients: list[dict[str, Any]] = []
        for item in records:
            key_usage = str(item.get("key-usage", ""))
            issuer = str(item.get("issuer", ""))
            certificate_authority = str(item.get("ca", ""))
            if "tls-client" not in key_usage or (
                self.ovpn_ca and not include_legacy and certificate_authority != self.ovpn_ca
            ):
                continue
            clients.append(
                {
                    "id": str(item.get(".id", "")),
                    "name": str(item.get("name", "")),
                    "common_name": str(item.get("common-name", "")),
                    "fingerprint": str(item.get("fingerprint", "")),
                    "issuer": issuer,
                    "certificate_authority": certificate_authority,
                    "invalid_after": str(item.get("invalid-after", "")),
                    "expires_after": str(item.get("expires-after", "")),
                    "revoked": _certificate_is_revoked(item.get("revoked", "no")),
                    "trusted": _yes(item.get("trusted", "no")),
                }
            )
        return sorted(clients, key=lambda item: str(item["name"]).casefold())

    def list_ovpn_users(self, credentials: RouterOSCredentials) -> list[dict[str, Any]]:
        result = _records(
            self._request(
                "GET",
                "/ppp/secret",
                credentials,
                query={".proplist": ".id,name,service,profile,comment,disabled"},
            )
        )
        users = []
        for item in result:
            if item.get("service") != "ovpn":
                continue
            users.append(
                {
                    "id": item.get(".id", ""),
                    "name": item.get("name", ""),
                    "profile": item.get("profile", ""),
                    "comment": item.get("comment", ""),
                    "disabled": _yes(item.get("disabled", "no")),
                }
            )
        return sorted(users, key=lambda user: str(user["name"]).casefold())

    def list_active_ovpn_sessions(
        self, credentials: RouterOSCredentials
    ) -> list[dict[str, Any]]:
        """Return live OpenVPN sessions enriched with cumulative interface counters.

        RouterOS exposes authentication/session details under ``/ppp/active`` and
        traffic counters under ``/interface``.  Joining both resources avoids the
        continuous ``monitor-traffic`` command and keeps dashboard polling cheap.
        """
        active = _records(
            self._request(
                "GET",
                "/ppp/active",
                credentials,
                query={
                    ".proplist": (
                        ".id,name,service,caller-id,address,uptime,encoding,"
                        "session-id,comment"
                    )
                },
            )
        )
        interfaces = _records(
            self._request(
                "GET",
                "/interface",
                credentials,
                query={
                    ".proplist": (
                        ".id,name,type,running,actual-mtu,rx-byte,tx-byte,"
                        "rx-packet,tx-packet,rx-drop,tx-drop,rx-error,tx-error"
                    )
                },
            )
        )
        ovpn_interfaces = {
            str(item.get("name", "")): item
            for item in interfaces
            if item.get("type") == "ovpn-in" and _yes(item.get("running", "no"))
        }
        sessions: list[dict[str, Any]] = []
        for item in active:
            if item.get("service") != "ovpn":
                continue
            username = str(item.get("name", ""))
            interface_name = f"<ovpn-{username}>"
            interface = ovpn_interfaces.get(interface_name, {})
            sessions.append(
                {
                    "id": str(item.get(".id", "")),
                    "name": username,
                    "source_address": str(item.get("caller-id", "")),
                    "vpn_address": str(item.get("address", "")),
                    "uptime": str(item.get("uptime", "")),
                    "encoding": str(item.get("encoding", "")),
                    "session_id": str(item.get("session-id", "")),
                    "comment": str(item.get("comment", "")),
                    "interface": str(interface.get("name", interface_name)),
                    "mtu": _integer(interface.get("actual-mtu")),
                    "rx_bytes": _integer(interface.get("rx-byte")),
                    "tx_bytes": _integer(interface.get("tx-byte")),
                    "rx_packets": _integer(interface.get("rx-packet")),
                    "tx_packets": _integer(interface.get("tx-packet")),
                    "rx_drops": _integer(interface.get("rx-drop")),
                    "tx_drops": _integer(interface.get("tx-drop")),
                    "rx_errors": _integer(interface.get("rx-error")),
                    "tx_errors": _integer(interface.get("tx-error")),
                }
            )
        return sorted(sessions, key=lambda session: str(session["name"]).casefold())

    def terminate_session(
        self, credentials: RouterOSCredentials, *, session_id: str
    ) -> None:
        safe_id = urllib.parse.quote(session_id, safe="*")
        self._request("DELETE", f"/ppp/active/{safe_id}", credentials)

    def create_user(
        self,
        credentials: RouterOSCredentials,
        *,
        username: str,
        password: str,
        comment: str,
        profile: str | None = None,
    ) -> dict[str, Any]:
        if not (profile or self.ovpn_profile):
            raise RouterOSError("OVPN_PPP_PROFILE must be configured before creating VPN users")
        result = self._request(
            "PUT",
            "/ppp/secret",
            credentials,
            body={
                "name": username,
                "password": password,
                "service": "ovpn",
                "profile": profile or self.ovpn_profile,
                "comment": comment,
            },
        )
        records = _records(result)
        return records[0] if records else {"name": username}

    def rate_profile_snapshot(
        self,
        credentials: RouterOSCredentials,
        *,
        username: str,
    ) -> dict[str, Any]:
        """Return only the generated PPP profile fields relevant to a rate edit."""
        profile_name = f"vpn-ui-{_slug(username, 24)}"
        records = _records(
            self._request(
                "GET", "/ppp/profile", credentials,
                query={"name": profile_name, ".proplist": ".id,name,rate-limit"},
            )
        )
        if len(records) > 1:
            raise RouterOSError("RouterOS returned an ambiguous generated PPP profile")
        if not records:
            return {"exists": False}
        record = records[0]
        return {
            "exists": True,
            "id": str(record.get(".id", "")),
            "rate_limit": str(record.get("rate-limit", "")),
        }

    def ensure_rate_profile(
        self,
        credentials: RouterOSCredentials,
        *,
        username: str,
        rate_limit_kbps: int,
        expected_state: dict[str, Any] | None = None,
    ) -> str:
        if not rate_limit_kbps:
            if not self.ovpn_profile:
                raise RouterOSError("OVPN_PPP_PROFILE must be configured before creating VPN users")
            return self.ovpn_profile
        profile_name = f"vpn-ui-{_slug(username, 24)}"
        current_state = self.rate_profile_snapshot(credentials, username=username)
        if expected_state is not None and current_state != expected_state:
            raise RouterOSError("Generated PPP profile changed since it was reviewed")
        values = {"name": profile_name, "rate-limit": f"{int(rate_limit_kbps)}k/{int(rate_limit_kbps)}k"}
        if current_state["exists"]:
            if current_state["rate_limit"] == values["rate-limit"]:
                return profile_name
            safe_id = urllib.parse.quote(str(current_state.get("id") or profile_name), safe="*")
            mutation = ("PATCH", f"/ppp/profile/{safe_id}")
        else:
            mutation = ("PUT", "/ppp/profile")
        mutation_error: RouterOSError | None = None
        try:
            self._request(mutation[0], mutation[1], credentials, body=values)
        except RouterOSError as error:
            # RouterOS can commit a write before the HTTP response is lost.
            # Reconcile by reading the exact target before deciding its state.
            mutation_error = error
        verified_state = self.rate_profile_snapshot(credentials, username=username)
        if (
            not verified_state["exists"]
            or verified_state["rate_limit"] != values["rate-limit"]
        ):
            raise RouterOSError(
                "RouterOS PPP profile rate limit could not be verified",
                failure_kind="unknown" if mutation_error is not None else "mismatch",
            ) from mutation_error
        return profile_name

    def update_user(
        self,
        credentials: RouterOSCredentials,
        *,
        user_id: str,
        password: str | None = None,
        comment: str | None = None,
        disabled: bool | None = None,
        profile: str | None = None,
    ) -> None:
        changes: dict[str, Any] = {}
        if password:
            changes["password"] = password
        if comment is not None:
            changes["comment"] = comment
        if disabled is not None:
            changes["disabled"] = "yes" if disabled else "no"
        if profile is not None:
            changes["profile"] = profile
        if not changes:
            return
        safe_id = urllib.parse.quote(user_id, safe="*")
        self._request("PATCH", f"/ppp/secret/{safe_id}", credentials, body=changes)

    def delete_user(self, credentials: RouterOSCredentials, *, user_id: str) -> None:
        safe_id = urllib.parse.quote(user_id, safe="*")
        self._request("DELETE", f"/ppp/secret/{safe_id}", credentials)

    def revoke_certificate(self, credentials: RouterOSCredentials, *, certificate_id: str) -> None:
        # Issued certificates must be revoked, not removed. RouterOS records the
        # revocation timestamp on the certificate and includes it in its CRL.
        self._request(
            "POST",
            "/certificate/issued-revoke",
            credentials,
            body={"numbers": certificate_id},
        )

    def _files(self, credentials: RouterOSCredentials) -> dict[str, dict[str, Any]]:
        records = _records(
            self._request(
                "GET",
                "/file",
                credentials,
                query={".proplist": ".id,name,type,size,last-modified"},
            )
        )
        return {str(item.get("name", "")): item for item in records if item.get("name")}

    def _file_contents(self, credentials: RouterOSCredentials, name: str) -> str:
        record = self._files(credentials).get(name)
        if not record or not record.get(".id"):
            raise RouterOSError(f"RouterOS did not return generated file {name!r}")
        result = self._request(
            "POST",
            "/file/get",
            credentials,
            body={"number": record[".id"], "value-name": "contents"},
        )
        if not isinstance(result, dict) or "ret" not in result:
            raise RouterOSError(f"RouterOS did not return generated file {name!r}")
        return str(result["ret"])

    def _delete_file(self, credentials: RouterOSCredentials, file_id: str | None) -> None:
        if not file_id:
            return
        safe_id = urllib.parse.quote(file_id, safe="*")
        try:
            self._request("DELETE", f"/file/{safe_id}", credentials)
        except RouterOSError:
            pass

    def _ensure_ca_export(self, credentials: RouterOSCredentials) -> str:
        files = self._files(credentials)
        # RouterOS normally prefixes certificate exports with
        # ``cert_export_``.  Older installations may already contain an
        # explicitly named ``<ca>.crt`` export, so accept either form.
        candidates = (f"{self.ovpn_ca}.crt", f"cert_export_{self.ovpn_ca}.crt")
        # Never trust an existing export solely by filename.  RouterOS keeps
        # exported files across certificate rotations, so a same-named file
        # can contain the previous CA and cause clients to reject the server
        # certificate.  Remove only the dashboard's known CA export names,
        # then create a fresh export for the configured CA.
        for filename in candidates:
            record = files.get(filename)
            if record and record.get(".id"):
                self._delete_file(credentials, str(record[".id"]))

        before = set(self._files(credentials))
        certs = _records(
            self._request(
                "GET",
                "/certificate",
                credentials,
                query={"name": self.ovpn_ca, ".proplist": ".id,name,fingerprint"},
            )
        )
        if len(certs) != 1:
            raise RouterOSError("Configured OpenVPN CA certificate was not found")
        expected_fingerprint = str(certs[0].get("fingerprint", "")).replace(":", "").lower()
        if len(expected_fingerprint) != 64:
            raise RouterOSError("Configured OpenVPN CA certificate has no usable fingerprint")
        self._request(
            "POST",
            "/certificate/export-certificate",
            credentials,
            body={"numbers": certs[0].get(".id", self.ovpn_ca), "type": "pem"},
        )
        files_after = self._files(credentials)
        for filename in candidates:
            if filename in files_after:
                ca_pem = self._file_contents(credentials, filename)
                encoded = "".join(
                    line.strip()
                    for line in ca_pem.splitlines()
                    if not line.startswith("---")
                )
                try:
                    actual_fingerprint = hashlib.sha256(base64.b64decode(encoded)).hexdigest()
                except (ValueError, binascii.Error) as error:
                    raise RouterOSError("RouterOS exported an invalid OpenVPN CA certificate") from error
                if actual_fingerprint != expected_fingerprint:
                    raise RouterOSError(
                        "RouterOS exported a CA that does not match the configured OpenVPN CA"
                    )
                return filename
        # Fall back to the newly-created .crt file if RouterOS uses a
        # version-specific export prefix.
        created = [
            name for name, record in files_after.items()
            if name not in before and name.lower().endswith(".crt")
        ]
        if len(created) == 1:
            ca_pem = self._file_contents(credentials, created[0])
            encoded = "".join(
                line.strip() for line in ca_pem.splitlines() if not line.startswith("---")
            )
            try:
                actual_fingerprint = hashlib.sha256(base64.b64decode(encoded)).hexdigest()
            except (ValueError, binascii.Error) as error:
                raise RouterOSError("RouterOS exported an invalid OpenVPN CA certificate") from error
            if actual_fingerprint != expected_fingerprint:
                raise RouterOSError("RouterOS exported a CA that does not match the configured OpenVPN CA")
            return created[0]
        raise RouterOSError("RouterOS did not export the configured OpenVPN CA certificate")

    def provision_profile(
        self,
        credentials: RouterOSCredentials,
        *,
        vpn_user: str,
        device_name: str,
        key_passphrase: str,
        policy: str = "full-tunnel",
        dns_mode: str = "router",
    ) -> ProvisionedProfile:
        try:
            self.topology.require_profile_generation(policy=policy, dns_mode=dns_mode)
        except ConfigurationError as error:
            raise RouterOSError(str(error)) from None
        suffix = secrets.token_hex(3)
        certificate_name = f"ovpn-ui-{_slug(vpn_user, 18)}-{_slug(device_name, 18)}-{suffix}"
        common_name = f"{_slug(vpn_user, 24)}-{_slug(device_name, 24)}"
        certificate_id: str | None = None
        generated_file_ids: list[str | None] = []
        succeeded = False
        try:
            created = _records(
                self._request(
                    "PUT",
                    "/certificate",
                    credentials,
                    body={
                        "name": certificate_name,
                        "common-name": common_name,
                        "key-size": "2048",
                        "digest-algorithm": "sha256",
                        "days-valid": "1825",
                        "key-usage": "tls-client",
                    },
                )
            )
            if created:
                certificate_id = created[0].get(".id")
            if not certificate_id:
                matches = _records(
                    self._request(
                        "GET",
                        "/certificate",
                        credentials,
                        query={"name": certificate_name, ".proplist": ".id,name"},
                    )
                )
                if len(matches) != 1:
                    raise RouterOSError("Could not locate the new RouterOS certificate")
                certificate_id = matches[0].get(".id")

            self._request(
                "POST",
                "/certificate/sign",
                credentials,
                body={"number": certificate_id, "ca": self.ovpn_ca},
            )
            safe_cert_id = urllib.parse.quote(str(certificate_id), safe="*")
            self._request(
                "PATCH",
                f"/certificate/{safe_cert_id}",
                credentials,
                body={"trusted": "yes"},
            )

            self._request(
                "POST",
                "/certificate/export-certificate",
                credentials,
                body={
                    "numbers": certificate_id,
                    "type": "pem",
                    "export-passphrase": key_passphrase,
                },
            )
            exported_cert = f"cert_export_{certificate_name}.crt"
            exported_key = f"cert_export_{certificate_name}.key"
            ca_file = self._ensure_ca_export(credentials)
            files_before = self._files(credentials)
            if exported_cert not in files_before or exported_key not in files_before:
                raise RouterOSError("RouterOS did not export the client certificate and key")

            self._request(
                "POST",
                "/interface/ovpn-server/server/export-client-configuration",
                credentials,
                body={
                    "ca-certificate": ca_file,
                    "client-certificate": exported_cert,
                    "client-cert-key": exported_key,
                    "server-address": self.ovpn_host,
                    "server": self.ovpn_server,
                },
            )
            files_after = self._files(credentials)
            new_profiles = [
                name
                for name in files_after
                if name.endswith(".ovpn") and name not in files_before
            ]
            if len(new_profiles) != 1:
                raise RouterOSError("RouterOS did not produce exactly one client profile")
            profile_name = new_profiles[0]
            raw_profile = self._file_contents(credentials, profile_name)
            hardened = harden_profile(
                raw_profile,
                server_identity=self.topology.server_identity,
                lan_cidr=self.topology.lan_cidr or None,
                router_dns=self.topology.router_dns or None,
                policy=policy,
                dns_mode=dns_mode,
            )

            for file_name in (exported_cert, exported_key, profile_name):
                generated_file_ids.append(files_after.get(file_name, {}).get(".id"))

            certificate_records = _records(
                self._request(
                    "GET",
                    "/certificate",
                    credentials,
                    query={
                        "name": certificate_name,
                        ".proplist": ".id,name,fingerprint,ca",
                    },
                )
            )
            fingerprint = certificate_records[0].get("fingerprint") if certificate_records else None
            certificate_ca = str(certificate_records[0].get("ca", "")) if certificate_records else ""
            if certificate_ca != self.ovpn_ca:
                raise RouterOSError(
                    f"Generated client certificate is signed by {certificate_ca or 'an unknown CA'}, "
                    f"not the configured OpenVPN CA {self.ovpn_ca}"
                )
            succeeded = True
            return ProvisionedProfile(
                profile=hardened.encode("utf-8"),
                certificate_id=certificate_id,
                certificate_name=certificate_name,
                fingerprint=fingerprint,
            )
        finally:
            for file_id in generated_file_ids:
                self._delete_file(credentials, file_id)
            if not succeeded:
                self._remove_uncommitted_certificate(
                    credentials,
                    certificate_name=certificate_name,
                    certificate_id=certificate_id,
                )

    def _remove_uncommitted_certificate(
        self,
        credentials: RouterOSCredentials,
        *,
        certificate_name: str,
        certificate_id: str | None,
    ) -> None:
        """Delete a partial profile certificate and verify it is absent."""
        delete_error: RouterOSError | None = None
        if certificate_id:
            candidates = [{".id": certificate_id, "name": certificate_name}]
        else:
            try:
                candidates = _records(
                    self._request(
                        "GET",
                        "/certificate",
                        credentials,
                        query={"name": certificate_name, ".proplist": ".id,name"},
                    )
                )
            except RouterOSError as error:
                raise RouterOSError(
                    "Provisioning failed and RouterOS certificate cleanup could not be verified; "
                    "inspect the uniquely named partial certificate before retrying"
                ) from error
        candidates = [item for item in candidates if item.get("name") == certificate_name]
        if len(candidates) > 1:
            raise RouterOSError(
                "Provisioning failed and multiple matching RouterOS certificates need manual review"
            )
        if candidates:
            candidate_id = candidates[0].get(".id")
            if not candidate_id:
                raise RouterOSError(
                    "Provisioning failed and the partial RouterOS certificate has no verifiable ID"
                )
            safe_cert_id = urllib.parse.quote(str(candidate_id), safe="*")
            try:
                self._request("DELETE", f"/certificate/{safe_cert_id}", credentials)
            except RouterOSError as error:
                delete_error = error

        try:
            remaining = _records(
                self._request(
                    "GET",
                    "/certificate",
                    credentials,
                    query={"name": certificate_name, ".proplist": ".id,name"},
                )
            )
        except RouterOSError as error:
            raise RouterOSError(
                "Provisioning failed and RouterOS certificate cleanup could not be verified; "
                "inspect the uniquely named partial certificate before retrying"
            ) from (delete_error or error)
        if any(item.get("name") == certificate_name for item in remaining):
            raise RouterOSError(
                "Provisioning failed and a partial RouterOS certificate remains; "
                "verify or remove it before retrying"
            ) from delete_error
