from __future__ import annotations

import base64
import ipaddress
import json
import re
import secrets
import ssl
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from typing import Any

from config import ConfigurationError, OpenVPNTopology


class RouterOSError(RuntimeError):
    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


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
    raise RouterOSError("RouterOS returned an unexpected JSON shape")


def _yes(value: Any) -> bool:
    return str(value).lower() in {"yes", "true", "1"}


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
            suffix = f": {detail}" if detail else ""
            raise RouterOSError(
                f"RouterOS request failed with HTTP {error.code}{suffix}", error.code
            ) from None
        except (urllib.error.URLError, TimeoutError, OSError) as error:
            raise RouterOSError(f"RouterOS is unavailable: {error}") from None
        if not payload:
            return None
        try:
            return json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise RouterOSError("RouterOS returned an invalid JSON response") from None

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

    def get_admin_role(self, credentials: RouterOSCredentials) -> str:
        try:
            records = _records(
                self._request(
                    "GET",
                    "/user",
                    credentials,
                    query={"name": credentials.username, ".proplist": "name,group,disabled"},
                )
            )
        except RouterOSError:
            # Older RouterOS builds or restricted accounts may not expose /user.
            # Authentication already succeeded, so retain backwards-compatible owner access.
            return "owner"
        record = records[0] if records else {}
        group = str(record.get("group", "full")).lower()
        if group in {"read", "readonly", "read-only"}:
            return "viewer"
        if group in {"write", "operator", "policy"}:
            return "operator"
        return "owner"

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
        crl_records = _records(
            self._request(
                "GET",
                "/certificate/crl",
                credentials,
                query={".proplist": "cert,revoked,next-update,last-update"},
            )
        )
        active_ca_crl = any(
            str(item.get("cert", "")) == self.ovpn_ca
            and str(item.get("revoked", "")).casefold() != "unknown"
            and _crl_is_current(item.get("next-update"))
            for item in crl_records
        )
        crl_download = _yes(record.get("crl-download", "no"))
        crl_use = _yes(record.get("crl-use", "no"))
        crl_store = str(record.get("crl-store", ""))
        return {
            "crl_download": crl_download,
            "crl_use": crl_use,
            "crl_store": crl_store,
            "active_ovpn_ca_crl": active_ca_crl,
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
        self, credentials: RouterOSCredentials
    ) -> list[dict[str, Any]]:
        query: dict[str, Any] = {
            ".proplist": (
                ".id,name,common-name,fingerprint,issuer,invalid-after,"
                "expires-after,revoked,key-usage,trusted,ca"
            )
        }
        if self.ovpn_ca:
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
            if "tls-client" not in key_usage or (self.ovpn_ca and certificate_authority != self.ovpn_ca):
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
                    "revoked": _yes(item.get("revoked", "no")),
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

    def ensure_rate_profile(
        self,
        credentials: RouterOSCredentials,
        *,
        username: str,
        rate_limit_kbps: int,
    ) -> str:
        if not rate_limit_kbps:
            if not self.ovpn_profile:
                raise RouterOSError("OVPN_PPP_PROFILE must be configured before creating VPN users")
            return self.ovpn_profile
        profile_name = f"vpn-ui-{_slug(username, 24)}"
        records = _records(
            self._request(
                "GET",
                "/ppp/profile",
                credentials,
                query={"name": profile_name, ".proplist": ".id,name,rate-limit"},
            )
        )
        values = {"name": profile_name, "rate-limit": f"{int(rate_limit_kbps)}k/{int(rate_limit_kbps)}k"}
        if records:
            safe_id = urllib.parse.quote(str(records[0].get(".id", profile_name)), safe="*")
            self._request("PATCH", f"/ppp/profile/{safe_id}", credentials, body=values)
        else:
            self._request("PUT", "/ppp/profile", credentials, body=values)
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
        safe_id = urllib.parse.quote(certificate_id, safe="*")
        self._request("DELETE", f"/certificate/{safe_id}", credentials)

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
        filename = f"{self.ovpn_ca}.crt"
        if filename not in self._files(credentials):
            certs = _records(
                self._request(
                    "GET",
                    "/certificate",
                    credentials,
                    query={"name": self.ovpn_ca, ".proplist": ".id,name"},
                )
            )
            if len(certs) != 1:
                raise RouterOSError("Configured OpenVPN CA certificate was not found")
            self._request(
                "POST",
                "/certificate/export-certificate",
                credentials,
                body={"numbers": certs[0].get(".id", self.ovpn_ca), "type": "pem"},
            )
        return filename

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
                        ".proplist": ".id,name,fingerprint",
                    },
                )
            )
            fingerprint = certificate_records[0].get("fingerprint") if certificate_records else None
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
            if certificate_id and not succeeded:
                safe_cert_id = urllib.parse.quote(str(certificate_id), safe="*")
                try:
                    self._request("DELETE", f"/certificate/{safe_cert_id}", credentials)
                except RouterOSError:
                    pass
