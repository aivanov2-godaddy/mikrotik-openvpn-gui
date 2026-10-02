"""Redacted, read-only connection diagnostics for RouterOS OpenVPN."""

from __future__ import annotations

import re
import time
from typing import Any


_VERSION = re.compile(r"^(\d+)\.(\d+)(?:\.(\d+))?")
_CIPHERS = {
    "aes128-cbc", "aes128-gcm", "aes192-cbc", "aes192-gcm",
    "aes256-cbc", "aes256-gcm", "blowfish128", "null",
}
_AUTH = {"md5", "sha1", "sha256", "sha384", "sha512", "null"}


def connection_doctor_snapshot(
    *,
    username: str,
    router: dict[str, Any] | None,
    server: dict[str, Any] | None,
    users: list[dict[str, Any]] | None,
    sessions: list[dict[str, Any]] | None,
    checked_at: int | None = None,
) -> dict[str, Any]:
    """Summarize observable facts without returning identities or network data."""
    observed = int(checked_at if checked_at is not None else time.time())
    age_seconds = max(0, int(time.time()) - observed)
    freshness = "fresh" if age_seconds <= 30 else "stale"
    checks: list[dict[str, Any]] = []

    def add(
        identifier: str,
        status: str,
        message: str,
        source: str,
        confidence: str,
        next_step: str,
    ) -> None:
        checks.append({
            "id": identifier,
            "status": status,
            "message": message,
            "source": source,
            "checked_at": observed,
            "age_seconds": age_seconds,
            "freshness": freshness,
            "confidence": confidence,
            "next_step": next_step,
        })

    if router is None:
        add("router", "unavailable", "RouterOS did not return a system resource snapshot.",
            "/system/resource", "none", "Check the dashboard-to-RouterOS REST connection and credentials.")
        version = ""
    else:
        raw_version = str(router.get("version", ""))[:64]
        match = _VERSION.match(raw_version)
        version = raw_version if match else ""
        add("router", "pass" if version else "unknown",
            "RouterOS is reachable." if version else "RouterOS responded, but its version could not be parsed.",
            "/system/resource", "high" if version else "low",
            "No action needed." if version else "Confirm the RouterOS version in WinBox.")

    if server is None:
        add("server", "unknown", "The configured OpenVPN server could not be inspected.",
            "/interface/ovpn-server/server", "none", "Check the dashboard account's read permissions and configured server name.")
    elif not server.get("name"):
        add("server", "error", "The configured OpenVPN server was not found.",
            "/interface/ovpn-server/server", "high", "Select the intended OpenVPN server in the dashboard configuration.")
    elif server.get("enabled") is False:
        add("server", "error", "The configured OpenVPN server is disabled.",
            "/interface/ovpn-server/server", "high", "Review the server in WinBox; this diagnostic does not enable it.")
    else:
        add("server", "pass", "The configured OpenVPN server is enabled.",
            "/interface/ovpn-server/server", "high", "No action needed.")

    if users is None:
        add("account", "unknown", "The OpenVPN account list could not be inspected.",
            "/ppp/secret", "none", "Check read permissions for PPP secrets; no account data is shown here.")
    else:
        account = next((item for item in users if str(item.get("name", "")).casefold() == username.casefold()), None)
        if account is None:
            add("account", "error", "No matching OpenVPN account was found.",
                "/ppp/secret", "high", "Check the username and confirm its service is OpenVPN in WinBox.")
        elif account.get("disabled"):
            add("account", "error", "The OpenVPN account is disabled.",
                "/ppp/secret", "high", "Review the account status in WinBox; this diagnostic does not enable it.")
        else:
            add("account", "pass", "An enabled OpenVPN account was found.",
                "/ppp/secret", "high", "No action needed.")

    if sessions is None:
        add("session", "unknown", "Active PPP sessions could not be inspected.",
            "/ppp/active", "none", "Check read permissions for active PPP sessions.")
    else:
        active = any(
            str(item.get("name", "")).casefold() == username.casefold()
            and str(item.get("service", "ovpn")).casefold() == "ovpn"
            for item in sessions
        )
        add("session", "pass" if active else "warning",
            "RouterOS reports an active OpenVPN session." if active else "No active OpenVPN session was found for this account.",
            "/ppp/active", "high", "No action needed." if active else "Check the client connection log and server reachability from that device.")

    if server is None or "redirect_gateway" not in server:
        add("routes", "unknown", "The server's route-push setting could not be inspected.",
            "/interface/ovpn-server/server", "none", "Check the server's redirect-gateway setting in WinBox.")
    else:
        route_setting = str(server.get("redirect_gateway", "")).casefold()
        if route_setting in {"def1", "ipv6"}:
            add("routes", "pass", "RouterOS is configured to push default-route guidance to clients.",
                "/interface/ovpn-server/server", "high", "Confirm the VPN device accepted the route and that protected destinations respond.")
        elif route_setting == "disabled":
            add("routes", "warning", "The OpenVPN server does not push a default route.",
                "/interface/ovpn-server/server", "high", "Confirm the intended split-tunnel or full-tunnel route design before changing anything.")
        else:
            add("routes", "unknown", "RouterOS returned an unrecognized route-push setting.",
                "/interface/ovpn-server/server", "low", "Review the route-push setting in WinBox.")

    if server is None or not version:
        add("compatibility", "unknown", "RouterOS version and server settings are needed for a compatibility check.",
            "RouterOS OpenVPN capability reference", "none", "Verify the RouterOS version and server protocol in WinBox.")
    else:
        version_match = _VERSION.match(version)
        major = int(version_match.group(1)) if version_match else 0
        protocol = str(server.get("protocol", "")).casefold()
        cipher_values = [part.strip().casefold() for part in re.split(r"[,\s]+", str(server.get("cipher", ""))) if part.strip()]
        auth_values = [part.strip().casefold() for part in re.split(r"[,\s]+", str(server.get("auth", ""))) if part.strip()]
        unsupported = (protocol and protocol not in {"tcp", "udp"}) or (protocol == "udp" and major < 7)
        if unsupported:
            add("compatibility", "error", "The configured protocol is unsupported by this RouterOS version.",
                "/system/resource + OpenVPN server settings", "high", "Review the MikroTik OpenVPN compatibility notes before changing server settings.")
        elif not protocol or not cipher_values or not auth_values:
            add("compatibility", "unknown", "Some OpenVPN protocol or crypto capabilities could not be verified.",
                "/system/resource + OpenVPN server settings", "low", "Inspect protocol, cipher, and authentication settings in WinBox.")
        elif any(value not in _CIPHERS for value in cipher_values) or any(value not in _AUTH for value in auth_values):
            add("compatibility", "warning", "A configured cipher or authentication method is not in the documented RouterOS capability list.",
                "/system/resource + OpenVPN server settings", "medium", "Compare the configured algorithms with the MikroTik OpenVPN manual and client profile.")
        elif major == 7 and int(version_match.group(2)) < 17 and any(value.endswith("-gcm") for value in cipher_values) and any(value != "null" for value in auth_values):
            add("compatibility", "warning", "This RouterOS version predates documented non-null authentication support for GCM ciphers.",
                "/system/resource + OpenVPN server settings", "medium", "Review the documented GCM authentication requirements and RouterOS version history.")
        else:
            add("compatibility", "pass", "The configured protocol and algorithms are listed as supported by RouterOS OpenVPN.",
                "/system/resource + OpenVPN server settings", "medium", "No action needed.")

    add("client-path", "unknown", "Client-side DNS, firewall reachability, and route use cannot be proven from RouterOS control-plane snapshots alone.",
        "Not observable from this check", "none", "From the VPN device, test the intended DNS name and protected destination; compare with its profile routes.")
    counts = {state: sum(item["status"] == state for item in checks) for state in ("pass", "warning", "error", "unknown", "unavailable")}
    overall = "stale" if freshness == "stale" else ("unavailable" if counts["unavailable"] else ("error" if counts["error"] else ("warning" if counts["warning"] else ("unknown" if counts["unknown"] else "healthy"))))
    return {"overall": overall, "checked_at": observed, "freshness_seconds": age_seconds, "checks": checks, "counts": counts}
