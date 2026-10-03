"""Redacted, read-only RouterOS management access and exposure diagnostics."""

from __future__ import annotations

import ipaddress
import time
from typing import Any


_HIGH_IMPACT_POLICIES = {
    "write": "configuration-write",
    "policy": "user-and-policy-management",
    "sensitive": "sensitive-configuration-visibility",
    "ftp": "file-transfer-login",
    "sniff": "packet-inspection-tools",
    "test": "diagnostic-tools",
    "reboot": "router-reboot",
    "romon": "remote-management-overlay",
    "ssh": "SSH-login",
    "telnet": "Telnet-login",
    "winbox": "WinBox-login",
    "web": "WebFig-login",
    "password": "password-management",
    "local": "local-console-login",
}

# RouterOS' documented user-group policy vocabulary. If a newer RouterOS
# release returns another flag, don't silently claim that the checked policy
# set is complete. The raw flag is never included in diagnostic output.
_KNOWN_POLICIES = frozenset({
    "local", "telnet", "ssh", "ftp", "reboot", "read", "write", "policy",
    "test", "winbox", "password", "web", "sniff", "sensitive", "api",
    "rest-api", "romon",
})


def _truth(value: Any) -> bool | None:
    if value is None or str(value).strip() == "":
        return None
    normalized = str(value).strip().casefold()
    if normalized in {"yes", "true", "1", "enabled"}:
        return True
    if normalized in {"no", "false", "0", "disabled"}:
        return False
    return None


def _policy_set(value: Any) -> set[str] | None:
    if value is None:
        return None
    items = value if isinstance(value, list) else str(value).split(",")
    return {str(item).strip().casefold() for item in items if str(item).strip()}


def _address_scope(value: Any) -> str:
    if value is None:
        return "unknown"
    entries = [part.strip() for part in str(value).split(",") if part.strip()]
    if not entries:
        return "unrestricted"
    try:
        networks = [ipaddress.ip_network(part, strict=False) for part in entries]
    except ValueError:
        return "unknown"
    if any(network.prefixlen == 0 for network in networks):
        return "unrestricted"
    return "restricted"


def exposure_doctor_snapshot(
    *,
    account: dict[str, Any] | None,
    group: dict[str, Any] | None,
    services: list[dict[str, Any]] | None,
    source_status: dict[str, str] | None = None,
    checked_at: int | None = None,
) -> dict[str, Any]:
    """Return only allowlisted derived facts; never return RouterOS values."""
    observed = int(checked_at if checked_at is not None else time.time())
    statuses = source_status or {}
    checks: list[dict[str, str]] = []

    def add(identifier: str, status: str, message: str, next_step: str) -> None:
        checks.append({"id": identifier, "status": status, "message": message, "next_step": next_step})

    if account is None:
        add("account", statuses.get("account", "unknown"),
            "The signed-in RouterOS account settings could not be verified.",
            "Review this account in WinBox; this check does not change it.")
        policies = None
    else:
        disabled = _truth(account.get("disabled"))
        add("account", "verified" if disabled is False else "warning" if disabled is True else "unknown",
            "The signed-in account is enabled." if disabled is False else
            "RouterOS reports the signed-in account as disabled." if disabled is True else
            "RouterOS did not return a recognizable account enabled state.",
            "No action needed." if disabled is False else "Review the account state in WinBox; this check does not enable it.")
        source_scope = _address_scope(account.get("address"))
        add("account-source", "verified" if source_scope == "restricted" else "warning" if source_scope == "unrestricted" else "unknown",
            "A RouterOS account source-address restriction is configured." if source_scope == "restricted" else
            "No RouterOS account source-address restriction is configured; this does not prove network reachability." if source_scope == "unrestricted" else
            "RouterOS did not return the account source-address field.",
            "Check that the configured source range matches the dashboard's actual RouterOS-side address; firewall controls remain separate.")
        policies = _policy_set(group.get("policy")) if group else None

    if group is None or policies is None:
        add("group-policies", statuses.get("group", "unknown"),
            "The signed-in account's effective group policy could not be verified.",
            "Review the assigned group and its effective policies in WinBox; do not add broad policies as a generic fix.")
        add("unrecognized-policy-flags", "unknown",
            "RouterOS policy-flag completeness could not be verified.",
            "Review the group policy in WinBox; this diagnostic does not expose raw policy values.")
    else:
        policy_tokens = _policy_set(group.get("policy")) or set()
        unknown_policy_count = sum(
            1 for token in policy_tokens
            if token.removeprefix("!").strip() not in _KNOWN_POLICIES
        )
        add("unrecognized-policy-flags", "unknown" if unknown_policy_count else "verified",
            "RouterOS returned policy flags this diagnostic does not recognize; effective permission posture is incomplete."
            if unknown_policy_count else
            "All returned RouterOS policy flags match the currently recognized policy vocabulary.",
            "Review the group policy against the documentation for this RouterOS version; raw flag names are intentionally omitted.")
        feature_policies = (
            ("read", "configuration inspection"),
            ("rest-api", "REST API access"),
            ("api", "Binary API access"),
            ("write", "broad RouterOS configuration changes"),
            ("policy", "RouterOS user/group policy management"),
        )
        add("feature-access", "verified",
            "RouterOS policy mapping: " + "; ".join(
                f"{feature} ({name}) is {'enabled' if name in policies else 'not enabled'}"
                for name, feature in feature_policies
            ) + ". These are RouterOS policy flags, not a per-dashboard-feature authorization guarantee.",
            "Grant only the specifically required capabilities after testing the exact dashboard workflow; RouterOS write access is broader than this application.")
        elevated = sorted(label for flag, label in _HIGH_IMPACT_POLICIES.items() if flag in policies)
        add("high-impact-policies", "warning" if elevated else "verified",
            "High-impact policy categories are enabled: " + ", ".join(elevated) + "." if elevated else
            "No additional high-impact policy categories from the checked list were reported.",
            "Confirm each enabled category is needed for this account. This report does not automatically prescribe a replacement policy set.")

    if services is None:
        add("management-services", statuses.get("services", "unknown"),
            "RouterOS management-service settings could not be verified.",
            "Review IP → Services in WinBox. The check does not enable, disable, or edit services.")
    else:
        by_name = {str(item.get("name", "")).casefold(): item for item in services if item.get("name")}
        for name, label in (("www", "REST over HTTP"), ("www-ssl", "REST over HTTPS"),
                            ("api", "RouterOS API"), ("api-ssl", "RouterOS API over TLS"),
                            ("telnet", "Telnet"), ("ftp", "FTP"), ("ssh", "SSH"), ("winbox", "WinBox")):
            item = by_name.get(name)
            if item is None:
                add(f"service-{name}", "unknown",
                    f"{label} service state is not available in this RouterOS response.",
                    "Verify the service in WinBox; service names and properties vary by RouterOS version.")
                continue
            disabled = _truth(item.get("disabled"))
            source_ranges = item.get("available-from")
            if source_ranges is None:
                source_ranges = item.get("address")
            scope = _address_scope(source_ranges)
            if disabled is True:
                state = "verified"
                message = f"{label} is disabled."
            elif disabled is False and scope == "unrestricted":
                state = "warning"
                message = f"{label} is enabled without a service-level source-address restriction; firewall enforcement is not verified."
            elif disabled is False and scope == "restricted":
                state = "verified"
                message = f"{label} is enabled with a service-level source-address restriction; firewall enforcement is not verified."
            else:
                state = "unknown"
                message = f"{label} is present, but its enabled state or source-address scope is not fully observable."
            if name in {"www", "api"} and disabled is False:
                state = "warning"
                message += " This is an unencrypted management service."
            if name in {"www-ssl", "api-ssl"} and disabled is False:
                certificate = item.get("certificate")
                if certificate is None:
                    state = "unknown" if state != "warning" else state
                    message += " TLS certificate assignment was not returned."
                elif str(certificate).strip().casefold() in {"", "none"}:
                    state = "warning"
                    message += " No service certificate is assigned."
            add(f"service-{name}", state, message,
                "Confirm the intended management path and a matching allowlist/firewall boundary in WinBox; this check never changes RouterOS.")

    add("firewall-boundary", "unknown",
        "A service allowlist is not a substitute for a firewall rule; effective network-layer exposure is not proven by this read-only service snapshot.",
        "Verify input-chain firewall policy and upstream network controls separately, without exposing their raw rules in this report.")

    order = {"warning": 0, "unknown": 1, "unsupported": 2, "verified": 3}
    overall = min((check["status"] for check in checks), key=lambda state: order.get(state, 1)) if checks else "unknown"
    counts = {state: sum(check["status"] == state for check in checks) for state in order}
    return {"overall": overall, "checked_at": observed, "read_only": True, "checks": checks, "counts": counts}
