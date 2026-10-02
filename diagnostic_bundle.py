"""Build a small, allowlist-only support bundle with no customer identifiers."""

from __future__ import annotations

import io
import json
import re
import zipfile
from typing import Any


MAX_DIAGNOSTIC_BUNDLE_BYTES = 32 * 1024
_REVISION = re.compile(r"^(?:[0-9a-f]{7,64}|unknown)$")
_VERSION = re.compile(r"^[0-9][A-Za-z0-9.+_-]{0,63}$")
_HEALTH_STATES = frozenset({"healthy", "warning", "unavailable", "unknown"})
_HEALTH_CHECKS = frozenset({
    "routeros-rest", "dashboard-storage", "openvpn-service", "profile-issuing",
    "certificate-revocation", "certificate-inventory", "router-capacity",
})
_TELEMETRY_STATES = frozenset({"healthy", "stale", "error", "disabled", "connecting", "unknown"})
_TRANSPORTS = frozenset({"rest", "sse", "socketio", "binary", "auto", "unknown"})


def _bounded_int(value: Any, *, maximum: int = 2**63 - 1) -> int | None:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        return None
    return min(value, maximum)


def _safe_revision(value: Any) -> str:
    candidate = str(value or "unknown").lower()
    return candidate if _REVISION.fullmatch(candidate) else "unknown"


def _safe_version(value: Any) -> str:
    candidate = str(value or "unknown")
    return candidate if _VERSION.fullmatch(candidate) else "unknown"


def _health_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"overall": "unknown", "checked_at": None, "checks": []}
    overall = value.get("overall")
    checks: list[dict[str, str]] = []
    raw_checks = value.get("checks")
    if isinstance(raw_checks, list):
        for item in raw_checks[:16]:
            if not isinstance(item, dict):
                continue
            identifier = item.get("id")
            status = item.get("status")
            # IDs are a stable machine enum; free-text labels, impact, and
            # remediation strings are intentionally never copied to exports.
            if isinstance(identifier, str) and identifier in _HEALTH_CHECKS:
                checks.append({
                    "id": identifier,
                    "status": status if isinstance(status, str) and status in _HEALTH_STATES else "unknown",
                })
    return {
        "overall": overall if isinstance(overall, str) and overall in _HEALTH_STATES else "unknown",
        "checked_at": _bounded_int(value.get("checked_at")),
        "checks": checks,
    }


def _telemetry_summary(value: Any) -> dict[str, Any]:
    if not isinstance(value, dict):
        return {"state": "unknown", "transport": "unknown", "supervisor": {"status": "unknown"}}
    transport = value.get("transport")
    state = value.get("state")
    summary: dict[str, Any] = {
        "state": state if isinstance(state, str) and state in _TELEMETRY_STATES else "unknown",
        "transport": transport if isinstance(transport, str) and transport in _TRANSPORTS else "unknown",
        "last_event_at": _bounded_int(value.get("last_event_at")),
        "last_reconciliation_at": _bounded_int(value.get("last_reconciliation_at")),
        "event_age_seconds": _bounded_int(value.get("event_age_seconds")),
        "reconnects": _bounded_int(value.get("reconnects")),
    }
    raw_supervisor = value.get("supervisor")
    if isinstance(raw_supervisor, dict):
        supervisor_status = raw_supervisor.get("status")
        summary["supervisor"] = {
            "status": supervisor_status if isinstance(supervisor_status, str) and supervisor_status in _TELEMETRY_STATES else "unknown",
            "enabled": raw_supervisor.get("enabled") is True,
            "attempts": _bounded_int(raw_supervisor.get("attempts")),
            "reconnects": _bounded_int(raw_supervisor.get("reconnects")),
            "failures": _bounded_int(raw_supervisor.get("failures")),
            "events": _bounded_int(raw_supervisor.get("events")),
            "last_connected_at": _bounded_int(raw_supervisor.get("last_connected_at")),
            "last_event_at": _bounded_int(raw_supervisor.get("last_event_at")),
            "last_snapshot_at": _bounded_int(raw_supervisor.get("last_snapshot_at")),
        }
    else:
        summary["supervisor"] = {"status": "unknown"}
    return summary


def build_diagnostic_bundle(
    *, version: Any, revision: Any, generated_at: int, health: Any, telemetry: Any,
) -> bytes:
    """Return a bounded ZIP containing only fixed-schema, redacted diagnostics."""
    document = {
        "format": "mikrotik-openvpn-gui-diagnostics",
        "schema_version": 1,
        "generated_at": _bounded_int(generated_at),
        "application": {"version": _safe_version(version), "revision": _safe_revision(revision)},
        "health": _health_summary(health),
        "telemetry": _telemetry_summary(telemetry),
        "privacy": {
            "contains_identifiers": False,
            "excluded": [
                "credentials and tokens", "usernames and email addresses", "IP addresses and hostnames",
                "certificates and keys", "VPN profiles", "RouterOS records", "logs and event payloads",
            ],
        },
    }
    payload = json.dumps(document, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(payload) > MAX_DIAGNOSTIC_BUNDLE_BYTES:
        raise ValueError("diagnostic payload exceeds the fixed size limit")
    stream = io.BytesIO()
    with zipfile.ZipFile(stream, "w", compression=zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("diagnostics.json", payload)
    result = stream.getvalue()
    if len(result) > MAX_DIAGNOSTIC_BUNDLE_BYTES:
        raise ValueError("diagnostic archive exceeds the fixed size limit")
    return result
