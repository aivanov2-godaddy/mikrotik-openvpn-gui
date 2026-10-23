"""Small, shared privacy boundary for outbound integration payloads."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from uuid import RFC_4122, UUID


_FORBIDDEN_KEY_PARTS = frozenset(
    {
        "password",
        "passphrase",
        "private_key",
        "private-key",
        "secret",
        "token",
        "cookie",
        "credential",
        "authorization",
        "api_key",
        "api-key",
        "certificate",
        "privatekey",
    }
)
_MAX_STRING_LENGTH = 2048
_SAFE_EVENT_VALUE = re.compile(r"^[a-z][a-z0-9]*(?:[._-][a-z0-9]+)*$")
_SAFE_ACTION_CATEGORIES = frozenset(
    {
        "admin-session",
        "alert",
        "api-token",
        "backup",
        "bootstrap",
        "break-glass",
        "bulk",
        "certificate",
        "checkpoint",
        "connection",
        "device",
        "login",
        "network",
        "policy_template",
        "profile",
        "report",
        "role",
        "security",
        "session",
        "user",
    }
)
_SAFE_STATUSES = frozenset(
    {
        "blocked",
        "completed",
        "denied",
        "failed",
        "failure",
        "operator_attested",
        "partial",
        "planned",
        "preview",
        "rejected",
        "running",
        "success",
        "unavailable",
        "unknown",
        "verified",
        "warning",
    }
)


def _forbidden_key(key: object) -> bool:
    normalized = str(key).strip().casefold().replace(" ", "_")
    return any(part in normalized for part in _FORBIDDEN_KEY_PARTS)


def sanitize_payload(value: Any) -> Any:
    """Return JSON-safe, recursively redacted integration data.

    Integration payloads are deliberately bounded and never contain values
    whose key suggests a credential, token, certificate, or private key.
    """

    if isinstance(value, Mapping):
        return {
            str(key)[:128]: sanitize_payload(item)
            for key, item in value.items()
            if not _forbidden_key(key)
        }
    if isinstance(value, (list, tuple, set)):
        return [sanitize_payload(item) for item in list(value)[:256]]
    if isinstance(value, str):
        return value[:_MAX_STRING_LENGTH]
    if value is None or isinstance(value, (bool, int, float)):
        return value
    return str(value)[:_MAX_STRING_LENGTH]


def sanitize_integration_event(value: Any) -> dict[str, Any]:
    """Build the minimized, versioned event contract used by remote sinks.

    Local audit records retain actor, target, and structured details. Remote
    integrations receive only event metadata and the fixed action/status
    classifications; identity, addresses, free-form details, and credentials
    are deliberately excluded.
    """

    if not isinstance(value, Mapping):
        return {"schema_version": 2, "event": "audit"}

    payload: dict[str, Any] = {"schema_version": 2, "event": "audit"}
    event_id = value.get("event_id")
    if isinstance(event_id, str) and event_id.strip():
        try:
            parsed_event_id = UUID(event_id.strip())
        except ValueError:
            pass
        else:
            if parsed_event_id.version == 4 and parsed_event_id.variant == RFC_4122:
                payload["event_id"] = str(parsed_event_id)

    action = value.get("action")
    if isinstance(action, str) and _SAFE_EVENT_VALUE.fullmatch(action):
        category = action.split(".", 1)[0]
        if category in _SAFE_ACTION_CATEGORIES:
            payload["action"] = category

    status = value.get("status")
    if isinstance(status, str) and status in _SAFE_STATUSES:
        payload["status"] = status

    created_at = value.get("created_at")
    if isinstance(created_at, int) and not isinstance(created_at, bool) and created_at >= 0:
        payload["created_at"] = created_at
    return payload
