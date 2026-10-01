"""Small, shared privacy boundary for outbound integration payloads."""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any


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
