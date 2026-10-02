"""Stable, privacy-safe guidance for common RouterOS API failures."""

from __future__ import annotations

from routeros import RouterOSError


# Public response text is deliberately static: never build it from exception
# messages, RouterOS response bodies, request URLs, or connection settings.
_ERROR_GUIDANCE: dict[str, tuple[str, str, str]] = {
    "authentication_failed": (
        "routeros.authentication_failed",
        "RouterOS did not accept the dashboard credentials.",
        "Sign in again and verify the RouterOS account is active.",
    ),
    "permission_denied": (
        "routeros.permission_denied",
        "The RouterOS account cannot read the requested information.",
        "Review the account's effective permissions; do not grant broad policies as a quick fix.",
    ),
    "endpoint_unavailable": (
        "routeros.endpoint_unavailable",
        "RouterOS does not expose the requested API resource.",
        "Check the RouterOS version and the feature's documented support.",
    ),
    "request_failed": (
        "routeros.request_failed",
        "RouterOS could not complete the API request.",
        "Check RouterOS service health and retry after it recovers.",
    ),
    "tls": (
        "routeros.tls_untrusted",
        "The dashboard could not establish a trusted TLS connection to RouterOS.",
        "Verify the configured RouterOS certificate and trusted CA; do not disable certificate validation.",
    ),
    "timeout": (
        "routeros.timeout",
        "RouterOS did not respond before the request timed out.",
        "Check RouterOS API service health and network reachability, then retry when the router is responsive.",
    ),
    "invalid_response": (
        "routeros.invalid_response",
        "RouterOS returned data the dashboard could not safely interpret.",
        "Check RouterOS service health and version compatibility; retry after confirming the API is responding normally.",
    ),
    "unavailable": (
        "routeros.unavailable",
        "The dashboard could not get a valid response from RouterOS.",
        "Check private network reachability, API service health, and TLS configuration.",
    ),
}


def routeros_error_payload(error: RouterOSError) -> dict[str, str]:
    """Map RouterOS failures to safe codes without echoing remote response text."""

    status = error.status
    if status == 401:
        key = "authentication_failed"
    elif status == 403:
        key = "permission_denied"
    elif status == 404:
        key = "endpoint_unavailable"
    elif status is not None and status >= 500:
        key = "request_failed"
    elif error.failure_kind in {"tls", "timeout", "invalid_response"}:
        key = error.failure_kind
    else:
        key = "unavailable"

    code, message, next_step = _ERROR_GUIDANCE[key]
    return {"code": code, "error": message, "next_step": next_step}
