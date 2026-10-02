"""Stable, privacy-safe guidance for common RouterOS API failures."""

from __future__ import annotations

from routeros import RouterOSError


def routeros_error_payload(error: RouterOSError) -> dict[str, str]:
    """Map RouterOS failures to safe codes without echoing remote response text."""

    status = error.status
    if status == 401:
        return {
            "code": "routeros.authentication_failed",
            "error": "RouterOS did not accept the dashboard credentials.",
            "next_step": "Sign in again and verify the RouterOS account is active.",
        }
    if status == 403:
        return {
            "code": "routeros.permission_denied",
            "error": "The RouterOS account cannot read the requested information.",
            "next_step": "Review the account's effective permissions; do not grant broad policies as a quick fix.",
        }
    if status == 404:
        return {
            "code": "routeros.endpoint_unavailable",
            "error": "RouterOS does not expose the requested API resource.",
            "next_step": "Check the RouterOS version and the feature's documented support.",
        }
    if status is not None and status >= 500:
        return {
            "code": "routeros.request_failed",
            "error": "RouterOS could not complete the API request.",
            "next_step": "Check RouterOS service health and retry after it recovers.",
        }
    return {
        "code": "routeros.unavailable",
        "error": "The dashboard could not get a valid response from RouterOS.",
        "next_step": "Check private network reachability, API service health, and TLS configuration.",
    }
