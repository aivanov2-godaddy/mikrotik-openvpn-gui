"""Verify a deployment readiness endpoint without exposing its response body."""

from __future__ import annotations

import argparse
import json
import ssl
import sys
import urllib.error
import urllib.parse
import urllib.request


class HealthCheckError(RuntimeError):
    """Raised when a deployment readiness gate fails."""


def verify_ready(url: str, expected_revision: str, *, ca_pem: str | None = None) -> None:
    parsed = urllib.parse.urlsplit(url)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path.rstrip("/") != "/readyz"
    ):
        raise HealthCheckError("health URL must be a credential-free HTTPS /readyz URL")
    if len(expected_revision) != 40 or any(character not in "0123456789abcdef" for character in expected_revision):
        raise HealthCheckError("expected revision must be a full lowercase Git commit SHA")

    context = ssl.create_default_context(cadata=ca_pem) if ca_pem else ssl.create_default_context()
    request = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "mikrotik-openvpn-gui-health/1"})
    try:
        with urllib.request.urlopen(request, context=context, timeout=20) as response:
            if response.status != 200:
                raise HealthCheckError(f"readiness endpoint returned HTTP {response.status}")
            payload = json.loads(response.read(4096).decode("utf-8"))
    except urllib.error.HTTPError as error:
        raise HealthCheckError(f"readiness endpoint returned HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError) as error:
        raise HealthCheckError("readiness endpoint was unreachable") from error
    except json.JSONDecodeError as error:
        raise HealthCheckError("readiness endpoint returned invalid JSON") from error

    if not isinstance(payload, dict) or payload.get("status") != "ready":
        raise HealthCheckError("readiness endpoint did not report ready")
    if payload.get("revision") != expected_revision:
        raise HealthCheckError("readiness endpoint reported a different revision")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Verify an HTTPS /readyz endpoint and release revision")
    parser.add_argument("--url", required=True, help="credential-free HTTPS /readyz URL")
    parser.add_argument("--expected-revision", required=True, help="full immutable commit SHA")
    parser.add_argument("--ca-file", help="PEM file for the endpoint certificate authority")
    arguments = parser.parse_args(argv)
    try:
        ca_pem = open(arguments.ca_file, encoding="utf-8").read() if arguments.ca_file else None
        verify_ready(arguments.url, arguments.expected_revision, ca_pem=ca_pem)
    except (HealthCheckError, OSError) as error:
        print(f"health gate blocked: {error}", file=sys.stderr)
        return 2
    print(f"readiness gate passed for revision {arguments.expected_revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
