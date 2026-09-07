"""Safely roll a published immutable GHCR image on a RouterOS container.

An operator runs this local client after selecting a validated release image.
It uses the RouterOS REST API only; no source files or credentials are uploaded
to the router. The existing container is updated in place so its network,
mounts, environment, and persistent data remain unchanged. If the new image
cannot start, the previous image is restored automatically.
"""

from __future__ import annotations

import argparse
import base64
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from typing import Any


_IMAGE_PATTERN = re.compile(
    r"^(?:ghcr\.io/)?[a-z0-9](?:[a-z0-9._-]{0,98})/[a-z0-9](?:[a-z0-9._-]{0,98}):sha-(?P<revision>[0-9a-f]{40})(?:-(?P<architecture>arm64|amd64))?$"
)
_STATUS_FAILURES = {"failed", "invalid", "error", "unhealthy"}
_LIFECYCLE_KEYS = (
    "status",
    "running",
    ".running",
    "stopped",
    "healthy",
    "healthcheck-status",
)
_EMPTY_STOP_CONFIRMATIONS = 2


class DeploymentError(RuntimeError):
    """Raised when a guarded RouterOS deployment gate fails."""


@dataclass(frozen=True, slots=True)
class DeploymentSettings:
    rest_url: str
    username: str
    password: str
    container_name: str
    release_image: str
    timeout_seconds: int = 600
    poll_seconds: float = 2.0
    ca_pem: str | None = None

    @property
    def revision(self) -> str:
        match = _IMAGE_PATTERN.fullmatch(self.release_image)
        if not match:
            raise DeploymentError(
                "release image must be a registry-relative or ghcr.io image with a full sha-commit tag"
            )
        return match.group("revision")

    def validate(self) -> None:
        parsed = urllib.parse.urlsplit(self.rest_url)
        if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password:
            raise DeploymentError("RouterOS REST URL must be credential-free HTTPS")
        if parsed.query or parsed.fragment or not parsed.path.rstrip("/").endswith("/rest"):
            raise DeploymentError("RouterOS REST URL must end in /rest without query or fragment")
        if not self.username or not self.password:
            raise DeploymentError("RouterOS deploy credentials are required")
        if not self.container_name or any(ch in self.container_name for ch in '"\\\r\n'):
            raise DeploymentError("container name must be a single safe RouterOS identifier")
        if self.timeout_seconds < 30 or self.timeout_seconds > 1800:
            raise DeploymentError("timeout must be between 30 and 1800 seconds")
        self.revision  # validate image


class RouterOSRest:
    """Small, redacting REST client for the RouterOS container menu."""

    def __init__(self, settings: DeploymentSettings) -> None:
        self.base_url = settings.rest_url.rstrip("/")
        self.auth = (settings.username, settings.password)
        self.timeout = 20
        if settings.ca_pem:
            self.ssl_context = ssl.create_default_context(cadata=settings.ca_pem)
        else:
            self.ssl_context = ssl.create_default_context()

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        safe_path = "/" + path.lstrip("/")
        request = urllib.request.Request(
            self.base_url + safe_path,
            data=json.dumps(body).encode("utf-8") if body is not None else None,
            headers={
                "Authorization": "Basic "
                + base64.b64encode(f"{self.auth[0]}:{self.auth[1]}".encode()).decode(),
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "mikrotik-openvpn-gui-deployer/1",
            },
            method=method,
        )
        try:
            with urllib.request.urlopen(request, context=self.ssl_context, timeout=self.timeout) as response:
                payload = response.read().decode("utf-8")
        except urllib.error.HTTPError as error:
            detail = error.read(512).decode("utf-8", errors="replace")
            raise DeploymentError(f"RouterOS REST {method} {safe_path} failed ({error.code}): {detail}") from error
        except (urllib.error.URLError, TimeoutError) as error:
            raise DeploymentError(f"RouterOS REST {method} {safe_path} was unreachable") from error
        if not payload:
            return []
        try:
            return json.loads(payload)
        except json.JSONDecodeError as error:
            raise DeploymentError(f"RouterOS REST {method} {safe_path} returned invalid JSON") from error

    def containers(self) -> list[dict[str, Any]]:
        result = self.request("GET", "/container")
        if isinstance(result, dict):
            return [result]
        if not isinstance(result, list):
            raise DeploymentError("RouterOS returned an unexpected container list")
        return [item for item in result if isinstance(item, dict)]

    def container(self, container_id: str) -> dict[str, Any]:
        encoded = urllib.parse.quote(container_id, safe="*")
        result = self.request("GET", f"/container/{encoded}")
        if isinstance(result, list):
            if len(result) != 1 or not isinstance(result[0], dict):
                raise DeploymentError("RouterOS returned an unexpected container record")
            return result[0]
        if isinstance(result, dict):
            return result
        raise DeploymentError("RouterOS returned an unexpected container record")

    def patch_container(self, container_id: str, values: dict[str, Any]) -> None:
        encoded = urllib.parse.quote(container_id, safe="*")
        self.request("PATCH", f"/container/{encoded}", values)

    def command(self, command: str, container_id: str) -> None:
        # RouterOS command endpoints normally select records with the
        # `numbers` argument, which is the REST equivalent of the CLI
        # positional id.  The container `update` command is an exception on
        # RouterOS 7.24: it rejects `numbers` and accepts the singular
        # `number` (or `.id`) selector instead.  Keep the selector scoped to
        # that command so start/stop retain their known-compatible shape.
        selector = {"number": container_id} if command == "update" else {"numbers": container_id}
        self.request("POST", f"/container/{command}", selector)


def _find_target(client: RouterOSRest, name: str) -> dict[str, Any]:
    matches = [item for item in client.containers() if str(item.get("name", "")) == name]
    if len(matches) != 1:
        raise DeploymentError(f"expected exactly one RouterOS container named {name!r}")
    container_id = str(matches[0].get(".id", ""))
    if not container_id:
        raise DeploymentError("RouterOS container record did not include an id")
    return client.container(container_id)


def _status(record: dict[str, Any]) -> str:
    pull_failed = str(record.get("download/extract failed", "")).casefold()
    has_pull_failure = pull_failed in {"true", "yes", "1"}
    status = str(record.get("status", "")).casefold()
    if status:
        # A HEALTHCHECK-enabled image is reported as `healthy` by newer
        # RouterOS builds; treat that as the running gate for this deployer.
        if status == "healthy":
            return "failed" if has_pull_failure else "running"
        if status in {"running", "starting", "starting-with-healthcheck"}:
            return "failed" if has_pull_failure else status
        return status
    # Some RouterOS REST builds expose the container state as a string
    # `.running` flag instead of the CLI `status` field.
    running = str(record.get("running", record.get(".running", ""))).casefold()
    if running in {"true", "yes", "1"}:
        return "failed" if has_pull_failure else "running"
    if running in {"false", "no", "0"}:
        return "stopped"
    # RouterOS 7.24 exposes the lifecycle flag as `stopped` on some
    # container records.  It is the inverse of `running`, so normalize it
    # when it positively confirms that the container is stopped.  A false
    # value only means startup has progressed past the stopped state; it is
    # not sufficient evidence that the application is ready.
    stopped = str(record.get("stopped", "")).casefold()
    if stopped in {"true", "yes", "1"}:
        return "stopped"
    # RouterOS reports a positive health probe separately from lifecycle
    # state.  Only a healthy container is ready for traffic and for the
    # deployment gate; an unhealthy probe is an explicit failure.
    healthy = str(record.get("healthy", "")).casefold()
    if healthy in {"true", "yes", "1"}:
        return "failed" if has_pull_failure else "running"
    if healthy in {"false", "no", "0"}:
        return "unhealthy"
    # RouterOS 7.24 may expose only the container health-probe result.  The
    # value is formatted as ``good, output: ...`` for a passing probe and as
    # a failure word when the probe cannot reach the application.
    healthcheck = str(record.get("healthcheck-status", "")).casefold().strip()
    if healthcheck.startswith("good"):
        return "failed" if has_pull_failure else "running"
    if healthcheck.startswith(("bad", "failed", "error", "unhealthy")):
        return "unhealthy"
    # RouterOS keeps a failed pull marker even after the container has been
    # stopped.  Preserve it as an explicit failure for the start gate.
    if has_pull_failure:
        return "failed"
    return ""


def _has_lifecycle_signal(record: dict[str, Any]) -> bool:
    """Return whether RouterOS supplied a non-empty lifecycle/probe value."""

    return any(
        record.get(key) is not None and str(record.get(key)).strip()
        for key in _LIFECYCLE_KEYS
    )


def _wait_for(
    client: RouterOSRest,
    container_id: str,
    desired: str,
    settings: DeploymentSettings,
    *,
    allow_empty_stopped: bool = False,
) -> dict[str, Any]:
    deadline = time.monotonic() + settings.timeout_seconds
    last = "unknown"
    empty_stop_observations = 0
    while time.monotonic() < deadline:
        record = client.container(container_id)
        last = _status(record)
        if last in _STATUS_FAILURES:
            # A failed download marker can remain after a stop and while the
            # lifecycle/probe fields are temporarily omitted.  The explicit
            # stop command plus the bounded empty-record confirmation below
            # is the only case where that stale marker is ignored.
            if not (
                desired == "stopped"
                and allow_empty_stopped
                and last == "failed"
                and not _has_lifecycle_signal(record)
            ):
                raise DeploymentError(f"RouterOS container entered failure state {last!r}")
            last = ""
        if last == desired:
            return record
        # RouterOS 7.24 briefly returns a record with no lifecycle or probe
        # fields while a stop is completing.  Once the explicit stop command
        # has been issued, two consecutive empty observations are sufficient
        # confirmation to continue; an empty response is never accepted for
        # the running/healthy gate.
        if (
            desired == "stopped"
            and allow_empty_stopped
            and last == ""
            and not _has_lifecycle_signal(record)
        ):
            empty_stop_observations += 1
            if empty_stop_observations >= _EMPTY_STOP_CONFIRMATIONS:
                return record
        else:
            empty_stop_observations = 0
        time.sleep(settings.poll_seconds)
    raise DeploymentError(f"timed out waiting for RouterOS container status {desired!r} (last {last!r})")


def _image(record: dict[str, Any]) -> str:
    return str(record.get("remote-image") or record.get("tag") or "")


def _registry_relative_image(image: str) -> str:
    """Return the image form expected by RouterOS container registry config."""

    return image.removeprefix("ghcr.io/")


def current_image(settings: DeploymentSettings, client: RouterOSRest | None = None) -> str:
    """Read and validate the installed immutable image without mutating RouterOS."""

    settings.validate()
    client = client or RouterOSRest(settings)
    image = _registry_relative_image(_image(_find_target(client, settings.container_name)))
    if not image or not _IMAGE_PATTERN.fullmatch(image):
        raise DeploymentError("target container does not use a supported immutable GHCR image")
    return image


def deploy(settings: DeploymentSettings, client: RouterOSRest | None = None) -> str:
    settings.validate()
    client = client or RouterOSRest(settings)
    target = _find_target(client, settings.container_name)
    container_id = str(target[".id"])
    # RouterOS resolves `remote-image` relative to `/container/config
    # registry-url`.  Normalize legacy fully qualified references before
    # comparing, patching, or rolling back so a previous deployment cannot
    # reintroduce the GHCR auth failure seen with `ghcr.io/...` on RouterOS
    # 7.24.
    previous_image = _registry_relative_image(_image(target))
    if not previous_image:
        raise DeploymentError("target container has no remote image/tag; refusing update")
    current_status = _status(target)
    release_image = _registry_relative_image(settings.release_image)
    changed = previous_image != release_image
    print(f"Deploying revision {settings.revision} to container {settings.container_name!r}")
    if not changed and current_status == "running":
        print("Container already runs the requested immutable image")
        return settings.revision

    try:
        if current_status != "stopped":
            client.command("stop", container_id)
            _wait_for(client, container_id, "stopped", settings, allow_empty_stopped=True)
        if changed:
            client.patch_container(container_id, {"remote-image": release_image})
            client.command("update", container_id)
            updated = _wait_for(client, container_id, "stopped", settings)
            observed = _registry_relative_image(_image(updated))
            if observed and observed != release_image:
                raise DeploymentError("RouterOS reported a different image after update")
        client.command("start", container_id)
        started = _wait_for(client, container_id, "running", settings)
        observed = _registry_relative_image(_image(started))
        if observed and observed != release_image:
            raise DeploymentError("RouterOS started a different image than requested")
    except Exception as error:
        if changed:
            print("Release failed; attempting automatic rollback to the previous immutable image", file=sys.stderr)
            try:
                record = client.container(container_id)
                if _status(record) != "stopped":
                    client.command("stop", container_id)
                    _wait_for(client, container_id, "stopped", settings, allow_empty_stopped=True)
                client.patch_container(container_id, {"remote-image": previous_image})
                client.command("update", container_id)
                _wait_for(client, container_id, "stopped", settings)
                client.command("start", container_id)
                _wait_for(client, container_id, "running", settings)
                print("Automatic rollback completed", file=sys.stderr)
            except Exception as rollback_error:
                raise DeploymentError(
                    f"release failed and rollback also failed: {rollback_error}"
                ) from error
        if isinstance(error, DeploymentError):
            raise
        raise DeploymentError("release failed") from error
    print("Deployment completed and the container is running")
    return settings.revision


def _settings_from_environment(arguments: argparse.Namespace) -> DeploymentSettings:
    values = {
        "rest_url": os.environ.get("ROUTEROS_REST_URL", ""),
        "username": os.environ.get("ROUTEROS_DEPLOY_USERNAME", ""),
        "password": os.environ.get("ROUTEROS_DEPLOY_PASSWORD", ""),
        "container_name": arguments.container_name or os.environ.get("ROUTEROS_CONTAINER_NAME", ""),
        "release_image": arguments.image or os.environ.get("RELEASE_IMAGE", ""),
        "ca_pem": os.environ.get("ROUTEROS_REST_CA_PEM") or None,
    }
    if not all(values[key] for key in ("rest_url", "username", "password", "container_name", "release_image")):
        raise DeploymentError(
            "ROUTEROS_REST_URL, ROUTEROS_DEPLOY_USERNAME, ROUTEROS_DEPLOY_PASSWORD, "
            "ROUTEROS_CONTAINER_NAME, and RELEASE_IMAGE are required"
        )
    return DeploymentSettings(**values, timeout_seconds=arguments.timeout)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Deploy one immutable GHCR image to a RouterOS container")
    parser.add_argument("--image", help="full immutable GHCR image; defaults to RELEASE_IMAGE")
    parser.add_argument("--container-name", help="exact RouterOS container name")
    parser.add_argument("--current-image", action="store_true", help="print the installed immutable image without changing RouterOS")
    parser.add_argument("--timeout", type=int, default=600, help="per-operation timeout in seconds")
    arguments = parser.parse_args(argv)
    try:
        settings = _settings_from_environment(arguments)
        if arguments.current_image:
            print(current_image(settings))
        else:
            deploy(settings)
    except DeploymentError as error:
        print(f"deployment blocked: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
