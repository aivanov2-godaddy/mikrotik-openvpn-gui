"""Normalize RouterOS container lifecycle records across RouterOS versions."""

from __future__ import annotations

import re
from typing import Any, Mapping


STATUS_FAILURES = {"failed", "invalid", "error", "unhealthy"}
LIFECYCLE_KEYS = (
    "status",
    "running",
    ".running",
    "stopped",
    "stopping",
    "starting",
    "healthy",
    "healthcheck-status",
    "download/extract failed",
)
MAX_HEALTHCHECK_STATUS_CHARS = 4096

LEGACY_CONTAINER_PROPLIST = "name,status,remote-image"
MODERN_CONTAINER_PROPLIST = (
    "name,running,stopped,starting,stopping,healthy,download/extract failed,remote-image"
)
HEALTHCHECK_CONTAINER_PROPLIST = (
    "name,running,stopped,starting,stopping,healthy,healthcheck-status,"
    "download/extract failed,remote-image"
)
RUNTIME_IDENTITY_CONTAINER_PROPLIST = (
    "name,running,stopped,starting,stopping,healthy,healthcheck-status,"
    "download/extract failed,remote-image,image-id,layers"
)
_ROUTEROS_VERSION = re.compile(r"^\s*(\d+)\.(\d+)(?:\.\d+)?(?=$|[^0-9])")


def container_proplist_for_version(
    version: str, *, include_runtime_identity: bool = False
) -> str:
    """Return lifecycle fields supported by a RouterOS release family.

    Runtime identity fields are opt-in because most readers do not need image
    layer ownership and should not request it.
    """

    match = _ROUTEROS_VERSION.match(version)
    if not match:
        raise ValueError("RouterOS version is missing or malformed")
    major, minor = (int(part) for part in match.groups())
    if major < 7:
        raise ValueError("RouterOS container state format is unsupported")
    if major == 7 and minor < 20:
        return LEGACY_CONTAINER_PROPLIST
    if major == 7 and minor < 23:
        return MODERN_CONTAINER_PROPLIST
    if include_runtime_identity and (major > 7 or minor >= 25):
        return RUNTIME_IDENTITY_CONTAINER_PROPLIST
    if major > 7 or minor >= 23:
        return HEALTHCHECK_CONTAINER_PROPLIST
    return MODERN_CONTAINER_PROPLIST


def healthcheck_status_categories(record: Mapping[str, Any]) -> list[str]:
    """Return allowlisted healthcheck indicators without preserving its text."""

    value = record.get("healthcheck-status")
    if not isinstance(value, str) or not value.strip():
        return ["unavailable"]
    if len(value) > MAX_HEALTHCHECK_STATUS_CHARS:
        return ["unclassified"]

    text = value.casefold()
    prefix = text.lstrip()
    if prefix.startswith("good"):
        return ["good"]

    categories = set()
    for marker, category in (
        ("segmentation fault", "segmentation_fault"),
        ("resource unavailable", "resource_unavailable"),
        ("resource temporarily unavailable", "resource_unavailable"),
        ("could not fork", "resource_unavailable"),
        ("timed out", "timeout"),
        ("timeout", "timeout"),
        ("not found", "command_not_found"),
    ):
        if marker in text:
            categories.add(category)

    if prefix.startswith(("bad", "failed", "error", "unhealthy")):
        categories.add("failed")
    if not categories:
        categories.add("other")
    return sorted(categories)


def normalize_container_status(record: dict[str, Any]) -> str:
    """Return a normalized lifecycle state, or an empty string if unknown."""

    pull_failed = str(record.get("download/extract failed", "")).casefold()
    has_pull_failure = pull_failed in {"true", "yes", "1"}
    if has_pull_failure:
        return "failed"

    true_values = {"true", "yes", "1"}
    false_values = {"false", "no", "0"}
    running_aliases = [key for key in ("running", ".running") if key in record]
    known_running_values = {
        str(record[key]).casefold()
        for key in running_aliases
        if str(record[key]).casefold() in true_values | false_values
    }
    if len(known_running_values) > 1:
        return ""

    active_flags = set()
    if any(str(record[key]).casefold() in true_values for key in running_aliases):
        active_flags.add("running")
    active_flags.update(
        state
        for state in ("stopped", "starting", "stopping")
        if str(record.get(state, "")).casefold() in true_values
    )
    if len(active_flags) > 1:
        return ""
    active_state = next(iter(active_flags), "")
    if active_state in {"starting", "stopping"}:
        return active_state

    healthy = str(record.get("healthy", "")).casefold()
    healthcheck = str(record.get("healthcheck-status", "")).casefold().strip()
    explicit_unhealthy = healthy in {"false", "no", "0"} or healthcheck.startswith(
        ("bad", "failed", "error", "unhealthy")
    )

    status = str(record.get("status", "")).casefold()
    if status:
        if status == "healthy":
            return "unhealthy" if explicit_unhealthy else "running"
        if status in {"running", "starting", "starting-with-healthcheck"}:
            return "unhealthy" if status == "running" and explicit_unhealthy else status
        return status

    running = str(record.get("running", record.get(".running", ""))).casefold()
    if running in {"true", "yes", "1"}:
        return "unhealthy" if explicit_unhealthy else "running"
    if running in {"false", "no", "0"}:
        return "stopped"

    stopped = str(record.get("stopped", "")).casefold()
    if stopped in {"true", "yes", "1"}:
        return "stopped"

    if healthy in {"true", "yes", "1"}:
        return "running"
    if healthy in {"false", "no", "0"}:
        return "unhealthy"

    if healthcheck.startswith("good"):
        return "running"
    if healthcheck.startswith(("bad", "failed", "error", "unhealthy")):
        return "unhealthy"
    return ""


def has_container_lifecycle_signal(record: dict[str, Any]) -> bool:
    """Whether the record has any non-empty lifecycle or probe field."""

    return any(
        record.get(key) is not None and str(record.get(key)).strip()
        for key in LIFECYCLE_KEYS
    )
