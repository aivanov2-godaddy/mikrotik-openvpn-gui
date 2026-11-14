"""Collect a bounded, redacted, read-only RouterOS acceptance window.

The Binary API and REST readers use verified TLS and fixed print/GET allowlists.
The report contains aggregate resource/session measurements and, for the two
named dashboard containers, normalized lifecycle health, source revisions, and
configured image digests. RouterOS 7.23+ healthcheck status is reduced to fixed
categories. On versions exposing container image identity, its config and
ordered layer descriptors are reconciled in memory with GHCR; only a boolean
and verified manifest digest are reported. Raw status/output, command text,
credentials, router/session identity, addresses, and raw replies are excluded.
"""

from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import getpass
import json
import math
import os
from pathlib import Path
import re
import ssl
import sys
import tempfile
import time
from typing import Any, Callable, Iterable, Mapping
from urllib.parse import quote, urlencode, urlsplit, urlunsplit
from urllib.request import HTTPSHandler, HTTPRedirectHandler, Request, build_opener

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from routeros_binary import RouterOSBinaryConnection, RouterOSBinaryError, RouterOSReply
if __package__ in {None, ""}:
    from routeros_container_state import (
        HEALTHCHECK_CONTAINER_PROPLIST,
        LEGACY_CONTAINER_PROPLIST,
        MODERN_CONTAINER_PROPLIST,
        RUNTIME_IDENTITY_CONTAINER_PROPLIST,
        container_proplist_for_version,
        healthcheck_status_categories,
        normalize_container_status,
    )
    from oci_registry_identity import (
        IMAGE_HEALTHCHECK_PROFILES,
        resolve_image_identity,
        runtime_identity_matches,
    )
else:
    from .routeros_container_state import (
        HEALTHCHECK_CONTAINER_PROPLIST,
        LEGACY_CONTAINER_PROPLIST,
        MODERN_CONTAINER_PROPLIST,
        RUNTIME_IDENTITY_CONTAINER_PROPLIST,
        container_proplist_for_version,
        healthcheck_status_categories,
        normalize_container_status,
    )
    from .oci_registry_identity import (
        IMAGE_HEALTHCHECK_PROFILES,
        resolve_image_identity,
        runtime_identity_matches,
    )


MAX_WINDOW_SECONDS = 86_400
MAX_SAMPLES = 10_000
MAX_SAMPLE_GAP_SECONDS = 120
MIN_WINDOW_SECONDS = 1_800
MIN_SAMPLES = 30
MAX_CPU_PERCENT = 80
MAX_MEMORY_PERCENT = 90
MAX_STORAGE_PERCENT = 90
CONTAINER_NAMES = {"canary": "vpn-dashboard-canary", "production": "vpn-dashboard-production"}
FORMAT = "vpn-dashboard-routeros-acceptance-v5"
DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
PROJECT_IMAGE = re.compile(
    r"^(?:ghcr\.io/)?aivanov2-godaddy/mikrotik-openvpn-gui:"
    r"sha-(?P<revision>[0-9a-f]{40})-arm64(?:@(?P<digest>sha256:[0-9a-f]{64}))?$"
)
RESOURCE_PROPLIST = "cpu-load,total-memory,free-memory,total-hdd-space,free-hdd-space,uptime,version"
LAYER_PROPLIST = "name,type,containers"
SESSION_PROPLIST = ".id"
MAX_REST_RESPONSE_BYTES = 1_048_576
REST_TIMEOUT_SECONDS = 10
PARITY_TOLERANCE = {
    "router_cpu_percent": 10.0,
    "router_memory_used_percent": 1.0,
    "router_storage_used_percent": 1.0,
}
REST_PATHS = {
    "resource": ("system/resource", RESOURCE_PROPLIST),
    "containers": ("container", None),
    "layers": ("container/layers", LAYER_PROPLIST),
    "sessions": ("ppp/active", SESSION_PROPLIST),
}


def _container_proplist_for_version(version: str) -> str:
    """Select only properties supported by the reported RouterOS family."""
    return container_proplist_for_version(version, include_runtime_identity=True)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _records(replies: Iterable[RouterOSReply]) -> list[dict[str, Any]]:
    return [reply.attributes for reply in replies if reply.kind == "re" and not reply.dead]


def _single_record(replies: Iterable[RouterOSReply]) -> dict[str, Any]:
    records = _records(replies)
    if len(records) != 1:
        raise ValueError("unexpected RouterOS response shape")
    return records[0]


def _number(values: Mapping[str, Any], key: str, *, integer: bool = False) -> float:
    raw = values.get(key, "")
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+)?", raw):
        raise ValueError("invalid RouterOS numeric field")
    value = float(raw)
    if not math.isfinite(value) or value < 0 or (integer and not value.is_integer()):
        raise ValueError("invalid RouterOS numeric field")
    return value


def _percent(used: float, total: float) -> float:
    if total <= 0 or used < 0 or used > total:
        raise ValueError("invalid RouterOS capacity fields")
    return round(100.0 * used / total, 2)


def _multi_values(value: Any) -> list[str] | None:
    if isinstance(value, str):
        values = [part.strip() for part in value.split(",")]
    elif isinstance(value, list) and all(isinstance(part, str) for part in value):
        values = [part.strip() for part in value]
    else:
        return None
    if not values or any(not part for part in values) or len(values) != len(set(values)):
        return None
    return values


def _runtime_layer_names(
    container_name: str,
    container_row: Mapping[str, Any],
    layer_records: Iterable[Mapping[str, Any]],
) -> list[str] | None:
    listed_names = _multi_values(container_row.get("layers"))
    if listed_names is None:
        return None
    by_name: dict[str, list[Mapping[str, Any]]] = {}
    for record in layer_records:
        name = record.get("name")
        layer_type = record.get("type")
        owners = _multi_values(record.get("containers"))
        if (
            not isinstance(name, str) or not name
            or layer_type not in {"layer", "root-dir"}
            or owners is None
        ):
            return None
        by_name.setdefault(name, []).append(record)
    runtime_names: list[str] = []
    associated_names: set[str] = set()
    for name in listed_names:
        matches = by_name.get(name, [])
        if len(matches) != 1:
            return None
        record = matches[0]
        owners = _multi_values(record.get("containers"))
        layer_type = record.get("type")
        if owners is None or container_name not in owners:
            return None
        associated_names.add(name)
        if layer_type == "layer":
            if not re.fullmatch(r"[0-9a-f]{64}", name):
                return None
            runtime_names.append(name)
        elif layer_type != "root-dir":
            return None
    for name, records in by_name.items():
        if (
            any(container_name in (_multi_values(record.get("containers")) or []) for record in records)
            and name not in associated_names
        ):
            return None
    return runtime_names if runtime_names else None


def _snapshot_from_records(
    resource: Mapping[str, Any],
    containers: Iterable[Mapping[str, Any]],
    active_sessions: int,
    *,
    layer_records: Iterable[Mapping[str, Any]] = (),
    runtime_identities: Mapping[str, Any] | None = None,
    expected_image_references: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    cpu = _number(resource, "cpu-load", integer=True)
    total_memory = _number(resource, "total-memory", integer=True)
    free_memory = _number(resource, "free-memory", integer=True)
    total_storage = _number(resource, "total-hdd-space", integer=True)
    free_storage = _number(resource, "free-hdd-space", integer=True)
    if cpu > 100 or free_memory > total_memory or free_storage > total_storage:
        raise ValueError("invalid RouterOS resource fields")

    containers = list(containers)
    layer_records = list(layer_records)
    runtime_identities = runtime_identities or {}
    expected_image_references = expected_image_references or {}
    result_containers: dict[str, dict[str, Any]] = {}
    healthcheck_statuses: dict[str, list[str]] = {}
    healthcheck_status_supported = (
        _container_proplist_for_version(resource.get("version", ""))
        in {HEALTHCHECK_CONTAINER_PROPLIST, RUNTIME_IDENTITY_CONTAINER_PROPLIST}
    )
    for environment, expected_name in CONTAINER_NAMES.items():
        matching = [row for row in containers if row.get("name") == expected_name]
        if len(matching) != 1:
            raise ValueError("expected dashboard container was not uniquely reported")
        row = matching[0]
        image_match = PROJECT_IMAGE.fullmatch(row.get("remote-image", ""))
        result_containers[environment] = {
            # Keep raw healthcheck text out of the report while preserving the
            # existing fail-closed lifecycle normalization for this signal.
            "healthy": normalize_container_status(dict(row)) == "running",
            "revision": image_match.group("revision") if image_match else None,
            "configured_digest": image_match.group("digest") if image_match else None,
            "runtime_manifest_digest": None,
            "runtime_manifest_digest_verified": False,
            "registry_image_config_healthcheck_profile": None,
        }
        expected_reference = expected_image_references.get(environment)
        identity = runtime_identities.get(environment)
        runtime_layers = _runtime_layer_names(expected_name, row, layer_records)
        configured_image = row.get("remote-image")
        reference_matches = (
            isinstance(expected_reference, str)
            and isinstance(configured_image, str)
            and configured_image.removeprefix("ghcr.io/")
            == expected_reference.removeprefix("ghcr.io/")
        )
        runtime_verified = (
            reference_matches
            and runtime_layers is not None
            and runtime_identity_matches(row.get("image-id"), runtime_layers, identity)
        )
        manifest_digest = identity.get("manifest_digest") if isinstance(identity, dict) else None
        if not isinstance(manifest_digest, str) or DIGEST.fullmatch(manifest_digest) is None:
            manifest_digest = None
            runtime_verified = False
        result_containers[environment]["runtime_manifest_digest"] = (
            manifest_digest if runtime_verified else None
        )
        result_containers[environment]["runtime_manifest_digest_verified"] = bool(runtime_verified)
        image_healthcheck_profile = (
            identity.get("image_healthcheck_profile") if isinstance(identity, dict) else None
        )
        if (
            not isinstance(image_healthcheck_profile, str)
            or image_healthcheck_profile not in IMAGE_HEALTHCHECK_PROFILES
        ):
            image_healthcheck_profile = None
        result_containers[environment]["registry_image_config_healthcheck_profile"] = (
            image_healthcheck_profile if runtime_verified else None
        )
        healthcheck_statuses[environment] = (
            healthcheck_status_categories(row)
            if healthcheck_status_supported
            else ["unavailable"]
        )

    return {
        "router_cpu_percent": int(cpu),
        "router_memory_used_percent": _percent(total_memory - free_memory, total_memory),
        "router_storage_used_percent": _percent(total_storage - free_storage, total_storage),
        "active_vpn_sessions": active_sessions,
        "containers": result_containers,
        "healthcheck_status_categories": healthcheck_statuses,
    }


def _snapshot(
    connection: RouterOSBinaryConnection,
    *,
    runtime_identities: Mapping[str, Any] | None = None,
    expected_image_references: Mapping[str, str] | None = None,
) -> dict[str, Any]:
    """Read only the allowlisted aggregate fields; discard every raw reply."""
    resource = _single_record(connection.execute(
        "/system/resource/print", query=(f".proplist={RESOURCE_PROPLIST}",)
    ))
    container_proplist = _container_proplist_for_version(resource.get("version", ""))
    containers = _records(connection.execute(
        "/container/print", query=(f".proplist={container_proplist}",)
    ))
    layers = (
        _records(connection.execute("/container/layers/print", query=(f".proplist={LAYER_PROPLIST}",)))
        if container_proplist == RUNTIME_IDENTITY_CONTAINER_PROPLIST else []
    )
    # Read .id values only to count active sessions. IDs, usernames, addresses,
    # and other RouterOS attributes are deliberately discarded.
    active_sessions = len(_records(connection.execute(
        "/ppp/active/print", query=(f".proplist={SESSION_PROPLIST}",)
    )))
    return _snapshot_from_records(
        resource,
        containers,
        active_sessions,
        layer_records=layers,
        runtime_identities=runtime_identities,
        expected_image_references=expected_image_references,
    )


class _NoRedirectHandler(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class RouterOSRestAcceptanceReader:
    """Narrow HTTPS-only REST reader for independent snapshot parity."""

    def __init__(
        self,
        base_url: str,
        username: str,
        password: str,
        *,
        ca_file: str | None = None,
        timeout: float = REST_TIMEOUT_SECONDS,
    ) -> None:
        parsed = urlsplit(base_url)
        if (
            parsed.scheme != "https"
            or not parsed.hostname
            or parsed.username is not None
            or parsed.password is not None
            or parsed.query
            or parsed.fragment
            or parsed.path not in {"", "/", "/rest"}
            or not username
            or not password
        ):
            raise ValueError("REST acceptance requires a credential-free HTTPS origin and credentials")
        if not math.isfinite(timeout) or not 1 <= timeout <= 30:
            raise ValueError("REST timeout is outside the allowed range")
        host = parsed.hostname.encode("idna").decode("ascii").lower()
        netloc = f"[{host}]" if ":" in host else host
        if parsed.port is not None:
            netloc += f":{parsed.port}"
        self._origin = urlunsplit(("https", netloc, "", "", ""))
        self._authorization = "Basic " + base64.b64encode(
            f"{username}:{password}".encode("utf-8")
        ).decode("ascii")
        self._timeout = timeout
        context = ssl.create_default_context(cafile=ca_file)
        self._opener = build_opener(HTTPSHandler(context=context), _NoRedirectHandler())

    def _get_records(self, path_key: str, *, proplist: str | None = None) -> list[dict[str, str]]:
        if path_key not in REST_PATHS:
            raise ValueError("REST path is not allowlisted")
        path, fixed_proplist = REST_PATHS[path_key]
        if fixed_proplist is None:
            if proplist not in {
                LEGACY_CONTAINER_PROPLIST,
                MODERN_CONTAINER_PROPLIST,
                HEALTHCHECK_CONTAINER_PROPLIST,
                RUNTIME_IDENTITY_CONTAINER_PROPLIST,
            }:
                raise ValueError("REST container property list is not allowlisted")
        elif proplist is not None:
            raise ValueError("REST property override is not allowlisted")
        else:
            proplist = fixed_proplist
        query = urlencode({".proplist": proplist}, safe=".,")
        url = f"{self._origin}/rest/{quote(path, safe='/')}?{query}"
        request = Request(
            url,
            headers={"Authorization": self._authorization, "Accept": "application/json"},
            method="GET",
        )
        with self._opener.open(request, timeout=self._timeout) as response:
            if response.status != 200:
                raise ValueError("unexpected RouterOS REST status")
            body = response.read(MAX_REST_RESPONSE_BYTES + 1)
        if len(body) > MAX_REST_RESPONSE_BYTES:
            raise ValueError("RouterOS REST response exceeded the size limit")
        decoded = json.loads(body)
        if not isinstance(decoded, list) or any(
            not isinstance(record, dict)
            or any(
                not isinstance(key, str)
                or not (
                    isinstance(value, str)
                    or (key in {"layers", "containers"} and isinstance(value, list)
                        and all(isinstance(part, str) for part in value))
                )
                for key, value in record.items()
            )
            for record in decoded
        ):
            raise ValueError("unexpected RouterOS REST response shape")
        return decoded

    def snapshot(
        self,
        *,
        runtime_identities: Mapping[str, Any] | None = None,
        expected_image_references: Mapping[str, str] | None = None,
    ) -> dict[str, Any]:
        resource_records = self._get_records("resource")
        if len(resource_records) != 1:
            raise ValueError("unexpected RouterOS REST resource response shape")
        container_proplist = _container_proplist_for_version(resource_records[0].get("version", ""))
        containers = self._get_records("containers", proplist=container_proplist)
        layers = self._get_records("layers") if container_proplist == RUNTIME_IDENTITY_CONTAINER_PROPLIST else []
        sessions = self._get_records("sessions")
        return _snapshot_from_records(
            resource_records[0],
            containers,
            len(sessions),
            layer_records=layers,
            runtime_identities=runtime_identities,
            expected_image_references=expected_image_references,
        )

    def close(self) -> None:
        self._authorization = ""


def _snapshot_mismatches(binary: Mapping[str, Any], rest: Mapping[str, Any]) -> list[str]:
    """Return safe field labels only; never retain or report either payload."""
    mismatches = []
    for field, tolerance in PARITY_TOLERANCE.items():
        left, right = binary.get(field), rest.get(field)
        if (
            isinstance(left, bool) or not isinstance(left, (int, float))
            or isinstance(right, bool) or not isinstance(right, (int, float))
            or abs(left - right) > tolerance
        ):
            mismatches.append(field)
    if binary.get("active_vpn_sessions") != rest.get("active_vpn_sessions"):
        mismatches.append("active_vpn_sessions")
    if binary.get("containers") != rest.get("containers"):
        mismatches.append("containers")
    return mismatches


def collect(
    connection: RouterOSBinaryConnection,
    *,
    rest_reader: RouterOSRestAcceptanceReader,
    username: str,
    password: str,
    expected_revisions: Mapping[str, str],
    expected_digests: Mapping[str, str | None],
    duration_seconds: float = MIN_WINDOW_SECONDS,
    interval_seconds: float = 60,
    clock: Callable[[], datetime] = _utc_now,
    monotonic: Callable[[], float] = time.monotonic,
    sleep: Callable[[float], None] = time.sleep,
    registry_identity_resolver: Callable[..., Any] | None = None,
    registry_timeout_seconds: float = 8,
) -> dict[str, Any]:
    if not math.isfinite(duration_seconds) or not MIN_WINDOW_SECONDS <= duration_seconds <= MAX_WINDOW_SECONDS:
        raise ValueError("window duration must be between 1800 seconds and 24 hours")
    if not math.isfinite(interval_seconds) or not 1 <= interval_seconds <= MAX_SAMPLE_GAP_SECONDS:
        raise ValueError("sample interval must be between 1 and 120 seconds")
    if math.ceil(duration_seconds / interval_seconds) > MAX_SAMPLES:
        raise ValueError("sample count exceeds the configured limit")
    if not username or not password:
        raise ValueError("RouterOS credentials are required")
    if set(expected_revisions) != set(CONTAINER_NAMES) or any(
        not re.fullmatch(r"[0-9a-f]{40}", revision) for revision in expected_revisions.values()
    ):
        raise ValueError("expected canary and production revisions must be full commit SHAs")
    if (
        set(expected_digests) != set(CONTAINER_NAMES)
        or not isinstance(expected_digests["canary"], str)
        or DIGEST.fullmatch(expected_digests["canary"]) is None
        or (
            expected_digests["production"] is not None
            and (
                not isinstance(expected_digests["production"], str)
                or DIGEST.fullmatch(expected_digests["production"]) is None
            )
        )
    ):
        raise ValueError("expected canary digest and optional production digest must be lowercase SHA-256")

    if not math.isfinite(registry_timeout_seconds) or not 1 <= registry_timeout_seconds <= 30:
        raise ValueError("registry identity timeout must be between 1 and 30 seconds")
    if registry_identity_resolver is None:
        registry_identity_resolver = resolve_image_identity

    expected_image_references = {
        environment: (
            f"ghcr.io/aivanov2-godaddy/mikrotik-openvpn-gui:"
            f"sha-{expected_revisions[environment]}-arm64"
            + (f"@{expected_digests[environment]}" if expected_digests[environment] else "")
        )
        for environment in CONTAINER_NAMES
    }
    runtime_identities_before: dict[str, Any] = {}
    for environment, image in expected_image_references.items():
        try:
            runtime_identities_before[environment] = registry_identity_resolver(
                image, timeout=registry_timeout_seconds
            )
        except Exception:
            runtime_identities_before[environment] = None

    samples: list[dict[str, Any]] = []
    try:
        connection.connect(username, password)
        started = clock()
        start_tick = monotonic()
        deadline = start_tick + duration_seconds
        while True:
            at = clock()
            tick = monotonic()
            try:
                binary_values = _snapshot(
                    connection,
                    runtime_identities=runtime_identities_before,
                    expected_image_references=expected_image_references,
                )
                rest_values = rest_reader.snapshot(
                    runtime_identities=runtime_identities_before,
                    expected_image_references=expected_image_references,
                )
                mismatches = _snapshot_mismatches(binary_values, rest_values)
                sample = {
                    "at": at.isoformat(), "_tick": tick, **binary_values,
                    "ok": not mismatches, "rest_parity_ok": not mismatches,
                    "rest_mismatches": mismatches,
                }
            except Exception as error:  # Fail closed; never retain RouterOS response text.
                sample = {
                    "at": at.isoformat(), "_tick": tick, "ok": False,
                    "rest_parity_ok": False, "rest_mismatches": [],
                    "error": type(error).__name__,
                }
            samples.append(sample)
            remaining = deadline - monotonic()
            if remaining <= 0:
                break
            sleep(min(interval_seconds, remaining))
        ended = clock()
        end_tick = monotonic()
        runtime_identities_after: dict[str, Any] = {}
        for environment, image in expected_image_references.items():
            try:
                runtime_identities_after[environment] = registry_identity_resolver(
                    image, timeout=registry_timeout_seconds
                )
            except Exception:
                runtime_identities_after[environment] = None
    finally:
        connection.close()
        rest_reader.close()

    wall_gaps = [
        (datetime.fromisoformat(right["at"]) - datetime.fromisoformat(left["at"])).total_seconds()
        for left, right in zip(samples, samples[1:])
    ]
    gaps = [right["_tick"] - left["_tick"] for left, right in zip(samples, samples[1:])]
    successful = [sample for sample in samples if sample["ok"]]
    container_names = tuple(CONTAINER_NAMES)
    container_healthy = bool(successful) and all(
        sample["containers"][name]["healthy"]
        for sample in successful
        for name in container_names
    )
    revision_values = {
        name: {sample["containers"][name]["revision"] for sample in successful}
        for name in container_names
    }
    revisions = {
        name: sorted(revision for revision in revision_values[name] if revision is not None)
        for name in container_names
    }
    digest_values = {
        name: {sample["containers"][name]["configured_digest"] for sample in successful}
        for name in container_names
    }
    runtime_identity_values = {
        name: {sample["containers"][name]["runtime_manifest_digest"] for sample in successful}
        for name in container_names
    }
    runtime_identity_sample_matches = {
        name: bool(successful) and all(
            sample["containers"][name]["runtime_manifest_digest_verified"]
            for sample in successful
        )
        for name in container_names
    }
    runtime_identity_stable = {
        name: (
            isinstance(runtime_identities_before.get(name), dict)
            and isinstance(runtime_identities_after.get(name), dict)
            and runtime_identities_before[name] == runtime_identities_after[name]
            and len(runtime_identity_values[name]) == 1
            and None not in runtime_identity_values[name]
            and next(iter(runtime_identity_values[name]))
            == runtime_identities_before[name].get("manifest_digest")
        )
        for name in container_names
    }
    runtime_identity_verified = {
        name: runtime_identity_sample_matches[name] and runtime_identity_stable[name]
        for name in container_names
    }
    image_healthcheck_profile_values = {
        name: {
            sample["containers"][name]["registry_image_config_healthcheck_profile"]
            for sample in successful
        }
        for name in container_names
    }
    registry_image_config_healthcheck_profiles = {}
    for name in container_names:
        identity = runtime_identities_before.get(name)
        profile = identity.get("image_healthcheck_profile") if isinstance(identity, dict) else None
        registry_image_config_healthcheck_profiles[name] = (
            profile
            if runtime_identity_verified[name]
            and isinstance(profile, str)
            and profile in IMAGE_HEALTHCHECK_PROFILES
            and image_healthcheck_profile_values[name] == {profile}
            else None
        )
    cpu_values = [sample["router_cpu_percent"] for sample in successful]
    memory_values = [sample["router_memory_used_percent"] for sample in successful]
    storage_values = [sample["router_storage_used_percent"] for sample in successful]
    session_values = [sample["active_vpn_sessions"] for sample in successful]
    wall_duration = (ended - started).total_seconds()
    duration = max(0.0, end_tick - start_tick)
    failed = []
    if duration < MIN_WINDOW_SECONDS:
        failed.append("soak_window_too_short")
    if len(successful) < MIN_SAMPLES:
        failed.append("successful_samples_insufficient")
    if len(successful) != len(samples):
        failed.append("routeros_sample_failures")
    if any(not sample["rest_parity_ok"] for sample in samples):
        failed.append("routeros_rest_parity_unavailable_or_mismatched")
    if max(gaps, default=0) > MAX_SAMPLE_GAP_SECONDS:
        failed.append("sample_gap_exceeded")
    if any(
        wall_gap <= 0 or monotonic_gap <= 0 or abs(wall_gap - monotonic_gap) > 5
        for wall_gap, monotonic_gap in zip(wall_gaps, gaps)
    ) or wall_duration < 0 or abs(wall_duration - duration) > 5:
        failed.append("collection_clock_anomaly")
    if not container_healthy:
        failed.append("dashboard_container_unhealthy")
    if not all(
        revisions[name] and len(revision_values[name]) == 1 and None not in revision_values[name]
        for name in container_names
    ):
        failed.append("container_revision_missing_or_changed")
    if any(
        revisions[name] != [expected_revisions[name]] or None in revision_values[name]
        for name in container_names
    ):
        failed.append("container_revision_mismatch")
    if any(len(digest_values[name]) != 1 for name in container_names):
        failed.append("container_configured_digest_missing_or_changed")
    if any(digest_values[name] != {expected_digests[name]} for name in container_names):
        failed.append("container_configured_digest_mismatch")
    if not all(runtime_identity_verified.values()):
        failed.append("container_runtime_manifest_digest_unverified")
    if max(cpu_values, default=math.inf) > MAX_CPU_PERCENT:
        failed.append("router_cpu_threshold_exceeded")
    if max(memory_values, default=math.inf) > MAX_MEMORY_PERCENT:
        failed.append("router_memory_threshold_exceeded")
    if max(storage_values, default=math.inf) > MAX_STORAGE_PERCENT:
        failed.append("router_storage_threshold_exceeded")
    # A quiet or empty router window cannot prove that the disposable VPN
    # client's session was observed. Disconnect/reconnect tests are allowed;
    # require at least one active session at some point, not throughout.
    if max(session_values, default=0) < 1:
        failed.append("vpn_test_session_not_observed")

    return {
        "format": FORMAT,
        "collected_at": ended.isoformat(),
        "observation_started_at": started.isoformat(),
        "observation_ended_at": ended.isoformat(),
        "duration_seconds": round(duration, 3),
        "sample_interval_seconds": interval_seconds,
        "sample_count": len(samples),
        "successful_sample_count": len(successful),
        "failed_sample_count": len(samples) - len(successful),
        "rest_parity_successful_sample_count": sum(sample["rest_parity_ok"] for sample in samples),
        "rest_parity_failed_sample_count": sum(not sample["rest_parity_ok"] for sample in samples),
        "rest_parity_numeric_tolerances": PARITY_TOLERANCE,
        "max_sample_gap_seconds": round(max(gaps, default=0), 3),
        "router_cpu_peak_percent": max(cpu_values, default=None),
        "router_memory_peak_percent": max(memory_values, default=None),
        "router_storage_peak_percent": max(storage_values, default=None),
        "resource_thresholds_percent": {
            "router_cpu_max": MAX_CPU_PERCENT,
            "router_memory_max": MAX_MEMORY_PERCENT,
            "router_storage_max": MAX_STORAGE_PERCENT,
        },
        "active_vpn_sessions_min": min(session_values, default=None),
        "active_vpn_sessions_max": max(session_values, default=None),
        "containers": {
            name: {
                "healthy_for_all_successful_samples": bool(successful) and all(
                    sample["containers"][name]["healthy"] for sample in successful
                ),
                "observed_source_revisions": revisions[name],
                "observed_configured_digests": sorted(
                    digest for digest in digest_values[name] if digest is not None
                ),
                "configured_digest_matches_expected": (
                    bool(successful) and digest_values[name] == {expected_digests[name]}
                ),
                "runtime_manifest_digest": (
                    runtime_identities_before[name]["manifest_digest"]
                    if runtime_identity_verified[name] else None
                ),
                "runtime_manifest_digest_verified": runtime_identity_verified[name],
                "registry_image_config_healthcheck_profile": (
                    registry_image_config_healthcheck_profiles[name]
                ),
            }
            for name in container_names
        },
        "healthcheck_status_categories": {
            name: sorted(
                {
                    category
                    for sample in successful
                    for category in sample["healthcheck_status_categories"][name]
                }
            )
            for name in container_names
        },
        "passed": not failed,
        "failed_gates": sorted(set(failed)),
        "read_only_api_paths": [
            "/system/resource/print", "/container/print", "/container/layers/print", "/ppp/active/print"
        ],
        "read_only_rest_paths": [
            "/rest/system/resource", "/rest/container", "/rest/container/layers", "/rest/ppp/active"
        ],
        "credentials_or_raw_router_data_written": False,
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="local private output JSON path")
    parser.add_argument("--host-env", default="ROUTEROS_ACCEPTANCE_HOST", help="environment variable with the verified TLS API hostname")
    parser.add_argument("--username-env", default="ROUTEROS_ACCEPTANCE_USERNAME")
    parser.add_argument("--password-env", default="ROUTEROS_ACCEPTANCE_PASSWORD")
    parser.add_argument("--ca-file-env", default="ROUTEROS_ACCEPTANCE_CA_FILE")
    parser.add_argument("--rest-url-env", default="ROUTEROS_ACCEPTANCE_REST_URL")
    parser.add_argument("--rest-username-env", default="ROUTEROS_ACCEPTANCE_REST_USERNAME")
    parser.add_argument("--rest-password-env", default="ROUTEROS_ACCEPTANCE_REST_PASSWORD")
    parser.add_argument("--rest-ca-file-env", default="ROUTEROS_ACCEPTANCE_REST_CA_FILE")
    parser.add_argument("--port", type=int, default=8729)
    parser.add_argument("--canary-revision", required=True, help="expected full immutable canary source commit")
    parser.add_argument("--production-revision", required=True, help="expected full immutable production source commit")
    parser.add_argument("--canary-digest", required=True, help="expected digest pinned in the canary RouterOS image reference")
    parser.add_argument("--production-digest", help="expected digest pinned in the production RouterOS image reference; omit for a tag-only prior image")
    parser.add_argument("--duration-seconds", type=float, default=MIN_WINDOW_SECONDS)
    parser.add_argument("--interval-seconds", type=float, default=60)
    args = parser.parse_args()
    try:
        host = os.environ.get(args.host_env, "")
        username = os.environ.get(args.username_env, "")
        password = os.environ.get(args.password_env, "") or getpass.getpass("RouterOS read-only API password: ")
        rest_url = os.environ.get(args.rest_url_env, "")
        rest_username = os.environ.get(args.rest_username_env, "")
        rest_password = os.environ.get(args.rest_password_env, "") or getpass.getpass("RouterOS read-only REST password: ")
        if not host or not username or not rest_url or not rest_username or not 1 <= args.port <= 65535:
            raise ValueError("required connection settings are missing")
        connection = RouterOSBinaryConnection(
            host,
            port=args.port,
            ca_file=os.environ.get(args.ca_file_env) or None,
            timeout=10,
        )
        report = collect(
            connection,
            rest_reader=RouterOSRestAcceptanceReader(
                rest_url,
                rest_username,
                rest_password,
                ca_file=os.environ.get(args.rest_ca_file_env) or None,
            ),
            username=username,
            password=password,
            expected_revisions={
                "canary": args.canary_revision,
                "production": args.production_revision,
            },
            expected_digests={
                "canary": args.canary_digest,
                "production": args.production_digest,
            },
            duration_seconds=args.duration_seconds,
            interval_seconds=args.interval_seconds,
        )
        _write_report(Path(args.output), report)
        print(json.dumps({key: value for key, value in report.items() if key not in {"containers"}}, sort_keys=True))
        return 0 if report["passed"] else 1
    except (OSError, ValueError, RouterOSBinaryError) as error:
        # Exception text can contain private endpoints or RouterOS response data.
        failure_report = {
            "format": FORMAT,
            "collected": False,
            "collected_at": _utc_now().isoformat(),
            "passed": False,
            "failed_gates": ["collection_failed"],
            "error": type(error).__name__,
            "credentials_or_raw_router_data_written": False,
        }
        try:
            _write_report(Path(args.output), failure_report)
        except OSError:
            # Preserve the failure exit even when the requested output is unwritable.
            pass
        print(json.dumps({key: value for key, value in failure_report.items() if key != "collected_at"}, sort_keys=True))
        return 2


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    """Atomically replace a report so readers never observe partial JSON."""
    temporary_path: Path | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as temporary:
            temporary_path = Path(temporary.name)
            temporary.write(json.dumps(report, indent=2, sort_keys=True) + "\n")
            temporary.flush()
            os.fsync(temporary.fileno())
        os.replace(temporary_path, path)
    finally:
        if temporary_path is not None:
            temporary_path.unlink(missing_ok=True)


if __name__ == "__main__":
    raise SystemExit(main())
