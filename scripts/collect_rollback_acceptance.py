"""Capture source-checked canary rollback checkpoints without changing RouterOS."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import getpass
import json
import os
from pathlib import Path
import re
import sys
from typing import Any, Callable, Mapping
from urllib.parse import urlsplit

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from routeros_binary import RouterOSBinaryConnection, RouterOSBinaryError
from scripts.collect_release_acceptance import _get, _json_status, _probe_url, _write_json_atomically
from scripts.collect_routeros_acceptance import (
    CONTAINER_NAMES,
    PROJECT_IMAGE,
    RouterOSRestAcceptanceReader,
    _snapshot,
    _snapshot_mismatches,
)
from scripts.rollback_acceptance import DIGEST, READBACKS, REPORT_FORMAT, SOURCE_FIELDS


CHECKPOINT_INSTRUCTIONS = {
    "production_before": "Before the canary drill, with production and the prior canary image healthy.",
    "canary_before": "Confirm the canary is still on its prior digest-pinned image.",
    "canary_candidate": "Apply the candidate to canary only and wait for it to become ready.",
    "canary_after_rollback": "Rollback canary to its exact prior image and wait for readiness.",
    "production_after": "Confirm production is still unchanged after the canary rollback.",
    "canary_candidate_restored": "Reapply the candidate to canary and wait for readiness before its soak.",
}
READYZ_HOSTS = {"canary": "vpn-dev.wanted.sx", "production": "vpn.wanted.sx"}


def _validate_origin(value: str, *, expected_host: str) -> str:
    parsed = urlsplit(value)
    if (
        parsed.scheme not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ValueError("readiness origins must be credential-free HTTP(S) origins")
    try:
        hostname = parsed.hostname.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError as error:
        raise ValueError("readiness host is invalid") from error
    if (
        parsed.scheme != "https"
        or hostname != expected_host
        or hostname not in set(READYZ_HOSTS.values())
        or parsed.port not in {None, 443}
    ):
        raise ValueError("readiness origin must use the exact configured HTTPS environment host")
    _probe_url(value, "/readyz")
    return value


def collect_checkpoint(
    connection: RouterOSBinaryConnection,
    rest_reader: RouterOSRestAcceptanceReader,
    *,
    username: str,
    password: str,
    readyz_origins: Mapping[str, str],
    probe: Callable[..., tuple[int, bytes]] = _get,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
) -> dict[str, Any]:
    """Read both container states through independent authenticated APIs and app readiness."""
    if set(readyz_origins) != set(CONTAINER_NAMES):
        raise ValueError("readiness origins must include canary and production")
    origins = {
        name: _validate_origin(origin, expected_host=READYZ_HOSTS[name])
        for name, origin in readyz_origins.items()
    }
    if not username or not password:
        raise ValueError("read-only RouterOS credentials are required")
    try:
        connection.connect(username, password)
        binary = _snapshot(connection)
        rest = rest_reader.snapshot()
        if _snapshot_mismatches(binary, rest):
            raise ValueError("RouterOS Binary API and REST snapshots did not match")
        ready_payloads: dict[str, dict[str, Any]] = {}
        for environment, origin in origins.items():
            status, body = probe(_probe_url(origin, "/readyz"), timeout=10)
            ready_payload = _json_status(body) if status == 200 else {}
            revision = binary["containers"][environment]["revision"]
            if (
                ready_payload.get("status") != "ready"
                or ready_payload.get("revision") != revision
                or not isinstance(revision, str)
                or re.fullmatch(r"[0-9a-f]{40}", revision) is None
            ):
                raise ValueError("application readiness did not match RouterOS container revision")
            ready_payloads[environment] = ready_payload
        captured_at = clock()
        if captured_at.tzinfo is None or captured_at.utcoffset() is None:
            raise ValueError("checkpoint clock must return a timezone-aware timestamp")
        observed_at = captured_at.astimezone(timezone.utc).isoformat()
        revisions = {
            environment: binary["containers"][environment]["revision"]
            for environment in CONTAINER_NAMES
        }
        health = {
            environment: binary["containers"][environment]["healthy"] is True
            for environment in CONTAINER_NAMES
        }
        readiness = {
            environment: ready_payloads[environment].get("status") == "ready"
            for environment in CONTAINER_NAMES
        }
        return {
            "observed_at": observed_at,
            "containers": binary["containers"],
            "readiness": ready_payloads,
            "source": {
                "collector": "authenticated-routeros-api-rest-readyz-v1",
                "captured_at": observed_at,
                "api_authenticated": True,
                "rest_authenticated": True,
                "rest_parity_verified": True,
                "canary_revision": revisions["canary"],
                "production_revision": revisions["production"],
                "canary_ready_revision": ready_payloads["canary"]["revision"],
                "production_ready_revision": ready_payloads["production"]["revision"],
                "canary_healthy": health["canary"],
                "production_healthy": health["production"],
                "canary_ready": readiness["canary"],
                "production_ready": readiness["production"],
            },
        }
    finally:
        connection.close()
        rest_reader.close()


def build_report(
    *,
    candidate_image: str,
    candidate_digest: str,
    previous_canary_image: str,
    production_image: str,
    checkpoints: Mapping[str, Mapping[str, Any]],
) -> dict[str, Any]:
    candidate = PROJECT_IMAGE.fullmatch(candidate_image)
    previous = PROJECT_IMAGE.fullmatch(previous_canary_image)
    production = PROJECT_IMAGE.fullmatch(production_image)
    if (
        candidate is None
        or previous is None
        or production is None
        or candidate_image == previous_canary_image
        or not isinstance(candidate_digest, str)
        or DIGEST.fullmatch(candidate_digest) is None
        or candidate.group("digest") != candidate_digest
        or previous.group("digest") is None
        or set(checkpoints) != set(READBACKS)
    ):
        raise ValueError("candidate identity or rollback checkpoint set is invalid")

    readbacks: dict[str, dict[str, Any]] = {}
    expected_canary = previous.group("revision")
    expected_production = production.group("revision")
    for name in READBACKS:
        checkpoint = checkpoints[name]
        environment = "production" if name.startswith("production_") else "canary"
        expected_image = production_image if environment == "production" else (
            candidate_image if name in {"canary_candidate", "canary_candidate_restored"}
            else previous_canary_image
        )
        item_image = expected_image
        source = checkpoint.get("source")
        containers = checkpoint.get("containers")
        readiness = checkpoint.get("readiness")
        if (
            not isinstance(source, dict)
            or set(source) != SOURCE_FIELDS
            or not isinstance(containers, dict)
            or not isinstance(readiness, dict)
            or any(not isinstance(containers.get(env), dict) for env in CONTAINER_NAMES)
            or any(not isinstance(readiness.get(env), dict) for env in CONTAINER_NAMES)
        ):
            raise ValueError("checkpoint did not come from the authenticated collector")
        current_canary_revision = candidate.group("revision") if name in {
            "canary_candidate", "canary_candidate_restored"
        } else expected_canary
        if (
            containers["canary"].get("revision") != current_canary_revision
            or containers["production"].get("revision") != expected_production
            or readiness["canary"].get("revision") != current_canary_revision
            or readiness["production"].get("revision") != expected_production
            or containers["canary"].get("healthy") is not True
            or containers["production"].get("healthy") is not True
            or source.get("canary_revision") != containers["canary"].get("revision")
            or source.get("production_revision") != containers["production"].get("revision")
            or source.get("canary_ready_revision") != readiness["canary"].get("revision")
            or source.get("production_ready_revision") != readiness["production"].get("revision")
            or readiness["canary"].get("status") != "ready"
            or readiness["production"].get("status") != "ready"
            or source.get("canary_healthy") is not containers["canary"].get("healthy")
            or source.get("production_healthy") is not containers["production"].get("healthy")
            or source.get("collector") != "authenticated-routeros-api-rest-readyz-v1"
            or source.get("api_authenticated") is not True
            or source.get("rest_authenticated") is not True
            or source.get("rest_parity_verified") is not True
            or source.get("captured_at") != checkpoint.get("observed_at")
            or source.get("canary_ready") is not True
            or source.get("production_ready") is not True
        ):
            raise ValueError("observed RouterOS state did not match the expected rollback checkpoint")
        readbacks[name] = {
            "environment": environment,
            "observed_at": checkpoint["observed_at"],
            "image": item_image,
            "healthy": source[f"{environment}_healthy"],
            "ready": source[f"{environment}_ready"],
            "source": source,
        }
    return {
        "format": REPORT_FORMAT,
        "candidate_image": candidate_image,
        "candidate_digest": candidate_digest,
        **readbacks,
    }


def _write_report(path: Path, report: Mapping[str, Any]) -> None:
    _write_json_atomically(path, dict(report))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, help="private local report path")
    parser.add_argument("--candidate-image", required=True)
    parser.add_argument("--candidate-digest", required=True)
    parser.add_argument("--previous-canary-image", required=True)
    parser.add_argument("--production-image", required=True)
    parser.add_argument("--canary-url", required=True, help="private readiness origin for canary")
    parser.add_argument("--production-url", required=True, help="private readiness origin for production")
    parser.add_argument("--host-env", default="ROUTEROS_ACCEPTANCE_HOST")
    parser.add_argument("--username-env", default="ROUTEROS_ACCEPTANCE_USERNAME")
    parser.add_argument("--password-env", default="ROUTEROS_ACCEPTANCE_PASSWORD")
    parser.add_argument("--ca-file-env", default="ROUTEROS_ACCEPTANCE_CA_FILE")
    parser.add_argument("--rest-url-env", default="ROUTEROS_ACCEPTANCE_REST_URL")
    parser.add_argument("--rest-username-env", default="ROUTEROS_ACCEPTANCE_REST_USERNAME")
    parser.add_argument("--rest-password-env", default="ROUTEROS_ACCEPTANCE_REST_PASSWORD")
    parser.add_argument("--rest-ca-file-env", default="ROUTEROS_ACCEPTANCE_REST_CA_FILE")
    parser.add_argument("--port", type=int, default=8729)
    args = parser.parse_args()
    try:
        host = os.environ.get(args.host_env, "")
        username = os.environ.get(args.username_env, "")
        password = os.environ.get(args.password_env, "") or getpass.getpass("RouterOS read-only API password: ")
        rest_url = os.environ.get(args.rest_url_env, "")
        rest_username = os.environ.get(args.rest_username_env, "")
        rest_password = os.environ.get(args.rest_password_env, "") or getpass.getpass("RouterOS read-only REST password: ")
        if not host or not username or not rest_url or not rest_username or not 1 <= args.port <= 65535:
            raise ValueError("required RouterOS connection settings are missing")
        origins = {
            "canary": args.canary_url,
            "production": args.production_url,
        }
        checkpoints: dict[str, Mapping[str, Any]] = {}
        for name in READBACKS:
            print(CHECKPOINT_INSTRUCTIONS[name])
            input("After the named state is stable, press Enter to capture read-only evidence: ")
            connection = RouterOSBinaryConnection(
                host, port=args.port, ca_file=os.environ.get(args.ca_file_env) or None, timeout=10
            )
            rest_reader = RouterOSRestAcceptanceReader(
                rest_url,
                rest_username,
                rest_password,
                ca_file=os.environ.get(args.rest_ca_file_env) or None,
            )
            checkpoints[name] = collect_checkpoint(
                connection,
                rest_reader,
                username=username,
                password=password,
                readyz_origins=origins,
            )
        report = build_report(
            candidate_image=args.candidate_image,
            candidate_digest=args.candidate_digest,
            previous_canary_image=args.previous_canary_image,
            production_image=args.production_image,
            checkpoints=checkpoints,
        )
        _write_report(Path(args.output), report)
        print(json.dumps({"captured": True, "checkpoint_count": len(READBACKS), "output": str(Path(args.output).resolve())}))
        return 0
    except (OSError, ValueError, RouterOSBinaryError) as error:
        print(f"Rollback evidence capture failed ({type(error).__name__}); no acceptance claim was produced", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
