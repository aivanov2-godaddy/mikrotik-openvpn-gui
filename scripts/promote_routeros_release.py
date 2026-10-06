"""Promote a staged MikroTik canary only with fresh passing acceptance evidence.

This local controller re-evaluates the collected canary-prepromotion evidence,
checks the live RouterOS canary and production image/revision, then updates only
the named production container. It never uploads evidence or credentials.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import re
import ssl
import sys
import time
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import quote, urlsplit
from urllib.request import HTTPRedirectHandler, Request, HTTPSHandler, build_opener

from scripts.deploy_routeros_release import (
    DeploymentError,
    DeploymentSettings,
    RouterOSRest,
    _find_target,
    _image,
    _registry_relative_image,
    _status,
    deploy,
)
from scripts.release_acceptance import evaluate


_CONTAINER_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$")
_PROJECT_ARM64_IMAGE = re.compile(
    r"^ghcr\.io/aivanov2-godaddy/mikrotik-openvpn-gui:sha-(?P<revision>[0-9a-f]{40})-arm64$"
)
_ROUTER_FILE = re.compile(r"^[A-Za-z0-9._/-]{1,160}$")
_PRIVATE_V4 = tuple(
    ipaddress.ip_network(value)
    for value in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")
)
_READY_MAX_BYTES = 65536


@dataclass(frozen=True, slots=True)
class PromotionSettings:
    rest_url: str
    username: str
    password: str
    canary_container: str
    production_container: str
    canary_ready_url: str
    production_ready_url: str
    pending_file: str = "disk1/vpn-dashboard/routeros-update-pending.txt"
    state_file: str = "disk1/vpn-dashboard/routeros-update-state.txt"
    failure_file: str = "disk1/vpn-dashboard/routeros-update-state.txt.failed"
    timeout_seconds: int = 600
    poll_seconds: float = 2.0
    ca_pem: str | None = None
    ready_ca_pem: str | None = None


class _NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request: Request, response: Any, code: int, message: str, headers: Any, new_url: str) -> None:
        return None


def _safe_ready_url(url: str) -> None:
    try:
        parsed = urlsplit(url)
    except ValueError as error:
        raise DeploymentError("readiness URL is malformed") from error
    if (
        parsed.scheme not in {"https", "http"}
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path != "/readyz"
    ):
        raise DeploymentError("readiness URL must be a credential-free HTTPS or private /readyz origin")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as error:
        raise DeploymentError("readiness URL port is invalid") from error
    if parsed.scheme == "http":
        try:
            address = ipaddress.ip_address(parsed.hostname)
        except ValueError as error:
            raise DeploymentError("plain HTTP readiness requires an RFC1918 IPv4 literal") from error
        if not isinstance(address, ipaddress.IPv4Address) or not any(address in net for net in _PRIVATE_V4) or port != 8080:
            raise DeploymentError("plain HTTP readiness is limited to RFC1918 IPv4 on port 8080")


def _revision(image: str) -> str:
    match = _PROJECT_ARM64_IMAGE.fullmatch(image)
    if not match:
        raise DeploymentError("promotion evidence must name this project's immutable ARM64 image")
    return match.group("revision")


def _ready_probe(url: str, expected_revision: str, timeout: float, ca_pem: str | None) -> bool:
    try:
        _safe_ready_url(url)
        request = Request(url, headers={"Accept": "application/json"}, method="GET")
        handlers: list[Any] = [_NoRedirect()]
        if ca_pem:
            handlers.append(HTTPSHandler(context=ssl.create_default_context(cadata=ca_pem)))
        with build_opener(*handlers).open(request, timeout=timeout) as response:
            if response.status != 200:
                return False
            payload = response.read(_READY_MAX_BYTES + 1)
        if len(payload) > _READY_MAX_BYTES:
            return False
        body = json.loads(payload.decode("utf-8"))
    except (HTTPError, URLError, TimeoutError, OSError, UnicodeDecodeError, json.JSONDecodeError, ValueError):
        return False
    return isinstance(body, dict) and body.get("status") == "ready" and body.get("revision") == expected_revision


def _records(client: RouterOSRest, canary_name: str, production_name: str) -> tuple[dict[str, Any], dict[str, Any]]:
    canary = _find_target(client, canary_name)
    production = _find_target(client, production_name)
    if canary.get(".id") == production.get(".id"):
        raise DeploymentError("canary and production must be distinct RouterOS containers")
    return canary, production


def _file_record(client: RouterOSRest, file_name: str) -> dict[str, Any]:
    result = client.request(
        "POST",
        "/file/print",
        {".proplist": [".id", "name"], ".query": [f"name={file_name}"]},
    )
    records = [result] if isinstance(result, dict) else result
    if not isinstance(records, list):
        raise DeploymentError("RouterOS returned an unexpected local release file record")
    matches = [
        record for record in records
        if isinstance(record, dict) and record.get("name") == file_name and record.get(".id")
    ]
    if len(matches) != 1:
        raise DeploymentError("required router-local release metadata file is missing or ambiguous")
    return matches[0]


def _validate_file_path(file_name: str) -> None:
    if (
        not _ROUTER_FILE.fullmatch(file_name)
        or file_name.startswith("/")
        or "//" in file_name
        or any(part in {"", ".", ".."} for part in file_name.split("/"))
    ):
        raise DeploymentError("RouterOS release metadata path is invalid")


def _read_router_text_file(client: RouterOSRest, file_name: str) -> str:
    record = _file_record(client, file_name)
    identifier = quote(str(record[".id"]), safe="*")
    detail = client.request("GET", f"/file/{identifier}")
    if isinstance(detail, list):
        if len(detail) != 1 or not isinstance(detail[0], dict):
            raise DeploymentError("RouterOS returned an unexpected local release file")
        detail = detail[0]
    if not isinstance(detail, dict) or detail.get("name") != file_name:
        raise DeploymentError("RouterOS returned an unexpected local release file")
    contents = detail.get("contents")
    if not isinstance(contents, str) or not contents or len(contents) > 4096:
        raise DeploymentError("router-local release metadata file is invalid")
    return contents


def _key_value_file(contents: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in contents.splitlines():
        if not line:
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or key in fields or not value:
            raise DeploymentError("router-local release metadata file is malformed")
        fields[key] = value
    return fields


def _verify_staged_record(client: RouterOSRest, file_name: str, candidate: str, prior: str, revision: str) -> None:
    fields = _key_value_file(_read_router_text_file(client, file_name))
    if (
        fields.get("candidate-image") != candidate
        or fields.get("prior-production-image") != prior
        or fields.get("commit") != revision
        or not fields.get("staged-at")
    ):
        raise DeploymentError("router-local staged-candidate record does not match the accepted report")


def _write_router_text_file(client: RouterOSRest, file_name: str, contents: str) -> None:
    existing = client.request(
        "POST",
        "/file/print",
        {".proplist": [".id", "name"], ".query": [f"name={file_name}"]},
    )
    records = [existing] if isinstance(existing, dict) else existing
    if not isinstance(records, list):
        raise DeploymentError("RouterOS returned an unexpected release metadata file record")
    matches = [
        record for record in records
        if isinstance(record, dict) and record.get("name") == file_name and record.get(".id")
    ]
    if len(matches) > 1:
        raise DeploymentError("router-local release metadata file is ambiguous")
    if matches:
        client.request("POST", "/file/set", {"numbers": str(matches[0][".id"]), "contents": contents})
    else:
        client.request("PUT", "/file", {"name": file_name, "contents": contents})
    stored = _read_router_text_file(client, file_name)
    if stored != contents:
        raise DeploymentError("RouterOS did not persist the release metadata record")


def _write_last_good(client: RouterOSRest, file_name: str, image: str, revision: str, updated_at: datetime) -> None:
    if updated_at.tzinfo is None or updated_at.utcoffset() is None:
        raise DeploymentError("promotion timestamp must include a timezone")
    contents = (
        f"last-good-image={image}\n"
        f"commit={revision}\n"
        f"updated-at={updated_at.astimezone(timezone.utc).isoformat()}\n"
    )
    _write_router_text_file(client, file_name, contents)


def _write_quarantine(client: RouterOSRest, file_name: str, image: str, updated_at: datetime) -> None:
    if updated_at.tzinfo is None or updated_at.utcoffset() is None:
        raise DeploymentError("promotion timestamp must include a timezone")
    contents = (
        f"failed-image={image}\n"
        "failure-count=3\n"
        f"failed-at={updated_at.astimezone(timezone.utc).isoformat()}\n"
    )
    _write_router_text_file(client, file_name, contents)


def _assert_router_matches(
    canary: dict[str, Any],
    production: dict[str, Any],
    candidate_image: str,
    prior_image: str,
) -> None:
    if _registry_relative_image(_image(canary)) != _registry_relative_image(candidate_image):
        raise DeploymentError("RouterOS canary image does not match the accepted candidate")
    if _registry_relative_image(_image(production)) != _registry_relative_image(prior_image):
        raise DeploymentError("RouterOS production image changed since acceptance evidence was collected")
    if _status(canary) != "running" or _status(production) != "running":
        raise DeploymentError("both RouterOS containers must be healthy before promotion")


def _require_ready(
    probe: Callable[[str, str, float, str | None], bool],
    url: str,
    revision: str,
    settings: PromotionSettings,
) -> None:
    if not probe(url, revision, min(30.0, float(settings.timeout_seconds)), settings.ready_ca_pem):
        raise DeploymentError("RouterOS app readiness did not match the expected immutable revision")


def promote(
    evidence: Any,
    settings: PromotionSettings,
    *,
    client: RouterOSRest | None = None,
    ready_probe: Callable[[str, str, float, str | None], bool] = _ready_probe,
    clock: Callable[[], datetime] = lambda: datetime.now(timezone.utc),
    sleep: Callable[[float], None] | None = None,
    check_only: bool = False,
) -> str:
    """Fail closed on evidence or router drift; return the candidate revision."""

    if not _CONTAINER_NAME.fullmatch(settings.canary_container) or not _CONTAINER_NAME.fullmatch(settings.production_container):
        raise DeploymentError("container names must be exact safe RouterOS identifiers")
    if settings.canary_container == settings.production_container:
        raise DeploymentError("canary and production container names must differ")
    for file_name in (settings.pending_file, settings.state_file, settings.failure_file):
        _validate_file_path(file_name)
    _safe_ready_url(settings.canary_ready_url)
    _safe_ready_url(settings.production_ready_url)

    try:
        code, report = evaluate(evidence, now=clock(), phase="canary-prepromotion")
    except (TypeError, ValueError) as error:
        raise DeploymentError("acceptance evidence is invalid") from error
    if code != 0 or report.get("promotion_eligible") is not True:
        raise DeploymentError("fresh canary-prepromotion acceptance did not pass")
    if sleep is None:
        sleep = time.sleep

    deployments = report.get("deployments")
    if not isinstance(deployments, list) or len(deployments) != 2:
        raise DeploymentError("acceptance report is missing the canary or production baseline")
    candidate_image = str(deployments[0].get("image", ""))
    prior_image = str(deployments[1].get("image", ""))
    candidate_revision = _revision(candidate_image)
    prior_revision = _revision(prior_image)

    deployment_settings = DeploymentSettings(
        rest_url=settings.rest_url,
        username=settings.username,
        password=settings.password,
        container_name=settings.production_container,
        release_image=candidate_image,
        timeout_seconds=settings.timeout_seconds,
        poll_seconds=settings.poll_seconds,
        ca_pem=settings.ca_pem,
    )
    deployment_settings.validate()
    client = client or RouterOSRest(deployment_settings)

    canary, production = _records(client, settings.canary_container, settings.production_container)
    _assert_router_matches(canary, production, candidate_image, prior_image)
    _verify_staged_record(client, settings.pending_file, candidate_image, prior_image, candidate_revision)
    _require_ready(ready_probe, settings.canary_ready_url, candidate_revision, settings)
    _require_ready(ready_probe, settings.production_ready_url, prior_revision, settings)

    # Re-read both live image records immediately before the first write. This
    # rejects changed deployments and stale report/container pairings.
    canary, production = _records(client, settings.canary_container, settings.production_container)
    _assert_router_matches(canary, production, candidate_image, prior_image)
    _verify_staged_record(client, settings.pending_file, candidate_image, prior_image, candidate_revision)
    if check_only:
        return candidate_revision

    try:
        deploy(deployment_settings, client)
        ready = False
        for _attempt in range(6):
            if ready_probe(
                settings.production_ready_url,
                candidate_revision,
                min(30.0, float(settings.timeout_seconds)),
                settings.ready_ca_pem,
            ):
                ready = True
                break
            sleep(min(5.0, settings.poll_seconds or 1.0))
        if not ready:
            raise DeploymentError("promoted production revision did not become ready")
        _write_last_good(client, settings.state_file, candidate_image, candidate_revision, clock())
    except Exception as error:
        rollback_settings = DeploymentSettings(
            rest_url=settings.rest_url,
            username=settings.username,
            password=settings.password,
            container_name=settings.production_container,
            release_image=prior_image,
            timeout_seconds=settings.timeout_seconds,
            poll_seconds=settings.poll_seconds,
            ca_pem=settings.ca_pem,
        )
        try:
            if _registry_relative_image(_image(_find_target(client, settings.production_container))) != _registry_relative_image(prior_image):
                deploy(rollback_settings, client)
            _require_ready(ready_probe, settings.production_ready_url, prior_revision, settings)
        except Exception as rollback_error:
            raise DeploymentError("promotion failed and prior production readiness could not be restored; operator action required") from rollback_error
        try:
            _write_last_good(client, settings.state_file, prior_image, prior_revision, clock())
        except Exception as state_error:
            raise DeploymentError("prior production was restored but last-good state could not be reset; operator action required") from state_error
        try:
            _write_quarantine(client, settings.failure_file, candidate_image, clock())
        except Exception as quarantine_error:
            raise DeploymentError("promotion failed; prior production was restored but candidate quarantine could not be recorded") from quarantine_error
        raise DeploymentError("promotion failed; the prior production image was restored") from error
    return candidate_revision


def _settings_from_environment(args: argparse.Namespace) -> PromotionSettings:
    values = {
        "rest_url": os.environ.get("ROUTEROS_REST_URL", ""),
        "username": os.environ.get("ROUTEROS_DEPLOY_USERNAME", ""),
        "password": os.environ.get("ROUTEROS_DEPLOY_PASSWORD", ""),
    }
    if not all(values.values()):
        raise DeploymentError("RouterOS REST deployment credentials are required in the environment")
    ready_ca = os.environ.get("VPN_ACCEPTANCE_READY_CA_PEM") or None
    return PromotionSettings(
        **values,
        canary_container=args.canary_container,
        production_container=args.production_container,
        canary_ready_url=args.canary_ready_url,
        production_ready_url=args.production_ready_url,
        pending_file=args.pending_file,
        state_file=args.state_file,
        failure_file=args.failure_file,
        timeout_seconds=args.timeout,
        ca_pem=os.environ.get("ROUTEROS_REST_CA_PEM") or None,
        ready_ca_pem=ready_ca,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", required=True, help="private collected canary-prepromotion evidence JSON")
    parser.add_argument("--canary-container", default="vpn-dashboard-canary")
    parser.add_argument("--production-container", default="vpn-dashboard-production")
    parser.add_argument("--canary-ready-url", required=True, help="private app /readyz origin; URL is never printed")
    parser.add_argument("--production-ready-url", required=True, help="private app /readyz origin; URL is never printed")
    parser.add_argument("--pending-file", default="disk1/vpn-dashboard/routeros-update-pending.txt")
    parser.add_argument("--state-file", default="disk1/vpn-dashboard/routeros-update-state.txt")
    parser.add_argument("--failure-file", default="disk1/vpn-dashboard/routeros-update-state.txt.failed")
    parser.add_argument("--timeout", type=int, default=600)
    parser.add_argument("--check-only", action="store_true", help="validate evidence and live images/readiness without changing RouterOS")
    args = parser.parse_args(argv)
    try:
        evidence = json.loads(Path(args.input).read_text(encoding="utf-8"))
        settings = _settings_from_environment(args)
        revision = promote(evidence, settings, check_only=args.check_only)
    except (OSError, json.JSONDecodeError, DeploymentError) as error:
        if isinstance(error, DeploymentError):
            print(json.dumps({"promoted": False, "error": str(error)}), file=sys.stderr)
        else:
            print(json.dumps({"promoted": False, "error": type(error).__name__}), file=sys.stderr)
        return 2
    print(json.dumps({"promoted": not args.check_only, "eligible_revision": revision}))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
