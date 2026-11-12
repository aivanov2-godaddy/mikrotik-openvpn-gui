"""Canary-only RouterOS staging with a verified healthy rollback baseline."""

from __future__ import annotations

import argparse
from dataclasses import dataclass, field, replace
from datetime import datetime, timedelta, timezone
import json
import os
import re
import sys
from typing import Any, Callable
from urllib.parse import quote

from scripts.deploy_routeros_release import (
    DeploymentError,
    DeploymentSettings,
    RouterOSRest,
    _find_target,
    _image,
    _registry_relative_image,
    _status,
    _wait_for,
    deploy,
)
from scripts.promote_routeros_release import _ready_probe, _safe_ready_url
from scripts.release_images import parse_project_image


CANARY_CONTAINER = "vpn-dashboard-canary"
PRODUCTION_CONTAINER = "vpn-dashboard-production"
BACKUP_RECEIPT = "disk1/vpn-dashboard/backups/canary-backup-receipt.txt"
BACKUP_PREFIX = "disk1/vpn-dashboard/backups/vpn-dashboard-predeploy-"
BACKUP_FORMAT = "vpn-gui-encrypted-canary-backup-v1"
BACKUP_MAX_AGE_SECONDS = 3600
BACKUP_FUTURE_TOLERANCE_SECONDS = 300
_BACKUP_NAME = re.compile(
    r"^disk1/vpn-dashboard/backups/vpn-dashboard-predeploy-[0-2]\.backup$"
)
_ROUTER_DATE = re.compile(
    r"^(?:(?P<iso_year>[0-9]{4})-(?P<iso_month>[0-9]{2})-(?P<iso_day>[0-9]{2})|"
    r"(?P<month>jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)/"
    r"(?P<day>[0-9]{2})/(?P<year>[0-9]{4}))$",
    re.IGNORECASE,
)
_ROUTER_TIME = re.compile(r"^(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2}):(?P<second>[0-9]{2})$")
_GMT_OFFSET = re.compile(r"^(?P<sign>[+-])?(?P<hour>[0-9]{2}):(?P<minute>[0-9]{2})$")

_DIAGNOSTIC_RESULTS = frozenset(
    {"preflight_blocked", "stage_failed_prior_state_verified", "recovery_unverified"}
)
_DIAGNOSTIC_PHASES = frozenset(
    {"configuration", "baseline", "backup", "prewrite", "candidate", "production", "recovery"}
)
_DIAGNOSTIC_CODES = frozenset(
    {
        "configuration_invalid",
        "baseline_readback_failed",
        "canary_unhealthy",
        "production_unhealthy",
        "baseline_image_invalid",
        "canary_readiness_failed",
        "production_readiness_failed",
        "backup_receipt_invalid",
        "prewrite_recheck_failed",
        "prewrite_state_drift",
        "candidate_stage_failed",
        "candidate_readback_failed",
        "candidate_readiness_failed",
        "production_changed",
        "rollback_unverified",
        "post_failure_readback_failed",
        "post_failure_state_mismatch",
        "unclassified_preflight_failure",
        "unclassified_stage_failure",
    }
)


@dataclass(frozen=True, slots=True)
class StageFailureDiagnostic:
    result: str
    phase: str
    code: str
    router_writes_may_have_started: bool
    rollback_attempted: bool
    canary_prior_state_verified: bool | None
    production_unchanged_verified: bool | None
    manual_recovery_required: bool
    review_before_retry: bool = True

    def as_dict(self) -> dict[str, object]:
        return {
            "schema": "mikrotik-canary-stage-diagnostic-v1",
            "result": self.result,
            "phase": self.phase,
            "code": self.code,
            "router_writes_may_have_started": self.router_writes_may_have_started,
            "rollback_attempted": self.rollback_attempted,
            "canary_prior_state_verified": self.canary_prior_state_verified,
            "production_unchanged_verified": self.production_unchanged_verified,
            "manual_recovery_required": self.manual_recovery_required,
            "review_before_retry": self.review_before_retry,
        }


class CanaryStageFailure(DeploymentError):
    """A staging failure with a closed, non-sensitive diagnostic payload."""

    def __init__(self, diagnostic: StageFailureDiagnostic) -> None:
        if (
            diagnostic.result not in _DIAGNOSTIC_RESULTS
            or diagnostic.phase not in _DIAGNOSTIC_PHASES
            or diagnostic.code not in _DIAGNOSTIC_CODES
        ):
            raise ValueError("invalid canary staging diagnostic")
        self.diagnostic = diagnostic
        super().__init__(diagnostic.code)


def _stage_failure(
    result: str,
    phase: str,
    code: str,
    *,
    writes_may_have_started: bool,
    rollback_attempted: bool = False,
    canary_prior_state_verified: bool | None = None,
    production_unchanged_verified: bool | None = None,
    manual_recovery_required: bool = False,
) -> CanaryStageFailure:
    return CanaryStageFailure(
        StageFailureDiagnostic(
            result=result,
            phase=phase,
            code=code,
            router_writes_may_have_started=writes_may_have_started,
            rollback_attempted=rollback_attempted,
            canary_prior_state_verified=canary_prior_state_verified,
            production_unchanged_verified=production_unchanged_verified,
            manual_recovery_required=manual_recovery_required,
        )
    )


@dataclass(frozen=True, slots=True)
class CanaryStageSettings:
    rest_url: str
    username: str
    password: str = field(repr=False)
    candidate_image: str
    canary_ready_url: str
    production_ready_url: str
    timeout_seconds: int = 600
    poll_seconds: float = 2.0
    ca_pem: str | None = None
    ready_ca_pem: str | None = None

    @property
    def candidate_identity(self):
        try:
            return parse_project_image(
                self.candidate_image,
                require_digest=True,
                architecture="arm64",
            )
        except ValueError as error:
            raise DeploymentError(
                "candidate must be this project's immutable ARM64 image"
            ) from error

    def validate(self) -> None:
        DeploymentSettings(
            rest_url=self.rest_url,
            username=self.username,
            password=self.password,
            container_name=CANARY_CONTAINER,
            release_image=self.candidate_image,
            timeout_seconds=self.timeout_seconds,
            poll_seconds=self.poll_seconds,
            ca_pem=self.ca_pem,
        ).validate()
        _safe_ready_url(self.canary_ready_url)
        _safe_ready_url(self.production_ready_url)
        self.candidate_identity


def _records(client: RouterOSRest) -> tuple[dict[str, Any], dict[str, Any]]:
    canary = _find_target(client, CANARY_CONTAINER)
    production = _find_target(client, PRODUCTION_CONTAINER)
    if canary.get(".id") == production.get(".id"):
        raise DeploymentError("canary and production must be distinct containers")
    return canary, production


def _image_identity(record: dict[str, Any], *, require_digest: bool) -> tuple[str, str]:
    try:
        image = _registry_relative_image(_image(record))
        identity = parse_project_image(
            image,
            require_digest=require_digest,
            architecture="arm64",
        )
    except (DeploymentError, ValueError) as error:
        raise DeploymentError("RouterOS image reference is not an approved ARM64 release") from error
    return image, identity.revision


def _clock_row(client: RouterOSRest) -> dict[str, Any]:
    result = client.request("GET", "/system/clock")
    if isinstance(result, list):
        if len(result) != 1 or not isinstance(result[0], dict):
            raise DeploymentError("RouterOS clock read-back is missing or ambiguous")
        result = result[0]
    if not isinstance(result, dict):
        raise DeploymentError("RouterOS clock read-back is invalid")
    return result


def _parse_router_datetime(date_value: object, time_value: object, offset_value: object) -> datetime:
    if not isinstance(date_value, str) or not isinstance(time_value, str) or not isinstance(offset_value, str):
        raise DeploymentError("RouterOS backup timestamp is incomplete")
    date_match = _ROUTER_DATE.fullmatch(date_value.strip())
    time_match = _ROUTER_TIME.fullmatch(time_value.strip())
    offset_match = _GMT_OFFSET.fullmatch(offset_value.strip())
    if date_match is None or time_match is None or offset_match is None:
        raise DeploymentError("RouterOS backup timestamp is invalid")
    if date_match.group("iso_year"):
        year = int(date_match.group("iso_year"))
        month = int(date_match.group("iso_month"))
        day = int(date_match.group("iso_day"))
    else:
        months = {
            "jan": 1,
            "feb": 2,
            "mar": 3,
            "apr": 4,
            "may": 5,
            "jun": 6,
            "jul": 7,
            "aug": 8,
            "sep": 9,
            "oct": 10,
            "nov": 11,
            "dec": 12,
        }
        year = int(date_match.group("year"))
        month = months[date_match.group("month").casefold()]
        day = int(date_match.group("day"))
    sign = -1 if offset_match.group("sign") == "-" else 1
    hours = int(offset_match.group("hour"))
    minutes = int(offset_match.group("minute"))
    if hours > 14 or minutes > 59 or (hours == 14 and minutes):
        raise DeploymentError("RouterOS GMT offset is invalid")
    offset = sign * timedelta(hours=hours, minutes=minutes)
    try:
        return datetime(
            year,
            month,
            day,
            int(time_match.group("hour")),
            int(time_match.group("minute")),
            int(time_match.group("second")),
            tzinfo=timezone(offset),
        )
    except ValueError as error:
        raise DeploymentError("RouterOS backup timestamp is invalid") from error


def _file_record(client: RouterOSRest, name: str) -> dict[str, Any]:
    result = client.request(
        "POST",
        "/file/print",
        {".proplist": [".id", "name", "size"], ".query": [f"name={name}"]},
    )
    records = [result] if isinstance(result, dict) else result
    if not isinstance(records, list):
        raise DeploymentError("RouterOS backup file read-back is invalid")
    matches = [
        item
        for item in records
        if isinstance(item, dict) and item.get("name") == name and item.get(".id")
    ]
    if len(matches) != 1:
        raise DeploymentError("required encrypted canary backup is missing or ambiguous")
    return matches[0]


def _read_file_text(client: RouterOSRest, name: str) -> str:
    record = _file_record(client, name)
    identifier = quote(str(record[".id"]), safe="*")
    detail = client.request("GET", f"/file/{identifier}")
    if isinstance(detail, list):
        if len(detail) != 1 or not isinstance(detail[0], dict):
            raise DeploymentError("RouterOS backup receipt read-back is invalid")
        detail = detail[0]
    contents = detail.get("contents") if isinstance(detail, dict) else None
    if not isinstance(detail, dict) or detail.get("name") != name or not isinstance(contents, str) or not contents or len(contents) > 4096:
        raise DeploymentError("RouterOS backup receipt is missing or invalid")
    return contents


def _parse_key_values(contents: str) -> dict[str, str]:
    fields: dict[str, str] = {}
    for line in contents.splitlines():
        if not line:
            continue
        key, separator, value = line.partition("=")
        if not separator or not key or key in fields or not value:
            raise DeploymentError("RouterOS backup receipt is malformed")
        fields[key] = value
    expected = {
        "format",
        "encrypted",
        "backup-file",
        "backup-size",
        "prior-canary-image",
        "created-date",
        "created-time",
        "created-gmt-offset",
    }
    if set(fields) != expected:
        raise DeploymentError("RouterOS backup receipt fields are invalid")
    return fields


def _verify_backup_receipt(
    client: RouterOSRest,
    *,
    prior_canary_image: str,
) -> None:
    receipt = _parse_key_values(_read_file_text(client, BACKUP_RECEIPT))
    backup_name = receipt["backup-file"]
    try:
        receipt_prior_image = _registry_relative_image(receipt["prior-canary-image"])
    except DeploymentError as error:
        raise DeploymentError("encrypted backup receipt has an invalid prior canary image") from error
    if (
        receipt["format"] != BACKUP_FORMAT
        or receipt["encrypted"] != "true"
        or not _BACKUP_NAME.fullmatch(backup_name)
        or not backup_name.startswith(BACKUP_PREFIX)
        or receipt_prior_image != prior_canary_image
    ):
        raise DeploymentError("encrypted backup receipt does not match the current canary baseline")
    try:
        receipt_size = int(receipt["backup-size"])
    except ValueError as error:
        raise DeploymentError("encrypted backup size is invalid") from error
    backup_record = _file_record(client, backup_name)
    size_value = backup_record.get("size")
    try:
        observed_size = int(size_value)
    except (TypeError, ValueError) as error:
        raise DeploymentError("encrypted backup size read-back is invalid") from error
    if receipt_size <= 0 or observed_size != receipt_size:
        raise DeploymentError("encrypted backup file does not match its receipt")
    clock = _clock_row(client)
    backup_at = _parse_router_datetime(
        receipt["created-date"],
        receipt["created-time"],
        receipt["created-gmt-offset"],
    )
    router_now = _parse_router_datetime(clock.get("date"), clock.get("time"), clock.get("gmt-offset"))
    age = (router_now - backup_at).total_seconds()
    if age < -BACKUP_FUTURE_TOLERANCE_SECONDS or age > BACKUP_MAX_AGE_SECONDS:
        raise DeploymentError("encrypted canary backup receipt is stale")


def _assert_ready(
    ready_probe: Callable[[str, str, float, str | None], bool],
    url: str,
    revision: str,
    settings: CanaryStageSettings,
    *,
    phase: str,
    failure_code: str,
    writes_may_have_started: bool = False,
    rollback_attempted: bool = False,
) -> None:
    try:
        ready = ready_probe(
            url,
            revision,
            min(30.0, float(settings.timeout_seconds)),
            settings.ready_ca_pem,
        )
    except Exception as error:
        raise _stage_failure(
            "preflight_blocked" if not writes_may_have_started else "recovery_unverified",
            phase,
            failure_code,
            writes_may_have_started=writes_may_have_started,
            rollback_attempted=rollback_attempted,
            manual_recovery_required=writes_may_have_started,
        ) from error
    if not ready:
        raise _stage_failure(
            "preflight_blocked" if not writes_may_have_started else "recovery_unverified",
            phase,
            failure_code,
            writes_may_have_started=writes_may_have_started,
            rollback_attempted=rollback_attempted,
            manual_recovery_required=writes_may_have_started,
        )


def _healthy_snapshot(
    client: RouterOSRest,
    settings: CanaryStageSettings,
    ready_probe: Callable[[str, str, float, str | None], bool],
) -> tuple[str, str, str]:
    try:
        canary, production = _records(client)
    except Exception as error:
        raise _stage_failure(
            "preflight_blocked", "baseline", "baseline_readback_failed", writes_may_have_started=False
        ) from error
    if _status(canary) != "running":
        raise _stage_failure(
            "preflight_blocked", "baseline", "canary_unhealthy", writes_may_have_started=False
        )
    if _status(production) != "running":
        raise _stage_failure(
            "preflight_blocked", "baseline", "production_unhealthy", writes_may_have_started=False
        )
    try:
        canary_image, canary_revision = _image_identity(canary, require_digest=True)
        production_image, production_revision = _image_identity(production, require_digest=False)
    except Exception as error:
        raise _stage_failure(
            "preflight_blocked", "baseline", "baseline_image_invalid", writes_may_have_started=False
        ) from error
    _assert_ready(
        ready_probe,
        settings.canary_ready_url,
        canary_revision,
        settings,
        phase="baseline",
        failure_code="canary_readiness_failed",
    )
    _assert_ready(
        ready_probe,
        settings.production_ready_url,
        production_revision,
        settings,
        phase="baseline",
        failure_code="production_readiness_failed",
    )
    return canary_image, production_image, production_revision


def _restore_canary(
    client: RouterOSRest,
    settings: CanaryStageSettings,
    *,
    candidate_image: str,
    previous_image: str,
    previous_revision: str,
    ready_probe: Callable[[str, str, float, str | None], bool],
) -> None:
    record = _find_target(client, CANARY_CONTAINER)
    if _registry_relative_image(_image(record)) != candidate_image:
        raise DeploymentError("canary image drifted; refusing an automatic rollback")
    container_id = str(record[".id"])
    deploy_settings = DeploymentSettings(
        rest_url=settings.rest_url,
        username=settings.username,
        password=settings.password,
        container_name=CANARY_CONTAINER,
        release_image=candidate_image,
        timeout_seconds=settings.timeout_seconds,
        poll_seconds=settings.poll_seconds,
        ca_pem=settings.ca_pem,
    )
    if _status(record) != "stopped":
        client.command("stop", container_id)
        _wait_for(client, container_id, "stopped", deploy_settings, allow_empty_stopped=True)
    client.patch_container(container_id, {"remote-image": previous_image})
    client.command("update", container_id)
    updated = _wait_for(client, container_id, "stopped", deploy_settings)
    if _registry_relative_image(_image(updated)) != previous_image:
        raise DeploymentError("RouterOS did not restore the exact prior canary image")
    client.command("start", container_id)
    started = _wait_for(client, container_id, "running", deploy_settings)
    if _registry_relative_image(_image(started)) != previous_image:
        raise DeploymentError("RouterOS did not start the exact prior canary image")
    _assert_ready(
        ready_probe,
        settings.canary_ready_url,
        previous_revision,
        settings,
        phase="recovery",
        failure_code="rollback_unverified",
        writes_may_have_started=True,
        rollback_attempted=True,
    )


def stage_canary(
    settings: CanaryStageSettings,
    *,
    client: RouterOSRest | None = None,
    ready_probe: Callable[[str, str, float, str | None], bool] = _ready_probe,
    check_only: bool = False,
) -> str:
    """Stage one immutable image on the isolated canary, never on production."""

    try:
        settings.validate()
        candidate = _registry_relative_image(settings.candidate_image)
        candidate_revision = settings.candidate_identity.revision
        deploy_settings = DeploymentSettings(
            rest_url=settings.rest_url,
            username=settings.username,
            password=settings.password,
            container_name=CANARY_CONTAINER,
            release_image=candidate,
            timeout_seconds=settings.timeout_seconds,
            poll_seconds=settings.poll_seconds,
            ca_pem=settings.ca_pem,
        )
        client = client or RouterOSRest(deploy_settings)
    except Exception as error:
        raise _stage_failure(
            "preflight_blocked",
            "configuration",
            "configuration_invalid",
            writes_may_have_started=False,
        ) from error

    try:
        prior_canary_image, prior_production_image, _ = _healthy_snapshot(client, settings, ready_probe)
    except CanaryStageFailure:
        raise
    except Exception as error:
        raise _stage_failure(
            "preflight_blocked", "baseline", "baseline_readback_failed", writes_may_have_started=False
        ) from error
    try:
        _verify_backup_receipt(
            client,
            prior_canary_image=prior_canary_image,
        )
    except Exception as error:
        raise _stage_failure(
            "preflight_blocked", "backup", "backup_receipt_invalid", writes_may_have_started=False
        ) from error
    # Repeat the live image/readiness check immediately before the first write.
    try:
        rechecked_canary, rechecked_production, _ = _healthy_snapshot(client, settings, ready_probe)
    except Exception as error:
        raise _stage_failure(
            "preflight_blocked", "prewrite", "prewrite_recheck_failed", writes_may_have_started=False
        ) from error
    if rechecked_canary != prior_canary_image or rechecked_production != prior_production_image:
        raise _stage_failure(
            "preflight_blocked", "prewrite", "prewrite_state_drift", writes_may_have_started=False
        )
    if check_only:
        return candidate_revision

    try:
        deploy(
            deploy_settings,
            client,
            rollback_image=prior_canary_image,
        )
        staged = _find_target(client, CANARY_CONTAINER)
        if (
            _registry_relative_image(_image(staged)) != candidate
            or _status(staged) != "running"
        ):
            raise _stage_failure(
                "recovery_unverified",
                "candidate",
                "candidate_readback_failed",
                writes_may_have_started=True,
                manual_recovery_required=True,
            )
        _assert_ready(
            ready_probe,
            settings.canary_ready_url,
            candidate_revision,
            settings,
            phase="candidate",
            failure_code="candidate_readiness_failed",
            writes_may_have_started=True,
        )
        production_after = _find_target(client, PRODUCTION_CONTAINER)
        if (
            _registry_relative_image(_image(production_after)) != prior_production_image
            or _status(production_after) != "running"
        ):
            raise _stage_failure(
                "recovery_unverified",
                "production",
                "production_changed",
                writes_may_have_started=True,
                manual_recovery_required=True,
            )
        _assert_ready(
            ready_probe,
            settings.production_ready_url,
            _image_identity(production_after, require_digest=False)[1],
            settings,
            phase="production",
            failure_code="production_readiness_failed",
            writes_may_have_started=True,
        )
    except Exception as error:
        failure_code = "candidate_stage_failed"
        failure_phase = "candidate"
        if isinstance(error, CanaryStageFailure):
            failure_code = error.diagnostic.code
            failure_phase = error.diagnostic.phase
        try:
            current_canary = _find_target(client, CANARY_CONTAINER)
            candidate_is_configured = _registry_relative_image(_image(current_canary)) == candidate
        except Exception as readback_error:
            raise _stage_failure(
                "recovery_unverified",
                "recovery",
                "post_failure_readback_failed",
                writes_may_have_started=True,
                manual_recovery_required=True,
            ) from readback_error
        rollback_attempted = False
        if candidate_is_configured:
            rollback_attempted = True
            try:
                _restore_canary(
                    client,
                    settings,
                    candidate_image=candidate,
                    previous_image=prior_canary_image,
                    previous_revision=parse_project_image(
                        prior_canary_image,
                        require_digest=True,
                        architecture="arm64",
                    ).revision,
                    ready_probe=ready_probe,
                )
            except Exception as rollback_error:
                raise _stage_failure(
                    "recovery_unverified",
                    "recovery",
                    "rollback_unverified",
                    writes_may_have_started=True,
                    rollback_attempted=True,
                    manual_recovery_required=True,
                ) from rollback_error
        try:
            restored_canary, restored_production, _ = _healthy_snapshot(client, settings, ready_probe)
        except Exception as readback_error:
            raise _stage_failure(
                "recovery_unverified",
                "recovery",
                "post_failure_readback_failed",
                writes_may_have_started=True,
                rollback_attempted=rollback_attempted,
                manual_recovery_required=True,
            ) from readback_error
        canary_prior_state_verified = restored_canary == prior_canary_image
        production_unchanged_verified = restored_production == prior_production_image
        if not canary_prior_state_verified or not production_unchanged_verified:
            raise _stage_failure(
                "recovery_unverified",
                "recovery",
                "post_failure_state_mismatch",
                writes_may_have_started=True,
                rollback_attempted=rollback_attempted,
                canary_prior_state_verified=canary_prior_state_verified,
                production_unchanged_verified=production_unchanged_verified,
                manual_recovery_required=True,
            ) from error
        raise _stage_failure(
            "stage_failed_prior_state_verified",
            failure_phase,
            failure_code,
            writes_may_have_started=True,
            rollback_attempted=rollback_attempted,
            canary_prior_state_verified=True,
            production_unchanged_verified=True,
        ) from error
    return candidate_revision


def _settings_from_environment(args: argparse.Namespace) -> CanaryStageSettings:
    values = {
        "rest_url": os.environ.get("ROUTEROS_REST_URL", ""),
        "username": os.environ.get("ROUTEROS_DEPLOY_USERNAME", ""),
        "password": os.environ.get("ROUTEROS_DEPLOY_PASSWORD", ""),
        "candidate_image": args.image or os.environ.get("RELEASE_IMAGE", ""),
        "canary_ready_url": os.environ.get("ROUTEROS_CANARY_READY_URL", ""),
        "production_ready_url": os.environ.get("ROUTEROS_PRODUCTION_READY_URL", ""),
        "ca_pem": os.environ.get("ROUTEROS_REST_CA_PEM") or None,
        "ready_ca_pem": os.environ.get("ROUTEROS_READY_CA_PEM") or None,
    }
    required = (
        "rest_url",
        "username",
        "password",
        "candidate_image",
        "canary_ready_url",
        "production_ready_url",
    )
    if not all(values[key] for key in required):
        raise DeploymentError(
            "RouterOS REST credentials, candidate image, and both readiness URLs are required"
        )
    return CanaryStageSettings(**values)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Stage one immutable image on the fixed RouterOS canary container"
    )
    parser.add_argument("--image", help="full immutable ARM64 release image; defaults to RELEASE_IMAGE")
    parser.add_argument("--timeout", type=int, default=600, help="per-operation timeout in seconds")
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="verify healthy baselines and the fresh encrypted backup without changing RouterOS",
    )
    arguments = parser.parse_args(argv)
    stage_started = False
    try:
        settings = _settings_from_environment(arguments)
        settings = replace(settings, timeout_seconds=arguments.timeout)
        stage_started = True
        revision = stage_canary(settings, check_only=arguments.check_only)
    except CanaryStageFailure as error:
        print(json.dumps(error.diagnostic.as_dict(), separators=(",", ":")), file=sys.stderr)
        return 2
    except Exception:
        if stage_started and not arguments.check_only:
            diagnostic = StageFailureDiagnostic(
                result="recovery_unverified",
                phase="recovery",
                code="unclassified_stage_failure",
                router_writes_may_have_started=True,
                rollback_attempted=False,
                canary_prior_state_verified=None,
                production_unchanged_verified=None,
                manual_recovery_required=True,
            )
        else:
            diagnostic = StageFailureDiagnostic(
                result="preflight_blocked",
                phase="configuration",
                code="unclassified_preflight_failure",
                router_writes_may_have_started=False,
                rollback_attempted=False,
                canary_prior_state_verified=None,
                production_unchanged_verified=None,
                manual_recovery_required=False,
            )
        print(json.dumps(diagnostic.as_dict(), separators=(",", ":")), file=sys.stderr)
        return 2
    action = "preflight passed for" if arguments.check_only else "staged revision"
    print(f"canary {action} {revision}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
