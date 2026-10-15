"""Validate redacted, candidate-bound certificate lifecycle acceptance evidence."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Any


CERTIFICATE_LIFECYCLE_FORMAT = "vpn-dashboard-certificate-lifecycle-acceptance-v1"
MAX_EVIDENCE_AGE_SECONDS = 86_400
MAX_CLOCK_SKEW_SECONDS = 5

_TIMESTAMP_FIELDS = (
    "replacement_tested_at",
    "failed_renewal_rollback_read_back_at",
    "routeros_revocation_read_back_at",
    "crl_fresh_loaded_at",
    "existing_session_read_back_at",
    "fresh_connection_rejection_at",
    "dashboard_status_distinctions_verified_at",
)
_TRUE_FIELDS = (
    "replacement_tested_before_retirement",
    "failed_renewal_rollback_read_back_verified",
    "routeros_revocation_read_back_verified",
    "crl_fresh_and_loaded_verified",
    "existing_session_read_back_verified",
    "fresh_connection_rejection_verified",
    "dashboard_status_distinctions_verified",
)
_FIELDS = {
    "format",
    "environment",
    "candidate_image",
    "candidate_digest",
    *_TRUE_FIELDS,
    "existing_session_outcome",
    *_TIMESTAMP_FIELDS,
    "private_material_or_profile_contents_in_evidence",
    "raw_logs_in_evidence",
}
_NORMALIZED_FIELDS = _FIELDS | {"evidence_provenance", "independently_observed"}


def _timestamp(value: Any) -> datetime:
    if not isinstance(value, str):
        raise ValueError("certificate lifecycle timestamp is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise ValueError("certificate lifecycle timestamp is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise ValueError("certificate lifecycle timestamp is invalid")
    return parsed


def validate_certificate_lifecycle_acceptance(
    document: Any,
    *,
    candidate_image: str,
    candidate_digest: str,
    collection_started_at: str,
    collection_ended_at: str,
    allow_normalized_output: bool = False,
) -> dict[str, Any]:
    """Return only allow-listed evidence, rejecting stale or mismatched claims.

    This validates an operator-supplied assertion; it does not authenticate the
    operator or independently observe RouterOS actions.
    """
    if not isinstance(document, dict):
        raise ValueError("certificate lifecycle evidence schema is invalid")
    fields = set(document)
    if fields != _FIELDS and not (allow_normalized_output and fields == _NORMALIZED_FIELDS):
        raise ValueError("certificate lifecycle evidence schema is invalid")
    if fields == _NORMALIZED_FIELDS and (
        document.get("evidence_provenance") != "operator_attested"
        or document.get("independently_observed") is not False
    ):
        raise ValueError("certificate lifecycle evidence provenance is invalid")
    if (
        document.get("format") != CERTIFICATE_LIFECYCLE_FORMAT
        or document.get("environment") != "canary"
        or document.get("candidate_image") != candidate_image
        or document.get("candidate_digest") != candidate_digest
    ):
        raise ValueError("certificate lifecycle evidence does not match the canary candidate")

    for field in _TRUE_FIELDS:
        if document.get(field) is not True:
            raise ValueError("certificate lifecycle acceptance assertion failed")
    if document.get("private_material_or_profile_contents_in_evidence") is not False:
        raise ValueError("certificate lifecycle evidence privacy assertion failed")
    if document.get("raw_logs_in_evidence") is not False:
        raise ValueError("certificate lifecycle evidence privacy assertion failed")
    session_outcome = document.get("existing_session_outcome")
    if not isinstance(session_outcome, str) or session_outcome not in {"terminated", "remained_active"}:
        raise ValueError("certificate lifecycle session outcome is invalid")

    collection_start = _timestamp(collection_started_at)
    collection_end = _timestamp(collection_ended_at)
    timestamps = [_timestamp(document.get(field)) for field in _TIMESTAMP_FIELDS]
    earliest = collection_start - timedelta(seconds=MAX_EVIDENCE_AGE_SECONDS)
    latest = collection_end + timedelta(seconds=MAX_CLOCK_SKEW_SECONDS)
    if any(value < earliest or value > latest for value in timestamps):
        raise ValueError("certificate lifecycle evidence is stale or outside the collection window")
    if timestamps != sorted(timestamps):
        raise ValueError("certificate lifecycle evidence is out of sequence")

    return {
        "format": CERTIFICATE_LIFECYCLE_FORMAT,
        "environment": "canary",
        "candidate_image": candidate_image,
        "candidate_digest": candidate_digest,
        "evidence_provenance": "operator_attested",
        "independently_observed": False,
        **{field: True for field in _TRUE_FIELDS},
        "existing_session_outcome": session_outcome,
        **{field: value.isoformat() for field, value in zip(_TIMESTAMP_FIELDS, timestamps)},
        "private_material_or_profile_contents_in_evidence": False,
        "raw_logs_in_evidence": False,
    }
