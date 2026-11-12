"""Verify candidate-bound external ASVS review and owner risk evidence.

The promotion controller uses authenticated GitHub issue comments as the
identity-bearing envelope for two narrowly scoped JSON records. The review
report itself stays at its referenced location; this module retains only the
candidate digest, reviewer identity, risk IDs, and owner identity.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
from typing import Any, Callable
from urllib.parse import urlsplit


REPOSITORY = "aivanov2-godaddy/mikrotik-openvpn-gui"
ASSURANCE_ISSUE = 200
REPOSITORY_OWNER = "aivanov2-godaddy"
ASVS_REQUIREMENT_COUNT = 43
MAX_COMMENT_BODY_CHARS = 8192
MAX_GH_OUTPUT_BYTES = 1_048_576
MAX_REPORT_BYTES = 20 * 1024 * 1024
MAX_REVIEW_AGE = timedelta(days=90)
COMMENT_QUERY = (
    "[.[] | select(.body | type == \"string\") | "
    "select((.body | contains(\"<!-- vpn-gui-external-asvs-review:v1 -->\")) or "
    "(.body | contains(\"<!-- vpn-gui-owner-risk-decision:v1 -->\"))) | "
    "{id, body: .body[0:8193], body_length: (.body | length), created_at, updated_at, "
    "author_association, user: {login: .user.login, type: .user.type}}]"
)

_DIGEST = re.compile(r"^sha256:[0-9a-f]{64}$")
_FINDING_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,63}$")
_EXTERNAL_ASSOCIATIONS = {
    "COLLABORATOR", "CONTRIBUTOR", "FIRST_TIMER", "FIRST_TIME_CONTRIBUTOR", "NONE"
}
_REVIEW_MARKER = "<!-- vpn-gui-external-asvs-review:v1 -->"
_OWNER_MARKER = "<!-- vpn-gui-owner-risk-decision:v1 -->"
_REVIEW_KEYS = {
    "schema", "candidate_digest", "asvs_version", "scope", "review_status",
    "independent", "reviewed_requirement_count", "reviewed_at", "expires_at",
    "report_sha256", "report_reference", "unresolved_findings",
}
_OWNER_KEYS = {
    "schema", "candidate_digest", "decision", "decided_at", "rationale",
    "accepted_finding_ids",
}


class SecurityAssuranceError(ValueError):
    """Raised when external security assurance is absent or cannot be trusted."""


def _timestamp(value: Any, field: str) -> datetime:
    if not isinstance(value, str) or len(value) > 40:
        raise SecurityAssuranceError(f"{field} is invalid")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise SecurityAssuranceError(f"{field} is invalid") from error
    if parsed.tzinfo is None or parsed.utcoffset() is None:
        raise SecurityAssuranceError(f"{field} must include a timezone")
    return parsed.astimezone(timezone.utc)


def _comment_record(comment: Any) -> tuple[str, dict[str, Any], datetime]:
    if not isinstance(comment, dict):
        raise SecurityAssuranceError("assurance comment is invalid")
    created = _timestamp(comment.get("created_at"), "comment creation time")
    updated = _timestamp(comment.get("updated_at"), "comment update time")
    if created != updated:
        raise SecurityAssuranceError("assurance comments must not be edited")
    body_length = comment.get("body_length")
    if body_length is not None and (
        type(body_length) is not int or body_length > MAX_COMMENT_BODY_CHARS
    ):
        raise SecurityAssuranceError("assurance comment exceeds the size limit")
    body = comment.get("body")
    if not isinstance(body, str) or len(body) > MAX_COMMENT_BODY_CHARS:
        raise SecurityAssuranceError("assurance comment body is invalid")
    if body_length is not None and body_length != len(body):
        raise SecurityAssuranceError("assurance comment body length is inconsistent")
    marker = _REVIEW_MARKER if _REVIEW_MARKER in body else _OWNER_MARKER if _OWNER_MARKER in body else None
    if marker is None or body.count(marker) != 1:
        raise SecurityAssuranceError("assurance comment marker is invalid")
    encoded = body.split(marker, 1)[1].strip()
    try:
        record = json.loads(encoded)
    except json.JSONDecodeError as error:
        raise SecurityAssuranceError("assurance comment record is invalid") from error
    if not isinstance(record, dict):
        raise SecurityAssuranceError("assurance comment record is invalid")
    return marker, record, created


def _matching_record(
    comments: list[dict[str, Any]], marker: str, expected_digest: str
) -> tuple[dict[str, Any], dict[str, Any], datetime]:
    matches: list[tuple[dict[str, Any], dict[str, Any], datetime]] = []
    for comment in comments:
        if not isinstance(comment, dict):
            raise SecurityAssuranceError("assurance comment list is invalid")
        body = comment.get("body")
        if not isinstance(body, str) or marker not in body:
            continue
        observed_marker, record, created = _comment_record(comment)
        if observed_marker != marker:
            continue
        digest = record.get("candidate_digest")
        if digest == expected_digest:
            matches.append((comment, record, created))
    if len(matches) != 1:
        raise SecurityAssuranceError("exactly one current candidate-bound assurance record is required")
    return matches[0]


def _validate_reviewer(comment: dict[str, Any], record: dict[str, Any]) -> str:
    user = comment.get("user")
    login = user.get("login") if isinstance(user, dict) else None
    if (
        not isinstance(login, str)
        or not re.fullmatch(r"[A-Za-z0-9-]{1,39}", login)
        or user.get("type") != "User"
        or login.casefold() == REPOSITORY_OWNER.casefold()
        or comment.get("author_association") not in _EXTERNAL_ASSOCIATIONS
    ):
        raise SecurityAssuranceError("reviewer is not an external GitHub user")
    if set(record) != _REVIEW_KEYS:
        raise SecurityAssuranceError("external review record is incomplete or has unknown fields")
    if (
        record.get("schema") != "vpn-gui-external-asvs-review-v1"
        or record.get("asvs_version") != "5.0"
        or record.get("scope") != "mikrotik-openvpn-gui-single-router"
        or record.get("review_status") != "complete"
        or record.get("independent") is not True
        or record.get("reviewed_requirement_count") != ASVS_REQUIREMENT_COUNT
    ):
        raise SecurityAssuranceError("external ASVS review is incomplete")
    if not isinstance(record.get("candidate_digest"), str) or not _DIGEST.fullmatch(record["candidate_digest"]):
        raise SecurityAssuranceError("external review candidate digest is invalid")
    if not isinstance(record.get("report_sha256"), str) or not _DIGEST.fullmatch(record["report_sha256"]):
        raise SecurityAssuranceError("external review report hash is invalid")
    reference = record.get("report_reference")
    if not isinstance(reference, str) or len(reference) > 2048:
        raise SecurityAssuranceError("external review report reference is invalid")
    try:
        parsed_reference = urlsplit(reference)
    except ValueError as error:
        raise SecurityAssuranceError("external review report reference is invalid") from error
    if (
        parsed_reference.scheme != "https"
        or not parsed_reference.hostname
        or parsed_reference.username
        or parsed_reference.password
        or parsed_reference.query
        or parsed_reference.fragment
        or not parsed_reference.path
    ):
        raise SecurityAssuranceError("external review report reference must be a credential-free HTTPS path")
    findings = record.get("unresolved_findings")
    if not isinstance(findings, list) or len(findings) > 200:
        raise SecurityAssuranceError("external review findings are incomplete")
    finding_ids: set[str] = set()
    for finding in findings:
        if (
            not isinstance(finding, dict)
            or set(finding) != {"id", "severity"}
            or not isinstance(finding.get("id"), str)
            or not _FINDING_ID.fullmatch(finding["id"])
            or finding["id"] in finding_ids
            or finding.get("severity") not in {"critical", "high", "moderate", "low"}
        ):
            raise SecurityAssuranceError("external review findings are invalid")
        if finding["severity"] in {"critical", "high"}:
            raise SecurityAssuranceError("unresolved critical or high security findings block promotion")
        finding_ids.add(finding["id"])
    return login


def _validate_owner(comment: dict[str, Any], record: dict[str, Any], expected_ids: set[str]) -> str:
    user = comment.get("user")
    login = user.get("login") if isinstance(user, dict) else None
    if (
        login != REPOSITORY_OWNER
        or not isinstance(user, dict)
        or user.get("type") != "User"
        or comment.get("author_association") != "OWNER"
    ):
        raise SecurityAssuranceError("risk decision must be recorded by the repository owner")
    if set(record) != _OWNER_KEYS:
        raise SecurityAssuranceError("owner risk decision is incomplete or has unknown fields")
    if (
        record.get("schema") != "vpn-gui-owner-risk-decision-v1"
        or record.get("candidate_digest") is None
        or record.get("decision") != "accept"
    ):
        raise SecurityAssuranceError("owner risk decision does not accept this candidate")
    accepted = record.get("accepted_finding_ids")
    if (
        not isinstance(accepted, list)
        or any(not isinstance(value, str) or not _FINDING_ID.fullmatch(value) for value in accepted)
        or len(accepted) != len(set(accepted))
        or set(accepted) != expected_ids
    ):
        raise SecurityAssuranceError("owner decision does not cover the unresolved review findings")
    rationale = record.get("rationale")
    if not isinstance(rationale, str) or not 40 <= len(rationale.strip()) <= 2000:
        raise SecurityAssuranceError("owner risk rationale is incomplete")
    return login


def verify_security_assurance_comments(
    comments: list[dict[str, Any]],
    *,
    candidate_digest: str,
    now: datetime,
) -> dict[str, Any]:
    """Validate GitHub-authenticated review and owner records for one digest."""

    if not isinstance(candidate_digest, str) or not _DIGEST.fullmatch(candidate_digest):
        raise SecurityAssuranceError("candidate digest is invalid")
    if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
        raise SecurityAssuranceError("verification time must include a timezone")
    now_utc = now.astimezone(timezone.utc)
    if not isinstance(comments, list) or len(comments) > 100:
        raise SecurityAssuranceError("assurance comment list is invalid")
    review_comment, review, review_created = _matching_record(comments, _REVIEW_MARKER, candidate_digest)
    owner_comment, owner, owner_created = _matching_record(comments, _OWNER_MARKER, candidate_digest)
    reviewer_login = _validate_reviewer(review_comment, review)
    findings = review["unresolved_findings"]
    finding_ids = {finding["id"] for finding in findings}
    risk_owner_login = _validate_owner(owner_comment, owner, finding_ids)
    if owner.get("candidate_digest") != candidate_digest:
        raise SecurityAssuranceError("owner risk decision does not match the candidate digest")
    reviewed_at = _timestamp(review.get("reviewed_at"), "review time")
    expires_at = _timestamp(review.get("expires_at"), "review expiry")
    decided_at = _timestamp(owner.get("decided_at"), "risk decision time")
    if abs((review_created - reviewed_at).total_seconds()) > 300:
        raise SecurityAssuranceError("external review timestamp does not match its GitHub record")
    if abs((owner_created - decided_at).total_seconds()) > 300:
        raise SecurityAssuranceError("owner decision timestamp does not match its GitHub record")
    if reviewed_at > now_utc + timedelta(minutes=5) or decided_at > now_utc + timedelta(minutes=5):
        raise SecurityAssuranceError("security assurance evidence is future-dated")
    if expires_at <= now_utc or expires_at > reviewed_at + MAX_REVIEW_AGE:
        raise SecurityAssuranceError("external security review is expired or has an invalid expiry")
    if decided_at < reviewed_at or decided_at > expires_at:
        raise SecurityAssuranceError("owner risk decision is outside the external review validity window")
    return {
        "candidate_digest": candidate_digest,
        "reviewer_login": reviewer_login,
        "risk_owner_login": risk_owner_login,
        "unresolved_finding_ids": sorted(finding_ids),
        "report_sha256": review["report_sha256"],
        "verified_at": now_utc.isoformat(),
    }


def load_security_assurance_comments(
    *,
    runner: Callable[..., Any] = subprocess.run,
) -> list[dict[str, Any]]:
    """Read bounded assurance comments from GitHub without retaining unrelated issue data."""

    endpoint = (
        f"repos/{REPOSITORY}/issues/{ASSURANCE_ISSUE}/comments"
        "?per_page=100&sort=created&direction=desc"
    )
    try:
        result = runner(
            ["gh", "api", endpoint, "--jq", COMMENT_QUERY],
            capture_output=True,
            text=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as error:
        raise SecurityAssuranceError("GitHub security assurance evidence is unavailable") from error
    stdout = result.stdout if isinstance(result.stdout, str) else ""
    if result.returncode != 0 or len(stdout.encode("utf-8")) > MAX_GH_OUTPUT_BYTES:
        raise SecurityAssuranceError("GitHub security assurance evidence could not be verified")
    try:
        comments = json.loads(stdout)
    except json.JSONDecodeError as error:
        raise SecurityAssuranceError("GitHub security assurance response is invalid") from error
    if not isinstance(comments, list) or len(comments) > 100:
        raise SecurityAssuranceError("GitHub security assurance response is invalid")
    return comments


def verify_promotion_security_assurance(
    candidate_digest: str,
    *,
    now: datetime,
    report_path: str | None,
    comment_loader: Callable[[], list[dict[str, Any]]] = load_security_assurance_comments,
) -> dict[str, Any]:
    """Load and validate the authenticated issue evidence for a promotion candidate."""

    verified = verify_security_assurance_comments(
        comment_loader(), candidate_digest=candidate_digest, now=now
    )
    if not isinstance(report_path, str) or not report_path.strip():
        raise SecurityAssuranceError("private external review report is required")
    report_file = Path(report_path)
    try:
        if not report_file.is_file() or report_file.stat().st_size > MAX_REPORT_BYTES:
            raise SecurityAssuranceError("private external review report is unavailable or too large")
        hasher = hashlib.sha256()
        total_bytes = 0
        with report_file.open("rb") as source:
            for chunk in iter(lambda: source.read(64 * 1024), b""):
                total_bytes += len(chunk)
                if total_bytes > MAX_REPORT_BYTES:
                    raise SecurityAssuranceError("private external review report is too large")
                hasher.update(chunk)
    except OSError as error:
        raise SecurityAssuranceError("private external review report is unavailable") from error
    if f"sha256:{hasher.hexdigest()}" != verified["report_sha256"]:
        raise SecurityAssuranceError("private external review report hash does not match")
    return verified
