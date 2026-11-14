from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import tempfile
import unittest

from scripts.release_security_assurance import (
    SecurityAssuranceError,
    verify_promotion_security_assurance,
    verify_security_assurance_comments,
)


NOW = datetime(2026, 11, 12, 12, 0, tzinfo=timezone.utc)
CANDIDATE_DIGEST = "sha256:" + "c" * 64
OTHER_DIGEST = "sha256:" + "d" * 64
REVIEW_MARKER = "<!-- vpn-gui-external-asvs-review:v1 -->"
OWNER_MARKER = "<!-- vpn-gui-owner-risk-decision:v1 -->"


def assurance_comments(
    *,
    digest: str = CANDIDATE_DIGEST,
    review_created: datetime | None = None,
    review_expiry: datetime | None = None,
    requirement_count: int = 43,
    findings: list[dict[str, str]] | None = None,
    accepted_findings: list[str] | None = None,
    reviewer_login: str = "independent-reviewer",
    reviewer_association: str = "NONE",
) -> list[dict[str, object]]:
    reviewed = review_created or (NOW - timedelta(minutes=2))
    expiry = review_expiry or (reviewed + timedelta(days=30))
    findings = findings if findings is not None else [{"id": "V8.3.2", "severity": "moderate"}]
    accepted_findings = accepted_findings if accepted_findings is not None else [item["id"] for item in findings]
    review = {
        "schema": "vpn-gui-external-asvs-review-v1",
        "candidate_digest": digest,
        "asvs_version": "5.0",
        "scope": "mikrotik-openvpn-gui-single-router",
        "review_status": "complete",
        "independent": True,
        "reviewed_requirement_count": requirement_count,
        "reviewed_at": reviewed.isoformat(),
        "expires_at": expiry.isoformat(),
        "report_sha256": "sha256:" + "a" * 64,
        "report_reference": "https://review.example.test/reports/candidate-review.pdf",
        "unresolved_findings": findings,
    }
    owner_created = NOW - timedelta(minutes=1)
    owner = {
        "schema": "vpn-gui-owner-risk-decision-v1",
        "candidate_digest": digest,
        "decision": "accept",
        "decided_at": owner_created.isoformat(),
        "rationale": "Accepted the remaining documented moderate finding with the stated monitoring and remediation controls.",
        "accepted_finding_ids": accepted_findings,
    }
    return [
        {
            "id": 1,
            "body": REVIEW_MARKER + "\n" + json.dumps(review),
            "body_length": len(REVIEW_MARKER + "\n" + json.dumps(review)),
            "created_at": reviewed.isoformat(),
            "updated_at": reviewed.isoformat(),
            "author_association": reviewer_association,
            "user": {"login": reviewer_login, "type": "User"},
        },
        {
            "id": 2,
            "body": OWNER_MARKER + "\n" + json.dumps(owner),
            "body_length": len(OWNER_MARKER + "\n" + json.dumps(owner)),
            "created_at": owner_created.isoformat(),
            "updated_at": owner_created.isoformat(),
            "author_association": "OWNER",
            "user": {"login": "aivanov2-godaddy", "type": "User"},
        },
    ]


class SecurityAssuranceTests(unittest.TestCase):
    def test_candidate_bound_complete_review_and_owner_decision_pass(self) -> None:
        result = verify_security_assurance_comments(
            assurance_comments(), candidate_digest=CANDIDATE_DIGEST, now=NOW
        )
        self.assertEqual(result["candidate_digest"], CANDIDATE_DIGEST)
        self.assertEqual(result["reviewer_login"], "independent-reviewer")
        self.assertEqual(result["risk_owner_login"], "aivanov2-godaddy")
        self.assertEqual(result["unresolved_finding_ids"], ["V8.3.2"])

    def test_missing_external_review_fails_closed(self) -> None:
        comments = assurance_comments()[1:]
        with self.assertRaisesRegex(SecurityAssuranceError, "exactly one current"):
            verify_security_assurance_comments(comments, candidate_digest=CANDIDATE_DIGEST, now=NOW)

    def test_review_for_a_different_digest_is_stale_for_this_candidate(self) -> None:
        with self.assertRaisesRegex(SecurityAssuranceError, "exactly one current"):
            verify_security_assurance_comments(
                assurance_comments(digest=OTHER_DIGEST), candidate_digest=CANDIDATE_DIGEST, now=NOW
            )

    def test_expired_review_fails_closed(self) -> None:
        comments = assurance_comments(review_expiry=NOW - timedelta(seconds=1))
        with self.assertRaisesRegex(SecurityAssuranceError, "expired"):
            verify_security_assurance_comments(comments, candidate_digest=CANDIDATE_DIGEST, now=NOW)

    def test_review_with_incomplete_requirement_coverage_fails_closed(self) -> None:
        comments = assurance_comments(requirement_count=42)
        with self.assertRaisesRegex(SecurityAssuranceError, "incomplete"):
            verify_security_assurance_comments(comments, candidate_digest=CANDIDATE_DIGEST, now=NOW)

    def test_unresolved_critical_or_high_finding_blocks_promotion(self) -> None:
        for severity in ("critical", "high"):
            with self.subTest(severity=severity):
                comments = assurance_comments(findings=[{"id": "V8.3.2", "severity": severity}])
                with self.assertRaisesRegex(SecurityAssuranceError, "block promotion"):
                    verify_security_assurance_comments(comments, candidate_digest=CANDIDATE_DIGEST, now=NOW)

    def test_owner_must_accept_exactly_the_unresolved_finding_ids(self) -> None:
        comments = assurance_comments(accepted_findings=[])
        with self.assertRaisesRegex(SecurityAssuranceError, "does not cover"):
            verify_security_assurance_comments(comments, candidate_digest=CANDIDATE_DIGEST, now=NOW)

    def test_reviewer_must_be_an_external_user(self) -> None:
        cases = (("aivanov2-godaddy", "NONE"), ("reviewer", "MEMBER"))
        for login, association in cases:
            with self.subTest(login=login, association=association):
                comments = assurance_comments(reviewer_login=login, reviewer_association=association)
                with self.assertRaisesRegex(SecurityAssuranceError, "external GitHub user"):
                    verify_security_assurance_comments(comments, candidate_digest=CANDIDATE_DIGEST, now=NOW)

    def test_edited_comment_fails_closed(self) -> None:
        comments = assurance_comments()
        comments[0]["updated_at"] = (NOW - timedelta(minutes=1)).isoformat()
        with self.assertRaisesRegex(SecurityAssuranceError, "must not be edited"):
            verify_security_assurance_comments(comments, candidate_digest=CANDIDATE_DIGEST, now=NOW)

    def test_invalid_remote_comment_length_fails_closed(self) -> None:
        comments = assurance_comments()
        comments[0]["body_length"] = "unbounded"
        with self.assertRaisesRegex(SecurityAssuranceError, "size limit"):
            verify_security_assurance_comments(comments, candidate_digest=CANDIDATE_DIGEST, now=NOW)

    def test_ambiguous_duplicate_review_fails_closed(self) -> None:
        comments = assurance_comments()
        comments.append(deepcopy(comments[0]))
        with self.assertRaisesRegex(SecurityAssuranceError, "exactly one current"):
            verify_security_assurance_comments(comments, candidate_digest=CANDIDATE_DIGEST, now=NOW)

    def test_owner_decision_must_be_candidate_bound(self) -> None:
        comments = assurance_comments()
        owner_record = json.loads(comments[1]["body"].split(OWNER_MARKER, 1)[1])
        owner_record["candidate_digest"] = OTHER_DIGEST
        comments[1]["body"] = OWNER_MARKER + "\n" + json.dumps(owner_record)
        with self.assertRaisesRegex(SecurityAssuranceError, "exactly one current"):
            verify_security_assurance_comments(comments, candidate_digest=CANDIDATE_DIGEST, now=NOW)

    def test_private_report_bytes_must_match_the_public_review_hash(self) -> None:
        report_bytes = b"candidate-bound external report fixture"
        expected_hash = "sha256:" + hashlib.sha256(report_bytes).hexdigest()
        comments = assurance_comments()
        review_record = json.loads(comments[0]["body"].split(REVIEW_MARKER, 1)[1])
        review_record["report_sha256"] = expected_hash
        comments[0]["body"] = REVIEW_MARKER + "\n" + json.dumps(review_record)
        comments[0]["body_length"] = len(comments[0]["body"])

        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "private-report.pdf"
            report_path.write_bytes(report_bytes)
            result = verify_promotion_security_assurance(
                CANDIDATE_DIGEST,
                now=NOW,
                report_path=str(report_path),
                comment_loader=lambda: comments,
            )

        self.assertEqual(result["report_sha256"], expected_hash)

    def test_missing_or_mismatched_private_report_fails_closed(self) -> None:
        comments = assurance_comments()
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "private-report.pdf"
            report_path.write_bytes(b"different report")
            with self.assertRaisesRegex(SecurityAssuranceError, "hash does not match"):
                verify_promotion_security_assurance(
                    CANDIDATE_DIGEST,
                    now=NOW,
                    report_path=str(report_path),
                    comment_loader=lambda: comments,
                )
            with self.assertRaisesRegex(SecurityAssuranceError, "report is required"):
                verify_promotion_security_assurance(
                    CANDIDATE_DIGEST,
                    now=NOW,
                    report_path=None,
                    comment_loader=lambda: comments,
                )


    def test_duplicate_record_docs_match_fail_closed_behavior(self) -> None:
        document_path = (
            Path(__file__).resolve().parents[1]
            / "docs"
            / "SECURITY_PROMOTION_EVIDENCE.md"
        )
        document = document_path.read_text(encoding="utf-8")
        compact = " ".join(document.split())
        self.assertIn(
            "Duplicate candidate-bound records in the sampled comments are treated as ambiguous and block promotion.",
            compact,
        )
        self.assertNotIn(
            "Duplicate candidate-bound records are within the review's validity window.",
            compact,
        )


if __name__ == "__main__":
    unittest.main()
