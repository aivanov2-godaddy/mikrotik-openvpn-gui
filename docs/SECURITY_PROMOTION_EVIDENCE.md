# Candidate-bound security promotion evidence

The production promotion controller has a second, fail-closed gate after the
technical canary evidence passes. It reads the latest 100 issue comments and
retains only marker-bearing records from [#200](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui/issues/200)
through the authenticated GitHub CLI. It performs this check before resolving
registry digests or contacting RouterOS. A passing technical `promotion_eligible`
report alone does not authorize a production promotion.

The external review report stays in its access-controlled storage. Do not put
report contents, router addresses, credentials, private API output, or readiness
URLs in the public issue comment. The report reference must be a credential-free
HTTPS URL with no query or fragment. Its SHA-256 binds the comment to the
reviewed report. The promotion command also requires a private local copy of
that report and verifies the file's SHA-256 against the comment before any
registry or RouterOS operation. The controller does not print the path or
report contents.

## External scoped ASVS review comment

An independent reviewer posts this marker followed by one JSON object:

```text
<!-- vpn-gui-external-asvs-review:v1 -->
{
  "schema": "vpn-gui-external-asvs-review-v1",
  "candidate_digest": "sha256:<64 lowercase hex digits>",
  "asvs_version": "5.0",
  "scope": "mikrotik-openvpn-gui-single-router",
  "review_status": "complete",
  "independent": true,
  "reviewed_requirement_count": 43,
  "reviewed_at": "<RFC 3339 timestamp>",
  "expires_at": "<RFC 3339 timestamp, at most 90 days after review>",
  "report_sha256": "sha256:<64 lowercase hex digits>",
  "report_reference": "https://<access-controlled-report-location>/<path>",
  "unresolved_findings": [
    {"id": "<finding identifier>", "severity": "moderate"}
  ]
}
```

The comment must be authored by a GitHub `User` outside the repository owner's
and member associations. An external collaborator may review if they affirm
independence in the record. The declared coverage count is pinned to
the current matrix's 43 unique ASVS requirements. Critical and high unresolved
findings block promotion. Finding IDs must be unique, and only the `critical`,
`high`, `moderate`, and `low` severities are accepted.

## Owner residual-risk decision comment

The repository owner posts this marker and one JSON object after reviewing the
external report and its findings:

```text
<!-- vpn-gui-owner-risk-decision:v1 -->
{
  "schema": "vpn-gui-owner-risk-decision-v1",
  "candidate_digest": "sha256:<same candidate digest>",
  "decision": "accept",
  "decided_at": "<RFC 3339 timestamp>",
  "rationale": "<specific rationale and controls for residual risk>",
  "accepted_finding_ids": ["<every unresolved moderate/low finding ID>"]
}
```

The owner must accept exactly the unresolved moderate/low finding IDs; a
rejected, incomplete, or different-digest decision blocks promotion. Both
comments must be unedited and created within five minutes of their declared
timestamps. The review must not be expired, and the owner decision must fall
within the review's validity window. Duplicate candidate-bound records are
within the review's validity window. Duplicate candidate-bound records in the
sampled comments are treated as ambiguous and block promotion. If either record
falls outside the sampled 100 comments, the gate fails closed for missing
evidence.

The gate verifies authenticated GitHub account identity and record shape. It
does not independently perform or certify the ASVS review, validate a reviewer
employment history, or waive candidate-bound device, privacy, reliability, or
rollback acceptance. Issue #200 remains open until those separate requirements
are completed with evidence.
