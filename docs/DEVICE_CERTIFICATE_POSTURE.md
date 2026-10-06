# Device certificate posture: inventory-only evidence

The Device Profiles view evaluates dashboard-managed device metadata against
the read-only RouterOS OpenVPN client-certificate inventory. An **Inventory
match** means the exact named certificate was found, is not marked revoked,
has a parseable expiry date in the future, and reports the configured current
CA as issuer. Certificates expiring within 30 days are marked **Expiring
soon**; expired, unknown-expiry, missing, revoked, legacy-issuer, or
unverifiable-issuer records require review.

For a dashboard-managed device with a known expiry within 30 days (or already
expired), Device Profiles offers **Renew certificate**. This stages a new
client identity under the configured current CA and records only the source
and replacement certificate names plus operator progress. Issuing the new
certificate does not revoke the existing one while the operator imports and
tests the replacement; an expired certificate may already be unusable.
The database records only safe lifecycle metadata (user, certificate names,
timestamps, and operator progress), never profile contents or private keys.
Retirement is a separate reviewed action and requires a current RouterOS
read-back of the active source and usable replacement. The flow does not
change CA-wide policy. Previous-CA certificates continue to use the same
staged replacement sequence.

This is not proof that a VPN client can connect or is rejected. In particular,
the inventory result does not establish CRL publication/enforcement, terminate
an already active VPN session, or prove that a revoked/expired identity is
rejected on a fresh connection. Existing sessions may remain active after
certificate revocation unless separately terminated. Those are RouterOS and
live-client acceptance checks, not facts inferred from this inventory view.

The posture evaluator and certificate inventory read are read-only. Separate
profile-issuance and certificate-retirement actions use a one-time review,
explicit operator confirmation where applicable, and RouterOS read-back.
They do not alter CA/CRL settings or terminate existing VPN sessions.
Certificate names and fingerprint display remain part of the operator
inventory UI; profile archives and private keys are never persisted or added
to telemetry, logs, or reports.

## Lost profile recovery

Issued private keys are not retained for later re-download. The VPN Users
profile actions therefore issue a **new device certificate** and a new
protected profile; they do not retrieve the earlier profile or private key. If
a profile is lost, issue a replacement, import and test it, then separately
revoke the prior certificate. Issuing a replacement does not itself terminate
an active VPN session, and inventory/revocation read-back does not prove CRL
enforcement or rejection on a fresh connection. Do not describe this as
same-identity re-download. After issuance, the Device Profiles replacement row
shows the replacement certificate name and reminds the operator to import and
test it before revoking the legacy certificate. “Replacement issued” records
only that issuance completed; it is not evidence that the profile was imported,
tested, or connected successfully.

To record the connection-test step, the dashboard requires both an explicit
operator confirmation and a read-only RouterOS observation of an active session
for the matching VPN user at that moment. This raises the evidence bar but does
not identify the session's client certificate, so the UI continues to label the
test as operator-confirmed and does not claim cryptographic attribution. Older
migration records without this live-session observation must be re-confirmed
before the legacy certificate can be retired.

## Validation

Run the focused checks with:

```powershell
python -m unittest tests.test_app.DevicePostureTests
```

The tests use synthetic records and a supplied clock. No live router,
certificate, profile archive, or user record is used by these checks.

## Remaining acceptance work

- Verify actual RouterOS certificate inventory and CA/issuer mapping across
  supported RouterOS versions, including unavailable or malformed fields.
- Confirm CRL use and CRL freshness on the router; the dashboard does not
  infer successful revocation enforcement from a certificate's `revoked`
  flag alone.
- Under an approved test window, prove that revocation prevents a fresh
  connection and separately test the handling of an already-active session.
- Accept the guided staged per-device renewal flow on RouterOS: issue a new
  same-CA renewal or previous-CA replacement, import and test it, then
  separately retire the prior identity. PR #429 clarifies this is a new identity, not
  same-identity re-download; issued private keys are deliberately not retained.
  Validate renewal, replacement recovery, and RouterOS read-back outcomes in
  the approved test window.
- Exercise those workflows on a canary with rollback evidence before any
  production rollout. No such live validation or deployment is claimed here.
