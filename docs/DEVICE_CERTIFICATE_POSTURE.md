# Device certificate posture: inventory-only evidence

The Device Profiles view evaluates dashboard-managed device metadata against
the read-only RouterOS OpenVPN client-certificate inventory. An **Inventory
match** means the exact named certificate was found, is not marked revoked,
has a parseable expiry date in the future, and reports the configured current
CA as issuer. Certificates expiring within 30 days are marked **Expiring
soon**; expired, unknown-expiry, missing, revoked, legacy-issuer, or
unverifiable-issuer records require review.

This is not proof that a VPN client can connect or is rejected. In particular,
the inventory result does not establish CRL publication/enforcement, terminate
an already active VPN session, or prove that a revoked/expired identity is
rejected on a fresh connection. Existing sessions may remain active after
certificate revocation unless separately terminated. Those are RouterOS and
live-client acceptance checks, not facts inferred from this inventory view.

This view and its evaluator are read-only. They do not create, renew, revoke,
or import certificates; alter CA/CRL settings; terminate VPN sessions; or
change RouterOS configuration. Certificate names and fingerprint display
remain part of the existing operator inventory UI; this change adds no new
identifiers, private data, or raw RouterOS fields to telemetry, logs, or
reports.

## Lost profile recovery

Issued private keys are not retained for later re-download. The VPN Users
profile actions therefore issue a **new device certificate** and a new
protected profile; they do not retrieve the earlier profile or private key. If
a profile is lost, issue a replacement, import and test it, then separately
revoke the prior certificate. Issuing a replacement does not itself terminate
an active VPN session, and inventory/revocation read-back does not prove CRL
enforcement or rejection on a fresh connection. Do not describe this as
same-identity re-download.

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
- Complete and accept the guided staged per-device renewal flow: issue a
  replacement, import and test it, then separately retire the prior identity.
  PR #429 clarifies that this is a new identity, not same-identity re-download;
  issued private keys are deliberately not retained. Validate the replacement
  recovery flow and its RouterOS outcomes in the approved test window. This
  read-only posture evaluator itself adds no mutation action.
- Exercise those workflows on a canary with rollback evidence before any
  production rollout. No such live validation or deployment is claimed here.
