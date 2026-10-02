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
- Design staged per-device renewal so replacement can be imported and tested
  before the previous identity is retired; validate profile redownload and
  recovery behavior. This partial adds no renewal or revocation actions.
- Exercise those workflows on a canary with rollback evidence before any
  production rollout. No such live validation or deployment is claimed here.
