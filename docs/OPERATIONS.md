# Operations runbook

## Daily checks

- Container status is running without restart churn.
- `/healthz` reports process liveness, `/readyz` reports cached SQLite readiness and the deployed revision, and the public path follows the configured HTTPS access flow.
- RouterOS REST certificate validation succeeds; `ROUTEROS_INSECURE_TLS` remains `false`.
- SQLite storage, RouterOS container storage, CPU, and memory stay below local alert thresholds.
- Dashboard users, connected sessions, and interface counters agree with WinBox for a sample identity.
- Audit events contain no passwords, tokens, private keys, profile bodies, or raw authorization headers.

## Safe update cadence

1. Review dependency alerts and every available repository security signal.
2. Merge through a pull request with the required pre-commit, secret, test, and ARM64 checks.
3. Select and validate an immutable full-commit `sha-` tag using the local procedure in [DEPLOYMENT.md](DEPLOYMENT.md).
4. Confirm the selected image, RouterOS container status, dashboard `/readyz` revision, and the public login path.
5. Retain the previous image and data checkpoint until the observation window ends.

Never follow `edge`, change mutable registry settings, or modify the container's mounts and environment during a routine update. Use the canary-first procedure in [DEPLOYMENT.md](DEPLOYMENT.md) for schema, data, or RouterOS-policy migrations before promoting them.

## Database backup

The dashboard's **Download backup** control creates a self-verifying metadata-only ZIP. Its manifest contains the SHA-256 checksum for `metadata.json`; it never includes RouterOS configuration, credentials, private keys, issued profiles, or active sessions. Keep it in an operator-controlled location.

SQLite backups must be consistent:

1. Stop the dashboard container during an approved maintenance window.
2. Copy the complete `/data` source directory, including sidecar files, into an immutable checkpoint.
3. Verify the recursive copy and SQLite integrity before restarting the writer.
4. Start the container and verify `/readyz` immediately.
5. Export the checkpoint to encrypted off-router storage.
6. Test restoration periodically into an isolated canary, never over production.

Apply retention appropriate to the sensitivity of email ownership, address, usage, and audit metadata. Destroy expired backups securely.

## Credential and certificate rotation

- Rotate the GHCR package-read token before expiry and after any suspected exposure.
- Keep its scope to `read:packages`; validate the new token with a canary pull before revoking the old token.
- Rotate the RouterOS REST server certificate with an overlap window: install the new public CA/config mount, canary the connection, then retire the old trust material.
- Revoke device certificates through RouterOS and the dashboard; do not rely on deleting a downloaded profile.
- Review Cloudflare and RouterOS administrator membership regularly.

## Capacity

Track:

- root-directory and temporary image extraction space;
- `/data` growth and backup size;
- container memory/restarts;
- RouterOS CPU under concurrent profile generation and session polling;
- active OpenVPN sessions versus configured account/device limits.

MikroTik recommends external storage for containers. Do not start a pull unless there is room for the compressed layers, extraction, current image, canary, and rollback image.

## Incident containment

If administration access is suspected compromised:

1. Restrict or disable public dashboard access at the edge while preserving OpenVPN service.
2. Revoke the suspected Cloudflare/GitHub/RouterOS credential.
3. Stop profile issuance and destructive dashboard actions.
4. Preserve sanitized logs, image digest, RouterOS configuration snapshot, and audit database through approved private storage.
5. Review RouterOS users, PPP secrets, certificates, active sessions, firewall, proxy, and scheduler state directly in WinBox.
6. Rotate affected client credentials/certificates and restore only from a known-good image and checkpoint.

Never paste raw incident artifacts into an issue. Use a private security advisory.

## Disaster recovery inventory

Keep, outside the router and this repository:

- last known-good image digest and commit SHA;
- RouterOS configuration backup/export protected according to local policy;
- encrypted dashboard `/data` checkpoint;
- public RouterOS REST CA certificate and its rotation record;
- documented bridge/VETH/proxy/firewall topology;
- registry-token recovery and revocation procedure.
