# Live telemetry full-revert runbook

The live telemetry migration is designed so the existing REST/SSE telemetry
path remains a complete fallback. This runbook returns the application to the
last known-good behavior without touching OpenVPN CA material, certificates,
profiles, RouterOS VPN configuration, or router-local dashboard data.

## Fast application rollback

1. Stop promoting the candidate image. Keep the current production immutable
   image reference recorded by the RouterOS watchdog.
2. Set the dashboard live transport feature flag to `rest` (or remove the
   Binary API flag if the release uses the default).
3. Restart only the dashboard canary container and verify `/readyz`, then
   repeat for production if the candidate was already promoted.
4. Confirm the UI receives `/api/status` responses and the existing
   `/api/events` stream reconnects.
5. Leave the RouterOS scheduler/watchdog enabled; it will continue to manage
   immutable image promotion and will not change VPN objects or data mounts.

## Image rollback

If the application image itself is unhealthy:

1. Identify the previous immutable image tag from the watchdog's last-good
   release record.
2. Promote that exact previous tag through the existing canary-first watchdog
   process.
3. Wait for canary readiness and stability validation.
4. Promote production only after the canary passes.
5. Verify both containers report the previous image and a healthy readiness
   response.

Do not use `latest`, `edge`, or another mutable tag during rollback.

## Optional API-SSL cleanup

Only if the migration explicitly enabled a new, dedicated management API-SSL
service and the operator chooses to remove it after rollback:

1. Confirm the dashboard is using REST over the existing HTTPS endpoint.
2. Confirm no other service or administrator depends on the new API-SSL
   listener.
3. Remove only the feature-specific API-SSL address/firewall/service entries
   using a reviewed RouterOS export and maintenance window.
4. Do not remove or modify the OpenVPN UDP service, OpenVPN server certificate,
   OpenVPN CA, client certificates, profiles, or VPN firewall rules.

If API-SSL was already used by another RouterOS service, do not remove it;
disable only the dashboard feature flag and keep the service intact.

## Data and certificate invariants

The following must remain unchanged throughout rollback:

- `/data/dashboard.sqlite` and its router storage mount.
- `/config/routeros-ca.crt` and the REST trust configuration.
- The configured OpenVPN CA and server certificate.
- Existing OpenVPN client certificates and downloaded profiles.
- RouterOS PPP users, OpenVPN server, PPP profile, address pool, and firewall.
- RouterOS scheduler/watchdog state, except for the immutable image reference
  selected by the normal rollback procedure.

## Verification checklist

- `/readyz` returns `ready`.
- `/api/status` returns current users and sessions.
- `/api/events` delivers live session snapshots.
- Connected VPN users remain connected during transport rollback unless the
  image rollback itself requires a planned container restart.
- CA/profile issuance still uses the existing REST path.
- `git diff` and the deployment audit contain no certificate/profile/data
  changes.

