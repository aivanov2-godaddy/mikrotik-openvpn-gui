# Live telemetry rollback and fallback

This runbook covers application telemetry behavior on one MikroTik router. It
must preserve authenticated access, RouterOS as the source of truth, and the
same privacy boundary used by normal release acceptance. It does not authorize
an unreviewed container, RouterOS, certificate, or VPN configuration change.

## Telemetry transport fallback

The application supports LIVE_TRANSPORT values rest, binary, and auto; the
configuration defaults to rest. Use only a fallback supported by the exact
candidate and its tested acceptance report.

1. Stop further promotion if the candidate's live telemetry fails freshness,
   authorization, reconnect, event-integrity, or REST/Binary parity checks.
2. Keep the accepted production image reference recorded. Verify the fallback
   behavior on the isolated canary through the normal reviewed release and
   configuration path; do not edit a production container's environment list
   or restart it ad hoc.
3. If a reviewed canary test shows LIVE_TRANSPORT=rest restores the required
   behavior, record the exact setting and candidate revision in private
   evidence. If there is no supported way to change the setting safely, use
   the last-good image rollback procedure instead of improvising RouterOS
   writes.
4. Change production only after the current promotion gates pass, or through
   the operator-reviewed emergency rollback procedure in ROLLBACK.md.
5. Verify that authorized clients receive current snapshots and live updates
   without manual refresh, and that expired or revoked sessions receive no
   telemetry. Keep live session identifiers and addresses out of reports.

A telemetry transport fallback must not change OpenVPN server configuration,
VPN users, certificates, profiles, address pools, firewall rules, or RouterOS
REST trust material. A dashboard image restart may interrupt dashboard/API
access; confirm the maintenance impact before a production rollback.

## Image rollback

For a code or image regression, follow ROLLBACK.md. The operator-reviewed
helper selects only vpn-dashboard-production, requires a one-use global
`vpnGuiRollbackAuthorization` naming the exact current and previous immutable ARM64 images,
and refuses a live image that differs from the current journal entry. Save it
as the single RouterOS system script named
`vpn-gui-manual-rollback`; it rejects duplicate names, other script names, and
terminal execution, while the active-job guard serializes runs.
It derives the production container's VETH address and accepts readiness only
at its exact private `http://<VETH-IPv4>:8080/readyz` origin. It writes
RouterOS's registry-relative previous-good image, then checks
remote-image read-back and readiness revision. After readiness succeeds, it
updates the journal to record the restored image as current and clears the
previous rollback target. A RouterOS command failure can leave production
stopped or partially changed; inspect its state before recovery.

The helper refuses old-format journals without `previous-good-image`. A
reviewed promotion must first record both immutable image references. Never
seed that target from a mutable tag, opaque RouterOS `image-id`, or a registry
lookup that does not prove the running image.

The helper does not restore or delete /data, mounts, environment lists, or VPN
configuration. Older application startup may still write events or schema
changes to SQLite, and an image rollback does not reverse those writes.

The helper does not prove RouterOS healthcheck success or the running OCI
manifest digest. Verify those through the separate release acceptance evidence;
do not substitute an opaque RouterOS image-id or configured reference for a
verified running digest.

## Data and certificate invariants

Throughout a telemetry or image rollback, keep these unchanged:

- /data/dashboard.sqlite and its router storage mount;
- /config/routeros-ca.crt and the REST trust configuration;
- the OpenVPN CA, server certificate, client certificates, and issued profiles;
- RouterOS PPP users, OpenVPN server, PPP profile, address pool, and firewall;
- canary and production data separation and the RouterOS source-of-truth
  boundary.

## Verification checklist

- /healthz succeeds and /readyz returns the expected source revision;
- /api/status and telemetry snapshots show only authorized current records;
- live events arrive without refresh and respect event-age and ordering limits;
- logout, expiry, revocation, reconnect, and transport fallback retain the
  authorization boundary;
- Binary API interruptions recover through the tested REST fallback;
- no unapproved production change, extra listener, or shared database writer
  remains.
