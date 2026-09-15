# Production observability

The dashboard includes a read-only operations view for understanding what is
running, how health has changed, and whether an immutable rollback point is
available. It is intentionally local: observations are stored in the
RouterOS-hosted `/data` SQLite database and are never published to GitHub,
GHCR, Cloudflare, or a webhook unless an operator has separately configured an
audit webhook.

## What the view shows

- **Deployment history** records the version and immutable source revision seen
  when a dashboard container starts. Duplicate observations for the same
  revision are coalesced for five minutes.
- **Health timeline** stores compact outcomes from the existing read-only
  service-health checks. It retains the overall state and counts only; it does
  not store credentials, certificate material, packet payloads, or RouterOS
  configuration.
- **Rollback visibility** identifies the running revision and the most recent
  different known-good runtime revision. It is a visibility aid, not an
  automatic rollback action. The router-local watchdog remains the authority
  for canary validation and promotion.

The panel is available under **Service Health**. The authenticated API is
`GET /api/observability`; the live status response also includes the same
`observability` object so the panel refreshes with the normal five-second
telemetry loop.

## Data and recovery boundary

The new `deployment_events` and `health_snapshots` tables are metadata-only and
are included in the existing local metadata backup archive. Retention pruning
uses the configured history-retention window. Restoring or deleting these rows
cannot change RouterOS users, certificates, CA state, firewall rules, proxy
settings, or the persistent OpenVPN profile files.

Deployment identity comes from the image's baked `VERSION` and `REVISION`
files. A revision is considered rollback-visible only when a previous runtime
observation exists; selecting or applying that image still happens through the
reviewed router-local immutable updater and its canary/readiness gates.
