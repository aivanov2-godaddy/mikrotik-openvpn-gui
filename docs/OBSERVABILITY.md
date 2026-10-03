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
- **Operations timeline** uses stable source-row identifiers for local audit
  events. Those identifiers make a row addressable across refreshes; they are
  not cross-system incident IDs and do not correlate RouterOS telemetry or
  Redis deliveries. The timeline remains bounded and explicitly incomplete.
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

## Live telemetry freshness metrics

The authenticated, aggregate `GET /metrics` endpoint exposes independent age
gauges for the most recently observed session event and interface-counter
sample: `vpn_dashboard_telemetry_session_event_age_seconds` and
`vpn_dashboard_telemetry_traffic_sample_age_seconds`. The corresponding
`*_timestamp_seconds` gauges give the process observation time, and
`*_total` counters report aggregate observations. These series have no labels
and contain no usernames, addresses, session identifiers, event IDs, or
payloads. A value of `-1` for an age or timestamp means that observation type
has not yet been seen since process start; zero is a valid fresh age.

Age measures elapsed wall time since this process accepted an observation. It
is a freshness signal, not end-to-end RouterOS-to-browser latency or proof of
delivery to every client. Session observations are marked by the REST/SSE
reconciliation path and live session stream; traffic-sample freshness is marked
when interface-counter events enter the telemetry runtime. A later acceptance
collector can sample these gauges over a window without calling RouterOS or
adding event-level/private data to metrics.
