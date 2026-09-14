# Public roadmap

The project is developed public-first: generic features are designed, tested,
and released here before an operator optionally evaluates them in a private
canary. This source repository never receives router credentials, live user
data, deployment runners, or production network details.

## v1.1 — Installation Wizard

An offline, review-only installer that validates non-secret answers and renders
a RouterOS `.rsc` plan. It keeps Container package installation, device-mode
physical confirmation, TLS, storage checks, firewall/DNS work, and applying
commands explicitly manual.

## v1.2 — Policy templates and groups (implemented)

Protected `standard`, `contractor`, and `administrator` templates, plus custom
templates. Selected users receive a preview before an explicit, checkpointed
apply; later direct edits are retained as visible per-user overrides.

## v1.3 — Health and actionable alerts

Storage, certificate, REST reachability, profile-issuance, quota, and schedule
signals with concise remediation guidance.

## v1.4 — Reports and audit

Readable date-range reports, redacted CSV/JSON exports, and retention controls.

## v1.5 — Backup and restore safety

Guided SQLite backup/restore checks, checksum verification, and compatibility
preflight. Backups remain local to the operator.

## v1.6 — Administrator guardrails

Clear capability matrix, explicit destructive-action confirmations, and richer
audit rationale without a second administrator-password database.

## v1.7 — Opt-in integrations

Signed generic webhook notifications and health endpoints. Provider-specific
services remain optional adapters rather than hard dependencies.

## Planned installation expansion — RouterOS OpenVPN bootstrap

The current installation wizard deploys the dashboard but deliberately expects
an existing OpenVPN server, PPP profile, and CA. A future review-first bootstrap
will generate an explicit plan for those prerequisites, with no hidden network
or certificate mutations and a required backup/checkpoint before apply.

Every roadmap item gets a focused issue, pull request, passing CI, and squash
merge. See the live GitHub [roadmap issue](https://github.com/aivanov2-godaddy/mikrotik-openvpn-gui-public/issues/4).
