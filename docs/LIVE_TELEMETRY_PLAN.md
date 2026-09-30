# Live telemetry transport plan

This document describes the staged migration from RouterOS REST/SSE polling to
RouterOS Binary API-SSL with a Socket.IO browser gateway. It is a plan and a
design contract; the current release continues to use the existing REST/SSE
path until each phase is validated.

## Goals

- Make connected-device state and traffic graphs update without page refreshes.
- Reduce duplicate RouterOS REST reads when several administrators are viewing
  the dashboard.
- Keep RouterOS credentials server-side and publish only redacted telemetry.
- Preserve the existing REST mutation path for users, certificates, profiles,
  policies, checkpoints, and rollback.
- Preserve the OpenVPN CA, server certificate, client certificates, profiles,
  SQLite data, and RouterOS configuration.

## Target architecture

```text
Browser -- Socket.IO over same-origin HTTPS/WSS --> dashboard container
                                                     |
                                                     +-- Binary API-SSL (8729)
                                                     |   read-only telemetry
                                                     +-- REST over HTTPS
                                                         mutations, bootstrap,
                                                         reconciliation/fallback
                                                     |
                                                     v
                                                   RouterOS
```

Socket.IO is a browser delivery layer, not a RouterOS protocol. The dashboard
container is the only component allowed to connect to RouterOS API-SSL. The
browser never sees RouterOS credentials or the API-SSL port.

## Event model

The broker will publish versioned, redacted events with a sequence number and
router timestamp:

- `telemetry.snapshot`
- `vpn.session.connected`
- `vpn.session.updated`
- `vpn.session.disconnected`
- `vpn.interface.counters`
- `router.capacity.updated`
- `router.health.updated`
- `telemetry.reconciled`

Session events contain only the same safe fields currently rendered by the
dashboard: username, VPN address, source address, uptime, encoding, counters,
and packet totals. Passwords, tokens, certificate material, private keys,
profiles, and RouterOS exports are never emitted.

## Phases

1. **Protocol foundation (complete).** Validate Binary API word framing,
   sentence parsing, tags, dead records, traps, and buffered reconnect-safe
   reads. This phase is disabled at runtime.
2. **Read-only Binary API adapter (transport and supervisor slice complete).**
   Add TLS/API-SSL connection management, `listen` support for the active PPP
   resource, bounded reconnect/backoff, health metrics, and periodic snapshot
   reconciliation. Do not add configuration mutation helpers. The supervisor
   remains disabled by default and accepts injected dependencies for canary
   validation.
3. **Telemetry broker (complete).** Maintain an in-memory state cache,
   normalize records, calculate rates from monotonic counters, and run
   periodic reconciliation.
4. **Socket.IO gateway (adapter complete; runtime opt-in).** Authenticate with
   the existing dashboard session, enforce role/session timeouts, support
   reconnect and snapshot recovery, and apply per-client backpressure. The
   dependency-free adapter targets a compatible Socket.IO server object and is
   never attached by the default stdlib runtime.
5. **Frontend migration (fallback-safe slice complete).** Capability discovery
   can select Socket.IO when an explicitly enabled server advertises it; the
   browser otherwise keeps the existing EventSource stream and five-second
   REST refresh. Socket.IO disconnects fall back to SSE without changing any
   mutation or profile flow.
6. **Canary validation (comparison harness complete; router acceptance pending).**
   A dependency-free comparator checks redacted session identity and freshness,
   requires consecutive healthy samples before promotion, and records no
   secrets. Router restart/reconnect, CPU, and latency acceptance still belong
   to the operator's canary window before enabling the adapter.

## Proposed acceptance targets

- Session connect/disconnect visible within 1 second under normal conditions.
- Traffic samples no older than 2 seconds while the stream is healthy.
- Automatic reconnect and full snapshot recovery after a temporary API outage.
- No unauthenticated event delivery and no secret-bearing event payloads.
- REST fallback remains available at all times during the migration.
- Router CPU and memory impact measured on the canary before production use.

## Current runtime gate

The public image reports the requested ``LIVE_TRANSPORT`` value plus the
effective ``transport: sse`` from ``/api/telemetry`` and does not attach a
Socket.IO server. This is intentional: enabling ``binary`` or ``auto`` only
selects a canary intent; it never promotes a new transport or changes the
router. The status also reports redacted freshness, reconciliation age, and
error state for the current SSE path. A future canary image must provide the
optional server, run the comparator, and retain the same immutable release and
rollback record before switching the advertised transport.

The operator procedure and redacted NDJSON comparator are documented in
`docs/LIVE_TELEMETRY_CANARY.md`; they are local-only and never upload sample
records.

## Configuration boundary

If API-SSL is not already available, the deployment review may add a separate
RouterOS management-plane API-SSL service restricted to the container network.
It must use a management certificate and must not replace or reuse the
OpenVPN CA as part of this feature. The existing REST CA file, OpenVPN CA,
certificates, profiles, and data mounts remain unchanged.
