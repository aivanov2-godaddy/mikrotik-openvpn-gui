# Architecture

This document describes the stable system boundaries. Environment-specific hostnames, addresses, credentials, certificate material, and account identifiers intentionally do not belong in this repository.

## Request and control paths

```text
Administrator browser
  -> Cloudflare proxy and Access policy (optional but recommended)
  -> RouterOS TLS reverse proxy and origin firewall
  -> dashboard container :8080
  -> RouterOS REST API on a private address
  -> PPP/OpenVPN users, sessions, interfaces, certificates, and policy

OpenVPN client
  -> public OpenVPN endpoint
  -> RouterOS OpenVPN server
  -> permitted LAN and/or internet routes
```

The website is a management control plane. OpenVPN client traffic does not traverse the dashboard container or Cloudflare.

## Data ownership

| Owner | Data |
| --- | --- |
| RouterOS | Administrator identities, PPP/OpenVPN users, VPN server settings, active sessions, interfaces, CA, and client certificates |
| `/data` SQLite volume | Owner email, device metadata, policy metadata, certificate identifiers, usage checkpoints, and sanitized audit events |
| Process memory | RouterOS credentials for active dashboard sessions and short-lived QR download payloads |
| Browser | Opaque secure session cookie, CSRF token, and bounded live graph samples |
| GHCR | Immutable application image, ARM64 manifest digest, and OCI source/revision labels |

The database does not hold VPN passwords or private keys. QR hand-offs expire and are not persisted.

## Container filesystem

```text
/app      immutable application files copied into the GHCR image
/data     persistent RouterOS host mount containing dashboard.sqlite
/config   configuration-only RouterOS host mount containing public CA files
```

Mounting a host source directory onto `/app` defeats image-based delivery and can hide the version published by GitHub. The GHCR production architecture therefore mounts `/data` and `/config` only. RouterOS container mounts do not provide a read-only flag, so `/config` is a convention and must be protected through router management controls.

## Live session model

The service joins RouterOS PPP active records with dynamic OpenVPN interface counters. The authenticated browser polls a status endpoint and derives rates from cumulative counter deltas. Polling pauses while the document is hidden, retains only a bounded client-side sample window, and must not rewrite the current view during an unchanged refresh.

Session termination is deliberately narrow: the requested identifier is validated against a fresh RouterOS OpenVPN active-session list before a delete request is sent.

## Trust boundaries

1. The public edge enforces the selected geographic and identity policy.
2. The RouterOS firewall accepts web-origin traffic only from the configured edge networks.
3. The reverse proxy terminates origin TLS and forwards to a private container address.
4. The container accepts forwarded client headers only from explicitly configured proxy source addresses.
5. The container verifies RouterOS REST TLS with a dedicated CA file.
6. RouterOS applies all VPN identity and forwarding changes; the dashboard never edits RouterOS outside its OpenVPN scope.

## GitHub delivery path

```text
pull request -> CI and dependency/security review -> merge to default branch
  -> repeat tests -> build linux/arm64 image -> GHCR package
  -> operator selects immutable SHA/digest -> isolated RouterOS canary
  -> health and login smoke tests -> controlled proxy cutover
```

The router pulls from GHCR with an expiring package-read token. Deployment is promotion-based rather than an unattended pull of a mutable tag. The previous container record and image digest remain available until the observation window closes.

## Availability and rollback

SQLite is the only mutable application state and remains on the RouterOS host. Every promotion takes a database checkpoint and records the running image digest before starting a canary. A rollback restores the previous proxy target/container and, only when required by a data migration, the matching database checkpoint.

Detailed procedures are in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md), [docs/ROLLBACK.md](docs/ROLLBACK.md), and [docs/OPERATIONS.md](docs/OPERATIONS.md).
