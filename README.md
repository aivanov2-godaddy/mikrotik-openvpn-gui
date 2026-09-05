# MikroTik OpenVPN GUI

MikroTik OpenVPN GUI is a focused web control plane for an OpenVPN server running on RouterOS 7. It gives operators a responsive, WinBox-inspired interface for managing users, per-device profiles, live sessions, policy presets, and a sanitized audit trail while RouterOS remains the authority for VPN access.

This is a private, proprietary project. Do not mirror the repository, publish its container package, or distribute its source without the owner's permission.

## What it does

- Authenticates administrators directly against RouterOS rather than maintaining a second administrator password database.
- Creates, updates, disables, duplicates, and removes OpenVPN users on RouterOS.
- Issues independent client certificates and password-protected profile archives for each device.
- Provides short-lived QR hand-offs for phone and tablet onboarding.
- Shows active OpenVPN sessions, traffic counters, byte/packet rate graphs, source addresses, and session termination controls.
- Supports full-tunnel and access-policy presets, device limits, expiration, schedule, speed, DNS, and quota controls.
- Stores only dashboard metadata and sanitized audit events in SQLite; RouterOS stays the VPN source of truth.
- Uses Cloudflare Access and an origin allowlist as an optional first authentication and perimeter layer.

## Security boundaries

- RouterOS management credentials are supplied at login and retained only in short-lived process memory.
- VPN passwords and private keys must never be committed, logged, placed in image layers, or stored in the dashboard database.
- The RouterOS REST client should validate a dedicated CA certificate mounted at `/config/routeros-ca.crt`; RouterOS mounts are not read-only, so protect the source directory through management policy and never place secrets beside it.
- Persistent application state lives only under `/data`.
- Application code lives in the immutable container image. A production deployment from GHCR must not bind-mount a host `/app` directory over it.
- Private GHCR pulls use a dedicated, expiring token with `read:packages` only. Do not use an administrator token.

See [SECURITY.md](SECURITY.md) and [docs/SECURITY.md](docs/SECURITY.md) before deploying.

## Repository layout

| Path | Purpose |
| --- | --- |
| `app.py` | HTTP service and application API |
| `routeros.py` | RouterOS REST integration and OpenVPN provisioning |
| `automation.py` | Policy automation and operational checks |
| `store.py` | SQLite metadata and audit storage |
| `templates.py`, `static/` | WinBox-inspired web interface |
| `tests/` | Unit and mock RouterOS integration tests |
| `.github/workflows/` | CI, security analysis, and ARM64 image publishing |
| `docs/` | Deployment, rollback, security, and operations runbooks |

## Local verification

The project uses the Python standard library; no application dependencies need to be installed.

```powershell
python scripts/check-secrets.py
python -m compileall -q app.py automation.py cloudflare.py deploy_routeros_canary.py deployment.py favicon.py icons.py qr.py routeros.py security.py store.py templates.py update_routeros_app.py
python -m unittest discover -s tests -v
```

For a local UI backed by the bundled mock RouterOS service:

```powershell
python tests/run_mock_app.py --port 18080
```

Then open `http://127.0.0.1:18080`. The mock does not contact a router or Cloudflare account.

## Runtime configuration

Set deployment values through the RouterOS container environment list. Never commit a populated environment file.

| Variable | Required | Description |
| --- | --- | --- |
| `PUBLIC_ORIGIN` | Yes | Public HTTPS origin, for example `https://vpn.example.com` |
| `ROUTEROS_REST_URL` | Yes | Private RouterOS REST base URL ending in `/rest` |
| `ROUTEROS_CA_FILE` | Yes | CA file used to verify RouterOS REST, recommended `/config/routeros-ca.crt` |
| `ROUTEROS_INSECURE_TLS` | Yes | Keep `false` in production |
| `DATABASE_PATH` | Yes | Persistent SQLite path, recommended `/data/dashboard.sqlite` |
| `APP_PORT` | No | Dashboard listener; defaults to `8080` |
| `REDIRECT_PORT` | No | HTTP redirect listener; defaults to `8081` |
| `DROP_PRIVILEGES` | Yes | Keep `true` so the app drops to an unprivileged UID/GID |
| `RUN_UID`, `RUN_GID` | No | Runtime identity; both default to `65534` |
| `TRUST_CLOUDFLARE` | Conditional | Enable only when every request reaches the app through the trusted origin proxy |
| `TRUSTED_PROXY_SOURCES` | Conditional | Comma-separated private source addresses allowed to set forwarded client headers |

## Image release model

Pull requests and pushes run compilation, secret-pattern checks, the complete test suite, and an ARM64 container build. A push to the default branch publishes private GHCR images only after the workflow's test job succeeds.

Published image tags include:

- `sha-<full-commit>` for immutable production rollouts and rollback;
- `edge` for operator inspection only;
- a Git tag when an explicit release tag is pushed.

Production should deploy the immutable full-commit `sha-` tag, never automatically follow `edge`. Attached SBOM/provenance manifests are disabled on the deployable image because RouterOS 7 does not document support for the resulting OCI indexes; enable them only after an isolated pull test on the installed RouterOS version. GitHub Actions receive only the minimum repository and package permissions required by each job.

`deploy_routeros_canary.py` is an offline plan renderer with no network or apply mode. It validates the full image commit, HTTPS origins, REST certificate SAN, RouterOS-safe names/paths, proxy sources, and an isolated canary subnet before printing commands for review. The old `update_routeros_app.py` filename remains only as a fail-closed tombstone: it exits without contacting RouterOS and explains the supported migration path.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the canary-first RouterOS procedure and [docs/ROLLBACK.md](docs/ROLLBACK.md) before the first production update.

## Contributing

Changes use pull requests, passing CI, and a human-reviewed production promotion. See [CONTRIBUTING.md](CONTRIBUTING.md). Security reports belong in a private GitHub security advisory as described in [SECURITY.md](SECURITY.md).

## License

Proprietary and confidential. See [LICENSE](LICENSE).
