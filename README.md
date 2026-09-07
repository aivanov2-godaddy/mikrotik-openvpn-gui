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

## Dashboard preview

The live dashboard was opened through Cloudflare Access and RouterOS
authentication to verify the navigation. These representative screenshots
show the menu structure and the main operator views with sample values; live
user details and addresses are intentionally omitted.

![MikroTik-style dashboard navigation](docs/screenshots/dashboard-navigation.svg)

![VPN dashboard sections](docs/screenshots/dashboard-sections.svg)

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
| `.github/workflows/` | CI, security analysis, and architecture-aware image publishing |
| `docs/` | Deployment, rollback, security, and operations runbooks |

## Get started

1. Check the [supported RouterOS platform requirements](docs/INSTALLATION.md#1-check-the-platform).
2. Run the offline [Installation Wizard](docs/INSTALL_WIZARD.md) and follow the [first-time installation guide](docs/INSTALLATION.md) to enable Container mode, create storage/networking, configure RouterOS REST trust, and start an immutable image.
3. Expose the dashboard safely with the [HTTPS and reverse-proxy guide](docs/EXPOSURE.md). Direct TLS, a normal DNS name, local-only access, and optional Cloudflare are supported.
4. Use the dashboard’s setup plan generator or [manual update guide](docs/DEPLOYMENT.md) for later image updates.

## Local verification

The project uses the Python standard library; no application dependencies need to be installed.

```powershell
python -m pip install pre-commit
python -m pre_commit install
python -m pre_commit run --all-files
python scripts/check-secrets.py
python -m compileall -q app.py automation.py cloudflare.py deploy_routeros_canary.py deployment.py favicon.py icons.py qr.py routeros.py security.py store.py templates.py update_routeros_app.py
python -m unittest discover -s tests -v
```

For a local UI backed by the bundled mock RouterOS service:

```powershell
python tests/run_mock_app.py --port 18080
```

Then open `http://127.0.0.1:18080`. The mock does not contact a router or Cloudflare account.

## Install on a new MikroTik

For the supported platform matrix, Container package and device-mode setup,
persistent storage, first image pull, HTTPS exposure, validation, and
GitHub-driven updates, follow [First-time MikroTik installation](docs/INSTALLATION.md).
ARM64 is the supported RouterOS production target; validate the exact RouterOS
release and hardware with an isolated canary before promotion.

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
| `OVPN_PPP_PROFILE` | Yes for profile issuing | Existing RouterOS PPP profile for new OpenVPN users |
| `OVPN_SERVER_NAME` | Yes for profile issuing | Existing RouterOS OpenVPN server name |
| `OVPN_CA_NAME` | Yes for profile issuing | Existing RouterOS CA used to sign client certificates |
| `OVPN_HOST` | Yes for profile issuing | Public OpenVPN DNS name or IP written into device profiles |
| `OVPN_SERVER_IDENTITY` | No | Certificate identity verified by profiles; defaults to `OVPN_HOST` |
| `VPN_LAN_CIDR` | Yes for LAN/full-tunnel profiles | IPv4 LAN route included in generated profiles |
| `VPN_ROUTER_DNS` | Yes for RouterOS-DNS profiles | Router DNS server written into generated profiles |
| `DASHBOARD_NAME`, `ROUTER_DISPLAY_NAME` | No | Optional presentation labels; generic defaults are used |

The image includes only safe local defaults and does not infer an OpenVPN topology. Read-only router status remains available without the `OVPN_*` settings, but create-user, duplicate-user, and add-device actions fail closed until the topology values are configured in the RouterOS container environment list.

## Image release and deployment model

Pull requests and pushes run compilation, secret-pattern checks, the complete test suite, pre-commit hooks, and readiness/revision smoke tests for ARM64 and AMD64 images. A merge to the default branch publishes GHCR images only after verification succeeds. The unsuffixed full-commit tag remains an ARM64 compatibility alias for the validated RouterOS target.

RouterOS labels its 32-bit devices as `arm`, but its container documentation calls out ARM32/ARMv5 compatibility; it does not establish ARMv7 compatibility. This project therefore does **not** publish an `arm` image tag. ARM64 is the only RouterOS target validated in production. AMD64 is published for x86/CHR evaluation and must be canary-tested on the exact RouterOS release before use. A future `arm` image will be added only after it is built for and verified on a real ARM32 RouterOS target.

Published image tags include:

- `sha-<full-commit>` for immutable production rollouts and rollback;
- `edge` for operator inspection only;
- a Git tag when an explicit release tag is pushed.

Production deploys the immutable full-commit `sha-` tag, never the mutable `edge` tag. Deployment is manual by default and requires an explicit `DEPLOY` confirmation in the protected **Deploy production to RouterOS** workflow. After a recorded canary and rollback validation, an owner may set `ENABLE_ROUTEROS_AUTODEPLOY=true` as a repository variable to opt into same-repository default-branch automation. Forks never inherit an owner router path or credentials. The deployer stops the existing container, asks RouterOS to update its configured image, starts it, waits for a running state, and restores the previous image automatically if an update or start gate fails. It never changes mounts, environment lists, interfaces, firewall rules, or persistent data. The workflow requires a protected `production` environment with the five RouterOS secrets documented in [DEPLOYMENT.md](docs/DEPLOYMENT.md). Attached SBOM/provenance manifests are disabled on the deployable image because RouterOS 7 does not document support for the resulting OCI indexes; enable them only after an isolated pull test on the installed RouterOS version. GitHub Actions receive only the minimum repository and package permissions required by each job.

`/healthz` is a process-liveness check. `/readyz` adds a cached SQLite quick-check and writable transaction that is rolled back, and reports the full revision baked into the image. Promotion separately performs a full integrity check against the stopped checkpoint and requires the `/readyz` revision to match the selected workflow commit.

`deploy_routeros_canary.py` is an offline plan renderer with no network or apply mode. It validates the full image commit, HTTPS origins, REST certificate SAN, RouterOS-safe names/paths, proxy sources, and an isolated canary subnet before printing commands for review. The old `update_routeros_app.py` filename remains only as a fail-closed tombstone: it exits without contacting RouterOS and explains the supported migration path.

See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) for the one-time automation setup, private runner boundary, canary procedure, and rollback gates. The workflow is intentionally fail-closed until its production secrets and private REST path are configured. Even then, it remains manual unless the repository owner deliberately completes the documented automatic-deployment opt-in.

## Contributing

Changes use pull requests and passing CI. A merge to `main` publishes immutable architecture-specific images; production deployment is a separate protected opt-in action. See [CONTRIBUTING.md](CONTRIBUTING.md) and [the release contract](docs/RELEASES.md). Security reports belong in a private GitHub security advisory as described in [SECURITY.md](SECURITY.md).

The planned public releases are tracked in [docs/ROADMAP.md](docs/ROADMAP.md).

## License

Proprietary and confidential. See [LICENSE](LICENSE).
