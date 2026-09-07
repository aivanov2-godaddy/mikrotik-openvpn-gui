# First-time MikroTik installation

This guide installs the VPN Dashboard container on a new RouterOS device. It is deliberately separate from the automated production rollout in [DEPLOYMENT.md](DEPLOYMENT.md): complete this guide once, then let GitHub Actions publish and deploy later changes.

## Support matrix

| Requirement | Supported target |
| --- | --- |
| RouterOS | RouterOS 7; validated in production on 7.24.2 |
| CPU | `arm64` (the validated RouterOS container target) |
| Known-good device | MikroTik RB5009UPr+S+ |
| Container package | Installed and enabled |
| Device mode | `container=yes` |
| Storage | External disk strongly recommended; reserve space for two image roots, temporary extraction, and SQLite data |
| Network | An unused container subnet, DNS, and outbound HTTPS to GHCR |

Other ARM64 MikroTik models may work if they have the Container package and adequate storage/RAM. The project also publishes an `amd64` image for x86/CHR evaluation, but it is not production-validated. RouterOS labels its 32-bit devices as `arm`; MikroTik's container documentation calls out ARM32/ARMv5 compatibility, so this project intentionally does not publish an `arm` (ARMv7) image. Other architectures remain outside this installation guide until a matching RouterOS container pull and runtime validation has been completed.

## Before you start

Create an encrypted RouterOS backup and export a redacted configuration. Perform package installation and device-mode changes during a maintenance window: enabling device-mode requires a physical confirmation and reboots the router. Use a dedicated least-privilege RouterOS account for the dashboard and deployment runner; do not use the owner password in automation.

Before onboarding users, record the existing OpenVPN PPP profile name, OpenVPN server name, certificate authority name, public OpenVPN hostname or IP, LAN CIDR, and RouterOS DNS address. These are configured per installation through the container environment list; the image does not assume any particular topology.

## 1. Confirm version and architecture

In WinBox open **System → Resources** and note **Architecture Name**. The published images use explicit tags: `arm64` for the validated ARM64 target and `amd64` for x86/CHR evaluation. Do not use an ARMv7 image for a RouterOS `arm` device: MikroTik documents ARM32/ARMv5 constraints for that target, and this project does not publish an ARM image until it has been verified there. In **System → Packages**, record the exact RouterOS version. From New Terminal:

```routeros
/system/resource/print
/system/package/print
```

Use a Container package with the exact same RouterOS version and architecture. Do not mix packages from another release.

## 2. Install the Container package

On RouterOS 7.18 and newer, open **System → Packages → Check for Updates**. Select the disabled `container` extra package, choose **Enable**, then **Apply Changes** and reboot. Verify:

```routeros
/system/package/print where name="container"
```

If the package is not offered, download the matching `container-<version>-<architecture>.npk` from MikroTik's [Packages](https://help.mikrotik.com/docs/spaces/ROS/pages/40992872/Packages) page, upload it with **WinBox → Files**, reboot, and run the verification command again. A package for the wrong architecture or RouterOS version will not work.

## 3. Enable Container device-mode

RouterOS 7.17+ Advanced mode disables containers by default. Check the feature state:

```routeros
/system/device-mode/print
```

If it shows `container: no`, request enablement:

```routeros
/system/device-mode/update container=yes
```

Within the displayed confirmation window (normally five minutes), press the router's reset/mode button or perform a cold power-cycle as RouterOS requests. The router reboots. After it returns, verify `container: yes`. This physical-presence step is intentional; it prevents remote-only activation of a powerful feature. ROSE mode may already include containers, but still verify the state.

## 4. Prepare storage and container networking

Use an external disk for `/container` roots, temporary extraction, and persistent application data. The exact disk name is device-specific. Create directories on that disk and ensure they are writable by RouterOS.

The following example uses an isolated subnet; replace it if it overlaps your LAN, VPN, or an existing container network. Do not duplicate the production topology blindly:

```routeros
/interface/bridge/add name=containers
/interface/veth/add name=veth-vpn-dashboard address=172.31.255.2/24 gateway=172.31.255.1
/ip/address/add address=172.31.255.1/24 interface=containers
/interface/bridge/port/add bridge=containers interface=veth-vpn-dashboard
/ip/firewall/nat/add chain=srcnat action=masquerade src-address=172.31.255.0/24
```

The application listens on container port `8080`; its redirect listener is `8081`. Keep the container network private and expose it through the existing reverse proxy, not by forwarding RouterOS management services to the internet.

## 5. Prepare RouterOS HTTPS REST and OpenVPN

Enable only `www-ssl` for management, keep `www` disabled, and restrict the service and firewall to the private management runner and approved operator sources. The REST URL must end in `/rest`, for example `https://router.example.invalid:8443/rest`.

Install a RouterOS HTTPS certificate whose Subject Alternative Name matches the REST hostname exactly. Export only the public CA certificate to the container's configuration directory; never export a private key. Confirm the OpenVPN server, PPP profile, CA, public endpoint, DNS, and LAN route that you recorded above. The dashboard does not replace RouterOS as the VPN source of truth.

## 6. Configure private GHCR access

The package is private. Create an expiring GitHub classic token with only `read:packages` and grant it access to this repository's package. Store it only in RouterOS's sensitive container configuration; never place it in Git, an issue, a workflow file, or a screenshot.

```routeros
/container/config/set registry-url=https://ghcr.io username="<github-user>" password="<read-packages-token>" tmpdir="<external-disk>/containers/tmp"
```

RouterOS resolves `remote-image` relative to this registry URL. Therefore use `aivanov2-godaddy/mikrotik-openvpn-gui:sha-<full-commit-sha>-<architecture>`, not a `ghcr.io/...`-prefixed value. For the production RB5009 ARM64 deployment, the legacy `sha-<full-commit-sha>` tag remains an ARM64 alias and is safe to keep using. Commit tags are immutable deployment references; do not use `edge` in production.

## 7. Create mounts and environment lists

Create separate persistent directories for SQLite data and configuration (including the public RouterOS CA):

```routeros
/container/mounts/add list=vpn-dashboard-mounts src="<external-disk>/vpn-dashboard/data" dst=/data
/container/mounts/add list=vpn-dashboard-mounts src="<external-disk>/vpn-dashboard/config" dst=/config
```

Create an environment list with these values:

```text
PUBLIC_ORIGIN=https://vpn.example.com
ROUTEROS_REST_URL=https://<router-rest-host>:8443/rest
ROUTEROS_CA_FILE=/config/routeros-ca.crt
ROUTEROS_INSECURE_TLS=false
DATABASE_PATH=/data/dashboard.sqlite
APP_PORT=8080
REDIRECT_PORT=8081
DROP_PRIVILEGES=true
TRUST_CLOUDFLARE=true
TRUSTED_PROXY_SOURCES=<approved-proxy-sources>
OVPN_PPP_PROFILE=<existing-ppp-profile>
OVPN_SERVER_NAME=<existing-openvpn-server>
OVPN_CA_NAME=<existing-certificate-authority>
OVPN_HOST=ovpn.example.com
# Optional when it equals OVPN_HOST:
OVPN_SERVER_IDENTITY=
VPN_LAN_CIDR=192.0.2.0/24
VPN_ROUTER_DNS=192.0.2.1
DASHBOARD_NAME=MikroTik OpenVPN GUI
ROUTER_DISPLAY_NAME=RouterOS
```

Keep `ROUTEROS_INSECURE_TLS=false` in production. `TRUST_CLOUDFLARE` is safe only when every request reaches the app through a trusted Cloudflare/reverse-proxy path. The `OVPN_*`, `VPN_LAN_CIDR`, and `VPN_ROUTER_DNS` values are required before the dashboard can create a user or issue a profile; the dashboard fails closed until they are present.

## 8. Add and start the first container

Choose the full SHA from a successful **Publish container** workflow run. Check the package digest and visibility before pulling. Then add the container (replace placeholders with reviewed, device-specific paths):

```routeros
/container/add name=vpn-dashboard remote-image=aivanov2-godaddy/mikrotik-openvpn-gui:sha-<full-commit-sha> interface=veth-vpn-dashboard root-dir="<external-disk>/vpn-dashboard/root" mountlists=vpn-dashboard-mounts envlists=vpn-dashboard-env start-on-boot=yes logging=yes
/container/print detail
```

RouterOS downloads and extracts the image during `add`; it does not necessarily start it automatically. Wait until extraction completes, then start it:

```routeros
/container/start vpn-dashboard
/container/print detail
```

The expected state is `status=running`, `healthy=true`, and a successful health check. The container's `/healthz` endpoint is liveness; `/readyz` also checks SQLite integrity and reports the image revision.

## 9. Publish the HTTPS dashboard

Keep the container address private. Configure the existing reverse proxy or RouterOS web proxy so your `PUBLIC_ORIGIN` terminates TLS on port 443 and proxies to the container's `8080`; redirect port 80 to HTTPS. Cloudflare may provide the public certificate and country/access policy, but it must not proxy RouterOS REST or OpenVPN UDP traffic. Never expose the container or REST endpoint directly to the public internet.

## 10. Validate the installation

From the private management network, verify the health endpoints and browser flow:

```powershell
curl.exe -fsS http://<container-ip>:8080/healthz
curl.exe -fsS http://<container-ip>:8080/readyz
```

Then open the configured `PUBLIC_ORIGIN`, authenticate through the configured perimeter and RouterOS credentials, confirm the router status is online, inspect **VPN Users** and **Active Sessions**, create a test profile, and verify download/QR onboarding. Finally confirm `start-on-boot=yes` and that the container survives a controlled reboot.

## 11. Enable GitHub-driven updates

After the first install, follow [DEPLOYMENT.md](DEPLOYMENT.md) and [REPOSITORY_SETUP.md](REPOSITORY_SETUP.md): configure the protected `production` environment, the five RouterOS secrets, and the repository-scoped Windows runner labeled `routeros-private`. A merge to `main` runs CI, publishes private ARM64 and AMD64 images with architecture-specific immutable tags, and preserves the unsuffixed ARM64 tag used by production. The deployment workflow updates only that immutable ARM64 reference and automatically restores the previous image if update or startup gates fail.

## Troubleshooting

| Symptom | Check |
| --- | --- |
| `container` package missing | Architecture/version match; install the extra package and reboot |
| Device-mode refuses enablement | Run `/system/device-mode/update container=yes` again and complete the physical confirmation window |
| Architecture error during pull | Confirm the router's `architecture-name`; use `arm64` only on the validated ARM64 target or `amd64` only for a tested x86/CHR evaluation. Do not substitute an ARMv7 image for RouterOS `arm`. |
| GHCR `auth error` | Token is classic, has `read:packages`, and can read the private package; check `/container/config` without exposing the token |
| Manifest not found | Use registry-relative `owner/repo:sha-<fullsha>` and keep `registry-url=https://ghcr.io` |
| Extraction fails | Move roots and `tmpdir` to external storage and check free space |
| REST TLS failure | URL hostname must match the certificate SAN; mount the signing CA at `/config/routeros-ca.crt` |
| 502 or blinking UI | Check proxy target/ports, container `running` state, `/healthz`, and `/readyz` |
| Dashboard cannot manage VPN | Verify REST reachability, RouterOS permissions, and the expected OpenVPN object names/subnet |

For rollback, stop the container and restore the prior immutable `sha-<fullsha>` image as documented in [ROLLBACK.md](ROLLBACK.md). Keep the persistent `/data` directory unchanged.

## Official references

- [MikroTik Container](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container)
- [MikroTik Device-mode](https://help.mikrotik.com/docs/spaces/ROS/pages/93749258/Device-mode)
- [MikroTik Packages](https://help.mikrotik.com/docs/spaces/ROS/pages/40992872/Packages)
- [GitHub Container registry](https://docs.github.com/en/packages/working-with-a-github-packages-registry/working-with-the-container-registry)
- [GitHub package permissions](https://docs.github.com/en/packages/learn-github-packages/about-permissions-for-github-packages)
