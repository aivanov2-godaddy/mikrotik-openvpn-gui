# Getting started: install on a MikroTik router

This is the newcomer path for installing MikroTik OpenVPN GUI on a supported
RouterOS router. It assumes no prior experience with this project. Every name,
address, and hostname below is an example: replace it before applying a
command.

> [!IMPORTANT]
> Do not paste a whole guide into a live router at once. Create a backup,
> change one section at a time, and confirm the expected result before moving
> on. The container is a management application; RouterOS remains the source
> of truth for VPN users, certificates, and traffic policy.

![Deployment path](screenshots/deployment-architecture.svg)

## Choose your path

| Your goal | Choose | Result |
| --- | --- | --- |
| A public dashboard at `https://vpn.example.com`, Cloudflare Access/WAF, or a normal browser-trusted certificate | [Scenario A — domain + HTTPS + optional Cloudflare](INSTALLATION_PLAYBOOK.md#scenario-a-domain-https-and-optional-cloudflare) | Recommended public setup |
| No domain for OpenVPN; users connect to a public IP | [Scenario B — IP-only OpenVPN](INSTALLATION_PLAYBOOK.md#scenario-b-ip-only-openvpn-and-a-secure-dashboard) | OpenVPN can use an IP; dashboard still needs private or valid HTTPS access |
| A router that has no existing OpenVPN configuration | [OpenVPN foundations](INSTALLATION_PLAYBOOK.md#new-router-create-an-openvpn-foundation-plan) | A review-only plan; it never auto-configures the VPN |

## What this project installs—and what it deliberately does not

| Component | Installed/configured by | Why |
| --- | --- | --- |
| Dashboard application | RouterOS Container | The public GHCR image is pinned to an immutable Git commit |
| SQLite data and public RouterOS CA | Router-local mounts | Data stays on the router across image changes |
| RouterOS REST service and certificate | Router operator | The application verifies RouterOS TLS; it never receives a router private key |
| VPN server, CA, PPP profile, firewall and NAT | Existing router setup or reviewed foundation plan | These are network-security decisions, not silent installer defaults |
| Browser HTTPS, Cloudflare DNS/Access, reverse proxy | Your perimeter | The dashboard image serves HTTP only on its private container network |

The offline installation wizard helps produce a reviewable RouterOS script from
non-secret values. It does **not** log into a router, create Cloudflare records,
accept passwords or tokens, configure TLS/firewalls, copy certificates, start a
container, or send data anywhere.

## Before opening the detailed guide

Have these ready:

- A RouterOS 7 **arm64** router with enough RAM and external storage. `amd64`
  is only for separately tested CHR/x86 evaluation; RouterOS `arm` is not
  supported by this image.
- A maintenance window and local/physical access for enabling Container mode.
- An existing OpenVPN server, PPP profile, and CA **or** time to carefully
  review the opt-in foundation plan after the dashboard is running.
- An unused RFC1918 container subnet, such as `172.31.250.0/24`.
- For Scenario A: a domain you control and, optionally, a Cloudflare account.
- For Scenario B: a plan to trust the dashboard's TLS certificate on every
  administrator device. Public plaintext HTTP is not supported.

Continue with the complete [step-by-step installation playbook](INSTALLATION_PLAYBOOK.md).
