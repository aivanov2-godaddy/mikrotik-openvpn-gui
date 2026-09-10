# Installation Wizard

The installation wizard is an offline command-line helper for a first-time
RouterOS deployment. It does not contact a router, log in, store answers, read
configuration exports, create a Cloudflare record, or apply commands. Its only
output is a reviewable RouterOS script built from non-secret values you supply.

## Before running it

Complete the manual safety gates in [INSTALLATION.md](INSTALLATION.md): make a
backup, verify the RouterOS version and architecture, install the matching
Container package, enable `container=yes` with physical confirmation, prepare
external storage, and decide the container subnet and HTTPS/reverse-proxy path.

Never provide a RouterOS password, package token, Cloudflare token, private key,
or a configuration export to this command.

## Interactive use

Run the prompt-driven wizard from a clone of the repository:

```powershell
python install_routeros.py --interactive --output routeros-install.rsc
```

It asks for the GitHub owner and immutable commit, supported architecture,
dashboard/REST TLS names, storage path, container network, existing OpenVPN
objects, and VPN network settings. The default public repository is
`mikrotik-openvpn-gui`. Use `arm64` for the validated RouterOS target or
`amd64` only for a separately tested CHR/x86 installation. RouterOS `arm` is
not supported.

## Non-interactive use

Automation can supply the same non-secret choices explicitly:

```powershell
python install_routeros.py `
  --owner <github-owner> `
  --commit <40-character-commit> `
  --architecture arm64 `
  --public-origin https://vpn.example.com `
  --routeros-rest-url https://router.example.com:8443/rest `
  --routeros-rest-san router.example.com `
  --external-root disk1/vpn-dashboard `
  --bridge containers `
  --container-address 172.31.250.2/24 `
  --gateway 172.31.250.1 `
  --ovpn-ppp-profile vpn-full-tunnel `
  --ovpn-server-name vpn-server `
  --ovpn-ca-name vpn-ca `
  --ovpn-host ovpn.example.com `
  --vpn-lan-cidr 192.168.88.0/24 `
  --vpn-router-dns 192.168.88.1 `
  --output routeros-install.rsc
```

The wizard rejects unsafe RouterOS names and paths, quotes/control characters,
non-HTTPS public/REST origins, REST certificate-SAN mismatches, bad SHA tags,
unsupported architectures, invalid gateway/subnet pairs, and incomplete
OpenVPN topology.

## Review and apply manually

Open the generated script in a text editor. Confirm every name, address, path,
and route against the live router. Copy the verified RouterOS REST CA into the
planned `/config` source directory, then paste commands manually in WinBox or
New Terminal. Do not start the dashboard until container extraction and logs
have been inspected.

After starting it, follow the [validation checklist](INSTALLATION.md#10-validate-the-installation). For later image changes, use [DEPLOYMENT.md](DEPLOYMENT.md).

## Optional OpenVPN foundations plan

The dashboard's **Setup Planner → OpenVPN foundations** form is separate from
this compact installer. Use it only for a supported router that has no existing
OpenVPN server. It reads the current RouterOS inventory and refuses to generate
a plan if it would overlap an existing OpenVPN server, PPP profile, or named
certificate.

Its output is still review-only: it creates a RouterOS export checkpoint first,
then shows commands for a CA, server certificate, client-address pool, PPP
profile, disabled OpenVPN server, and disabled firewall rule. Firewall ordering
and WAN source-NAT are topology-specific, so they remain an explicit operator
review before the server is enabled. This preserves the normal fast install
experience for already-configured routers.
