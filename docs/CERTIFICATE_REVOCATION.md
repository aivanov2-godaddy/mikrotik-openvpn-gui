# Certificate revocation migration

RouterOS can reject a revoked OpenVPN client certificate only when all of the
following are true:

1. the OpenVPN CA has a Certificate Revocation List (CRL) distribution point;
2. the active CA either has a RouterOS-hosted CRL endpoint or RouterOS can
   obtain a current downloaded CRL for that exact CA;
3. CRL download and use are enabled; and
4. the list is retained in persistent RouterOS storage.

The dashboard deliberately reports a warning unless it can verify all four
conditions. Enabling `crl-use` by itself is not a fix: on a router with a CA
that has no CRL endpoint, it can reject otherwise valid certificate chains.

## Before you begin

This is a certificate-authority migration. It changes the server certificate
trusted by every OpenVPN profile, so schedule it and distribute replacement
profiles before the server cutover. Never alter or delete the existing CA until
the new profiles have connected successfully and the rollback window has ended.

- Export a non-sensitive RouterOS configuration checkpoint and back up the
  dashboard `/data` mount.
- Record the existing OVPN server, CA, server certificate, PPP profile and
  client certificate names.
- Keep the current CA, server certificate and OpenVPN server enabled through
  the preparation phase.
- Use a dedicated CRL-only HTTP publication path. RouterOS renews downloaded
  CRLs over HTTP, not HTTPS.

The router's built-in web server supports a CRL-only mode. Disable its index,
WebFig, graph, REST, SCEP and ACME sub-services when using it solely for this
purpose; do not expose management services just to publish a CRL.

### RouterOS 7.24 endpoint check

When a CA is signed with `ca-crl-host=<router-address>`, RouterOS embeds a
versioned URL such as `http://router.example.test/crl/227.crl` in the **CA
certificate**. The numeric suffix is derived from RouterOS' internal
certificate ID; it is not the row number shown by `/certificate print`. Do not
guess it. Export the public CA certificate and inspect its CRL Distribution
Points extension to obtain the exact URL:

```routeros
/certificate/export-certificate <new-ca> file-name=<new-ca-public>
```

```sh
openssl x509 -in <new-ca-public>.crt -noout -text
```

The URL must return a non-empty DER or PEM CRL over plain HTTP. Validate it
from a **separate management-network host** with a browser or `curl`. A
RouterOS `/tool fetch` request to the router's own address is useful only as a
supplementary check: some RouterOS service/firewall combinations reject that
self-fetch even when an independent LAN request succeeds. Conversely, a
successful self-fetch does not prove that another verifier can reach the URL.

If an independent LAN check fails, open **IP → Services → Web server
properties** in WebFig and confirm the
plain-HTTP CRL service is enabled (`crl-plain=yes`) and that the `www`
service's `available-from` list permits the validator. Keep WebFig, REST and
the index disabled on any CRL-only listener. On RouterOS builds that do not
expose the web-server property in the CLI, use WebFig or upgrade to a current
stable build before proceeding; do not mark the migration healthy based only
on the CA's `L` flag.

Only after the URL returns a CRL should you continue with the staged
revocation test. Do not enable `crl-use=yes` merely because a replacement CA
is ready: this RouterOS setting is global. Keep it disabled during preparation
if the currently active OpenVPN CA has no working CRL distribution point.

## Staged procedure

1. Choose a CRL URL reachable from the router. A loopback-restricted endpoint
   is appropriate when only this RouterOS device validates OpenVPN clients;
   use a dedicated protected HTTP hostname when other validators need it.
2. Create and sign a *new* CA with `ca-crl-host=<CRL host>`. The CRL endpoint
   is embedded while signing and cannot be retrofitted into the existing CA.
3. Create a replacement server certificate and a test client certificate from
   the new CA. Do not point the live OVPN server at it yet.
4. Enable `crl-download=yes` and `crl-store=system`. For a CA signed on
   RouterOS with `ca-crl-host`, confirm the CA shows the `L` flag in
   Terminal/WinBox and a non-empty `ca-crl-host`; it is normal for
   `/certificate/crl/print` to list only downloaded CRLs, not this local CRL.
5. Revoke the disposable test certificate and verify that the published CRL
   contains its serial number. Keep a separate non-revoked test certificate to
   prove normal authentication later.
6. Generate replacement profiles for every user from the new CA and have them
   install the replacements while the old server certificate remains live.
7. In the maintenance window, point the OVPN server at the replacement server
   certificate, switch the dashboard's router-local `OVPN_CA_NAME` to the new
   CA, then enable `crl-use=yes`. Validate that the revoked test profile is
   rejected and the non-revoked test profile succeeds. Restart only the
   dashboard container(s) through the canary-first deployment process.
8. Verify the dashboard reports **Certificate revocation checks — Healthy**.
   Retain the old chain for the documented rollback window before retiring it.

## Verification commands

Run these in RouterOS Terminal, substituting only router-local names:

```routeros
/certificate/settings/print
/certificate/print detail where name=<new-ca>
/certificate/print where akid=<new-ca-skid>
/interface/ovpn-server/server/print
```

The expected healthy state includes `crl-download: yes`, `crl-use: yes`,
`crl-store: system`, and either a trusted `<new-ca>` with a non-empty
`ca-crl-host` and `L` flag, or a non-expired downloaded CRL record for it.

## Rollback

If the replacement server certificate or profile authentication fails:

1. point the OVPN server back to the previous server certificate;
2. restore the prior router-local `OVPN_CA_NAME` in the container environment;
3. deploy the previous immutable dashboard image only if the new dashboard
   release itself is implicated; and
4. leave the replacement CA and CRL endpoint in place for inspection rather
   than deleting evidence.

Do not disable CRL enforcement merely to hide a verification failure.
