# Security policy

## Supported code

Security fixes are applied to the current default branch. Historical commits and retired container images are not supported.

## Reporting a vulnerability

Do not include a vulnerability, credential, private key, access token, production hostname, or exploit trace in a normal issue.

Use the repository's **Security > Report a vulnerability** flow to open a private GitHub security advisory. Include:

- the affected commit or image digest;
- a concise description of impact and prerequisites;
- reproducible steps using mock or redacted data;
- a suggested mitigation, if known.

If private advisories are unavailable, ask a maintainer for a private reporting
channel without disclosing the vulnerability in a public issue.

There is no public bug-bounty program or guaranteed response SLA. Maintainers
will assess impact before publishing a fix.

## Sensitive material

Never commit or attach:

- RouterOS, OpenVPN, Cloudflare, or GitHub passwords and tokens;
- client or CA private keys, PKCS#12 archives, or generated OpenVPN bundles;
- populated `.env` files, SQLite databases, backups, or logs;
- production exports that contain addresses, account names, emails, or firewall policy;
- browser session data or screenshots containing credentials.

If a secret reaches Git history, revoke or rotate it first. Removing the file or rewriting the branch is not sufficient on its own.

See [docs/SECURITY.md](docs/SECURITY.md) for deployment hardening and incident containment.
