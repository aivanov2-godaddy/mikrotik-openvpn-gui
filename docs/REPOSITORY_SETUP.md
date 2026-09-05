# GitHub repository settings

Apply these settings after creating the repository. They are documentation, not claims that a setting has already been enabled.

## Properties

| Setting | Value |
| --- | --- |
| Owner | `aivanov2-godaddy` |
| Repository | `mikrotik-openvpn-gui` |
| Display title | MikroTik OpenVPN GUI |
| Visibility | Private |
| Description | Private RouterOS OpenVPN user, device-profile, and session management dashboard |
| Default branch | `main` |
| Topics | `mikrotik`, `routeros`, `openvpn`, `vpn-dashboard`, `python`, `arm64`, `ghcr` |

Keep Issues enabled for authorized collaborators. Disable Wiki, Discussions, and Projects unless they are intentionally adopted and maintained. Do not initialize the remote with generated files when pushing this prepared history.

## Default-branch ruleset

GitHub currently reports that branch protection and rulesets are not enforced for this private personal-account repository. Treat the controls below as the required target state if the repository moves to a GitHub Team or Enterprise organization; do not describe them as active before GitHub confirms enforcement.

- Require a pull request before merge.
- Require at least one approving review and dismiss stale approvals.
- Require review from Code Owners.
- Require all conversations to be resolved.
- Require the CI secret-pattern scan, test matrix, and ARM64 build after their first successful run exposes the exact check names.
- Block force pushes and branch deletion.
- Require linear history if the team uses squash/rebase merging.
- Limit bypass to the repository owner and reserve it for documented incidents.

Avoid guessing required-check names before the first workflow run; GitHub rulesets can select only checks the repository has reported.

## Actions and packages

- Set workflow permissions to **Read repository contents** by default.
- Do not allow Actions to approve pull requests.
- Allow the GitHub-owned actions and the pinned Docker actions used in this repository.
- Keep the GHCR package private and inherit access from this repository.
- Retain immutable commit-tagged packages needed for current production and rollback.
- Do not expose the package publicly merely to avoid configuring a read-only pull token.

## Security settings

Enable where available:

- private vulnerability reporting;
- Dependabot alerts and security updates;
- secret scanning and push protection;
- code scanning with CodeQL, when GitHub Advanced Security is enabled for the private repository;
- automatic deletion of head branches after merge.

Use a protected `production` environment for the post-merge RouterOS deployment workflow. Require an owner review when the repository plan supports environment approvals and allow only the default branch. Image publication alone does not need RouterOS or Cloudflare credentials.

Create these environment secrets; never put them in repository variables, workflow files, or commit history:

| Secret | Purpose |
| --- | --- |
| `ROUTEROS_REST_URL` | HTTPS RouterOS REST base URL ending in `/rest` |
| `ROUTEROS_DEPLOY_USERNAME` | Dedicated least-privilege RouterOS deployment account |
| `ROUTEROS_DEPLOY_PASSWORD` | Password for that account |
| `ROUTEROS_CONTAINER_NAME` | Exact production container name (not a mutable image tag) |
| `ROUTEROS_REST_CA_B64` | Base64-encoded public CA certificate that signs the REST server certificate |

GitHub-hosted runner egress addresses are dynamic. Do not broadly allow GitHub's published ranges on RouterOS. The repository workflow targets a repository-scoped Windows runner with labels `self-hosted`, `Windows`, `X64`, and `routeros-private`; install it on a patched management workstation that can reach the private REST URL, and allow only that workstation in the RouterOS service and firewall rules. Keep the runner online only for this repository and do not run untrusted workflows on it. A narrowly scoped, authenticated deployment relay is the approved fallback. The workflow fails closed when any secret is missing or the REST certificate cannot be verified.

### Windows management runner

From the repository's **Settings → Actions → Runners → New self-hosted runner** page, download the current Windows x64 runner and verify the SHA-256 shown by GitHub. Configure it with the one-time registration token and the labels above, then keep the listener running from the runner directory. Do not paste the token into the repository, a workflow, a ticket, or shell history. If the workstation restarts, start `run.cmd` again (or install it using the runner's documented Windows service mode) and confirm the runner is **Idle** before testing a deploy.

## First-run checklist

1. Push the sanitized repository.
2. Verify all configured CI checks complete. If GitHub Advanced Security is later enabled, add the CodeQL workflow and require its successful check.
3. Merge or manually run **Publish container** on the default branch.
4. Open the package and confirm private visibility, source-repository linkage, ARM64 platform, full-commit tag, and manifest digest.
5. Apply the branch ruleset using the check names from the successful run.
6. Configure the protected `production` environment secrets above and run **Deploy production to RouterOS** manually with a known immutable commit as a connectivity test.
7. Confirm the run was assigned to the `routeros-private` runner and that RouterOS reports the requested immutable image and a healthy/running container.
8. Create an expiring `read:packages` pull token and follow [DEPLOYMENT.md](DEPLOYMENT.md).
