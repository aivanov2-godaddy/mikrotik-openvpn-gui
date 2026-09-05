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

Use a protected `production` environment if a future workflow performs deployment. Require an owner review and allow only the default branch. Image publication alone does not need RouterOS or Cloudflare credentials.

## First-run checklist

1. Push the sanitized repository.
2. Verify all configured CI checks complete. If GitHub Advanced Security is later enabled, add the CodeQL workflow and require its successful check.
3. Merge or manually run **Publish container** on the default branch.
4. Open the package and confirm private visibility, source-repository linkage, ARM64 platform, full-commit tag, and manifest digest.
5. Apply the branch ruleset using the check names from the successful run.
6. Create an expiring `read:packages` pull token and follow [DEPLOYMENT.md](DEPLOYMENT.md).
