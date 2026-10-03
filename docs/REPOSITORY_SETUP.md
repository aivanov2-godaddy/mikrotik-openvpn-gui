# Public repository maintenance

This document describes the recommended GitHub configuration for a public fork
or organization repository. It intentionally excludes router credentials,
deployment runners, and production infrastructure.

## Repository settings

| Setting | Recommended value |
| --- | --- |
| Visibility | Public |
| Default branch | `main` |
| Merge method | Squash merge |
| Delete head branches | Enabled |
| Issues | Enabled |
| Discussions / wiki / projects | Enable only if actively maintained |
| Actions default permission | Read repository contents |
| Workflow pull-request approval | Disabled |
| GHCR package | Public only if the project intends anonymous RouterOS pulls |

## Branch protection

The versioned desired configuration for this repository is
[`../.github/rulesets/protect-main.json`](../.github/rulesets/protect-main.json).
It requires a pull request and all nine named CI checks, blocks deletion and
force pushes, and allows squash merges without requiring a human approval. The
CI workflow runs on pull requests (and manual dispatch), not branch pushes, so
each PR has one unambiguous set of required checks. There are no bypass actors.

This file records the intended configuration; it does not apply itself. Apply
it to the repository's `Protect main` ruleset with GitHub's ruleset API, then
read the ruleset back and confirm `enforcement` is `active` and the required
contexts match. Do not say protection is enabled until that read-back succeeds.
After changing CI job names, update the required contexts and verify them on a
real PR before merging.

## Community health

Keep these files at the repository root or under `.github/`:

- `README.md` for quick start and supported platforms;
- `LICENSE` with the Apache-2.0 terms;
- `CONTRIBUTING.md` and a pull-request template;
- `SECURITY.md` with a private disclosure route;
- issue templates for bugs and feature requests;
- `CHANGELOG.md` and `docs/RELEASES.md` for release records.

Enable Dependabot alerts and updates, secret scanning, push protection, and
private vulnerability reporting where the account plan supports them. Review
dependabot pull requests like any other change.

## CI and packages

The included CI verifies pre-commit hooks, committed secret patterns, dependency
vulnerabilities, Python tests, Redis recovery, Socket.IO origin enforcement,
rendered browser accessibility/regressions, and a RouterOS-relevant ARM64 image
build. The image workflow publishes only after its verification job succeeds.
It receives `packages: write` only in the publishing job; no workflow has access
to router, Cloudflare, or deployment credentials.

Do not configure a self-hosted runner that can reach a router in this public
repository. If you automate an operator deployment, put the automation and
secrets in a separate private repository, require manual production approval,
and use a dedicated least-privilege RouterOS account.

## Release workflow

1. Open an issue for the intended change.
2. Create a short-lived branch and focused pull request.
3. Run the local checks from [CONTRIBUTING.md](../CONTRIBUTING.md).
4. Merge only after CI and review complete.
5. Verify the published image digest.
6. Validate on an operator-controlled canary outside GitHub Actions.
7. Update the operator's router using [DEPLOYMENT.md](DEPLOYMENT.md).
