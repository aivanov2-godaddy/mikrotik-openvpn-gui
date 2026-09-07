# Contributing

Changes are accepted through focused pull requests. The project is public and
uses an issue → pull request → CI → squash-merge workflow for traceability.
Please follow the [Code of Conduct](CODE_OF_CONDUCT.md) in every project space.

## Workflow

1. Create a short-lived branch from the current default branch.
2. Keep the change focused; do not combine router policy changes with unrelated UI work.
3. Add or update tests for observable behavior.
4. Run the local verification commands below.
5. Update `CHANGELOG.md` when operator-visible behavior changes.
6. Open a pull request and complete the security and rollout checklist.
7. Merge only after required checks and review succeed.

```powershell
python -m pip install pre-commit
python -m pre_commit install
python -m pre_commit run --all-files
python scripts/check-secrets.py
python -m compileall -q app.py automation.py cloudflare.py deploy_routeros_canary.py deployment.py favicon.py icons.py qr.py routeros.py security.py store.py templates.py update_routeros_app.py
python -m unittest discover -s tests -v
```

## Engineering rules

- RouterOS remains the source of truth for VPN identities and active sessions.
- Never weaken TLS verification to solve a certificate problem.
- Do not log credentials, private keys, profile payloads, raw authorization headers, or QR hand-off contents.
- Treat user names, email addresses, addresses, usage, and audit events as sensitive operational data.
- Preserve `/data` compatibility or document and test the migration and rollback boundary.
- Keep destructive operations behind explicit confirmation and validate target identifiers against fresh RouterOS state.
- Prefer immutable image tags/digests. Never make a router follow a mutable tag automatically.
- Do not reintroduce host-mounted `/app` updates or direct source uploads to RouterOS.
- Do not add RouterOS, Cloudflare, or deployment credentials; a self-hosted
  runner; or an automatic router-deployment workflow to this public repository.

## Commit and pull-request scope

Use clear imperative commit subjects. A pull request should explain the problem, user-visible result, tests performed, security impact, deployment plan, and rollback plan. Screenshots must use mock or redacted data.
