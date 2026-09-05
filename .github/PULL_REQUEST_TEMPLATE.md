## Result

Describe the operator-visible outcome and why the change is needed.

## Validation

- [ ] `python scripts/check-secrets.py`
- [ ] Python compilation completed
- [ ] Unit and mock RouterOS integration tests passed
- [ ] ARM64 image build passed, when container/runtime files changed
- [ ] UI checked at relevant desktop and mobile sizes, when presentation changed

## Security and privacy

- [ ] No credentials, tokens, private keys, profile archives, databases, logs, or unredacted production data are included
- [ ] Authentication, authorization, CSRF, TLS, proxy trust, and destructive-operation impact was reviewed
- [ ] Screenshots and test fixtures use mock or redacted data

## Deployment

State whether this is application-only, metadata-compatible, or a data/policy migration. Identify the immutable image tag, canary checks, observation window, and operator approval required.

## Rollback

Describe how to return to the previous image and whether the existing `/data` volume remains compatible.
