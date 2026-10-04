# Browser regression tests

The browser suite uses the existing mock RouterOS server. It does not connect
to a real router, mutate router configuration, or test live-stream timing.
Screenshot regression covers Dashboard, VPN Users, and Connections. Each case
logs in with the mock-only `admin` / `routerpass` fixture and captures a
full-page Chromium screenshot at 1440×1000, 768×1024, and 390×844 CSS pixels.
CI uses the same Windows runner family as the committed screenshot baselines to
keep font rasterization consistent.

## Run locally

Install Python runtime dependencies, Node.js 24, then run:

```powershell
python -m pip install --requirement requirements-runtime.txt
npm ci
npx playwright install chromium
npm run test:browser
```

The suite compares real browser screenshots against
`browser-tests/visual-baselines/`. To intentionally refresh them after
reviewing a visual change, run `npm run test:browser -- --update-snapshots`,
inspect every PNG diff, and commit only the expected baselines.

## Accessibility checks and current baseline

axe-core scans ten rendered operator views—Dashboard, VPN Users, Connections,
Device Profiles, Service Health, Connection Doctor, Policy Templates, Change
History, Administrator Sessions, and Setup Planner—against WCAG 2.2 A/AA rules
at desktop, tablet, and mobile viewports. The current committed
`browser-tests/accessibility-baseline.json` has no recorded findings for the
original three views, and the expanded scans assert there are no serious or
critical findings across all ten. Older descriptions of contrast and
scroll-region findings are historical and must not be presented as current
results. CI fails on new serious/critical findings. Removing or correcting a
finding is allowed; do not broaden the baseline to silence a new one.

This is automated coverage of ten views, not a whole-application conformance
claim. Additional populated/error states and open dialog states, assistive
technology, real browser zoom at 200%, and human task validation are not
established by this suite and remain separate review work.
