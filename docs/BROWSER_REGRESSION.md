# Browser regression tests

The browser suite exercises rendered Dashboard, VPN Users, and Connections
views using the existing mock RouterOS server. It does not connect to a real
router, mutate router configuration, or test live-stream timing. Each case logs
in with the mock-only `admin` / `routerpass` fixture and captures a full-page
Chromium screenshot at 1440×1000, 768×1024, and 390×844 CSS pixels. CI uses the
same Windows runner family as the committed screenshot baselines to keep font
rasterization consistent.

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

axe-core scans the rendered Dashboard, VPN Users, and Connections views against
WCAG 2.2 A/AA rules at every configured viewport. The current committed
`browser-tests/accessibility-baseline.json` contains no findings for those
scanned views; older descriptions of contrast and scroll-region findings are
historical and must not be presented as current results. CI fails on new
serious/critical findings. Removing or correcting a finding is allowed; do not
broaden the baseline to silence a new one.

This is automated coverage of three views, not a whole-application conformance
claim. Other operator views, populated/error states, more dialogs, assistive
technology, real browser zoom at 200%, and human task validation are not
established by this suite and remain separate review work.
