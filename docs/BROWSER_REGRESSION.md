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

axe-core scans the three rendered views against WCAG 2.2 A/AA rules at every
viewport. The initial scan found serious color-contrast findings and missing
keyboard focusability on scrollable regions. Since this test-only change must
not alter the product UI, those existing findings are recorded by exact rule,
impact, and target in `browser-tests/accessibility-baseline.json`. CI attaches
the current axe findings to each test and fails on any new serious/critical
target. Removing or correcting a finding is allowed; do not broaden the
baseline to silence a new one. The baseline is regression protection, not a
claim that the views currently conform to WCAG 2.2 AA. Product remediation and
human task validation remain separate work; no human validation is asserted by
this suite.
