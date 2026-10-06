# Browser regression tests

The browser suite uses the existing mock RouterOS server. It does not connect
to a real router or mutate router configuration. One targeted realtime
regression uses synthetic transport frames to verify that a fresh live snapshot
is not overwritten by a failed REST status poll; it does not measure production
stream latency or RouterOS availability.
Screenshot regression covers Dashboard, VPN Users, and Connections. Each case
logs in with the mock-only `admin` / `routerpass` fixture and captures a
full-page Chromium screenshot at 1440×1000, 768×1024, and 390×844 CSS pixels.
CI uses the same Windows runner family as the committed screenshot baselines to
keep font rasterization consistent.

In addition to the three default screenshots at every viewport, desktop-only
state snapshots cover a dashboard warning alert, a VPN Users no-results filter,
the add-user dialog, and the Connections termination-review prompt. The default
mock RouterOS fixture provides the populated/connected state. These cases use
the local mock app and fixed REST/UI fixtures; EventSource is disabled, and
neither live-stream timing nor a real router is involved. This is a selected
regression set, not an exhaustive combination of every view and state. The
no-results filter, add-user dialog, and termination-review dialog also receive
axe-core WCAG 2.2 A/AA scans in their rendered states; these focused state scans
run on desktop, while the ten primary-view scans run at all three viewports.

`design-system.spec.js` renders Dashboard, VPN Users, and Connections at each
viewport in Standard, Dark, and Light themes. It guards the shared font, text,
heading, panel, and metric roles against the semantic CSS tokens, and checks
4.5:1 contrast for primary text roles on the workspace and panel surfaces. The
keyboard-only navigation regression also verifies the rendered focus outline's
style, width, and offset on each primary view. These checks use the mock REST
fixture and do not assert telemetry cadence or wait on a live stream.

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
results. CI fails on new serious/critical findings. The three focused state
scans also fail on any serious/critical finding and do not use the baseline.
Removing or correcting a finding is allowed; do not broaden the baseline to
silence a new one.

At a separate 720×500 CSS-pixel viewport, the suite visits all ten views and
checks that each view and heading remain reachable without document-level
horizontal overflow. This approximates a 1440px desktop's content width at
200% zoom, but it is viewport emulation only and is not an actual browser-zoom
or manual usability result. A 574×700 CSS-pixel case checks the header and
sign-out control at the equivalent width of a 1148px desktop at 200%; a
separate 539×700 CSS-pixel case checks a narrower zoom-equivalent layout and
verifies that the mobile header's sign-out label is not clipped. Viewport
emulation checks responsive CSS behavior; it does not validate physical
browser-zoom rendering.

This is automated coverage of ten views, not a whole-application conformance
claim. Additional populated/error states beyond the selected screenshots,
assistive technology, real browser zoom at 200%, and human task validation are
not established by this suite and remain separate review work.
