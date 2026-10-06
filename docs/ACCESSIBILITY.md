# Accessible, consistent operator UI

The dashboard uses WCAG 2.2 AA as an informed target, while recognizing that
automated checks do not replace assistive-technology and human review. The UI
is a single-router operations console: live state must remain live, risky
RouterOS changes stay review-first, and status meaning must never rely on color
alone.

## Shared design rules

- Use the shared system font stack and semantic tokens: `--workspace`,
  `--panel`, `--panel-2`, `--line`, `--text`, `--text-bright`, `--muted`,
  `--blue`, `--green`, `--amber`, and `--red`. Body copy uses the standard
  page size. `--dim` is for decorative metadata only, never essential content
  or the only way to identify an action or status.
- Reuse the existing spacing rhythm (4/8/12/16/24 px), panel surfaces, and
  common button classes. Primary actions are visually distinct; secondary and
  destructive actions are not presented with equal emphasis.
- Status includes readable text and an icon/shape in addition to its color.
  Live state indicates freshness or delay; it must not imply that the operator
  needs to refresh the page.
- Interactive controls must have an accessible name, keyboard operation, a
  visible focus indicator, and a target suitable for touch. Use native buttons,
  links, labels, and disclosure elements where possible.
- Prefer short labels and progressive disclosure over dense explanatory copy.
  Keep live telemetry and current form values intact when views update.

## Primary-view design system

| View | Hierarchy and components | Accessibility guardrails |
| --- | --- | --- |
| Dashboard | Keep the page title and short summary first; use metric cards for the few at-a-glance values; group service health and security posture into panels. | Metric labels remain readable text; health and security states pair color with a word/icon; the primary action is clear without implying a manual refresh is needed for live data. |
| VPN Users | Lead each card with the person's VPN identity, then connection/profile status and secondary details; keep filters and add-user actions close to the list; put infrequent actions behind the existing per-user menu. | Search and empty results have names and text; status is not color-only; add, suspend, and remove dialogs preserve their review, reason, keyboard, and cancel behavior. |
| Connections | Put active devices before history; keep source, VPN address, uptime, and direction-labelled Rx/Tx rates distinct from cumulative totals; keep history in its labelled scroll region. | Graphs are supplementary to textual rates; keyboard-operable graph controls expose their selected state; termination remains an explicit review-and-confirm action. Updating telemetry must not steal focus or replace text being edited. |

Across these views, use the same page heading, panel heading, metric, and action
roles rather than inventing per-view colors or font stacks. Standard, Dark, and
Light palettes must preserve at least 4.5:1 contrast for the `--text`,
`--text-bright`, and `--muted` roles on the workspace and panel surfaces.
Status colors communicate category, not the entire meaning. Reuse the existing
spacing rhythm (4/8/12/16/24 px); introduce a new token only when a distinct,
reusable semantic role needs it.

## WCAG-informed review map

| UI area | Review points |
| --- | --- |
| Login and forms | Labels and instructions; required/invalid state; errors announced and associated with their controls; password-manager compatibility. |
| Navigation and page views | Landmark and heading hierarchy; current view is perceivable; links/buttons have clear names; keyboard users can reach every view. |
| Live connections and graphs | Connected/disconnected and stale states are text-labelled; graph controls expose pressed state; live updates do not steal focus or announce every sample. |
| Users and device actions | Status is not color-only; selection and review actions are keyboard operable; destructive operations explain impact and require the existing confirmation. |
| Dialogs and disclosures | Native open/close behavior; summary/button name is clear; focus remains visible; Escape and close controls work. |
| Tables, audit, and health | Headers and row meaning are understandable; empty/error states are explicit; charts and health states have textual equivalents. |

## Regression gate

Every UI pull request runs the repository pre-commit suite and Python tests,
including the frontend live-update contract tests. The deterministic CSS
contract tests inspect the declarations inside the actual rules: keyboard focus
must retain a visible outline and offset, reduced-motion mode must limit
animation and transition duration and disable smooth scrolling, and forced
colors must retain a system-color focus outline and control borders. The
rendered browser suite also emulates forced-colors mode and checks keyboard
focus, navigation, and the primary action at desktop, tablet, and mobile
viewports. Mobile breakpoints are checked as well. Run this focused gate with
`python -m unittest tests.test_accessibility_contract -v`; CI also runs it as
part of the full Python test suite. These source-level checks do not prove the
rendered UI is accessible; they do not replace browser, assistive-technology,
or human review, and they do not use sleeps to assert streaming behavior.

Before merging a user-visible layout change, reviewers also inspect Dashboard,
VPN Users, and Connections at 1440×900, 768×1024, and 390×844; at 200% browser
zoom; with keyboard only; with reduced motion enabled; and with Windows forced
colors/high contrast. Compare against the reviewed primary-view references in
`docs/screenshots/` where the component is represented, and add or update a
redacted screenshot when a persistent visual state changes. Do not capture
credentials, real VPN names, addresses, QR codes, or production data.

## Five operator usability tasks

Run with an administrator familiar with VPN basics but not the implementation.
Use a seeded, redacted test installation. A task succeeds only when completed
without moderator hints and without a wrong/destructive action.

| Task | Success criterion | Error signal |
| --- | --- | --- |
| Find whether a named VPN user is connected | Correct user and current state found within 30 seconds | Wrong account/state, or a manual page refresh is attempted |
| Find a connection's current throughput | Correct Rx/Tx rates and units identified within 30 seconds | Cumulative totals are mistaken for rates, or units/direction are reversed |
| Add a device profile to an existing user | Correct user/device workflow reached within 45 seconds; no profile is issued to another user | Wrong user, unintended access change, or moderator hint required |
| Diagnose a VPN service warning | Relevant health check and safe next step found within 45 seconds | Operator is directed to an unsafe mutation or cannot identify the affected service |
| Review a proposed destructive user action | Impact and target are correctly stated before confirming; cancel leaves state unchanged | Wrong target, unclear impact, or action executes without explicit confirmation |

Record completion time, unassisted completion, wrong turns, and task errors.
Do not claim usability improvement from visual preference alone; compare the
same tasks before and after a material navigation or interaction redesign.

The browser regression suite also checks keyboard-only activation and current
view indication while navigating Dashboard, VPN Users, and Connections. At a
720×500 CSS-pixel viewport, it checks that all ten automated accessibility
views remain reachable without document-level horizontal overflow and that
navigation can still scroll to its links. This viewport approximates the
available width of a 1440px desktop at 200% zoom; it does not emulate actual
browser zoom and does not replace the manual 200%-zoom review above.

Manual review record (2026-10-06): Dashboard, Connections, and VPN Users were
inspected in the authenticated browser at actual 200% zoom. Each view remained
reachable; the primary navigation used horizontal scrolling. The Dashboard's
traffic helper text was ellipsized. PR #530 changes that text to wrap and adds
a rendered regression at 540 CSS pixels; the PR and image publication passed,
but the image has not been read back from RouterOS, so this does not establish
that the visual fix is deployed. The operator task study and assistive-
technology review remain outstanding. This spot-check does not claim WCAG
conformance or replace the other manual review conditions above.
