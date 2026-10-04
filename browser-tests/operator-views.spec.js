const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const accessibilityBaseline = require('./accessibility-baseline.json');

const views = [
  { name: 'Dashboard', heading: 'VPN at a glance', target: 'overview' },
  { name: 'VPN Users', heading: 'VPN Users', target: 'vpn-users' },
  { name: 'Connections', heading: 'Connected Devices', target: 'live-sessions' },
];
const accessibilityViews = [
  ...views,
  { name: 'Device Profiles', heading: 'Device Profiles', target: 'profile-security' },
  { name: 'Service Health', heading: 'Service health', target: 'service-health' },
  { name: 'Connection Doctor', heading: 'Connection Doctor', target: 'connection-doctor' },
  { name: 'Policy Templates', heading: 'Policy Templates', target: 'policy-templates' },
  { name: 'Change History', heading: 'Change History', target: 'audit-log' },
  { name: 'Administrator Sessions', heading: 'Administrator sessions', target: 'admin-sessions' },
  { name: 'Setup Planner', heading: 'Installation planner', target: 'setup-planner' },
];

test.beforeEach(async ({ page }) => {
  // Freeze browser time and prevent a real-time transport from starting. The
  // mock app supplies deterministic REST fixtures; live-event timing is out of
  // scope for screenshot comparisons and has separate integration coverage.
  // Fix Date while allowing browser timers to keep running; axe and the app's
  // asynchronous UI need timers during its scan and render lifecycle.
  await page.clock.setFixedTime(new Date('2026-10-03T12:00:00.000Z'));
  await page.addInitScript(() => {
    Object.defineProperty(window, 'EventSource', { configurable: true, value: undefined });
  });
  await page.route('**/api/telemetry', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ transport: 'sse', socketio_enabled: false }),
  }));
  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();
  await page.waitForLoadState('networkidle');
});

for (const view of views) {
  test(`${view.name} renders consistently`, async ({ page }) => {
    if (view.target !== 'overview') {
      await page.getByRole('link', { name: view.name, exact: true }).click();
    }

    await expect(page.getByRole('heading', { name: view.heading, exact: true })).toBeVisible();
    await expect(page.locator(`[data-view="${view.target}"]`)).toBeVisible();

    await expect(page).toHaveScreenshot(`${view.target}.png`, {
      fullPage: true,
      style: '#system-status time { visibility: hidden !important; }',
    });
  });
}

test('Dashboard warning alert state renders consistently', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop-1440', 'Additional state snapshots are intentionally desktop-only.');
  await page.getByRole('link', { name: 'Dashboard', exact: true }).click();

  // Exercise the same REST-backed renderer used by status refreshes, but invoke
  // it directly with a fixed alert fixture. EventSource remains disabled by
  // beforeEach, and no stream or timing behavior is part of this screenshot.
  const statusResponse = await page.request.get('/api/status');
  const payload = await statusResponse.json();
  payload.alerts = [{
    id: 9201,
    severity: 'warning',
    title: 'VPN capacity needs review',
    details: 'The configured session limit is close to its current usage.',
    created_at: 1791028800,
    last_seen_at: 1791028800,
    occurrence_count: 1,
  }];
  await page.route('**/api/status', (route) => route.fulfill({ json: payload }));
  await page.evaluate(async () => {
    const response = await fetch('/api/status');
    updateDashboard(await response.json());
  });

  await expect(page.locator('[data-alert-id="9201"]')).toContainText('VPN capacity needs review');
  await expect(page).toHaveScreenshot('dashboard-warning.png', {
    fullPage: true,
    style: '#system-status time { visibility: hidden !important; }',
  });
});

test('VPN Users no-results state renders consistently', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop-1440', 'Additional state snapshots are intentionally desktop-only.');
  await page.getByRole('link', { name: 'VPN Users', exact: true }).click();
  const search = page.getByRole('searchbox', { name: 'Find VPN user' });
  await search.fill('no-such-user');
  await search.blur();
  await expect(page.locator('[data-user-filter-empty]')).toBeVisible();
  await expect(page.locator('[data-user-filter-empty]')).toContainText('No users match your search');
  await expect(page).toHaveScreenshot('vpn-users-no-results.png', {
    fullPage: true,
    style: '#system-status time { visibility: hidden !important; }',
  });
});

test('VPN Users add-user dialog renders consistently', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop-1440', 'Additional state snapshots are intentionally desktop-only.');
  await page.getByRole('link', { name: 'VPN Users', exact: true }).click();
  await page.getByRole('button', { name: 'Add VPN user' }).click();
  await expect(page.getByRole('dialog', { name: 'Add a person and phone' })).toBeVisible();
  await expect(page).toHaveScreenshot('vpn-users-add-dialog.png', {
    fullPage: true,
    style: '#system-status time { visibility: hidden !important; }',
  });
});

test('Connections termination-review prompt renders consistently', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop-1440', 'Additional state snapshots are intentionally desktop-only.');
  await page.getByRole('link', { name: 'Connections', exact: true }).click();
  await expect(page.locator('.session-card')).toHaveCount(1);
  await page.locator('.session-card [data-terminate]').click();
  await expect(page.locator('#terminate-dialog')).toBeVisible();
  await expect(page).toHaveScreenshot('connections-terminate-prompt.png', {
    fullPage: true,
    style: '#system-status time { visibility: hidden !important; }',
  });
});

for (const view of accessibilityViews) {
  test(`${view.name} has no new serious WCAG 2.2 A/AA violations`, async ({ page }, testInfo) => {
    if (view.target !== 'overview') {
      await page.getByRole('link', { name: view.name, exact: true }).click();
    }
    await expect(page.getByRole('heading', { name: view.heading, exact: true })).toBeVisible();
    await page.waitForLoadState('networkidle');

    const results = await new AxeBuilder({ page })
      .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
      .analyze();
    const serious = results.violations.filter((violation) =>
      ['critical', 'serious'].includes(violation.impact),
    );
    const allowed = new Set(
      (accessibilityBaseline[view.target] || []).map(({ id, impact, target }) => `${id}|${impact}|${target}`),
    );
    const current = serious.flatMap(({ id, impact, nodes }) =>
      nodes.map((node) => ({ id, impact, target: node.target.join(' ') })),
    );
    expect(
      current.filter(({ id }) => id === 'color-contrast'),
      `${view.name}: serious contrast findings must not be re-baselined`,
    ).toEqual([]);
    const unexpected = current.filter(({ id, impact, target }) => !allowed.has(`${id}|${impact}|${target}`));
    await testInfo.attach('axe-serious-findings.json', {
      body: Buffer.from(JSON.stringify({ view: view.target, findings: current }, null, 2)),
      contentType: 'application/json',
    });
    expect(unexpected, `${view.name}: new serious/critical WCAG findings`).toEqual([]);
  });
}

test('active alert recurrence is announced without creating duplicate rows', async ({ page }) => {
  await page.route('**/api/status', async (route) => {
    const response = await route.fetch();
    const payload = await response.json();
    payload.alerts = [{
      id: 9001,
      severity: 'critical',
      title: 'Access restriction needs review',
      details: 'RouterOS read-back remains uncertain.',
      created_at: 1791030000,
      last_seen_at: 1791030300,
      occurrence_count: 3,
    }];
    await route.fulfill({ response, body: JSON.stringify(payload) });
  });
  await page.reload();

  const row = page.locator('[data-alert-id="9001"]');
  await expect(row).toHaveCount(1);
  await expect(row).toContainText('Seen 3 times');
  await expect(row.locator('time')).toHaveAttribute('aria-label', /last seen.*first seen/i);
});

test('bulk destructive rationale stays hidden until needed and invalidates a stale review', async ({ page }) => {
  await page.getByRole('link', { name: 'VPN Users', exact: true }).click();
  await page.locator('[data-user-select]').first().check();
  const reasonContainer = page.locator('[data-bulk-reason-input]');
  const reason = page.locator('[data-bulk-reason]');
  const preview = page.locator('[data-bulk-preview]');
  await expect(reasonContainer).toBeHidden();
  await page.locator('[data-bulk-action]').selectOption('suspend');
  await expect(reasonContainer).toBeVisible();
  await expect(preview).toBeDisabled();
  await reason.fill('Quarterly VPN access review');
  await expect(preview).toBeEnabled();
  await reason.fill('');
  await expect(preview).toBeDisabled();
  await expect(page.locator('[data-bulk-review]')).toBeHidden();
});

test('account deletion requires and binds a reason before enabling apply', async ({ page }) => {
  await page.getByRole('link', { name: 'VPN Users', exact: true }).click();
  const firstUser = page.locator('.user-card').first();
  await firstUser.locator('.action-menu summary').click();
  await firstUser.locator('[data-delete]').click();
  const dialog = page.locator('#delete-dialog');
  const reason = dialog.getByLabel('Reason for removing access');
  const review = dialog.getByRole('button', { name: 'Review impact' });
  const apply = dialog.getByRole('button', { name: 'Remove access' });
  await expect(apply).toBeDisabled();
  await reason.fill('Quarterly access review approved');
  await review.click();
  await expect(dialog.locator('.form-status')).toContainText('Reason: Quarterly access review approved');
  await dialog.locator('[name="confirmation"]').fill(await dialog.locator('[data-delete-user]').textContent());
  await expect(apply).toBeEnabled();
  await reason.fill('Different reason after review');
  await expect(apply).toBeDisabled();
});

test('individual suspension requires and binds a reason before enabling apply', async ({ page }) => {
  await page.getByRole('link', { name: 'VPN Users', exact: true }).click();
  const firstUser = page.locator('.user-card').first();
  await firstUser.locator('.action-menu summary').click();
  await firstUser.locator('[data-suspend]').click();
  const dialog = page.locator('#suspend-dialog');
  const reason = dialog.getByLabel('Reason for suspending access');
  const review = dialog.getByRole('button', { name: 'Review impact' });
  const apply = dialog.getByRole('button', { name: 'Suspend and disconnect' });
  await expect(apply).toBeDisabled();
  await reason.fill('Security review is pending');
  await review.click();
  await expect(dialog.locator('[data-suspend-impact]')).toContainText('Reason: Security review is pending');
  await dialog.locator('[name="confirmation"]').fill(await dialog.locator('[data-suspend-user]').textContent());
  await expect(apply).toBeEnabled();
  await reason.fill('Different reason after review');
  await expect(apply).toBeDisabled();
});

test('new device profile requires a reason and invalidates review when it changes', async ({ page }) => {
  await page.getByRole('link', { name: 'VPN Users', exact: true }).click();
  const firstUser = page.locator('.user-card').first();
  await firstUser.locator('.action-menu summary').click();
  await firstUser.locator('[data-profile]').click();
  const dialog = page.locator('#profile-dialog');
  const reason = dialog.getByLabel('Reason for issuing access');
  const device = dialog.getByLabel('Phone or device');
  const passphrase = dialog.getByLabel('Protect file with');
  const apply = dialog.getByRole('button', { name: 'Review profile request' });
  await device.fill('Work tablet');
  await passphrase.fill('temporary-passphrase');
  await expect(apply).toBeDisabled();
  await reason.fill('Owner requested a second device');
  await expect(apply).toBeEnabled();
  await apply.click();
  await expect(dialog.locator('[data-profile-review]')).toContainText('Reason: Owner requested a second device');
  await reason.fill('Different issuance reason');
  await expect(dialog.locator('[data-profile-review]')).toBeHidden();
  await expect(dialog.locator('[data-profile-submit]')).toHaveText('Review profile request');
});

test('profile delivery actions clearly state that they issue a new identity', async ({ page }) => {
  await page.getByRole('link', { name: 'VPN Users', exact: true }).click();
  const firstUser = page.locator('.user-card').first();
  await firstUser.locator('.action-menu summary').click();
  const zipAction = firstUser.locator('[data-download-profile]');
  const qrAction = firstUser.locator('[data-qr-profile]');
  await expect(zipAction).toHaveText('Issue new profile (.zip)');
  await expect(qrAction).toHaveText('Issue profile by QR');

  await zipAction.click();
  const dialog = page.locator('#profile-dialog');
  await expect(dialog.locator('[data-profile-title]')).toHaveText('Issue new profile');
  await expect(dialog.locator('[data-profile-description]')).toContainText('new device certificate');
  await expect(dialog.locator('[data-profile-description]')).toContainText('cannot re-download an earlier profile');

  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await firstUser.locator('.action-menu summary').click();
  await qrAction.click();
  await expect(dialog.locator('[data-profile-title]')).toHaveText('Issue profile by QR');
  await expect(dialog.locator('[data-profile-description]')).toContainText('new device certificate');
  await expect(dialog.locator('[data-profile-description]')).toContainText('cannot re-download an earlier profile');
});

async function tabTo(page, locator) {
  for (let attempt = 0; attempt < 30; attempt += 1) {
    if (await locator.evaluate((element) => element === document.activeElement)) return;
    await page.keyboard.press('Tab');
  }
  throw new Error('Could not reach the requested navigation link using Tab');
}

test('keyboard-only navigation activates Dashboard, VPN Users, and Connections', async ({ page }) => {
  // Use a consistent narrow-desktop layout so every navigation link remains
  // in the same keyboard tab sequence across the configured browser projects.
  await page.setViewportSize({ width: 720, height: 500 });
  const navigation = [
    { name: 'Dashboard', target: 'overview', heading: 'VPN at a glance' },
    { name: 'Connections', target: 'live-sessions', heading: 'Connected Devices' },
    { name: 'VPN Users', target: 'vpn-users', heading: 'VPN Users' },
  ];

  for (const view of navigation) {
    const link = page.getByRole('link', { name: view.name, exact: true });
    await tabTo(page, link);
    await expect(link).toBeFocused();
    await page.keyboard.press('Enter');
    await expect(page.locator(`[data-view="${view.target}"]`)).toBeVisible();
    await expect(link).toHaveAttribute('aria-current', 'page');
    await expect(page.getByRole('heading', { name: view.heading, exact: true })).toBeVisible();
    if (view.target === 'vpn-users') {
      await expect(page.getByRole('button', { name: 'Add VPN user' })).toBeVisible();
    }
  }
});

test('720 CSS-pixel reflow keeps primary views and actions reachable', async ({ page }) => {
  // 720 CSS px is a 200%-zoom-equivalent reflow approximation for a 1440px
  // desktop layout. It does not emulate actual browser zoom.
  await page.setViewportSize({ width: 720, height: 500 });
  await expect(page.getByRole('link', { name: 'VPN Users', exact: true })).toBeVisible();
  for (const view of views) {
    if (view.target !== 'overview') {
      await page.getByRole('link', { name: view.name, exact: true }).click();
    }
    await expect(page.locator(`[data-view="${view.target}"]`)).toBeVisible();
    await expect(page.getByRole('heading', { name: view.heading, exact: true })).toBeVisible();
    if (view.target === 'vpn-users') {
      await expect(page.getByRole('button', { name: 'Add VPN user' })).toBeVisible();
    }
    const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
    expect(pageWidth, `${view.name}: document must not overflow the 720px viewport`).toBeLessThanOrEqual(720);
  }
  const navigationCanScroll = await page.locator('.winbox-sidebar').evaluate((element) => {
    const before = element.scrollLeft;
    element.scrollLeft = element.scrollWidth;
    const moved = element.scrollLeft > before;
    element.scrollLeft = before;
    return moved;
  });
  expect(navigationCanScroll, 'primary navigation remains horizontally scrollable').toBe(true);
});

test('forced-colors mode keeps Dashboard navigation and keyboard focus visible', async ({ page }) => {
  await page.emulateMedia({ forcedColors: 'active' });
  await expect.poll(() => page.evaluate(() => window.matchMedia('(forced-colors: active)').matches))
    .toBe(true);

  await page.keyboard.press('Tab');
  const focused = page.locator(':focus-visible');
  await expect(focused).toBeVisible();
  await expect.poll(() => focused.evaluate((element) => getComputedStyle(element).outlineStyle))
    .toBe('solid');
  await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();
  await expect(page.getByRole('link', { name: 'VPN Users', exact: true })).toBeVisible();
  await expect(page.getByRole('button', { name: 'Add VPN user' })).toBeVisible();
});

test('light theme has no serious WCAG 2.2 A/AA violations', async ({ page }, testInfo) => {
  await page.locator('.theme-menu > summary').click();
  await page.getByRole('button', { name: /Light Bright workspace/ }).click();
  await expect(page.locator('html')).toHaveAttribute('data-theme-resolved', 'light');
  await expect(page.locator('[data-theme-choice="light"]')).toHaveAttribute('aria-pressed', 'true');

  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  const serious = results.violations
    .filter(({ impact }) => ['critical', 'serious'].includes(impact))
    .flatMap(({ id, impact, nodes }) => nodes.map((node) => ({ id, impact, target: node.target.join(' ') })));
  await testInfo.attach('axe-light-theme-serious-findings.json', {
    body: Buffer.from(JSON.stringify({ theme: 'light', findings: serious }, null, 2)),
    contentType: 'application/json',
  });
  expect(
    serious.filter(({ id }) => id === 'color-contrast'),
    'light-theme contrast findings are not suppressed by the existing baseline',
  ).toEqual([]);
  expect(serious, 'light theme must not add serious/critical WCAG findings').toEqual([]);
});

test('add-user dialog has accessible controls, stays keyboard-modal, validates, and cancels safely', async ({ page }) => {
  await page.getByRole('link', { name: 'VPN Users', exact: true }).click();
  const openButton = page.getByRole('button', { name: 'Add VPN user' });
  await openButton.click();

  const dialog = page.getByRole('dialog', { name: 'Add a person and phone' });
  await expect(dialog).toBeVisible();
  const username = dialog.getByRole('textbox', { name: 'VPN username', exact: true });
  const email = dialog.getByRole('textbox', { name: /^Owner email/ });
  const reason = dialog.getByRole('textbox', { name: 'Reason for creating access' });
  const submit = dialog.getByRole('button', { name: 'Review ZIP' });
  await expect(username).toBeVisible();
  await expect(email).toBeVisible();
  await expect(reason).toHaveAttribute('minlength', '12');
  await expect(reason).toHaveAttribute('maxlength', '240');
  await expect(submit).toBeVisible();
  await expect.poll(() => dialog.evaluate((element) => element.contains(document.activeElement)))
    .toBe(true);

  await page.keyboard.press('Tab');
  await expect.poll(() => dialog.evaluate((element) => element.contains(document.activeElement)))
    .toBe(true);

  await username.fill('accessibility-test');
  await email.fill('not-an-email');
  await submit.click();
  await expect.poll(() => email.evaluate((element) => element.validity.typeMismatch)).toBe(true);
  await expect.poll(() => email.evaluate((element) => element.matches(':invalid'))).toBe(true);
  await expect(dialog).toBeVisible();

  await page.keyboard.press('Escape');
  await expect(dialog).not.toBeVisible();
  await expect(openButton).toBeFocused();

  await openButton.click();
  await expect(dialog).toBeVisible();
  await dialog.getByRole('button', { name: 'Cancel' }).focus();
  await page.keyboard.press('Enter');
  await expect(dialog).not.toBeVisible();
  await expect(openButton).toBeFocused();
});

test('reduced-motion preference suppresses dialog animation and smooth scrolling', async ({ page }) => {
  await page.emulateMedia({ reducedMotion: 'reduce' });
  await page.getByRole('link', { name: 'VPN Users', exact: true }).click();
  await page.getByRole('button', { name: 'Add VPN user' }).click();

  const dialog = page.getByRole('dialog', { name: 'Add a person and phone' });
  await expect(dialog).toBeVisible();
  const motion = await dialog.evaluate((element) => {
    const milliseconds = (value) => value.split(',').map((part) => {
      const duration = Number.parseFloat(part);
      return part.trim().endsWith('ms') ? duration : duration * 1000;
    });
    const dialogStyle = getComputedStyle(element);
    const controlStyle = getComputedStyle(element.querySelector('input'));
    return {
      reducedMotionMatches: matchMedia('(prefers-reduced-motion: reduce)').matches,
      scrollBehavior: getComputedStyle(document.documentElement).scrollBehavior,
      transitionDurations: [...milliseconds(dialogStyle.transitionDuration), ...milliseconds(controlStyle.transitionDuration)],
      animationDurations: [...milliseconds(dialogStyle.animationDuration), ...milliseconds(controlStyle.animationDuration)],
    };
  });

  expect(motion.reducedMotionMatches).toBe(true);
  expect(motion.scrollBehavior).toBe('auto');
  expect(motion.transitionDurations.every((duration) => duration <= 0.01)).toBe(true);
  expect(motion.animationDurations.every((duration) => duration <= 0.01)).toBe(true);
});

test('diagnostic ZIP can be previewed and downloaded only on explicit keyboard activation', async ({ page }) => {
  await page.getByRole('link', { name: 'Change History', exact: true }).click();
  const preview = page.getByText('Preview what the ZIP contains', { exact: true });
  await expect(preview).toBeVisible();
  const disclosure = page.locator('.diagnostic-export-preview');
  await expect(disclosure).not.toHaveAttribute('open', '');

  let downloads = 0;
  page.on('download', () => { downloads += 1; });
  await preview.focus();
  await page.keyboard.press('Enter');
  await expect(disclosure).toHaveAttribute('open', '');
  await expect(page.getByText(/fixed description; it does not inspect RouterOS/)).toBeVisible();
  await expect(page.getByText(/RouterOS credentials or tokens/)).toBeVisible();
  await expect(page.getByText(/Raw RouterOS configuration or records, logs, event payloads/)).toBeVisible();
  expect(downloads, 'opening the preview must not start a download').toBe(0);

  const downloadLink = page.getByRole('link', { name: 'Download redacted diagnostic ZIP' });
  await downloadLink.focus();
  const [download] = await Promise.all([
    page.waitForEvent('download'),
    page.keyboard.press('Enter'),
  ]);
  expect(download.suggestedFilename()).toBe('vpn-diagnostic-bundle.zip');
  expect(downloads, 'one download starts after explicit keyboard activation').toBe(1);

  const accessibility = await new AxeBuilder({ page })
    .include('.diagnostic-export-panel')
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  expect(accessibility.violations.filter(({ impact }) => ['critical', 'serious'].includes(impact)))
    .toEqual([]);
});

test('operations timeline filters bounded observations and labels its coverage', async ({ page }) => {
  const frozenObservability = await page.evaluate(async () => {
    const response = await fetch('/api/observability');
    return response.json();
  });
  const occurredAt = Math.floor(Date.now() / 1000);
  frozenObservability.operations_timeline.events = [
    {
      id: 'audit:focus-target', occurred_at: occurredAt, age_seconds: 2,
      source: 'Dashboard audit', type: 'change', actor: 'operator', target: 'admin',
      outcome: 'success', severity: 'info', summary: 'Role assigned',
      relationship_summary: '', related_events: [],
    },
    {
      id: 'integration:focus-source', occurred_at: occurredAt - 1, age_seconds: 3,
      source: 'Redis delivery', type: 'integration', actor: '', target: '',
      outcome: 'delivered', severity: 'info', summary: 'Event delivered',
      relationship_summary: '', related_events: [
        { event_id: 'audit:focus-target', relation: 'delivery-status' },
      ],
    },
    {
      id: 'health:focus-filter', occurred_at: occurredAt - 2, age_seconds: 4,
      source: 'Service health', type: 'health', actor: '', target: '',
      outcome: 'success', severity: 'info', summary: 'Router is healthy',
      relationship_summary: '', related_events: [],
    },
  ];
  await page.route('**/api/observability', (route) => route.fulfill({ json: frozenObservability }));
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, value: true });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await page.getByRole('link', { name: 'Change History', exact: true }).click();
  await page.evaluate((observability) => renderObservability({ observability }), frozenObservability);
  const panel = page.locator('.operations-timeline-panel');
  await expect(panel.getByText('Operations timeline', { exact: true })).toBeVisible();
  await expect(panel.locator('.history-coverage-note')).toContainText('gaps are possible');
  const relatedLink = panel.locator('[data-operation-row][data-operation-type="integration"] [data-operation-related-link]').first();
  await expect(relatedLink).toBeVisible();
  const relatedLabel = await relatedLink.getAttribute('aria-label');
  const relatedHref = await relatedLink.getAttribute('href');
  const relatedRowIdentity = await relatedLink.locator('xpath=ancestor::tr').evaluate((row) => ({
    type: row.dataset.operationType,
    created: row.dataset.operationCreated,
  }));
  expect(relatedHref).toMatch(/^#operation-event-\d+$/);
  await relatedLink.focus();
  await page.evaluate(async ({ snapshot, rowIdentity }) => {
    const observability = structuredClone(snapshot);
    observability.operations_timeline.events[0].age_seconds += 1;
    const sourceEvent = observability.operations_timeline.events.find((event) =>
      event.type === rowIdentity.type && String(Number(event.occurred_at) || 0) === rowIdentity.created
    );
    if (sourceEvent) sourceEvent.summary = `${sourceEvent.summary} updated`;
    renderObservability({ observability });
  }, { snapshot: frozenObservability, rowIdentity: relatedRowIdentity });
  const refreshedRelatedLink = panel.getByRole('link', { name: relatedLabel, exact: true }).first();
  await expect(refreshedRelatedLink).toBeFocused();
  const refreshedHref = await refreshedRelatedLink.getAttribute('href');
  const refreshedRow = panel.locator(refreshedHref);
  await refreshedRelatedLink.press('Enter');
  await expect(refreshedRow).toBeFocused();
  await expect(refreshedRow).toBeInViewport();

  await page.evaluate((snapshot) => {
    const observability = structuredClone(snapshot);
    observability.operations_timeline.events[0].age_seconds += 1;
    renderObservability({ observability });
  }, frozenObservability);
  await expect(panel.locator(refreshedHref)).toBeFocused();

  await expect(panel).not.toContainText('192.0.2.8');

  const type = panel.getByLabel('Filter timeline by event type');
  await type.selectOption('health');
  const visibleRows = panel.locator('[data-operation-row]:visible');
  await expect(visibleRows.first()).toBeVisible();
  await expect.poll(() => visibleRows.evaluateAll((rows) => rows.every((row) => row.dataset.operationType === 'health')))
    .toBe(true);
  await type.selectOption('all');
  await panel.getByLabel('Search operations timeline').fill('');

  const dateWindow = await panel.locator('[data-operation-row]').evaluateAll((rows) => {
    const dayFor = (timestamp) => {
      const date = new Date(Number(timestamp) * 1000);
      return [date.getFullYear(), String(date.getMonth() + 1).padStart(2, '0'), String(date.getDate()).padStart(2, '0')].join('-');
    };
    const dates = rows.map((row) => dayFor(row.dataset.operationCreated));
    return { selectedDay: dates[0] };
  });
  await page.locator('[data-history-from]').fill(dateWindow.selectedDay);
  await page.locator('[data-history-to]').fill(dateWindow.selectedDay);
  await expect.poll(() => panel.locator('[data-operation-row]').evaluateAll((rows) => {
    const dayFor = (timestamp) => {
      const date = new Date(Number(timestamp) * 1000);
      return [date.getFullYear(), String(date.getMonth() + 1).padStart(2, '0'), String(date.getDate()).padStart(2, '0')].join('-');
    };
    const from = document.querySelector('[data-history-from]').value;
    const to = document.querySelector('[data-history-to]').value;
    const matching = rows.filter((row) => dayFor(row.dataset.operationCreated) >= from && dayFor(row.dataset.operationCreated) <= to);
    const visible = rows.filter((row) => !row.classList.contains('is-filtered-out'));
    return matching.length > 0
      && visible.length === matching.length
      && visible.every((row) => dayFor(row.dataset.operationCreated) === from);
  })).toBe(true);

  await page.locator('[data-history-from]').fill('2100-01-01');
  await page.locator('[data-history-to]').fill('2100-01-01');
  await expect(panel.locator('[data-operation-row]:visible')).toHaveCount(0);
  await page.locator('[data-history-from]').fill('');
  await page.locator('[data-history-to]').fill('');

  await panel.getByLabel('Search operations timeline').fill('no-such-event');
  await expect(panel.locator('[data-operation-count]')).toContainText('0 shown');

  const report = await page.evaluate(async () => {
    const response = await fetch('/api/operations-timeline.json?from=2000-01-01&to=2100-01-01');
    return {
      ok: response.ok,
      disposition: response.headers.get('content-disposition'),
      body: await response.json(),
    };
  });
  expect(report.ok).toBeTruthy();
  expect(report.disposition).toContain('vpn-operations-timeline.json');
  const body = report.body;
  expect(body.coverage.complete).toBe(false);
  expect(body.events.every((event) => !('details' in event))).toBe(true);

  const accessibility = await new AxeBuilder({ page })
    .include('.operations-timeline-panel')
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  expect(accessibility.violations.filter(({ impact }) => ['critical', 'serious'].includes(impact)))
    .toEqual([]);
});
