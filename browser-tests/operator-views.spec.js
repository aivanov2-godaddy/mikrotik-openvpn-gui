const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;
const accessibilityBaseline = require('./accessibility-baseline.json');

const views = [
  { name: 'Dashboard', heading: 'VPN at a glance', target: 'overview' },
  { name: 'VPN Users', heading: 'VPN Users', target: 'vpn-users' },
  { name: 'Connections', heading: 'Connected Devices', target: 'live-sessions' },
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

  test(`${view.name} has no new serious WCAG 2.2 A/AA violations`, async ({ page }, testInfo) => {
    if (view.target !== 'overview') {
      await page.getByRole('link', { name: view.name, exact: true }).click();
    }
    await expect(page.getByRole('heading', { name: view.heading, exact: true })).toBeVisible();

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
  await page.getByRole('link', { name: 'Change History', exact: true }).click();
  const panel = page.locator('.operations-timeline-panel');
  await expect(panel.getByText('Operations timeline', { exact: true })).toBeVisible();
  await expect(panel.locator('.history-coverage-note')).toContainText('gaps are possible');
  const type = panel.getByLabel('Filter timeline by event type');
  await type.selectOption('health');
  const visibleRows = panel.locator('[data-operation-row]:visible');
  await expect(visibleRows.first()).toBeVisible();
  await expect.poll(() => visibleRows.evaluateAll((rows) => rows.every((row) => row.dataset.operationType === 'health')))
    .toBe(true);
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
