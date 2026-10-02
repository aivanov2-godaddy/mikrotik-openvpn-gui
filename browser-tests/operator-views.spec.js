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
    const unexpected = current.filter(({ id, impact, target }) => !allowed.has(`${id}|${impact}|${target}`));
    await testInfo.attach('axe-serious-findings.json', {
      body: Buffer.from(JSON.stringify({ view: view.target, findings: current }, null, 2)),
      contentType: 'application/json',
    });
    expect(unexpected, `${view.name}: new serious/critical WCAG findings`).toEqual([]);
  });
}
