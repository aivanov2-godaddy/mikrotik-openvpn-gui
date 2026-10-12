const { test, expect } = require('@playwright/test');

async function signIn(page) {
  await page.addInitScript(() => {
    window.__documentInstance = `${Date.now()}-${Math.random()}`;
  });
  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();
  await page.locator('[data-view-target="admin-sessions"]').click();
  await expect(page.getByRole('heading', { name: 'Administrator sessions' })).toBeVisible();
}

async function expectNoDocumentReload(page, originalDocument, navigations) {
  expect(await page.evaluate(() => window.__documentInstance)).toBe(originalDocument);
  expect(navigations.count).toBe(0);
}

test('failed re-authentication clears password and preserves the live dashboard session', async ({ page }) => {
  const navigations = { count: 0 };
  await signIn(page);
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.count += 1;
  });
  const originalDocument = await page.evaluate(() => window.__documentInstance);

  await page.getByRole('button', { name: 'Re-authenticate this session' }).click();
  const dialog = page.locator('#session-reauthenticate-dialog');
  await expect(dialog).toBeVisible();
  await dialog.getByLabel('RouterOS password').fill('wrong-password');
  const failed = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/api/auth/reauthenticate'
  ));
  await dialog.getByRole('button', { name: 'Re-authenticate session' }).click();
  expect((await failed).status()).toBe(401);
  await expect(dialog.getByRole('status')).toContainText('Authentication failed');
  await expect(dialog.getByLabel('RouterOS password')).toHaveValue('');

  const telemetryStatus = await page.evaluate(async () => (
    await fetch('/api/telemetry', { credentials: 'same-origin' })
  ).status);
  expect(telemetryStatus).toBe(200);
  await expectNoDocumentReload(page, originalDocument, navigations);
});

test('successful re-authentication adopts rotated CSRF and keeps the page in place', async ({ page }) => {
  const navigations = { count: 0 };
  await signIn(page);
  let releaseStaleStatus;
  let signalStaleStatus;
  let holdNextStatus = true;
  const staleStatusGate = new Promise((resolve) => { releaseStaleStatus = resolve; });
  const staleStatusCaptured = new Promise((resolve) => { signalStaleStatus = resolve; });
  const statusResponses = [];
  page.on('response', (response) => {
    if (new URL(response.url()).pathname === '/api/status') statusResponses.push(response.status());
  });
  await page.route('**/api/status', async (route) => {
    if (!holdNextStatus) {
      await route.continue();
      return;
    }
    holdNextStatus = false;
    signalStaleStatus();
    await staleStatusGate;
    await route.fulfill({ status: 401, contentType: 'application/json', body: '{"error":"expired"}' });
  });
  await staleStatusCaptured;
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.count += 1;
  });
  const originalDocument = await page.evaluate(() => window.__documentInstance);
  const originalCsrf = await page.locator('meta[name="csrf-token"]').getAttribute('content');

  const authenticate = async () => {
    await page.getByRole('button', { name: 'Re-authenticate this session' }).click();
    const dialog = page.locator('#session-reauthenticate-dialog');
    await expect(dialog).toBeVisible();
    await dialog.getByLabel('RouterOS password').fill('routerpass');
    const response = page.waitForResponse((item) => (
      item.request().method() === 'POST'
      && new URL(item.url()).pathname === '/api/auth/reauthenticate'
    ));
    await dialog.getByRole('button', { name: 'Re-authenticate session' }).click();
    expect((await response).status()).toBe(200);
    await expect(dialog).toBeHidden();
    await expect(dialog.getByLabel('RouterOS password')).toHaveValue('');
  };

  await authenticate();
  const statusResponseCount = statusResponses.length;
  releaseStaleStatus();
  await expect.poll(() => statusResponses.slice(statusResponseCount).includes(200)).toBe(true);
  const rotatedCsrf = await page.locator('meta[name="csrf-token"]').getAttribute('content');
  expect(rotatedCsrf).toBeTruthy();
  expect(rotatedCsrf).not.toBe(originalCsrf);
  await expectNoDocumentReload(page, originalDocument, navigations);

  // A second successful POST proves the SPA's request helper uses the adopted
  // in-memory CSRF token, not just the one returned by the first response.
  await authenticate();
  const secondRotatedCsrf = await page.locator('meta[name="csrf-token"]').getAttribute('content');
  expect(secondRotatedCsrf).not.toBe(rotatedCsrf);
  await expectNoDocumentReload(page, originalDocument, navigations);
});
