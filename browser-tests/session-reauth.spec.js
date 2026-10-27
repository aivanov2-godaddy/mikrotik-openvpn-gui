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

test('self-service sign-out preserves the current session and requires typed confirmation', async ({ page }) => {
  const navigations = { count: 0 };
  await signIn(page);
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.count += 1;
  });
  const originalDocument = await page.evaluate(() => window.__documentInstance);

  await page.getByRole('button', { name: 'Sign out my other sessions' }).click();
  const dialog = page.locator('#admin-session-reauth-dialog');
  await expect(page.locator('[data-own-session-count]')).toContainText('other dashboard session');
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText('only dashboard logins for your RouterOS account');
  await expect(dialog).toContainText('VPN tunnels are not disconnected');
  await dialog.getByLabel('Type SIGN OUT MY OTHER SESSIONS').fill('wrong phrase');
  await dialog.getByLabel('RouterOS password').fill('routerpass');
  const rejected = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/api/auth/sessions/revoke-others'
  ));
  await dialog.getByRole('button', { name: 'Verify and sign out my other sessions' }).click();
  expect((await rejected).status()).toBe(400);
  await expect(dialog.getByRole('status')).toContainText('Type SIGN OUT MY OTHER SESSIONS');

  await dialog.getByLabel('Type SIGN OUT MY OTHER SESSIONS').fill('SIGN OUT MY OTHER SESSIONS');
  await dialog.getByLabel('RouterOS password').fill('routerpass');
  const accepted = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/api/auth/sessions/revoke-others'
  ));
  await dialog.getByRole('button', { name: 'Verify and sign out my other sessions' }).click();
  expect((await accepted).status()).toBe(200);
  await expect(dialog).toBeHidden();
  await expect(dialog.getByLabel('RouterOS password')).toHaveValue('');
  expect(await page.evaluate(async () => (
    await fetch('/api/telemetry', { credentials: 'same-origin' })
  ).status)).toBe(200);
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

test('API token creation and revocation require step-up without reloading the live page', async ({ page }) => {
  const navigations = { count: 0 };
  const tokenLabel = `step-up browser ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  await signIn(page);
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.count += 1;
  });
  page.on('dialog', (dialog) => dialog.accept());
  const originalDocument = await page.evaluate(() => window.__documentInstance);

  await page.getByLabel('Token label').fill(tokenLabel);
  const createReauth = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/api/auth/reauthenticate'
  ));
  const createToken = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/api/admin/api-tokens'
  ));
  await page.getByRole('button', { name: 'Create scoped token' }).click();
  const dialog = page.locator('#session-reauthenticate-dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('status')).toContainText('before creating this scoped API token');
  await dialog.getByLabel('RouterOS password').fill('routerpass');
  await dialog.getByRole('button', { name: 'Re-authenticate session' }).click();
  expect((await createReauth).status()).toBe(200);
  expect((await createToken).status()).toBe(201);
  await expect(dialog).toBeHidden();
  await expect(page.locator('[data-created-token]')).toContainText('vpt_');

  // The audit timeline also contains the token label in its own table row;
  // scope this action locator to the token inventory row only.
  const tokenRow = page.locator('tr[data-token-id]').filter({ hasText: tokenLabel });
  await expect(tokenRow).toBeVisible();
  const revokeReauth = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/api/auth/reauthenticate'
  ));
  const revokeToken = page.waitForResponse((response) => (
    response.request().method() === 'DELETE'
    && /\/api\/admin\/api-tokens\//.test(new URL(response.url()).pathname)
  ));
  await tokenRow.getByRole('button', { name: 'Revoke' }).click();
  await expect(dialog).toBeVisible();
  await expect(dialog.getByRole('status')).toContainText('before revoking this API token');
  await dialog.getByLabel('RouterOS password').fill('routerpass');
  await dialog.getByRole('button', { name: 'Re-authenticate session' }).click();
  expect((await revokeReauth).status()).toBe(200);
  expect((await revokeToken).status()).toBe(200);
  await expect(tokenRow).toHaveCount(0);
  await expectNoDocumentReload(page, originalDocument, navigations);
});

test('VPN-user password changes require step-up and review active-session disconnects in place', async ({ page }) => {
  const navigations = { count: 0 };
  await signIn(page);
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.count += 1;
  });
  const originalDocument = await page.evaluate(() => window.__documentInstance);

  await page.locator('[data-view-target="vpn-users"]').click();
  const userCard = page.locator('.user-card').filter({ hasText: 'user-two' });
  await userCard.getByRole('button', { name: 'Edit user' }).click();
  const editDialog = page.locator('#edit-dialog');
  await expect(editDialog).toBeVisible();
  await editDialog.getByLabel('New password').fill('browser-rotated-vpn-password');
  await editDialog.getByLabel('Reason for this change').fill('Rotate this VPN user password');

  const previewResponse = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && /\/api\/users\/[^/]+\/preview$/.test(new URL(response.url()).pathname)
  ));
  await editDialog.getByRole('button', { name: 'Preview changes' }).click();

  const reauthDialog = page.locator('#session-reauthenticate-dialog');
  await expect(reauthDialog).toBeVisible();
  await expect(reauthDialog.getByRole('status')).toContainText('before changing this VPN user');
  const reauthResponse = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/api/auth/reauthenticate'
  ));
  await reauthDialog.getByLabel('RouterOS password').fill('routerpass');
  await reauthDialog.getByRole('button', { name: 'Re-authenticate session' }).click();
  expect((await reauthResponse).status()).toBe(200);
  expect((await previewResponse).status()).toBe(200);
  await expect(reauthDialog).toBeHidden();
  await expect(editDialog.locator('#edit-review')).toContainText('1 active VPN device will be disconnected');

  const applyResponse = page.waitForResponse((response) => (
    response.request().method() === 'PATCH'
    && /\/api\/users\/[^/]+$/.test(new URL(response.url()).pathname)
  ));
  await editDialog.getByRole('button', { name: 'Save changes' }).click();
  expect((await applyResponse).status()).toBe(200);
  await expect(editDialog).toBeHidden();
  await expect(editDialog.getByLabel('New password')).toHaveValue('');
  await expect(page.getByText(/1 active VPN device was disconnected/)).toBeVisible();
  await expectNoDocumentReload(page, originalDocument, navigations);
});
