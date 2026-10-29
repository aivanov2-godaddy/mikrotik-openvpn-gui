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

async function expectNoDocumentReload(page, originalDocument) {
  expect(await page.evaluate(() => window.__documentInstance)).toBe(originalDocument);
}

test('failed re-authentication clears password and preserves the live dashboard session', async ({ page }) => {
  await signIn(page);
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
  await expectNoDocumentReload(page, originalDocument);
});

test('self-service sign-out requires typed confirmation and retains the current dashboard view', async ({ page }) => {
  await signIn(page);
  const originalDocument = await page.evaluate(() => window.__documentInstance);
  const confirmationRequests = [];

  // Backend revocation semantics are covered by tests/test_app.py. Keep this
  // page-level interaction isolated: the browser suite shares one mock server,
  // so revoking every other login here would invalidate sessions in parallel tests.
  await page.route('**/api/auth/sessions/revoke-others', async (route) => {
    const { confirmation } = route.request().postDataJSON();
    confirmationRequests.push(confirmation);
    if (confirmation !== 'SIGN OUT MY OTHER SESSIONS') {
      await route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Type SIGN OUT MY OTHER SESSIONS to confirm this action' }),
      });
      return;
    }
    await route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ok: true, revoked_count: 1 }),
    });
  });

  await page.getByRole('button', { name: 'Sign out my other sessions' }).click();
  const dialog = page.locator('#admin-session-reauth-dialog');
  await expect(page.locator('[data-own-session-count]')).toContainText('other dashboard session');
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText('only dashboard logins for your RouterOS account');
  await expect(dialog).toContainText('does not disconnect any VPN tunnel');
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
  expect(confirmationRequests).toEqual(['wrong phrase', 'SIGN OUT MY OTHER SESSIONS']);
  await expect(dialog).toBeHidden();
  await expect(dialog.getByLabel('RouterOS password')).toHaveValue('');
  expect(await page.evaluate(async () => (
    await fetch('/api/telemetry', { credentials: 'same-origin' })
  ).status)).toBe(200);
  await expectNoDocumentReload(page, originalDocument);
});

test('administrator can revoke all dashboard sessions for one other account in place', async ({ page }) => {
  let revoked = false;
  let submitted;
  await page.route('**/api/admin/sessions**', async (route) => {
    if (route.request().method() === 'GET') {
      const sessions = [{
        id: 'current-session',
        username: 'admin',
        role: 'owner',
        source_address: '10.10.10.20',
        auth_method: 'routeros',
        created_at: 1700000000,
        last_seen: 1700000010,
        idle_remaining: 1800,
        absolute_remaining: 28800,
        current: true,
      }];
      if (!revoked) {
        sessions.push(
          {
            id: 'operator-session-a',
            username: 'operator',
            role: 'operator',
            source_address: '10.10.10.21',
            auth_method: 'routeros',
            created_at: 1700000000,
            last_seen: 1700000010,
            idle_remaining: 1800,
            absolute_remaining: 28800,
            current: false,
          },
          {
            id: 'operator-session-b',
            username: 'OPERATOR',
            role: 'operator',
            source_address: '10.10.10.22',
            auth_method: 'routeros',
            created_at: 1700000000,
            last_seen: 1700000010,
            idle_remaining: 1700,
            absolute_remaining: 28700,
            current: false,
          },
        );
      }
      return route.fulfill({
        status: 200,
        contentType: 'application/json',
        body: JSON.stringify({
          sessions,
          idle_timeout_seconds: 1800,
          absolute_timeout_seconds: 28800,
          generated_at: 1700000010,
        }),
      });
    }

    submitted = route.request().postDataJSON();
    const phrase = 'REVOKE ALL DASHBOARD SESSIONS FOR operator';
    if (submitted.confirmation !== phrase) {
      return route.fulfill({
        status: 400,
        contentType: 'application/json',
        body: JSON.stringify({ error: 'Type ' + phrase + ' to confirm this action' }),
      });
    }
    revoked = true;
    return route.fulfill({
      status: 200,
      contentType: 'application/json',
      body: JSON.stringify({ ok: true, username: 'operator', revoked_count: 2 }),
    });
  });

  await signIn(page);
  const originalDocument = await page.evaluate(() => window.__documentInstance);
  await expect(page.getByRole('button', { name: 'End all dashboard sessions for operator' })).toHaveCount(1);
  await expect(page.getByRole('button', { name: 'End all dashboard sessions for admin' })).toHaveCount(0);

  await page.getByRole('button', { name: 'End all dashboard sessions for operator' }).click();
  const dialog = page.locator('#admin-session-reauth-dialog');
  await expect(dialog).toBeVisible();
  await expect(dialog).toContainText('VPN tunnels stay connected');
  const phrase = 'REVOKE ALL DASHBOARD SESSIONS FOR operator';
  await dialog.getByLabel('Type ' + phrase).fill('wrong phrase');
  await dialog.getByLabel('RouterOS password').fill('routerpass');

  const rejected = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/api/admin/sessions/revoke-account'
  ));
  await dialog.getByRole('button', { name: 'Verify and end all sessions' }).click();
  expect((await rejected).status()).toBe(400);
  await expect(dialog.getByRole('status')).toContainText('Type ' + phrase);

  await dialog.getByLabel('Type ' + phrase).fill(phrase);
  await dialog.getByLabel('RouterOS password').fill('routerpass');
  const accepted = page.waitForResponse((response) => (
    response.request().method() === 'POST'
    && new URL(response.url()).pathname === '/api/admin/sessions/revoke-account'
  ));
  await dialog.getByRole('button', { name: 'Verify and end all sessions' }).click();
  expect((await accepted).status()).toBe(200);
  expect(submitted).toMatchObject({
    username: 'operator',
    password: 'routerpass',
    confirmation: phrase,
  });
  await expect(dialog).toBeHidden();
  await expect(page.locator('[data-admin-session-row]').filter({ hasText: 'operator' })).toHaveCount(0);
  await expectNoDocumentReload(page, originalDocument);
});

test('successful re-authentication adopts rotated CSRF and keeps the page in place', async ({ page }) => {
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
  await expectNoDocumentReload(page, originalDocument);

  // A second successful POST proves the SPA's request helper uses the adopted
  // in-memory CSRF token, not just the one returned by the first response.
  await authenticate();
  const secondRotatedCsrf = await page.locator('meta[name="csrf-token"]').getAttribute('content');
  expect(secondRotatedCsrf).not.toBe(rotatedCsrf);
  await expectNoDocumentReload(page, originalDocument);
});

test('API token creation and revocation require step-up without reloading the live page', async ({ page }) => {
  const tokenLabel = `step-up browser ${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  await signIn(page);
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
  await expectNoDocumentReload(page, originalDocument);
});

test('VPN-user password changes require step-up and review active-session disconnects in place', async ({ page }) => {
  let previewPayload;
  let applyPayload;
  await signIn(page);
  const originalDocument = await page.evaluate(() => window.__documentInstance);

  // Keep the browser test isolated from the shared mock RouterOS session used
  // by the other viewport projects. Backend mutation/revocation behavior is
  // covered by the dedicated Python integration tests.
  await page.route((url) => /\/api\/users\/[^/]+(?:\/preview)?$/.test(url.pathname), async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === 'POST' && pathname.endsWith('/preview')) {
      previewPayload = request.postDataJSON();
      return route.fulfill({ json: {
        review_token: 'browser-test-review-token',
        username: 'user-two',
        reason: 'Rotate this VPN user password',
        changes: {
          email: 'user-two@example.test',
          comment: 'Tablet test device',
          disabled: false,
          controls: { policy: 'full-tunnel' },
          password_changed: true,
          active_sessions_to_disconnect: 1,
        },
      } });
    }
    if (request.method() === 'PATCH' && /^\/api\/users\/[^/]+$/.test(pathname)) {
      applyPayload = request.postDataJSON();
      return route.fulfill({ json: {
        verification: 'partial',
        active_sessions_disconnected: 1,
      } });
    }
    return route.continue();
  });

  await page.locator('a[data-view-target="vpn-users"]').click();
  const userCard = page.locator('.user-card').filter({ hasText: 'user-two' });
  await userCard.locator('.action-menu summary').click();
  await userCard.getByRole('button', { name: 'Edit user' }).click();
  const editDialog = page.locator('#edit-dialog');
  await expect(editDialog).toBeVisible();
  await editDialog.getByLabel('Owner email').fill('user-two@example.test');
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
  expect(previewPayload).toMatchObject({
    email: 'user-two@example.test',
    password: 'browser-rotated-vpn-password',
    reason: 'Rotate this VPN user password',
  });
  await expect(reauthDialog).toBeHidden();
  await expect(editDialog.locator('#edit-review')).toContainText('1 active VPN device will be disconnected');

  const applyResponse = page.waitForResponse((response) => (
    response.request().method() === 'PATCH'
    && /\/api\/users\/[^/]+$/.test(new URL(response.url()).pathname)
  ));
  await editDialog.getByRole('button', { name: 'Save changes' }).click();
  expect((await applyResponse).status()).toBe(200);
  expect(applyPayload).toMatchObject({
    password: 'browser-rotated-vpn-password',
    reason: 'Rotate this VPN user password',
    review_token: 'browser-test-review-token',
  });
  await expect(editDialog).toBeHidden();
  await expect(editDialog.getByLabel('New password')).toHaveValue('');
  await expect(page.locator('.toast-region')).toContainText('1 active VPN device was disconnected');
  await expectNoDocumentReload(page, originalDocument);
});
