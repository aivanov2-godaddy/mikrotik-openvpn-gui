const { test, expect } = require('@playwright/test');
const AxeBuilder = require('@axe-core/playwright').default;

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
const accessibilityThemes = [
  { name: 'Standard', choice: 'standard', resolved: 'standard' },
  { name: 'Dark', choice: 'dark', resolved: 'dark' },
  { name: 'Light', choice: 'light', resolved: 'light' },
];

async function expectNoSeriousAxeViolations(page, testInfo, stateName) {
  const results = await new AxeBuilder({ page })
    .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
    .analyze();
  const serious = results.violations
    .filter(({ impact }) => ['critical', 'serious'].includes(impact))
    .flatMap(({ id, impact, nodes }) => nodes.map((node) => ({ id, impact, target: node.target.join(' ') })));
  await testInfo.attach(`axe-${stateName}-serious-findings.json`, {
    body: Buffer.from(JSON.stringify({ state: stateName, findings: serious }, null, 2)),
    contentType: 'application/json',
  });
  expect(serious, `${stateName}: no serious/critical WCAG 2.2 A/AA findings`).toEqual([]);
}

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
    if (view.target === 'overview') {
      const logo = page.getByRole('img', { name: 'OpenVPN', exact: true });
      await expect(logo).toBeVisible();
      const bounds = await logo.boundingBox();
      expect(bounds.x + bounds.width).toBeLessThanOrEqual(await page.evaluate(() => document.documentElement.clientWidth));
    }

    await expect(page).toHaveScreenshot(`${view.target}.png`, {
      fullPage: true,
      style: '#system-status time { visibility: hidden !important; }',
    });
  });
}

test('OpenVPN dashboard logo stays within a narrow mobile viewport', async ({ page }) => {
  await page.setViewportSize({ width: 320, height: 740 });
  const logo = page.getByRole('img', { name: 'OpenVPN', exact: true });
  await expect(logo).toBeVisible();
  const layout = await page.evaluate(() => {
    const brand = document.querySelector('#overview .dashboard-heading-brand');
    const image = document.querySelector('#overview .dashboard-openvpn-logo');
    return {
      brandRight: brand.getBoundingClientRect().right,
      imageRight: image.getBoundingClientRect().right,
      viewportWidth: document.documentElement.clientWidth,
      imageLoaded: image.complete && image.naturalWidth > 0,
    };
  });
  expect(layout.imageLoaded).toBe(true);
  expect(layout.brandRight).toBeLessThanOrEqual(layout.viewportWidth);
  expect(layout.imageRight).toBeLessThanOrEqual(layout.viewportWidth);
});

test('Dashboard warning alert state renders consistently', async ({ page }, testInfo) => {
  test.skip(testInfo.project.name !== 'desktop-1440', 'Additional state snapshots are intentionally desktop-only.');
  await page.getByRole('link', { name: 'Dashboard', exact: true }).click();

  // Exercise the same REST-backed renderer used by status refreshes, but invoke
  // it directly with a fixed alert fixture. EventSource remains disabled by
  // beforeEach, and no stream or timing behavior is part of this screenshot.
  const payload = await page.evaluate(async () => {
    const response = await fetch('/api/status');
    return response.json();
  });
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
  await expectNoSeriousAxeViolations(page, testInfo, 'vpn-users-no-results');
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
  await expectNoSeriousAxeViolations(page, testInfo, 'vpn-users-add-dialog');
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
  await expectNoSeriousAxeViolations(page, testInfo, 'connections-terminate-dialog');
  await expect(page).toHaveScreenshot('connections-terminate-prompt.png', {
    fullPage: true,
    style: '#system-status time { visibility: hidden !important; }',
  });
});

test('certificate migration confirmation refreshes its panel without a full page reload', async ({ page }) => {
  const navigations = [];
  page.on('dialog', (dialog) => dialog.accept());
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.push(frame.url());
  });

  await page.evaluate(() => {
    document.querySelector('[data-view="overview"]').hidden = true;
    document.querySelector('[data-view="profile-security"]').hidden = false;
    const panel = document.querySelector('.migration-panel');
    panel.dataset.refreshMarker = 'before';
    const button = document.createElement('button');
    button.type = 'button';
    button.dataset.migrationStep = 'imported';
    button.dataset.legacyCertificate = 'test-certificate';
    button.textContent = 'Confirm replacement imported';
    panel.querySelector('tbody').replaceChildren(Object.assign(document.createElement('tr'), {
      innerHTML: '<td>Existing certificate</td><td>Test user</td><td>Replacement pending</td><td></td>',
    }));
    panel.querySelector('tbody td:last-child').append(button);
    window.__unrelatedPageState = { preserved: true };
  });
  const refreshedHtml = await page.content();
  const markedHtml = refreshedHtml.replace('data-refresh-marker="before"', 'data-refresh-marker="after"');

  await page.route('**/api/profile-migrations/test-certificate/steps/imported', (route) => route.fulfill({
    status: 200,
    contentType: 'application/json',
    body: '{}',
  }));
  await page.route('**/dashboard', (route) => {
    if (route.request().resourceType() !== 'fetch') return route.continue();
    return route.fulfill({ status: 200, contentType: 'text/html', body: markedHtml });
  });

  await page.getByRole('button', { name: 'Confirm replacement imported' }).click();

  await expect(page.locator('.migration-panel')).toHaveAttribute('data-refresh-marker', 'after');
  await expect(page.locator('[data-view="profile-security"]')).toBeVisible();
  expect(navigations).toEqual([]);
  expect(await page.evaluate(() => window.__unrelatedPageState)).toEqual({ preserved: true });
});

test('replacement profile issuance refreshes certificate status without interrupting the page', async ({ page }) => {
  const navigations = [];
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.push(frame.url());
  });

  await page.evaluate(() => {
    const panel = document.querySelector('.migration-panel');
    panel.dataset.refreshMarker = 'before';
    const form = document.querySelector('#profile-form');
    form.elements.user_id.value = 'synthetic-user';
    form.elements.delivery.value = 'zip';
    form.elements.legacy_certificate.value = 'legacy-test-certificate';
    form.elements.review_token.value = 'reviewed-synthetic-request';
    form.elements.device_name.value = 'Replacement phone';
    form.elements.reason.value = 'Operator-approved replacement test';
    form.elements.key_passphrase.value = 'synthetic-only-passphrase';
    document.querySelector('[data-profile-user]').textContent = 'Synthetic user';
    document.querySelector('#profile-dialog').showModal();
    window.__unrelatedPageState = { preserved: true };
  });

  const refreshedHtml = await page.content();
  const markedHtml = refreshedHtml.replace('data-refresh-marker="before"', 'data-refresh-marker="after"');
  await page.route('**/api/users/synthetic-user/profiles', (route) => route.fulfill({
    status: 200,
    headers: {
      'content-type': 'application/zip',
      'content-disposition': 'attachment; filename="synthetic-profile.zip"',
    },
    body: 'synthetic archive only',
  }));
  await page.route('**/dashboard', (route) => {
    if (route.request().resourceType() !== 'fetch') return route.continue();
    return route.fulfill({ status: 200, contentType: 'text/html', body: markedHtml });
  });

  const download = page.waitForEvent('download');
  await page.locator('[data-profile-submit]').click();
  await download;

  await expect(page.locator('.migration-panel')).toHaveAttribute('data-refresh-marker', 'after');
  await expect(page.locator('#profile-dialog')).not.toBeVisible();
  expect(navigations).toEqual([]);
  expect(await page.evaluate(() => window.__unrelatedPageState)).toEqual({ preserved: true });
});

for (const theme of accessibilityThemes) {
  for (const view of accessibilityViews) {
    test(`${view.name} has no serious WCAG 2.2 A/AA violations in ${theme.name} theme`, async ({ page }, testInfo) => {
      await page.locator('.theme-menu > summary').click();
      await page.locator(`[data-theme-choice="${theme.choice}"]`).click();
      await expect(page.locator('html')).toHaveAttribute('data-theme-resolved', theme.resolved);
      if (view.target !== 'overview') {
        await page.getByRole('link', { name: view.name, exact: true }).click();
      }
      await expect(page.getByRole('heading', { name: view.heading, exact: true })).toBeVisible();
      await page.waitForLoadState('networkidle');

      const results = await new AxeBuilder({ page })
        .withTags(['wcag2a', 'wcag2aa', 'wcag21a', 'wcag21aa', 'wcag22aa'])
        .analyze();
      const serious = results.violations
        .filter(({ impact }) => ['critical', 'serious'].includes(impact))
        .flatMap(({ id, impact, nodes }) => nodes.map((node) => ({ id, impact, target: node.target.join(' ') })));
      await testInfo.attach('axe-serious-findings.json', {
        body: Buffer.from(JSON.stringify({ view: view.target, theme: theme.choice, findings: serious }, null, 2)),
        contentType: 'application/json',
      });
      expect(serious, `${view.name}/${theme.name}: no serious/critical WCAG findings (including contrast)`)
        .toEqual([]);
    });
  }
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

test('staged certificate renewal explains impact and stops at explicit review', async ({ page }) => {
  await page.getByRole('link', { name: 'Device Profiles', exact: true }).click();
  const firstUser = page.locator('.user-card').first();
  const userId = await firstUser.getAttribute('data-user-id');
  const userName = await firstUser.getAttribute('data-user-name');
  expect(userId).toBeTruthy();
  expect(userName).toBeTruthy();

  // The local mock fixture has no expiring certificate. Add the same delegated
  // action contract emitted by the server-rendered certificate inventory so
  // this browser test can exercise the renewal dialog without touching RouterOS.
  await page.evaluate(({ id, name }) => {
    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.textContent = 'Renew certificate';
    trigger.dataset.migrateProfile = '';
    trigger.dataset.userId = id;
    trigger.dataset.userName = name;
    trigger.dataset.legacyCertificate = 'managed-expiring-test-device';
    trigger.dataset.legacyDevice = 'Test device';
    trigger.dataset.replacementType = 'renewal';
    document.querySelector('[data-view="profile-security"]').append(trigger);
  }, { id: userId, name: userName });

  const previewRequests = [];
  const profileMutations = [];
  page.on('request', (request) => {
    if (request.method() !== 'POST') return;
    if (request.url().endsWith('/profiles/preview')) previewRequests.push(request);
    else if (/\/profiles(?:\?|$)/.test(new URL(request.url()).pathname)) profileMutations.push(request);
  });
  await page.route('**/api/users/*/profiles/preview', async (route) => {
    await route.fulfill({ json: {
      user: userName,
      device: 'Test device replacement',
      reason: 'Replace the expiring test device certificate',
      policy: 'full-tunnel',
      dns_mode: 'router',
      delivery: 'zip',
      legacy_migration: true,
      replacement_type: 'renewal',
      old_profile_remains_active: true,
      review_token: 'synthetic-review-token',
    } });
  });

  await page.getByRole('button', { name: 'Renew certificate', exact: true }).click();
  const dialog = page.locator('#profile-dialog');
  await expect(dialog.locator('[data-profile-title]')).toHaveText('Renew device certificate');
  await expect(dialog.locator('[data-profile-description]')).toContainText('does not revoke the existing certificate');
  await expect(dialog.locator('[data-migration-note]')).toContainText('No connection will be interrupted');

  await dialog.getByLabel('Phone or device').fill('Test device replacement');
  await dialog.getByLabel('Reason for issuing access').fill('Replace the expiring test device certificate');
  await dialog.getByLabel('Protect file with').fill('synthetic-passphrase');
  await dialog.getByRole('button', { name: 'Review profile request' }).click();

  await expect(dialog.locator('[data-profile-review]')).toContainText('without revoking the existing certificate');
  await expect(dialog.locator('[data-profile-submit]')).toHaveText('Create and download .zip');
  await expect.poll(() => previewRequests.length).toBe(1);
  expect(JSON.parse(previewRequests[0].postData()).legacy_certificate).toBe('managed-expiring-test-device');
  expect(profileMutations).toHaveLength(0);

  await dialog.getByLabel('Phone or device').fill('Different replacement device');
  await expect(dialog.locator('[data-profile-review]')).toBeHidden();
  await expect(dialog.locator('[data-profile-submit]')).toHaveText('Review profile request');
  expect(profileMutations).toHaveLength(0);

  await dialog.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toBeHidden();
  expect(profileMutations).toHaveLength(0);
});

test('certificate revocation stays disabled until target confirmation and fresh review', async ({ page }) => {
  await page.getByRole('link', { name: 'Device Profiles', exact: true }).click();
  await page.evaluate(() => {
    const trigger = document.createElement('button');
    trigger.type = 'button';
    trigger.textContent = 'Revoke device';
    trigger.dataset.deviceRevoke = '';
    trigger.dataset.deviceId = 'synthetic-retirement-device';
    trigger.dataset.deviceName = 'Test laptop';
    document.querySelector('[data-view="profile-security"]').append(trigger);
  });

  const previewRequests = [];
  const revokeRequests = [];
  page.on('request', (request) => {
    if (request.method() !== 'POST') return;
    if (request.url().endsWith('/revoke/preview')) previewRequests.push(request);
    else if (request.url().endsWith('/revoke')) revokeRequests.push(request);
  });
  await page.route('**/api/devices/synthetic-retirement-device/revoke/preview', async (route) => {
    await route.fulfill({ json: {
      device: 'Test laptop',
      vpn_user: 'synthetic-user',
      certificate: 'synthetic-certificate',
      active_sessions_for_user: 0,
      active_sessions_scope: 'RouterOS snapshot',
      effect: 'New connections using this certificate will be rejected when CRL enforcement applies.',
      review_token: `synthetic-review-${previewRequests.length + 1}`,
    } });
  });

  await page.getByRole('button', { name: 'Revoke device', exact: true }).click();
  const dialog = page.locator('#revoke-device-dialog');
  const reason = dialog.getByLabel('Reason for revocation');
  const confirmation = dialog.getByLabel('Type Test laptop to confirm');
  const review = dialog.getByRole('button', { name: 'Review impact' });
  const apply = dialog.getByRole('button', { name: 'Revoke certificate' });

  await expect(apply).toBeDisabled();
  await reason.fill('Replacement profile verified on the test device');
  await confirmation.fill('Wrong target');
  await expect(apply).toBeDisabled();
  await confirmation.fill('Test laptop');
  await expect(apply).toBeDisabled();

  await review.click();
  await expect(dialog.locator('[data-revoke-preview-text]')).toContainText('certificate synthetic-certificate is active on RouterOS');
  await expect(apply).toBeEnabled();
  await expect.poll(() => previewRequests.length).toBe(1);
  expect(revokeRequests).toHaveLength(0);

  await confirmation.fill('Wrong target');
  await expect(apply).toBeDisabled();
  await expect(dialog.locator('[data-revoke-summary]')).toBeHidden();
  await expect(review).toBeVisible();
  expect(revokeRequests).toHaveLength(0);

  await page.getByRole('button', { name: 'Cancel' }).click();
  await expect(dialog).toBeHidden();
  expect(revokeRequests).toHaveLength(0);
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
    const focusStyle = await link.evaluate((element) => {
      const style = getComputedStyle(element);
      return {
        outlineStyle: style.outlineStyle,
        outlineWidth: Number.parseFloat(style.outlineWidth),
        outlineOffset: Number.parseFloat(style.outlineOffset),
      };
    });
    expect(focusStyle.outlineStyle, `${view.name}: keyboard focus has a visible outline`).toBe('solid');
    expect(focusStyle.outlineWidth, `${view.name}: focus outline is at least 2 CSS pixels`).toBeGreaterThanOrEqual(2);
    expect(focusStyle.outlineOffset, `${view.name}: focus ring is offset from the control`).toBeGreaterThan(0);
    await page.keyboard.press('Enter');
    await expect(page.locator(`[data-view="${view.target}"]`)).toBeVisible();
    await expect(link).toHaveAttribute('aria-current', 'page');
    await expect(page.getByRole('heading', { name: view.heading, exact: true })).toBeVisible();
    if (view.target === 'vpn-users') {
      await expect(page.getByRole('button', { name: 'Add VPN user' })).toBeVisible();
    }
  }
});

test('720 CSS-pixel reflow keeps all operator views reachable', async ({ page }) => {
  // 720 CSS px is a 200%-zoom-equivalent reflow approximation for a 1440px
  // desktop layout. It does not emulate actual browser zoom.
  await page.setViewportSize({ width: 720, height: 500 });
  await expect(page.getByRole('link', { name: 'VPN Users', exact: true })).toBeVisible();
  for (const view of accessibilityViews) {
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
    element.scrollLeft = 0;
    const maxScroll = element.scrollWidth - element.clientWidth;
    element.scrollLeft = maxScroll;
    const moved = maxScroll > 0 && element.scrollLeft > 0;
    element.scrollLeft = before;
    return moved;
  });
  expect(navigationCanScroll, 'primary navigation remains horizontally scrollable').toBe(true);
});

test('574 CSS-pixel zoom-equivalent viewport keeps the header within the page', async ({ page }) => {
  // A 1148px desktop viewport at 200% browser zoom is approximately 574 CSS px.
  // This complements the narrower 539px guard and does not emulate browser zoom.
  await page.setViewportSize({ width: 574, height: 700 });

  const headerGeometry = await page.locator('.winbox-menubar').evaluate((header) => {
    const signOut = header.querySelector('.top-logout button');
    return {
      clientWidth: header.clientWidth,
      scrollWidth: header.scrollWidth,
      signOutRight: signOut.getBoundingClientRect().right,
      viewportWidth: window.innerWidth,
    };
  });
  expect(headerGeometry.scrollWidth, 'header contents must not overflow horizontally')
    .toBeLessThanOrEqual(headerGeometry.clientWidth);
  expect(headerGeometry.signOutRight, 'sign-out control must remain fully in the viewport')
    .toBeLessThanOrEqual(headerGeometry.viewportWidth);

  const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(pageWidth, 'the document must not overflow at the tested viewport').toBeLessThanOrEqual(574);
});

test('539 CSS-pixel 200% zoom-equivalent viewport keeps sign-out label readable', async ({ page }) => {
  // A 1078px desktop viewport at 200% browser zoom has roughly this CSS width.
  // This checks the responsive layout equivalent, not the browser zoom setting.
  await page.setViewportSize({ width: 539, height: 700 });
  const signOutButton = page.getByRole('button', { name: /Sign out/ });
  await expect(signOutButton).toBeVisible();

  const buttonGeometry = await page.locator('.top-logout button').evaluate((button) => ({
    clientWidth: button.clientWidth,
    scrollWidth: button.scrollWidth,
    labelVisible: getComputedStyle(button.querySelector('span')).display !== 'none',
  }));
  expect(buttonGeometry.labelVisible, 'the sign-out label remains present at this width').toBe(true);
  expect(buttonGeometry.scrollWidth, 'the sign-out label must not be clipped by flex shrink')
    .toBeLessThanOrEqual(buttonGeometry.clientWidth);

  const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(pageWidth, 'the page must not overflow the zoom-equivalent viewport').toBeLessThanOrEqual(539);
});

test('dashboard metric context wraps instead of truncating at 200%-zoom width', async ({ page }) => {
  // A 1080px desktop at 200% zoom is approximately 540 CSS px. This viewport
  // approximation supplements, but does not replace, a real browser-zoom check.
  await page.setViewportSize({ width: 540, height: 700 });
  const context = page.locator('#overview .metric span').filter({ hasText: 'Internet and home network protected' });
  await expect(context).toBeVisible();
  const layout = await context.evaluate((element) => {
    const style = getComputedStyle(element);
    return {
      whiteSpace: style.whiteSpace,
      textOverflow: style.textOverflow,
      lineClamp: style.webkitLineClamp,
      width: element.clientWidth,
      scrollWidth: element.scrollWidth,
    };
  });
  expect(layout.whiteSpace, 'essential metric context can wrap').toBe('normal');
  expect(layout.textOverflow, 'essential metric context is not ellipsized').toBe('clip');
  expect(layout.lineClamp, 'metric context remains compact').toBe('2');
  expect(layout.width, 'metric context has a rendered width').toBeGreaterThan(0);
  expect(layout.scrollWidth, 'metric context does not overflow its box').toBeLessThanOrEqual(layout.width);
  const pageWidth = await page.evaluate(() => document.documentElement.scrollWidth);
  expect(pageWidth, 'the page must not overflow at the zoom-equivalent viewport').toBeLessThanOrEqual(540);
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
