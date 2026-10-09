const { test, expect } = require('@playwright/test');

// Replacement-profile inputs and the downloaded archive in this test are
// synthetic. Do not persist traces, screenshots, or video that could capture
// profile form fields or download data if the regression fails.
test.use({ screenshot: 'off', trace: 'off', video: 'off' });

test.beforeEach(async ({ page }) => {
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

test('replacement profile issuance refreshes its result without recreating the live stream', async ({ page }) => {
  await page.getByRole('link', { name: 'Device Profiles', exact: true }).click();
  const navigations = [];
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.push(frame.url());
  });

  await page.evaluate(() => {
    class MockEventSource extends EventTarget {
      constructor(url, options) {
        super();
        this.url = url;
        this.withCredentials = options?.withCredentials;
        this.closed = false;
        this.readyState = 1;
        window.__mockEventSources.push(this);
      }

      emit(type, data) {
        const event = new Event(type);
        Object.defineProperty(event, 'data', { value: data });
        this.dispatchEvent(event);
      }

      close() {
        this.closed = true;
        this.readyState = 2;
      }
    }

    window.__mockEventSources = [];
    window.EventSource = MockEventSource;
    window.connectRealtime();
    window.__mockEventSource = window.__mockEventSources[0];

    document.querySelector('.migration-panel').dataset.refreshMarker = 'before';
    const form = document.querySelector('#profile-form');
    form.elements.user_id.value = 'synthetic-user';
    form.elements.delivery.value = 'zip';
    form.elements.legacy_certificate.value = 'legacy-test-certificate';
    form.elements.review_token.value = 'reviewed-synthetic-request';
    form.elements.device_name.value = 'Synthetic replacement device';
    form.elements.reason.value = 'Synthetic replacement browser regression';
    form.elements.key_passphrase.value = 'test-only-dummy-passphrase';
    document.querySelector('[data-profile-user]').textContent = 'Synthetic user';
    document.querySelector('#profile-dialog').showModal();
    window.__unrelatedPageState = { preserved: true };
  });

  expect(await page.evaluate(() => ({
    count: window.__mockEventSources.length,
    open: !window.__mockEventSource.closed,
    url: window.__mockEventSource.url,
  }))).toEqual({ count: 1, open: true, url: '/api/events' });

  const refreshedHtml = await page.evaluate(() => {
    const refreshedDocument = document.cloneNode(true);
    const panel = refreshedDocument.querySelector('.migration-panel');
    panel.dataset.refreshMarker = 'after';
    const row = refreshedDocument.createElement('tr');
    [
      'Synthetic legacy certificate',
      'Synthetic owner',
      'Replacement issued; import pending',
      'Import and test before retirement',
    ].forEach((value) => {
      const cell = refreshedDocument.createElement('td');
      cell.textContent = value;
      row.append(cell);
    });
    panel.querySelector('tbody').replaceChildren(row);
    return `<!doctype html>${refreshedDocument.documentElement.outerHTML}`;
  });

  let profileIssueRequests = 0;
  await page.route('**/api/users/synthetic-user/profiles', (route) => {
    profileIssueRequests += 1;
    return route.fulfill({
      status: 200,
      headers: {
        'content-type': 'application/zip',
        'content-disposition': 'attachment; filename="synthetic-profile.zip"',
      },
      body: 'synthetic archive only',
    });
  });
  let panelRefreshRequests = 0;
  await page.route('**/dashboard', (route) => {
    if (route.request().resourceType() !== 'fetch') return route.continue();
    panelRefreshRequests += 1;
    return route.fulfill({ status: 200, contentType: 'text/html', body: refreshedHtml });
  });

  const download = page.waitForEvent('download');
  await page.locator('[data-profile-submit]').click();
  await download;

  await expect(page.locator('.migration-panel')).toHaveAttribute('data-refresh-marker', 'after');
  await expect(page.locator('.migration-table tbody')).toContainText('Replacement issued; import pending');
  await expect(page.locator('#profile-dialog')).not.toBeVisible();
  await expect(page.locator('[data-view="profile-security"]')).toBeVisible();
  expect(profileIssueRequests).toBe(1);
  expect(panelRefreshRequests).toBe(1);
  expect(navigations).toEqual([]);
  expect(await page.evaluate(() => window.__unrelatedPageState)).toEqual({ preserved: true });

  await page.evaluate(() => {
    window.__mockEventSource.emit('status', JSON.stringify({
      sessions: [{
        id: 'synthetic-live-session',
        name: 'synthetic-live-user',
        uptime: '1m',
        source_address: '192.0.2.20',
        vpn_address: '10.8.0.20',
        encoding: 'AES-256-GCM',
        rx_bytes: 1024,
        tx_bytes: 2048,
        rx_packets: 10,
        tx_packets: 20,
      }],
    }));
  });
  await expect(page.locator('[data-active-session-list]')).toContainText('synthetic-live-user');
  await expect(page.locator('[data-live-indicator]').first()).toContainText('Live · SSE');
  expect(await page.evaluate(() => ({
    count: window.__mockEventSources.length,
    sameSource: window.__mockEventSource === window.__mockEventSources[0],
    open: !window.__mockEventSource.closed,
  }))).toEqual({ count: 1, sameSource: true, open: true });
  expect(navigations).toEqual([]);
});
