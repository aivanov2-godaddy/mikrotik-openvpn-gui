const { test, expect } = require('@playwright/test');

test('Connections selection survives live replacement and each disconnect keeps its individual review', async ({ page }) => {
  await page.clock.setFixedTime(new Date('2026-10-03T12:00:00.000Z'));
  await page.addInitScript(() => {
    Object.defineProperty(window, 'EventSource', { configurable: true, value: undefined });
    const nativeTimeout = window.setTimeout.bind(window);
    const nativeInterval = window.setInterval.bind(window);
    window.setTimeout = (handler, delay, ...args) => (
      delay === 1200 ? 0 : nativeTimeout(handler, delay, ...args)
    );
    window.setInterval = (handler, delay, ...args) => (
      delay === 5000 ? 0 : nativeInterval(handler, delay, ...args)
    );
  });
  await page.route('**/api/status', (route) => route.abort());
  await page.route('**/api/telemetry', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ transport: 'socketio', socketio_enabled: true, socketio_engine: 'asgi' }),
  }));
  await page.route('**/static/socket.io.min.js*', (route) => route.fulfill({
    contentType: 'application/javascript',
    body: `window.__liveTestSocket = {
      handlers: new Map(),
      on(name, callback) { this.handlers.set(name, callback); return this; },
      close() {},
      emit(name, payload) { this.handlers.get(name)?.(payload); },
    };
    window.io = () => window.__liveTestSocket;`,
  }));

  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();
  await expect.poll(() => page.evaluate(() => (
    window.__liveTestSocket?.handlers.has('telemetry.snapshot')
  ))).toBe(true);

  await page.getByRole('link', { name: 'Connections', exact: true }).click();
  const selected = page.getByRole('checkbox', { name: 'Select active connection for user-two' });
  await selected.focus();
  await page.keyboard.press('Space');
  await expect(selected).toBeChecked();
  await expect(page.getByRole('button', { name: 'Review selected disconnects' })).toBeEnabled();
  await expect(page.locator('[data-session-selection-count]')).toHaveAttribute('aria-live', 'polite');

  await page.evaluate(() => {
    window.scrollTo(0, Math.min(120, document.documentElement.scrollHeight));
    window.__selectionScrollBefore = window.scrollY;
    window.__selectionTimeOrigin = performance.timeOrigin;
    window.__liveTestSocket.emit('telemetry.snapshot', { payload: { sessions: [
      {
        id: '*A1', name: 'user-two', source_address: '192.0.2.8', vpn_address: '10.8.0.8',
        encoding: 'AES-256-GCM', uptime: '2m', rx_bytes: 4096, tx_bytes: 8192,
        rx_packets: 20, tx_packets: 30,
      },
      {
        id: '*B2', name: 'user-three', source_address: '192.0.2.9', vpn_address: '10.8.0.9',
        encoding: 'AES-256-GCM', uptime: '1m', rx_bytes: 512, tx_bytes: 1024,
        rx_packets: 5, tx_packets: 8,
      },
    ] } });
  });

  await expect(page.locator('[data-active-session-list] .session-card')).toHaveCount(2);
  await expect(selected).toBeChecked();
  await expect(selected).toBeFocused();
  expect(await page.evaluate(() => window.scrollY)).toBe(await page.evaluate(() => window.__selectionScrollBefore));
  expect(await page.evaluate(() => performance.timeOrigin)).toBe(await page.evaluate(() => window.__selectionTimeOrigin));

  let previewCalls = 0;
  let terminationCalls = 0;
  await page.route((url) => url.pathname === '/api/sessions/*A1/preview', async (route) => {
    previewCalls += 1;
    await route.fulfill({ json: {
      username: 'user-two', reason: 'Operator reviewed test disconnect', review_token: 'single-use-review-token',
    } });
  });
  page.on('request', (request) => {
    if (request.method() === 'DELETE' && request.url().includes('/api/sessions/')) terminationCalls += 1;
  });

  await page.getByRole('button', { name: 'Review selected disconnects' }).click();
  await expect(page.getByRole('region', { name: 'Sequential connection review' })).toBeVisible();
  await expect(page.locator('[data-session-bulk-review-list]')).toContainText('user-two');
  await page.getByRole('button', { name: 'Review next session' }).click();
  const dialog = page.locator('#terminate-dialog');
  await expect(dialog).toBeVisible();
  const terminate = dialog.getByRole('button', { name: 'Terminate session' });
  await expect(terminate).toBeDisabled();
  await dialog.getByLabel('Reason for disconnecting').fill('Operator reviewed test disconnect');
  await dialog.getByLabel('Type user-two to confirm').fill('user-two');
  await expect(terminate).toBeDisabled();
  await dialog.getByRole('button', { name: 'Review impact' }).click();
  await expect.poll(() => previewCalls).toBe(1);
  await expect(terminate).toBeEnabled();
  await expect.poll(() => terminationCalls).toBe(0);

  await dialog.getByLabel('Reason for disconnecting').fill('Changed after preview, must review again');
  await expect(terminate).toBeDisabled();
  await expect.poll(() => terminationCalls).toBe(0);
  await dialog.getByRole('button', { name: 'Keep connected' }).click();
  await expect(dialog).toBeHidden();
  await expect(page.getByRole('button', { name: 'Review next session' })).toBeEnabled();
  await page.getByRole('button', { name: 'Cancel remaining reviews' }).click();
  await expect(page.locator('[data-session-bulk-review]')).toBeHidden();
  await expect.poll(() => terminationCalls).toBe(0);

  const remainingSelection = page.getByRole('checkbox', { name: 'Select active connection for user-three' });
  await selected.focus();
  await page.evaluate(() => {
    window.__liveTestSocket.emit('telemetry.snapshot', { payload: { sessions: [
      {
        id: '*B2', name: 'user-three', source_address: '192.0.2.9', vpn_address: '10.8.0.9',
        encoding: 'AES-256-GCM', uptime: '2m', rx_bytes: 1024, tx_bytes: 2048,
        rx_packets: 10, tx_packets: 16,
      },
    ] } });
  });
  await expect(page.locator('[data-active-session-list] .session-card')).toHaveCount(1);
  await expect(remainingSelection).not.toBeChecked();
  await expect(remainingSelection).toBeFocused();
  await expect(page.locator('[data-session-selection-count]')).toHaveText('0 selected');
  await expect(page.locator('[data-session-bulk-status]')).toContainText('1 selected connection ended');
  await expect.poll(() => terminationCalls).toBe(0);
});
