const { test, expect } = require('@playwright/test');

test('falls back to SSE and applies a live snapshot after Socket.IO transport failure', async ({ page }) => {
  await page.clock.setFixedTime(new Date('2026-10-03T12:00:00.000Z'));

  let sseConnections = 0;
  await page.route('**/api/telemetry', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ transport: 'socketio', socketio_enabled: true, socketio_engine: 'asgi' }),
  }));
  await page.route('**/static/socket.io.min.js*', (route) => route.fulfill({
    contentType: 'application/javascript',
    body: `window.io = () => {
      const handlers = new Map();
      const socket = {
        on(name, callback) {
          handlers.set(name, callback);
          if (name === 'connect_error') setTimeout(() => callback(new Error('synthetic transport failure')), 0);
          return socket;
        },
        close() {},
      };
      return socket;
    };`,
  }));
  await page.route('**/api/events', async (route) => {
    sseConnections += 1;
    await route.fulfill({
      status: 200,
      contentType: 'text/event-stream',
      headers: { 'cache-control': 'no-cache' },
      body: [
        'event: status',
        'data: {"sessions":[{"id":"synthetic-session","name":"synthetic-user","encoding":"AES-256-GCM","vpn_address":"10.8.0.99","source_address":"192.0.2.99","uptime":"1m","rx_bytes":1024,"tx_bytes":2048,"rx_packets":10,"tx_packets":20}]}',
        '',
        '',
      ].join('\n'),
    });
  });

  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();

  await expect.poll(() => sseConnections, { timeout: 10_000 })
    .toBeGreaterThan(0);
  await expect(page.locator('[data-session-total]').first()).toHaveText('1');
  await page.getByRole('link', { name: 'Connections', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Connected Devices', exact: true })).toBeVisible();
  await expect(page.getByText('synthetic-user', { exact: true }).first()).toBeVisible();
});
