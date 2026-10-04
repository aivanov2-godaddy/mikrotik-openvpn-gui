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

test('reconnects the live stream and applies a fresh snapshot when a sleeping tab wakes', async ({ page }) => {
  await page.addInitScript(() => {
    window.__syntheticEventSources = [];
    window.__appliedStreamSnapshots = [];
    window.EventSource = class SyntheticEventSource {
      constructor() {
        this.handlers = new Map();
        this.closed = false;
        window.__syntheticEventSources.push(this);
      }

      addEventListener(name, callback) {
        this.handlers.set(name, callback);
        if (name === 'status') {
          const index = window.__syntheticEventSources.length;
          const data = JSON.stringify({
              sessions: [{
                id: `wake-session-${index}`,
                name: `wake-user-${index}`,
                encoding: 'AES-256-GCM',
                vpn_address: '10.8.0.99',
                source_address: '192.0.2.99',
                uptime: '1m',
                rx_bytes: index * 1024,
                tx_bytes: index * 2048,
                rx_packets: index * 10,
                tx_packets: index * 20,
              }],
            });
          queueMicrotask(() => {
            callback({ data });
            window.__appliedStreamSnapshots.push(
              [...document.querySelectorAll('[data-active-session-list] .session-card strong')]
                .map((item) => item.textContent),
            );
          });
        }
      }

      close() { this.closed = true; }
    };
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
  await expect(page.locator('[data-active-session-list] .session-card strong').first())
    .toHaveText('wake-user-1');

  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, value: true });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect.poll(() => page.evaluate(() => window.__syntheticEventSources[0]?.closed))
    .toBe(true);

  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, value: false });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect.poll(() => page.evaluate(() => window.__syntheticEventSources.length))
    .toBe(2);
  await expect.poll(() => page.evaluate(() => window.__appliedStreamSnapshots
    .some((names) => names.includes('wake-user-2')))).toBe(true);
});

test('reconnects Socket.IO and applies a fresh snapshot when a sleeping tab wakes', async ({ page }) => {
  await page.route('**/api/telemetry', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ transport: 'socketio', socketio_enabled: true, socketio_engine: 'asgi' }),
  }));
  await page.route('**/static/socket.io.min.js*', (route) => route.fulfill({
    contentType: 'application/javascript',
    body: `window.__syntheticSockets = [];
      window.__appliedStreamSnapshots = [];
      window.io = () => {
        const handlers = new Map();
        const index = window.__syntheticSockets.length + 1;
        const socket = {
          closed: false,
          on(name, callback) {
            handlers.set(name, callback);
            if (name === 'telemetry.snapshot') {
              const frame = { payload: { sessions: [{
                id: 'wake-socket-session-' + index,
                name: 'wake-socket-user-' + index,
                encoding: 'AES-256-GCM',
                vpn_address: '10.8.0.99',
                source_address: '192.0.2.99',
                uptime: '1m',
                rx_bytes: index * 1024,
                tx_bytes: index * 2048,
                rx_packets: index * 10,
                tx_packets: index * 20,
              }] } };
              queueMicrotask(() => {
                callback(frame);
                window.__appliedStreamSnapshots.push(
                  [...document.querySelectorAll('[data-active-session-list] .session-card strong')]
                    .map((item) => item.textContent),
                );
              });
            }
            return socket;
          },
          close() { this.closed = true; },
        };
        window.__syntheticSockets.push(socket);
        return socket;
      };`,
  }));

  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.locator('[data-active-session-list] .session-card strong').first())
    .toHaveText('wake-socket-user-1');

  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, value: true });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect.poll(() => page.evaluate(() => window.__syntheticSockets[0]?.closed))
    .toBe(true);

  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, value: false });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect.poll(() => page.evaluate(() => window.__syntheticSockets.length))
    .toBe(2);
  await expect.poll(() => page.evaluate(() => window.__appliedStreamSnapshots
    .some((names) => names.includes('wake-socket-user-2')))).toBe(true);
});
