const { test, expect } = require('@playwright/test');

test('same-origin polling GET carries Referer evidence under the dashboard policy', async ({ page }) => {
  let pollingHeaders = null;
  await page.route('**/api/telemetry', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ transport: 'socketio', socketio_enabled: true, socketio_engine: 'asgi' }),
  }));
  await page.route('**/static/socket.io.min.js*', (route) => route.fulfill({
    contentType: 'application/javascript',
    body: 'window.io = () => ({ on() { return this; }, close() {} });',
  }));
  await page.route('**/socket.io/**', async (route) => {
    pollingHeaders = await route.request().allHeaders();
    await route.fulfill({ status: 403, body: '' });
  });

  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();
  const dashboardUrl = page.url();

  await page.evaluate(() => fetch('/socket.io/?EIO=4&transport=polling', { credentials: 'same-origin' }));

  await expect.poll(() => pollingHeaders).not.toBeNull();
  expect(pollingHeaders.referer).toBe(dashboardUrl);
});

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
  await expect(page.locator('#system-status [data-session-total]')).toHaveText('1');
  await page.getByRole('link', { name: 'Connections', exact: true }).click();
  await expect(page.getByRole('heading', { name: 'Connected Devices', exact: true })).toBeVisible();
  await expect(page.getByText('synthetic-user', { exact: true }).first()).toBeVisible();
});

test('a failed status poll does not mark a recent Socket.IO snapshot as delayed', async ({ page }) => {
  let statusPolls = 0;
  await page.route('**/api/status', async (route) => {
    statusPolls += 1;
    await route.abort();
  });
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
  await expect.poll(() => statusPolls).toBeGreaterThan(0);

  await page.evaluate(() => window.__liveTestSocket.handlers.get('telemetry.snapshot')({
    payload: { sessions: [] },
  }));
  const indicators = page.locator('[data-live-indicator]');
  await expect(indicators).toHaveText(['Live · SOCKETIO', 'Live · SOCKETIO']);
  await page.getByRole('link', { name: 'Connections', exact: true }).click();
  const staleHistoryRow = page.locator('[data-router-session-id="*A1"]');
  await expect(staleHistoryRow.locator('.history-status')).toHaveText('Ended');
  await expect(staleHistoryRow.locator('td:nth-child(2) small')).toHaveText('Ended · syncing history');

  await expect.poll(() => statusPolls, { timeout: 8000 }).toBeGreaterThan(1);
  await expect(indicators).toHaveText(['Live · SOCKETIO', 'Live · SOCKETIO']);
});

test('a healthy Socket.IO heartbeat keeps quiet telemetry from appearing delayed', async ({ page }) => {
  await page.clock.install({ time: new Date('2026-10-03T12:00:00.000Z') });
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
    };
    window.io = () => window.__liveTestSocket;`,
  }));
  await page.route('**/api/status', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({
      telemetry: { state: 'stale', event_age_seconds: 30, transport: 'socketio' },
    }),
  }));

  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect.poll(() => page.evaluate(() => (
    window.__liveTestSocket?.handlers.has('telemetry.health')
  ))).toBe(true);

  await page.evaluate(() => window.__liveTestSocket.handlers.get('telemetry.health')({
    state: 'healthy', stream_connected: true,
  }));
  await expect(page.locator('[data-live-indicator]'))
    .toHaveText(['Live · SOCKETIO', 'Live · SOCKETIO']);
  await page.clock.fastForward(12_000);
  await expect(page.locator('[data-live-indicator]'))
    .toHaveText(['Live · SOCKETIO', 'Live · SOCKETIO']);
});

test('falls back to SSE when the connected Socket.IO upstream reports degraded health', async ({ page }) => {
  await page.addInitScript(() => {
    window.__degradedFallbackSockets = [];
    window.__degradedFallbackSources = [];
    window.EventSource = class DegradedFallbackEventSource {
      constructor(url) {
        this.url = url;
        this.handlers = new Map();
        this.closed = false;
        window.__degradedFallbackSources.push(this);
      }

      addEventListener(name, callback) { this.handlers.set(name, callback); }
      close() { this.closed = true; }
      emit(name, payload) { this.handlers.get(name)?.({ data: JSON.stringify(payload) }); }
    };
  });
  await page.route('**/api/telemetry', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ transport: 'socketio', socketio_enabled: true, socketio_engine: 'asgi' }),
  }));
  await page.route('**/static/socket.io.min.js*', (route) => route.fulfill({
    contentType: 'application/javascript',
    body: `window.io = () => {
      const handlers = new Map();
      const socket = {
        handlers,
        closed: false,
        on(name, callback) { handlers.set(name, callback); return socket; },
        close() { this.closed = true; },
        emit(name, payload) { handlers.get(name)?.(payload); },
      };
      window.__degradedFallbackSockets.push(socket);
      return socket;
    };`,
  }));

  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect.poll(() => page.evaluate(() => (
    window.__degradedFallbackSockets[0]?.handlers.has('telemetry.health')
  ))).toBe(true);

  await page.evaluate(() => window.__degradedFallbackSockets[0].emit('telemetry.health', {
    state: 'healthy', stream_connected: true,
  }));
  await expect(page.locator('[data-live-indicator]'))
    .toHaveText(['Live · SOCKETIO', 'Live · SOCKETIO']);

  const navigations = [];
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.push(frame.url());
  });
  await page.evaluate(() => window.__degradedFallbackSockets[0].emit('telemetry.health', {
    state: 'degraded', stream_connected: false,
  }));

  await expect.poll(() => page.evaluate(() => ({
    socketClosed: window.__degradedFallbackSockets[0]?.closed,
    sourceCount: window.__degradedFallbackSources.length,
    sourceUrl: window.__degradedFallbackSources[0]?.url,
  }))).toEqual({ socketClosed: true, sourceCount: 1, sourceUrl: '/api/events' });
  await expect(page.locator('[data-live-indicator]'))
    .toHaveText(['Connecting · SSE', 'Connecting · SSE']);

  await page.evaluate(() => window.__degradedFallbackSources[0].emit('status', {
    sessions: [{
      id: 'fallback-session', name: 'fallback-user', encoding: 'AES-256-GCM',
      vpn_address: '10.8.0.99', source_address: '192.0.2.99', uptime: '1m',
      rx_bytes: 1024, tx_bytes: 2048, rx_packets: 10, tx_packets: 20,
    }],
  }));
  await expect(page.getByText('fallback-user', { exact: true })).toBeVisible();
  await expect(page.locator('[data-live-indicator]'))
    .toHaveText(['Live · SSE', 'Live · SSE']);

  // A queued callback from the retired socket must not overwrite the SSE view.
  await page.evaluate(() => {
    window.__degradedFallbackSockets[0].emit('telemetry.health', {
      state: 'healthy', stream_connected: true,
    });
    window.__degradedFallbackSockets[0].emit('telemetry.snapshot', {
      payload: { sessions: [{
        id: 'retired-session', name: 'retired-socket-user', uptime: '1m',
        rx_bytes: 0, tx_bytes: 0, rx_packets: 0, tx_packets: 0,
      }] },
    });
  });
  await expect(page.getByText('fallback-user', { exact: true })).toBeVisible();
  await expect(page.getByText('retired-socket-user', { exact: true })).toHaveCount(0);
  await expect(page.locator('[data-live-indicator]'))
    .toHaveText(['Live · SSE', 'Live · SSE']);
  expect(await page.evaluate(() => window.__degradedFallbackSources.length)).toBe(1);
  expect(navigations).toEqual([]);
});

test('an incomplete Socket.IO snapshot preserves counters while an authoritative zero remains visible', async ({ page }) => {
  await page.addInitScript(() => {
    window.__liveTestSocket = {
      handlers: new Map(),
      on(name, callback) { this.handlers.set(name, callback); return this; },
      close() {},
    };
    window.io = () => window.__liveTestSocket;
  });
  await page.route('**/api/telemetry', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ transport: 'socketio', socketio_enabled: true, socketio_engine: 'asgi' }),
  }));
  await page.route('**/static/socket.io.min.js*', (route) => route.fulfill({
    contentType: 'application/javascript',
    body: 'window.io = window.io || (() => window.__liveTestSocket);',
  }));

  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect.poll(() => page.evaluate(() => window.__liveTestSocket?.handlers.has('telemetry.snapshot')))
    .toBe(true);

  const sendSnapshot = (counters, complete) => page.evaluate(({ counters: values, complete: isComplete }) => {
    window.__liveTestSocket.handlers.get('telemetry.snapshot')({
      payload: { sessions: [{
        id: '*synthetic', name: 'synthetic-user', uptime: '1m',
        rx_bytes: values.rx, tx_bytes: values.tx,
        rx_packets: values.rxPackets, tx_packets: values.txPackets,
        counter_complete: isComplete,
      }] },
    });
  }, { counters, complete });

  await sendSnapshot({ rx: 1024, tx: 2048, rxPackets: 10, txPackets: 20 }, true);
  const card = page.locator('[data-active-session-list] .session-card');
  await expect(card).toHaveAttribute('data-rx', '1024');
  await expect(card).toHaveAttribute('data-tx', '2048');

  await sendSnapshot({ rx: 0, tx: 0, rxPackets: 0, txPackets: 0 }, false);
  await expect(card).toHaveAttribute('data-rx', '1024');
  await expect(card).toHaveAttribute('data-tx', '2048');

  await sendSnapshot({ rx: 0, tx: 0, rxPackets: 0, txPackets: 0 }, true);
  await expect(card).toHaveAttribute('data-rx', '0');
  await expect(card).toHaveAttribute('data-tx', '0');
});

test('a failed status poll remains delayed when no live snapshot has arrived', async ({ page }) => {
  let statusPolls = 0;
  await page.route('**/api/status', async (route) => {
    statusPolls += 1;
    await route.abort();
  });
  await page.route('**/api/telemetry', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ transport: 'sse', socketio_enabled: false }),
  }));
  await page.route('**/api/events', (route) => route.abort());

  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();
  await expect.poll(() => statusPolls).toBeGreaterThan(0);
  await expect(page.locator('[data-live-indicator]'))
    .toHaveText(['Connection data delayed', 'Connection data delayed']);
});

test('stale active sessions are labeled last-known and termination re-enables after a fresh snapshot', async ({ page }) => {
  await page.clock.install({ time: new Date('2026-10-03T12:00:00.000Z') });
  await page.route('**/api/status', (route) => route.abort());
  await page.route('**/api/telemetry', (route) => route.fulfill({
    contentType: 'application/json',
    body: JSON.stringify({ transport: 'socketio', socketio_enabled: true }),
  }));
  await page.route('**/static/socket.io.min.js*', (route) => route.fulfill({
    contentType: 'application/javascript',
    body: `window.__liveTestSocket = {
      handlers: new Map(),
      on(name, callback) { this.handlers.set(name, callback); return this; },
      close() {},
    };
    window.io = () => window.__liveTestSocket;`,
  }));

  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect.poll(() => page.evaluate(() => (
    window.__liveTestSocket?.handlers.has('telemetry.snapshot')
  ))).toBe(true);
  const session = {
    id: '*synthetic-stale', name: 'synthetic-user', encoding: 'AES-256-GCM',
    uptime: '1m', rx_bytes: 100, tx_bytes: 200, rx_packets: 1, tx_packets: 2,
  };
  await page.evaluate((value) => window.__liveTestSocket.handlers.get('telemetry.snapshot')({
    payload: { sessions: [value] },
  }), session);
  const card = page.locator('[data-active-session-list] .session-card');
  await expect(card.locator('[data-session-state]')).toHaveText('Connected securely · AES-256-GCM');
  await expect(card.locator('[data-terminate]')).toBeEnabled();

  await page.clock.fastForward(11_000);
  await expect(card).toHaveClass(/session-stale/);
  await expect(card.locator('[data-session-state]')).toHaveText('Last known · live status delayed');
  await expect(card.locator('[data-terminate]')).toBeDisabled();

  await page.evaluate((value) => window.__liveTestSocket.handlers.get('telemetry.snapshot')({
    payload: { sessions: [value] },
  }), session);
  await expect(card).not.toHaveClass(/session-stale/);
  await expect(card.locator('[data-session-state]')).toHaveText('Connected securely · AES-256-GCM');
  await expect(card.locator('[data-terminate]')).toBeEnabled();
});

test('returns to the top-level Access flow when an API request is redirected', async ({ page }) => {
  let statusPolls = 0;
  let dashboardNavigations = 0;
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame() && new URL(frame.url()).pathname === '/dashboard') {
      dashboardNavigations += 1;
    }
  });
  await page.route('**/api/status', async (route) => {
    statusPolls += 1;
    if (statusPolls === 1) {
      await route.fulfill({
        status: 302,
        headers: { location: 'https://access.example.test/cdn-cgi/access/login' },
      });
      return;
    }
    await route.continue();
  });

  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();
  await expect.poll(() => dashboardNavigations, { timeout: 10_000 }).toBeGreaterThan(1);
  await expect.poll(() => statusPolls, { timeout: 10_000 }).toBeGreaterThan(1);
  await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();
});

test('returns to sign-in automatically when the dashboard session expires', async ({ page }) => {
  let statusPolls = 0;
  let initialStatusLoaded = false;
  await page.route('**/api/status', async (route) => {
    statusPolls += 1;
    if (statusPolls === 1) {
      const response = await route.fetch();
      await route.fulfill({ response });
      initialStatusLoaded = true;
      return;
    }
    // A real expired session no longer has a valid login cookie. Mirror that
    // server-side state so /login does not immediately bounce back to dashboard.
    await page.context().clearCookies();
    await route.fulfill({
      status: 401,
      contentType: 'application/json',
      body: JSON.stringify({ error: 'session expired' }),
    });
  });

  await page.goto('/login');
  await page.getByLabel('Login').fill('admin');
  await page.getByLabel('Password').fill('routerpass');
  await page.getByRole('button', { name: 'Connect' }).click();
  await expect(page).toHaveURL(/\/dashboard$/);
  await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();
  await expect.poll(() => initialStatusLoaded).toBe(true);
  // Let the first poll finish its finally block before simulating a visible-tab
  // wake, which requests a fresh snapshot immediately.
  await page.waitForTimeout(100);
  await page.evaluate(() => {
    Object.defineProperty(document, 'hidden', { configurable: true, value: false });
    document.dispatchEvent(new Event('visibilitychange'));
  });
  await expect.poll(() => statusPolls).toBeGreaterThan(1);

  await expect(page).toHaveURL(/\/login$/, { timeout: 10_000 });
  await expect(page.getByRole('heading', { name: 'Connect to VPN Dashboard' })).toBeVisible();
  await expect(page.locator('.session-card')).toHaveCount(0);
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
          const data = JSON.stringify({ sessions: Array.from({ length: index }, (_, sessionIndex) => ({
            id: `wake-session-${index}-${sessionIndex}`,
            name: sessionIndex === 0 ? `wake-user-${index}` : `wake-extra-${index}`,
            encoding: 'AES-256-GCM',
            vpn_address: `10.8.0.${99 + sessionIndex}`,
            source_address: `192.0.2.${99 + sessionIndex}`,
            uptime: '1m',
            rx_bytes: index * 1024,
            tx_bytes: index * 2048,
            rx_packets: index * 10,
            tx_packets: index * 20,
          })) });
          queueMicrotask(() => {
            callback({ data });
            window.__appliedStreamSnapshots.push({
              names: [...document.querySelectorAll('[data-active-session-list] .session-card strong')]
                .map((item) => item.textContent),
              statusbarCount: document.querySelector('#system-status [data-session-total]')?.textContent,
            });
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
    .some((snapshot) => snapshot.names.includes('wake-user-2') && snapshot.statusbarCount === '2'))).toBe(true);
});

test('certificate migration panel refresh preserves the live stream and later telemetry updates', async ({ page }) => {
  await page.addInitScript(() => {
    window.__syntheticEventSources = [];
    window.EventSource = class SyntheticEventSource {
      constructor(url) {
        this.url = url;
        this.handlers = new Map();
        this.closed = false;
        window.__syntheticEventSources.push(this);
      }

      addEventListener(name, callback) { this.handlers.set(name, callback); }
      close() { this.closed = true; }
      emit(name, payload) { this.handlers.get(name)?.({ data: JSON.stringify(payload) }); }
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
  await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();
  await expect.poll(() => page.evaluate(() => window.__syntheticEventSources.length)).toBe(1);

  const navigations = [];
  page.on('dialog', (dialog) => dialog.accept());
  page.on('framenavigated', (frame) => {
    if (frame === page.mainFrame()) navigations.push(frame.url());
  });
  await page.getByRole('link', { name: 'Device Profiles', exact: true }).click();
  await expect(page.locator('.migration-panel')).toBeVisible();
  await page.evaluate(() => {
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

  // Entering the Device Profiles view changes the URL hash. Only count
  // navigation caused by the certificate mutation/refresh itself.
  navigations.length = 0;
  await page.getByRole('button', { name: 'Confirm replacement imported' }).click();
  await expect(page.locator('.migration-panel')).toHaveAttribute('data-refresh-marker', 'after');
  expect(navigations).toEqual([]);
  expect(await page.evaluate(() => ({
    streamCount: window.__syntheticEventSources.length,
    streamClosed: window.__syntheticEventSources[0]?.closed,
  }))).toEqual({ streamCount: 1, streamClosed: false });

  await page.getByRole('link', { name: 'Connections', exact: true }).click();
  // Hash navigation updates the view asynchronously. Wait until the SSE
  // status listener is attached before delivering the synthetic event.
  await expect.poll(() => page.evaluate(() => (
    window.__syntheticEventSources[0]?.handlers?.has('status') || false
  ))).toBe(true);
  await page.evaluate(() => window.__syntheticEventSources[0].emit('status', {
    sessions: [{
      id: 'migration-live-session',
      name: 'migration-live-user',
      encoding: 'AES-256-GCM',
      vpn_address: '10.8.0.99',
      source_address: '192.0.2.99',
      uptime: '1m',
      rx_bytes: 1024,
      tx_bytes: 2048,
      rx_packets: 10,
      tx_packets: 20,
    }],
  }));
  await expect(page.getByText('migration-live-user', { exact: true })).toBeVisible();
  await expect(page.locator('[data-live-indicator]').first()).toHaveText('Live · SSE');
  expect(await page.evaluate(() => window.__syntheticEventSources[0]?.closed)).toBe(false);
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
          const frame = { payload: { sessions: Array.from({ length: index }, (_, sessionIndex) => ({
            id: 'wake-socket-session-' + index + '-' + sessionIndex,
            name: sessionIndex === 0 ? 'wake-socket-user-' + index : 'wake-socket-extra-' + index,
            encoding: 'AES-256-GCM',
            vpn_address: '10.8.0.' + (99 + sessionIndex),
            source_address: '192.0.2.' + (99 + sessionIndex),
            uptime: '1m',
            rx_bytes: index * 1024,
            tx_bytes: index * 2048,
            rx_packets: index * 10,
            tx_packets: index * 20,
          })) } };
              queueMicrotask(() => {
                callback(frame);
                window.__appliedStreamSnapshots.push({
                  names: [...document.querySelectorAll('[data-active-session-list] .session-card strong')]
                    .map((item) => item.textContent),
                  statusbarCount: document.querySelector('#system-status [data-session-total]')?.textContent,
                });
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
  await expect(page.locator('#system-status [data-session-total]')).toHaveText('1');

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
    .some((snapshot) => snapshot.names.includes('wake-socket-user-2') && snapshot.statusbarCount === '2'))).toBe(true);
});

test('stops telemetry after session revocation and denies reconnect with stale authorization', async ({ browser }, testInfo) => {
  const marker = `pw-authz-target-${testInfo.workerIndex}-${Date.now()}-${Math.random().toString(16).slice(2)}`;
  const targetContext = await browser.newContext({ userAgent: marker });
  const adminContext = await browser.newContext({ userAgent: `${marker}-admin` });
  const targetPage = await targetContext.newPage();
  const adminPage = await adminContext.newPage();
  const deniedReconnects = [];

  try {
    await targetPage.addInitScript(() => {
      // Keep the target view logically foregrounded when the separate admin
      // context is used to revoke its session.
      Object.defineProperty(document, 'hidden', { configurable: true, value: false });
      window.__authorizationStreamFrames = [];
      window.__authorizationEventSources = [];
      const NativeEventSource = window.EventSource;
      window.EventSource = class AuthorizationEventSource extends NativeEventSource {
        constructor(...args) {
          super(...args);
          window.__authorizationEventSources.push(this);
          this.addEventListener('status', (event) => {
            try { window.__authorizationStreamFrames.push(JSON.parse(event.data)); } catch (_) { /* ignore malformed test data */ }
          });
        }
      };
    });

    for (const page of [targetPage, adminPage]) {
      await page.route('**/api/telemetry', (route) => route.fulfill({
        contentType: 'application/json',
        body: JSON.stringify({ transport: 'sse', socketio_enabled: false }),
      }));
    }
    // Keep the regression focused on the event stream. The dashboard's
    // independent REST poll redirects on 401 and would otherwise navigate
    // away before its own reconnect can be observed.
    await targetPage.route('**/api/status', (route) => route.abort());
    targetPage.on('response', (response) => {
      if (new URL(response.url()).pathname === '/api/events' && response.status() === 401) deniedReconnects.push(response);
    });

    const signIn = async (page) => {
      await page.goto('/login');
      await page.getByLabel('Login').fill('admin');
      await page.getByLabel('Password').fill('routerpass');
      await page.getByRole('button', { name: 'Connect' }).click();
      await expect(page).toHaveURL(/\/dashboard$/);
      await expect(page.getByRole('heading', { name: 'VPN at a glance' })).toBeVisible();
    };

    await signIn(targetPage);
    await expect.poll(() => targetPage.evaluate(() => window.__authorizationStreamFrames.length))
      .toBeGreaterThan(0);
    await expect.poll(() => targetPage.evaluate(() => window.__authorizationEventSources
      .some((source) => source.readyState === EventSource.OPEN))).toBe(true);

    // A separate local administrator session revokes the target through the
    // same UI control operators use. The target's synthetic visibility state
    // keeps its live stream active during this cross-session action.
    await signIn(adminPage);
    await adminPage.locator('[data-view-target="admin-sessions"]').click();
    const targetSessionId = await adminPage.evaluate(async (userAgent) => {
      const response = await fetch('/api/admin/sessions', { credentials: 'same-origin' });
      if (!response.ok) return '';
      const payload = await response.json();
      return payload.sessions.find((session) => session.user_agent === userAgent)?.id || '';
    }, marker);
    expect(targetSessionId).not.toBe('');
    const cookieValues = [
      ...(await targetContext.cookies()).map((cookie) => cookie.value),
      ...(await adminContext.cookies()).map((cookie) => cookie.value),
    ];
    expect(cookieValues).not.toContain(targetSessionId);
    const revokeButton = adminPage.locator(
      `[data-admin-session-row][data-session-id="${targetSessionId}"] [data-admin-session-revoke]`,
    );
    await expect(revokeButton).toHaveCount(1);

    // The open SSE response is revalidated server-side. Once it closes, the
    // dashboard's app-level reconnect must use the now-revoked cookie and be
    // rejected, rather than receiving another telemetry snapshot.
    const deniedReconnect = targetPage.waitForResponse((response) => (
      new URL(response.url()).pathname === '/api/events' && response.status() === 401
    ), { timeout: 15_000 });
    const revocation = adminPage.waitForResponse((response) => (
      response.request().method() === 'DELETE'
      && new URL(response.url()).pathname.startsWith('/api/admin/sessions/')
    ));
    await revokeButton.click();
    const reauthentication = adminPage.locator('#admin-session-reauth-dialog');
    await expect(reauthentication).toBeVisible();
    await reauthentication.getByLabel('RouterOS password').fill('routerpass');
    await reauthentication.getByRole('button', { name: 'Verify and revoke session' }).click();
    const revoked = await revocation;
    expect(revoked.status()).toBe(200);
    const revocationPath = new URL(revoked.url()).pathname;
    expect(decodeURIComponent(revocationPath.split('/').at(-1))).toBe(targetSessionId);
    for (const cookieValue of cookieValues) expect(revocationPath).not.toContain(cookieValue);
    await expect(reauthentication).toBeHidden();
    await deniedReconnect;
    const framesAfterRevocation = await targetPage.evaluate(() => window.__authorizationStreamFrames.length);
    expect(framesAfterRevocation).toBeGreaterThan(0);
    await expect.poll(() => deniedReconnects.length, { timeout: 12_000 }).toBeGreaterThanOrEqual(2);
    await expect.poll(() => targetPage.evaluate(() => window.__authorizationStreamFrames.length))
      .toBe(framesAfterRevocation);
  } finally {
    await Promise.all([targetContext.close(), adminContext.close()]);
  }
});
