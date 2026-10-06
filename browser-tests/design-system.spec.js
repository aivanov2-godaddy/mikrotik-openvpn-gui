const { test, expect } = require('@playwright/test');

const themes = [
  { name: 'standard', resolved: 'standard' },
  { name: 'dark', resolved: 'dark' },
  { name: 'light', resolved: 'light' },
];
const views = [
  { name: 'Dashboard', target: 'overview', heading: 'VPN at a glance' },
  { name: 'VPN Users', target: 'vpn-users', heading: 'VPN Users' },
  { name: 'Connections', target: 'live-sessions', heading: 'Connected Devices' },
];

function rgbChannels(color) {
  const channels = color.match(/[\d.]+/g)?.map(Number);
  if (!channels || channels.length < 3) throw new Error(`Unsupported computed CSS color: ${color}`);
  return channels.slice(0, 3);
}

function relativeLuminance(color) {
  const [red, green, blue] = rgbChannels(color).map((channel) => {
    const value = channel / 255;
    return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
  });
  return (0.2126 * red) + (0.7152 * green) + (0.0722 * blue);
}

function contrastRatio(foreground, background) {
  const first = relativeLuminance(foreground);
  const second = relativeLuminance(background);
  return (Math.max(first, second) + 0.05) / (Math.min(first, second) + 0.05);
}

test.beforeEach(async ({ page }) => {
  // This gate uses the deterministic mock REST fixture, not live RouterOS data.
  // EventSource stays disabled so stream cadence cannot affect style checks.
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
});

test('primary views use shared semantic tokens and readable palettes', async ({ page }) => {
  for (const theme of themes) {
    await page.locator('.theme-menu > summary').click();
    await page.locator(`[data-theme-choice="${theme.name}"]`).click();
    await expect(page.locator('html')).toHaveAttribute('data-theme-resolved', theme.resolved);

    for (const view of views) {
      await page.getByRole('link', { name: view.name, exact: true }).click();
      await expect(page.getByRole('heading', { name: view.heading, exact: true })).toBeVisible();

      const rendered = await page.evaluate((target) => {
        const resolve = (token, property) => {
          const probe = document.createElement('span');
          probe.style.setProperty(property, `var(${token})`);
          document.body.append(probe);
          const value = getComputedStyle(probe).getPropertyValue(property);
          probe.remove();
          return value;
        };
        const viewRoot = document.querySelector(`[data-view="${target}"]`);
        const heading = viewRoot.querySelector('.view-heading h1');
        const subtitle = viewRoot.querySelector('.view-heading p:not(.eyebrow)');
        const panel = viewRoot.querySelector('.panel');
        const panelHeading = panel?.querySelector('.panel-heading');
        const panelTitle = panelHeading?.querySelector('strong');
        const metric = viewRoot.querySelector('.metric');
        const action = viewRoot.querySelector('.heading-actions button, .heading-actions a');
        const bodyStyle = getComputedStyle(document.body);
        const rootFont = document.createElement('span');
        rootFont.style.fontFamily = 'var(--font)';
        document.body.append(rootFont);
        const font = getComputedStyle(rootFont).fontFamily;
        rootFont.remove();
        return {
          tokens: {
            text: resolve('--text', 'color'),
            bright: resolve('--text-bright', 'color'),
            muted: resolve('--muted', 'color'),
            workspace: resolve('--workspace', 'background-color'),
            panel: resolve('--panel', 'background-color'),
            panel2: resolve('--panel-2', 'background-color'),
          },
          body: {
            color: bodyStyle.color,
            font: bodyStyle.fontFamily,
          },
          workspaceSurface: getComputedStyle(document.querySelector('.workspace-content')).backgroundColor,
          heading: getComputedStyle(heading).color,
          subtitle: subtitle ? getComputedStyle(subtitle).color : null,
          panel: panel ? getComputedStyle(panel).backgroundColor : null,
          panelHeading: panelHeading ? getComputedStyle(panelHeading).backgroundColor : null,
          panelTitle: panelTitle ? getComputedStyle(panelTitle).color : null,
          metric: metric ? getComputedStyle(metric).backgroundColor : null,
          actionFont: action ? getComputedStyle(action).fontFamily : null,
          rootFont: font,
        };
      }, view.target);

      expect(rendered.body.color, `${theme.name}/${view.name}: body text role`).toBe(rendered.tokens.text);
      expect(rendered.workspaceSurface, `${theme.name}/${view.name}: workspace surface role`).toBe(rendered.tokens.workspace);
      expect(rendered.body.font, `${theme.name}/${view.name}: application font`).toBe(rendered.rootFont);
      expect(rendered.heading, `${theme.name}/${view.name}: page title role`).toBe(rendered.tokens.bright);
      if (rendered.subtitle) {
        expect(rendered.subtitle, `${theme.name}/${view.name}: supporting copy role`).toBe(rendered.tokens.muted);
      }
      expect(rendered.panelTitle, `${theme.name}/${view.name}: panel title role`).toBe(rendered.tokens.bright);
      expect(rendered.panelHeading, `${theme.name}/${view.name}: panel header surface`).toBe(rendered.tokens.panel);
      expect([rendered.tokens.panel, rendered.tokens.panel2], `${theme.name}/${view.name}: panel uses a shared surface`)
        .toContain(rendered.panel);
      expect(rendered.actionFont, `${theme.name}/${view.name}: action uses the application font`).toBe(rendered.rootFont);
      if (view.target === 'overview') {
        expect(rendered.metric, `${theme.name}: dashboard metric uses the shared panel surface`).toBe(rendered.tokens.panel);
      }

      for (const role of ['text', 'bright', 'muted']) {
        for (const surface of ['workspace', 'panel', 'panel2']) {
          const ratio = contrastRatio(rendered.tokens[role], rendered.tokens[surface]);
          expect(ratio, `${theme.name}/${view.name}: ${role} on ${surface} contrast`).toBeGreaterThanOrEqual(4.5);
        }
      }
    }
  }
});
