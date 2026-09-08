const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
const counters = new Map();
const histories = new Map();
const HISTORY_LIMIT = 60;
let pollingFailures = 0;
let pendingDataRefresh = false;

const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const getDialog = (id) => document.getElementById(id);

function setStatus(form, text, error = false) {
  const node = $('.form-status', form);
  if (!node) return;
  node.textContent = text;
  node.classList.toggle('error', error);
}

function setBusy(form, busy) {
  $$('button, input', form).forEach((control) => { control.disabled = busy; });
  form.setAttribute('aria-busy', String(busy));
}

function openDialog(id) {
  const modal = getDialog(id);
  $('.form-status', modal)?.replaceChildren();
  modal.showModal();
}

function toast(message, type = 'success') {
  const region = $('.toast-region');
  if (!region) return;
  const item = document.createElement('div');
  item.className = `toast ${type}`;
  item.innerHTML = `<span aria-hidden="true">${type === 'error' ? '!' : '✓'}</span><p></p>`;
  $('p', item).textContent = message;
  region.appendChild(item);
  requestAnimationFrame(() => item.classList.add('visible'));
  setTimeout(() => {
    item.classList.remove('visible');
    setTimeout(() => item.remove(), 250);
  }, 4200);
}

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set('X-CSRF-Token', csrf);
  if (options.body && typeof options.body !== 'string') {
    headers.set('Content-Type', 'application/json');
    options.body = JSON.stringify(options.body);
  }
  const response = await fetch(url, { ...options, headers, credentials: 'same-origin' });
  if (response.status === 401) {
    location.assign('/login');
    throw new Error('Your session expired. Please sign in again.');
  }
  return response;
}

async function resultOrError(response) {
  if (response.ok) return response;
  let message = `Request failed (${response.status})`;
  try { message = (await response.json()).error || message; } catch (_) { /* response was not JSON */ }
  throw new Error(message);
}

async function downloadResponse(response, fallback) {
  const disposition = response.headers.get('content-disposition') || '';
  const match = disposition.match(/filename="([^"]+)"/);
  const blob = await response.blob();
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = match?.[1] || fallback;
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}

async function copyText(value) {
  if (navigator.clipboard?.writeText) {
    await navigator.clipboard.writeText(value);
    return;
  }
  const field = document.createElement('textarea');
  field.value = value;
  field.setAttribute('readonly', '');
  field.style.position = 'fixed';
  field.style.opacity = '0';
  document.body.appendChild(field);
  field.select();
  document.execCommand('copy');
  field.remove();
}

function formatRouterUptime(value) {
  const raw = String(value || '').trim();
  const match = raw.match(/^(?:(\d+)w)?(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/);
  if (!raw || !match) return raw || 'unknown';
  const [, weeks = 0, days = 0, hours = 0, minutes = 0, seconds = 0] = match;
  const dayTotal = Number(weeks) * 7 + Number(days);
  const clock = [hours, minutes, seconds].map((part) => String(part).padStart(2, '0')).join(':');
  return `${dayTotal ? `${dayTotal}d ` : ''}${clock}s`;
}

function formatBytes(value) {
  let size = Math.max(0, Number(value) || 0);
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let unit = 0;
  while (size >= 1024 && unit < units.length - 1) { size /= 1024; unit += 1; }
  const digits = size >= 100 || unit === 0 ? 0 : 1;
  return `${size.toFixed(digits)} ${units[unit]}`;
}

function formatRate(bytesPerSecond) {
  const bits = Math.max(0, bytesPerSecond * 8);
  if (bits < 1000) return `${Math.round(bits)} bps`;
  if (bits < 1000000) return `${(bits / 1000).toFixed(bits >= 100000 ? 0 : 1)} Kbps`;
  return `${(bits / 1000000).toFixed(bits >= 100000000 ? 0 : 1)} Mbps`;
}

function formatPacketRate(packetsPerSecond) {
  const packets = Math.max(0, Number(packetsPerSecond) || 0);
  if (packets < 1000) return `${Math.round(packets)} p/s`;
  if (packets < 1000000) return `${(packets / 1000).toFixed(packets >= 100000 ? 0 : 1)}K p/s`;
  return `${(packets / 1000000).toFixed(packets >= 100000000 ? 0 : 1)}M p/s`;
}

function node(tag, className, text) {
  const item = document.createElement(tag);
  if (className) item.className = className;
  if (text !== undefined) item.textContent = text;
  return item;
}

function svgIcon(name, extraClass = '') {
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('class', `wb-icon ${extraClass}`.trim());
  svg.setAttribute('aria-hidden', 'true');
  svg.setAttribute('focusable', 'false');
  const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
  use.setAttribute('href', `#i-${name}`);
  svg.append(use);
  return svg;
}

function fact(label, value, className = '') {
  const wrapper = node('div');
  wrapper.append(node('dt', '', label), node('dd', className, value));
  return wrapper;
}

function buildTrafficGraph(title, canvasAttribute, legendItems) {
  const panel = node('section', 'traffic-graph');
  const header = node('header');
  header.append(node('strong', '', title), node('span', '', 'Live · 5 second samples'));
  const canvas = node('canvas');
  canvas.setAttribute(canvasAttribute, '');
  canvas.setAttribute('aria-label', `${title} for this OpenVPN connection`);
  canvas.textContent = `${title} is shown when canvas is supported.`;
  const legend = node('div', 'graph-legend');
  legendItems.forEach(({ direction, attribute, value, label }) => {
    const item = node('span', `graph-${direction}`);
    item.append(node('i'), node('strong', '', value), node('small', '', label));
    $('strong', item).setAttribute(attribute, '');
    legend.append(item);
  });
  panel.append(header, canvas, legend);
  return panel;
}

function buildTrafficGraphs() {
  const graphs = node('div', 'session-graphs');
  graphs.setAttribute('aria-label', 'Live connection traffic');
  graphs.append(
    buildTrafficGraph('Byte Graph', 'data-byte-graph', [
      { direction: 'tx', attribute: 'data-graph-tx-rate', value: '0 bps', label: 'Tx' },
      { direction: 'rx', attribute: 'data-graph-rx-rate', value: '0 bps', label: 'Rx' },
    ]),
    buildTrafficGraph('Packet Graph', 'data-packet-graph', [
      { direction: 'tx', attribute: 'data-graph-tx-packets', value: '0 p/s', label: 'Tx Packet' },
      { direction: 'rx', attribute: 'data-graph-rx-packets', value: '0 p/s', label: 'Rx Packet' },
    ]),
  );
  return graphs;
}

function niceCeiling(value) {
  if (!Number.isFinite(value) || value <= 0) return 1;
  const magnitude = 10 ** Math.floor(Math.log10(value));
  const normalized = value / magnitude;
  const step = normalized <= 1 ? 1 : normalized <= 2 ? 2 : normalized <= 5 ? 5 : 10;
  return step * magnitude;
}

function drawGraph(canvas, samples, txKey, rxKey, formatter) {
  if (!canvas) return;
  const width = Math.max(260, canvas.clientWidth || 260);
  const height = Math.max(130, canvas.clientHeight || 130);
  const dpr = Math.min(window.devicePixelRatio || 1, 2);
  const pixelWidth = Math.round(width * dpr);
  const pixelHeight = Math.round(height * dpr);
  if (canvas.width !== pixelWidth || canvas.height !== pixelHeight) {
    canvas.width = pixelWidth;
    canvas.height = pixelHeight;
  }
  const context = canvas.getContext('2d');
  if (!context) return;
  context.setTransform(dpr, 0, 0, dpr, 0, 0);
  context.clearRect(0, 0, width, height);

  const left = 4;
  const right = 64;
  const top = 8;
  const bottom = 8;
  const graphWidth = Math.max(1, width - left - right);
  const graphHeight = Math.max(1, height - top - bottom);
  const maximum = niceCeiling(Math.max(1, ...samples.flatMap((sample) => [sample[txKey], sample[rxKey]])));
  context.font = '11px "Segoe UI", Arial, sans-serif';
  context.textBaseline = 'middle';
  for (let line = 0; line <= 4; line += 1) {
    const y = top + (graphHeight * line) / 4;
    context.strokeStyle = '#3b4750';
    context.lineWidth = 1;
    context.beginPath();
    context.moveTo(left, Math.round(y) + 0.5);
    context.lineTo(left + graphWidth, Math.round(y) + 0.5);
    context.stroke();
    context.fillStyle = '#c6d0d6';
    context.fillText(formatter(maximum * (1 - line / 4)), left + graphWidth + 7, y);
  }

  const drawSeries = (key, color) => {
    context.strokeStyle = color;
    context.lineWidth = 1.5;
    context.beginPath();
    samples.forEach((sample, index) => {
      const x = left + (graphWidth * index) / Math.max(HISTORY_LIMIT - 1, 1);
      const y = top + graphHeight - (Math.max(0, sample[key]) / maximum) * graphHeight;
      if (index === 0) context.moveTo(x, y);
      else context.lineTo(x, y);
    });
    context.stroke();
  };
  drawSeries(txKey, '#20a8ed');
  drawSeries(rxKey, '#35c819');
  canvas.dataset.samples = String(samples.length);
}

function updateGraphs(card, rates) {
  const sessionId = card.dataset.sessionId;
  const samples = histories.get(sessionId) || [];
  samples.push(rates);
  if (samples.length > HISTORY_LIMIT) samples.splice(0, samples.length - HISTORY_LIMIT);
  histories.set(sessionId, samples);
  $('[data-graph-tx-rate]', card).textContent = formatRate(rates.txBytes);
  $('[data-graph-rx-rate]', card).textContent = formatRate(rates.rxBytes);
  $('[data-graph-tx-packets]', card).textContent = formatPacketRate(rates.txPackets);
  $('[data-graph-rx-packets]', card).textContent = formatPacketRate(rates.rxPackets);
  drawGraph($('[data-byte-graph]', card), samples, 'txBytes', 'rxBytes', formatRate);
  drawGraph($('[data-packet-graph]', card), samples, 'txPackets', 'rxPackets', formatPacketRate);
}

function buildSessionCard(session) {
  const card = node('article', 'session-card');
  card.dataset.sessionId = session.id;
  card.dataset.sessionUser = session.name || '';
  card.dataset.rx = String(session.rx_bytes || 0);
  card.dataset.tx = String(session.tx_bytes || 0);
  card.dataset.rxPackets = String(session.rx_packets || 0);
  card.dataset.txPackets = String(session.tx_packets || 0);

  const main = node('div', 'session-main');
  const orb = node('div', 'live-orb');
  orb.setAttribute('aria-hidden', 'true');
  orb.append(svgIcon('session'));
  const copy = node('div');
  copy.append(node('strong', '', session.name || 'Unknown user'), node('small', '', `Connected securely · ${session.encoding || 'OpenVPN'}`));
  main.append(orb, copy);

  const facts = node('dl', 'session-facts');
  facts.append(
    fact('VPN address', session.vpn_address || '—'),
    fact('Source', session.source_address || '—'),
    fact('Uptime', session.uptime || '—', 'session-uptime'),
  );
  const traffic = node('div');
  traffic.append(node('dt', '', 'Traffic'));
  const trafficValue = node('dd');
  const rxRate = node('span', 'rx-rate', '↓ 0 bps');
  const txRate = node('span', 'tx-rate', '↑ 0 bps');
  const totals = node('small', 'traffic-totals', `↓ ${formatBytes(session.rx_bytes)} · ↑ ${formatBytes(session.tx_bytes)}`);
  trafficValue.append(rxRate, document.createTextNode(' · '), txRate, totals);
  traffic.append(trafficValue);
  facts.append(traffic);

  const terminate = node('button', 'terminate-button');
  terminate.type = 'button';
  terminate.dataset.terminate = '';
  terminate.dataset.sessionId = session.id;
  terminate.append(svgIcon('remove'), node('span', '', 'Terminate'));
  card.append(main, facts, terminate, buildTrafficGraphs());
  return card;
}

function buildOfflineState() {
  const state = node('div', 'empty session-empty');
  const icon = node('span', 'offline-icon');
  icon.setAttribute('aria-hidden', 'true');
  icon.append(svgIcon('session'));
  const copy = node('div');
  copy.append(node('strong', '', 'No devices connected'), node('small', '', 'Connections will appear here automatically.'));
  state.append(icon, copy);
  return state;
}

function updateSessionCard(card, session, timestamp) {
  $('[data-session-uptime], .session-uptime', card).textContent = session.uptime || '—';
  const previous = counters.get(session.id);
  let rxRate = 0;
  let txRate = 0;
  let rxPacketRate = 0;
  let txPacketRate = 0;
  if (previous && timestamp > previous.timestamp) {
    const seconds = (timestamp - previous.timestamp) / 1000;
    rxRate = Math.max(0, (Number(session.rx_bytes) - previous.rx) / seconds);
    txRate = Math.max(0, (Number(session.tx_bytes) - previous.tx) / seconds);
    rxPacketRate = Math.max(0, (Number(session.rx_packets) - previous.rxPackets) / seconds);
    txPacketRate = Math.max(0, (Number(session.tx_packets) - previous.txPackets) / seconds);
  }
  counters.set(session.id, {
    rx: Number(session.rx_bytes) || 0,
    tx: Number(session.tx_bytes) || 0,
    rxPackets: Number(session.rx_packets) || 0,
    txPackets: Number(session.tx_packets) || 0,
    timestamp,
  });
  $('.rx-rate', card).textContent = `↓ ${formatRate(rxRate)}`;
  $('.tx-rate', card).textContent = `↑ ${formatRate(txRate)}`;
  $('.traffic-totals', card).textContent = `↓ ${formatBytes(session.rx_bytes)} · ↑ ${formatBytes(session.tx_bytes)}`;
  card.dataset.rx = String(session.rx_bytes || 0);
  card.dataset.tx = String(session.tx_bytes || 0);
  card.dataset.rxPackets = String(session.rx_packets || 0);
  card.dataset.txPackets = String(session.tx_packets || 0);
  updateGraphs(card, { rxBytes: rxRate, txBytes: txRate, rxPackets: rxPacketRate, txPackets: txPacketRate });
}

function syncActiveSessions(sessions, timestamp) {
  const list = $('[data-active-session-list]');
  if (!list) return;
  const existingIds = $$('.session-card', list).map((item) => item.dataset.sessionId).sort();
  const incomingIds = sessions.map((item) => item.id).sort();
  if (existingIds.join('|') !== incomingIds.join('|')) {
    list.replaceChildren(...(sessions.length ? sessions.map(buildSessionCard) : [buildOfflineState()]));
  }
  sessions.forEach((session) => {
    const card = $$('.session-card', list).find((item) => item.dataset.sessionId === session.id);
    if (card) updateSessionCard(card, session, timestamp);
  });
}

function updateDashboard(payload) {
  const cards = $$('[data-user-id]');
  const incomingNames = payload.users.map((user) => user.name).sort();
  const currentNames = cards.map((card) => card.dataset.userName).sort();
  if (incomingNames.join('|') !== currentNames.join('|')) {
    deferFreshData('The VPN user list changed. Refresh to load it.');
    return;
  }

  const byUser = new Map();
  payload.sessions.forEach((session) => {
    if (!byUser.has(session.name)) byUser.set(session.name, []);
    byUser.get(session.name).push(session);
  });
  const timestamp = Date.now();
  cards.forEach((card) => {
    const user = payload.users.find((item) => item.name === card.dataset.userName);
    const sessions = byUser.get(card.dataset.userName) || [];
    card.dataset.userDisabled = String(Boolean(user.disabled));
    card.dataset.userComment = user.comment || 'No description';
    card.dataset.userEmail = user.email || 'Email not assigned';
    card.dataset.userMaxSessions = String(user.controls?.max_sessions || 5);
    $('.identity-email', card).textContent = user.email || 'Email not assigned';
    const account = $('[data-account-status]', card);
    account.textContent = user.disabled ? 'Disabled' : 'Enabled';
    account.className = `account-badge ${user.disabled ? 'disabled' : 'enabled'}`;
    const connection = $('[data-connection-status]', card);
    connection.className = `connection-badge ${sessions.length ? 'online' : 'offline'}`;
    $('span', connection).textContent = sessions.length ? 'Connected' : 'Offline';
    connection.disabled = !sessions.length;
    if (sessions.length) connection.dataset.viewTarget = 'live-sessions';
    else delete connection.dataset.viewTarget;
  });
  syncActiveSessions(payload.sessions, timestamp);

  $$('[data-user-total]').forEach((item) => { item.textContent = payload.users.length; });
  $$('[data-session-total]').forEach((item) => { item.textContent = payload.sessions.length; });
  $$('[data-nav-session-count]').forEach((item) => { item.textContent = payload.sessions.length; });
  const activeUsers = new Set(payload.sessions.map((session) => session.name)).size;
  $('[data-active-users]').textContent = `${activeUsers} connected user${activeUsers === 1 ? '' : 's'}`;
  const rx = payload.sessions.reduce((total, item) => total + (Number(item.rx_bytes) || 0), 0);
  const tx = payload.sessions.reduce((total, item) => total + (Number(item.tx_bytes) || 0), 0);
  $('[data-traffic-total]').textContent = `↓ ${formatBytes(rx)} · ↑ ${formatBytes(tx)}`;
  if (payload.router) {
    const percentUsed = (free, total) => {
      const totalValue = Number(total) || 0;
      if (!totalValue) return 0;
      return Math.max(0, Math.min(100, Math.round(((totalValue - (Number(free) || 0)) / totalValue) * 100)));
    };
    const cpu = Math.max(0, Math.min(100, Number(payload.router['cpu-load']) || 0));
    const memory = percentUsed(payload.router['free-memory'], payload.router['total-memory']);
    const storage = percentUsed(payload.router['free-hdd-space'], payload.router['total-hdd-space']);
    $('[data-router-cpu]').textContent = `${cpu}%`;
    $('[data-router-cpu-progress]').value = cpu;
    $('[data-router-memory]').textContent = `${memory}%`;
    $('[data-router-memory-progress]').value = memory;
    $('[data-router-storage]').textContent = `${storage}%`;
    $('[data-router-storage-progress]').value = storage;
    $('[data-router-uptime]').textContent = formatRouterUptime(payload.router.uptime);
  }
  const history = $('[data-connection-history]');
  if (history && Array.isArray(payload.connections)) {
    const openCount = payload.connections.filter((item) => !item.disconnected_at).length;
    if (openCount !== Number(history.dataset.openCount || 0)) {
      deferFreshData('Connection history changed. Refresh to load it.');
    }
  }
  if (Array.isArray(payload.alerts)) {
    const alertList = $('[data-alert-list]');
    const currentAlertIds = alertList ? $$('[data-alert-id]', alertList).map((item) => item.dataset.alertId).join('|') : '';
    const incomingAlertIds = payload.alerts.map((item) => String(item.id)).join('|');
    if (currentAlertIds !== incomingAlertIds) {
      deferFreshData('Security alerts changed. Refresh to load them.');
    }
  }
  const activeSessionIds = new Set(payload.sessions.map((session) => session.id));
  [...counters.keys()].forEach((id) => { if (!activeSessionIds.has(id)) counters.delete(id); });
  [...histories.keys()].forEach((id) => { if (!activeSessionIds.has(id)) histories.delete(id); });
}

async function pollStatus() {
  if (document.hidden) return;
  const indicators = $$('[data-live-indicator]');
  try {
    const response = await resultOrError(await api('/api/status'));
    const payload = await response.json();
    updateDashboard(payload);
    pollingFailures = 0;
    if (!pendingDataRefresh) {
      indicators.forEach((indicator) => {
        indicator.classList.remove('stale', 'pending');
        $('span', indicator).textContent = 'Live · updated now';
      });
    }
  } catch (error) {
    console.error('Live status refresh failed:', error);
    pollingFailures += 1;
    indicators.forEach((indicator) => {
      indicator.classList.add('stale');
      $('span', indicator).textContent = 'Connection data delayed';
    });
    if (pollingFailures === 2) toast('Live RouterOS data is temporarily unavailable. Retrying automatically.', 'error');
  }
}

function seedCounters() {
  const timestamp = Date.now();
  $$('.session-card').forEach((card) => counters.set(card.dataset.sessionId, {
    rx: Number(card.dataset.rx) || 0,
    tx: Number(card.dataset.tx) || 0,
    rxPackets: Number(card.dataset.rxPackets) || 0,
    txPackets: Number(card.dataset.txPackets) || 0,
    timestamp,
  }));
  $$('.session-card').forEach((card) => updateGraphs(card, { rxBytes: 0, txBytes: 0, rxPackets: 0, txPackets: 0 }));
}

const viewIds = new Set(['overview', 'vpn-users', 'live-sessions', 'profile-security', 'policy-templates', 'service-health', 'audit-log', 'setup-planner']);

function healthLabel(status) {
  return ({ healthy: 'Operational', warning: 'Attention needed', unavailable: 'Unavailable' }[status] || 'Unavailable');
}

function renderServiceHealth(payload) {
  const list = $('[data-service-health-list]');
  if (!list) return;
  const checks = Array.isArray(payload.checks) ? payload.checks : [];
  list.replaceChildren(...checks.map((check) => {
    const row = node('article', `service-health-check ${check.status || 'unavailable'}`);
    row.append(node('span', 'health-check-led'));
    const copy = node('div');
    copy.append(node('strong', '', check.name || 'Health check'), node('small', '', check.impact || 'No detail available.'));
    const next = node('p');
    next.append(node('b', '', 'Safe next step: '), document.createTextNode(check.remediation || 'No action needed.'));
    copy.append(next);
    row.append(copy);
    return row;
  }));
  if (!checks.length) list.append(node('div', 'empty', 'No health data is available yet.'));
  $('[data-service-health-overall]').textContent = healthLabel(payload.overall);
  $('[data-service-health-checked]').textContent = `${checks.length} checks completed just now`;
  ['healthy', 'warning', 'unavailable'].forEach((status) => {
    const counter = $(`[data-service-health-count="${status}"]`);
    if (counter) counter.textContent = checks.filter((check) => check.status === status).length;
  });
}

async function refreshServiceHealth() {
  const button = $('[data-service-health-refresh]');
  if (button) button.disabled = true;
  try {
    const response = await resultOrError(await api('/api/service-health'));
    renderServiceHealth(await response.json());
    toast('Service health checks refreshed.');
  } catch (error) {
    toast(error.message, 'error');
  } finally {
    if (button) button.disabled = false;
  }
}

function showView(requestedView, updateHash = true) {
  const view = viewIds.has(requestedView) ? requestedView : 'overview';
  $$('[data-view]').forEach((section) => { section.hidden = section.dataset.view !== view; });
  $$('.winbox-sidebar [data-view-target]').forEach((item) => {
    const active = item.dataset.viewTarget === view;
    item.classList.toggle('active', active);
    if (active) item.setAttribute('aria-current', 'page');
    else item.removeAttribute('aria-current');
  });
  if (updateHash && location.hash !== `#${view}`) history.pushState(null, '', `#${view}`);
  $('.workspace-content')?.scrollTo({ top: 0, behavior: 'auto' });
}

function viewFromHash() {
  return location.hash.slice(1) || 'overview';
}

function hasOpenDialog() {
  return Boolean($('dialog[open]'));
}

function deferFreshData(reason) {
  pendingDataRefresh = true;
  const control = $('[data-full-refresh]');
  if (control) {
    control.hidden = false;
    control.title = reason;
    const label = $('span', control);
    if (label) label.textContent = 'Refresh to apply changes';
  }
  $$('[data-live-indicator]').forEach((indicator) => {
    indicator.classList.remove('stale');
    indicator.classList.add('pending');
    $('span', indicator).textContent = 'Changes available';
  });
}

function prepareProfileDialog({ userId, userName, delivery = 'zip' }) {
  const form = $('#profile-form');
  form.reset();
  form.user_id.value = userId;
  form.delivery.value = delivery;
  $('[data-profile-user]', form).textContent = userName;
  $('[data-profile-title]', form).textContent = delivery === 'qr' ? 'Create QR code' : 'Download profile';
  $('[data-profile-description]', form).textContent = delivery === 'qr'
    ? 'Generate a protected profile link that the phone can open after scanning.'
    : 'A ZIP archive with the protected OpenVPN profile will download automatically.';
  $('[data-profile-submit]', form).textContent = delivery === 'qr' ? 'Create and show QR' : 'Create and download .zip';
  openDialog('profile-dialog');
}

function showQrDialog(payload, username = 'this user') {
  const dialog = getDialog('qr-dialog');
  const image = $('[data-qr-image]', dialog);
  image.src = `data:image/svg+xml;charset=utf-8,${encodeURIComponent(payload.qr_svg || '')}`;
  image.alt = `OpenVPN profile download QR code for ${username}`;
  $('[data-qr-url]', dialog).value = payload.download_url || '';
  $('[data-qr-description]', dialog).textContent = `Scan this code with the phone camera to download the ${username} OpenVPN profile.`;
  dialog.showModal();
}

let resizeFrame = 0;
window.addEventListener('resize', () => {
  cancelAnimationFrame(resizeFrame);
  resizeFrame = requestAnimationFrame(() => {
    $$('.session-card').forEach((card) => {
      const samples = histories.get(card.dataset.sessionId) || [];
      if (!samples.length) return;
      drawGraph($('[data-byte-graph]', card), samples, 'txBytes', 'rxBytes', formatRate);
      drawGraph($('[data-packet-graph]', card), samples, 'txPackets', 'rxPackets', formatPacketRate);
    });
  });
});

$$('dialog').forEach((modal) => {
  $$('[data-close]', modal).forEach((button) => button.addEventListener('click', () => modal.close()));
  modal.addEventListener('click', (event) => {
    if (event.target === modal) modal.close();
  });
});

$('[data-open-add]')?.addEventListener('click', () => {
  $('#add-form').reset();
  openDialog('add-dialog');
});

$$('[data-open-add]').slice(1).forEach((button) => button.addEventListener('click', () => {
  $('#add-form').reset();
  openDialog('add-dialog');
}));

$$('[data-refresh]').forEach((button) => button.addEventListener('click', async () => {
  if (pendingDataRefresh) {
    location.reload();
    return;
  }
  button.disabled = true;
  try { await pollStatus(); } finally { button.disabled = false; }
}));

$('[data-full-refresh]')?.addEventListener('click', () => location.reload());

$('[data-user-search]')?.addEventListener('input', (event) => {
  const query = event.currentTarget.value.trim().toLocaleLowerCase();
  $$('.user-card').forEach((card) => {
    const haystack = `${card.dataset.userName} ${card.dataset.userEmail} ${card.dataset.userComment}`.toLocaleLowerCase();
    card.classList.toggle('is-filtered-out', Boolean(query) && !haystack.includes(query));
  });
});

$('[data-history-search]')?.addEventListener('input', (event) => {
  const query = event.currentTarget.value.trim().toLocaleLowerCase();
  $$('[data-history-row]').forEach((row) => {
    row.classList.toggle('is-filtered-out', Boolean(query) && !row.dataset.historySearch.includes(query));
  });
});

$('[data-connection-search]')?.addEventListener('input', (event) => {
  const query = event.currentTarget.value.trim().toLocaleLowerCase();
  $$('[data-connection-row]').forEach((row) => {
    row.classList.toggle('is-filtered-out', Boolean(query) && !row.dataset.connectionSearch.includes(query));
  });
});

document.addEventListener('click', async (event) => {
  const trigger = event.target.closest('[data-view-target]');
  if (!trigger || trigger.disabled) return;
  event.preventDefault();
  showView(trigger.dataset.viewTarget);
});

window.addEventListener('hashchange', () => showView(viewFromHash(), false));

document.addEventListener('click', async (event) => {
  const button = event.target.closest('button');
  if (!button) return;
  const row = button.closest('[data-user-id]');
  if (button.matches('[data-open-template-create]')) {
    const form = $('#template-form');
    form.reset();
    form.notifications.checked = true;
    openDialog('template-dialog');
  } else if (button.matches('[data-select-template]')) {
    const form = $('[data-template-apply]');
    form.template_id.value = button.dataset.selectTemplate;
    showView('policy-templates');
    form.scrollIntoView({ block: 'center', behavior: 'smooth' });
    toast('Template selected. Choose users, then preview the differences.');
  } else if (button.matches('[data-create-device]') || button.matches('[data-profile]') || button.matches('[data-download-profile]') || button.matches('[data-qr-profile]')) {
    const userId = button.dataset.userId || row?.dataset.userId;
    const userName = button.dataset.userName || row?.dataset.userName;
    if (!userId || !userName) {
      toast('This user no longer exists. Refresh the page and try again.', 'error');
      return;
    }
    prepareProfileDialog({
      userId,
      userName,
      delivery: button.matches('[data-qr-profile]') ? 'qr' : 'zip',
    });
  } else if (button.matches('[data-duplicate]') && row) {
    const form = $('#duplicate-form');
    form.reset();
    form.source_id.value = row.dataset.userId;
    form.username.value = `${row.dataset.userName}-copy`.slice(0, 64);
    form.email.value = '';
    form.comment.value = `Copy of ${row.dataset.userName}`;
    $('[data-duplicate-source]', form).textContent = row.dataset.userName;
    openDialog('duplicate-dialog');
  } else if (button.matches('[data-edit]') && row) {
    const form = $('#edit-form');
    form.reset();
    form.user_id.value = row.dataset.userId;
    form.comment.value = row.dataset.userComment === 'No description' ? '' : row.dataset.userComment;
    form.email.value = row.dataset.userEmail === 'Email not assigned' ? '' : row.dataset.userEmail;
    form.policy.value = row.dataset.userPolicy || 'full-tunnel';
    if (row.dataset.userExpires && Number(row.dataset.userExpires) > Math.floor(Date.now() / 1000) && !form.expiry.querySelector('option[value="keep"]')) {
      form.expiry.insertBefore(new Option('Keep current', 'keep'), form.expiry.options[0]);
    }
    form.expiry.value = row.dataset.userExpires && Number(row.dataset.userExpires) > Math.floor(Date.now() / 1000) ? 'keep' : 'never';
    form.max_sessions.value = row.dataset.userMaxSessions || '5';
    const currentRate = row.dataset.userRateLimit || '0';
    if (currentRate !== '0' && !form.rate_limit_kbps.querySelector(`option[value="${currentRate}"]`)) {
      form.rate_limit_kbps.insertBefore(new Option(`Current limit (${currentRate} Kbps)`, currentRate), form.rate_limit_kbps.options[1] || null);
    }
    form.rate_limit_kbps.value = currentRate;
    form.quota_mb.value = row.dataset.userQuota || '0';
    form.schedule.value = row.dataset.userSchedule || 'always';
    form.dns_mode.value = row.dataset.userDns || 'router';
    form.notifications.checked = row.dataset.userNotifications !== 'false';
    form.disabled.checked = row.dataset.userDisabled === 'true';
    $('[data-edit-user]', form).textContent = row.dataset.userName;
    openDialog('edit-dialog');
  } else if (button.matches('[data-copy-username]') && row) {
    try {
      await copyText(row.dataset.userName);
      toast(`Username ${row.dataset.userName} copied.`);
    } catch (_) {
      toast('The browser could not copy the username.', 'error');
    }
  } else if (button.matches('[data-copy-share]')) {
    try {
      await copyText($('[data-qr-url]')?.value || '');
      toast('Download link copied.');
    } catch (_) {
      toast('The browser could not copy the download link.', 'error');
    }
  } else if (button.matches('[data-alert-ack]')) {
    button.disabled = true;
    try {
      await resultOrError(await api(`/api/alerts/${encodeURIComponent(button.dataset.alertAck)}/ack`, { method: 'POST' }));
      button.closest('[data-alert-id]')?.remove();
      toast('Alert acknowledged.');
    } catch (error) {
      toast(error.message, 'error');
      button.disabled = false;
    }
  } else if (button.matches('[data-suspend]') && row) {
    const form = $('#suspend-form');
    form.reset();
    form.user_id.value = row.dataset.userId;
    $('[data-suspend-user]', form).textContent = row.dataset.userName;
    openDialog('suspend-dialog');
  } else if (button.matches('[data-restore]') && row) {
    button.disabled = true;
    try {
      await resultOrError(await api(`/api/users/${encodeURIComponent(row.dataset.userId)}/restore`, { method: 'POST' }));
      toast(`VPN access restored for ${row.dataset.userName}.`);
      setTimeout(() => location.reload(), 450);
    } catch (error) {
      toast(error.message, 'error');
      button.disabled = false;
    }
  } else if (button.matches('[data-delete]') && row) {
    const form = $('#delete-form');
    form.reset();
    form.user_id.value = row.dataset.userId;
    $('[data-delete-user]', form).textContent = row.dataset.userName;
    openDialog('delete-dialog');
  } else if (button.matches('[data-terminate]')) {
    const form = $('#terminate-form');
    const sessionCard = button.closest('.session-card');
    form.reset();
    form.session_id.value = button.dataset.sessionId;
    $('[data-terminate-user]', form).textContent = sessionCard.dataset.sessionUser || 'VPN device';
    const facts = $$('dd', sessionCard).map((item) => item.textContent.trim());
    $('[data-terminate-detail]', form).textContent = `${facts[0] || 'VPN session'} · ${facts[1] || 'unknown source'}`;
    openDialog('terminate-dialog');
  }
  button.closest('details')?.removeAttribute('open');
});

$('#add-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const delivery = event.submitter?.dataset.delivery || 'zip';
  data.set('delivery', delivery);
  setBusy(form, true);
  setStatus(form, 'Preparing the user and secure phone file…');
  try {
    const response = await resultOrError(await api('/api/users', { method: 'POST', body: Object.fromEntries(data) }));
    if (delivery === 'qr') {
      const payload = await response.json();
      form.closest('dialog')?.close();
      toast(`User ${data.get('username')} created. QR code ready.`);
      showQrDialog(payload, data.get('username'));
      return;
    }
    await downloadResponse(response, `${data.get('username')}.zip`);
    setStatus(form, 'Profile ZIP downloaded successfully.');
    toast(`User ${data.get('username')} created and profile downloaded.`);
    setTimeout(() => location.reload(), 700);
  } catch (error) { setStatus(form, error.message, true); setBusy(form, false); }
});

$('#profile-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  setBusy(form, true);
  setStatus(form, 'Preparing a secure file for this device…');
  try {
    const delivery = data.get('delivery') || 'zip';
    const response = await resultOrError(await api(`/api/users/${encodeURIComponent(data.get('user_id'))}/profiles`, { method: 'POST', body: { device_name: data.get('device_name'), key_passphrase: data.get('key_passphrase'), delivery } }));
    if (delivery === 'qr') {
      const payload = await response.json();
      const username = $('[data-profile-user]', form).textContent;
      form.closest('dialog')?.close();
      toast('QR code ready for the new device.');
      showQrDialog(payload, username);
      return;
    }
    await downloadResponse(response, 'openvpn-profile.zip');
    setStatus(form, 'Profile ZIP downloaded successfully.');
    toast('New device profile generated and downloaded.');
    setTimeout(() => location.reload(), 700);
  } catch (error) { setStatus(form, error.message, true); setBusy(form, false); }
});

$('#duplicate-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  const sourceId = data.get('source_id');
  setBusy(form, true);
  setStatus(form, 'Creating separate access with the same settings…');
  try {
    const payload = Object.fromEntries(data);
    delete payload.source_id;
    const response = await resultOrError(await api(`/api/users/${encodeURIComponent(sourceId)}/duplicate`, { method: 'POST', body: payload }));
    await downloadResponse(response, `${data.get('username')}.ovpn`);
    setStatus(form, 'User duplicated and profile downloaded.');
    toast(`User ${data.get('username')} created from ${$('[data-duplicate-source]', form).textContent}.`);
    setTimeout(() => location.reload(), 700);
  } catch (error) { setStatus(form, error.message, true); setBusy(form, false); }
});

$('#edit-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const data = new FormData(form);
  setBusy(form, true);
  setStatus(form, 'Saving the access changes…');
  try {
    await resultOrError(await api(`/api/users/${encodeURIComponent(data.get('user_id'))}`, { method: 'PATCH', body: { email: data.get('email'), password: data.get('password'), comment: data.get('comment'), disabled: data.get('disabled') === 'on', policy: data.get('policy'), expiry: data.get('expiry'), max_sessions: data.get('max_sessions'), rate_limit_kbps: data.get('rate_limit_kbps'), quota_mb: data.get('quota_mb'), schedule: data.get('schedule'), dns_mode: data.get('dns_mode'), notifications: data.get('notifications') === 'on' } }));
    setStatus(form, 'Changes applied successfully.');
    toast('VPN user updated on RouterOS.');
    setTimeout(() => location.reload(), 500);
  } catch (error) { setStatus(form, error.message, true); setBusy(form, false); }
});

$('#template-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  values.notifications = form.notifications.checked;
  setBusy(form, true);
  setStatus(form, 'Saving the reusable policy…');
  try {
    const response = await resultOrError(await api('/api/policy-templates', { method: 'POST', body: values }));
    const payload = await response.json();
    setStatus(form, 'Template saved.');
    toast(`${payload.template.name} is ready to preview and apply.`);
    setTimeout(() => location.reload(), 450);
  } catch (error) { setStatus(form, error.message, true); setBusy(form, false); }
});

function selectedTemplateUsers(form) {
  return $$('input[name="user_ids"]:checked', form).map((input) => input.value);
}

function showTemplatePreview(form, payload) {
  const preview = $('[data-template-preview]', form);
  const affected = payload.users.filter((user) => user.changes.length);
  const safe = (value) => String(value).replace(/[&<>"']/g, (character) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[character]));
  preview.innerHTML = `<strong>${safe(payload.template.name)} preview</strong><small>${affected.length} of ${payload.users.length} selected user(s) will change.</small><ul>${payload.users.map((user) => `<li><b>${safe(user.username)}</b><span>${user.changes.length ? safe(user.changes.join(', ')) : 'Already matches'}</span></li>`).join('')}</ul>`;
  preview.hidden = false;
  $('[data-template-apply-button]', form).disabled = false;
}

$('[data-template-preview-button]')?.addEventListener('click', async () => {
  const form = $('[data-template-apply]');
  const templateId = form.template_id.value;
  const userIds = selectedTemplateUsers(form);
  if (!templateId || !userIds.length) {
    setStatus(form, 'Choose a template and at least one VPN user first.', true);
    return;
  }
  setBusy(form, true);
  setStatus(form, 'Comparing selected users with the template…');
  try {
    const response = await resultOrError(await api(`/api/policy-templates/${encodeURIComponent(templateId)}/preview`, { method: 'POST', body: { user_ids: userIds } }));
    showTemplatePreview(form, await response.json());
    setStatus(form, 'Review the list, then apply if it is correct.');
  } catch (error) { setStatus(form, error.message, true); }
  finally { setBusy(form, false); }
});

$('[data-template-apply]')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const templateId = form.template_id.value;
  const userIds = selectedTemplateUsers(form);
  if (!templateId || !userIds.length || $('[data-template-apply-button]', form).disabled) return;
  setBusy(form, true);
  setStatus(form, 'Creating a RouterOS checkpoint and applying the reviewed policy…');
  try {
    const response = await resultOrError(await api(`/api/policy-templates/${encodeURIComponent(templateId)}/apply`, { method: 'POST', body: { user_ids: userIds } }));
    const payload = await response.json();
    setStatus(form, `Applied to ${payload.selected} selected user(s).`);
    toast('Policy template applied and recorded in Change History.');
    setTimeout(() => location.reload(), 700);
  } catch (error) { setStatus(form, error.message, true); setBusy(form, false); }
});

$('#terminate-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const sessionId = new FormData(form).get('session_id');
  setBusy(form, true);
  setStatus(form, 'Disconnecting the device…');
  try {
    await resultOrError(await api(`/api/sessions/${encodeURIComponent(sessionId)}`, { method: 'DELETE' }));
    setStatus(form, 'Session terminated.');
    toast('OpenVPN session terminated.');
    setTimeout(() => { getDialog('terminate-dialog').close(); pollStatus(); }, 450);
  } catch (error) { setStatus(form, error.message, true); setBusy(form, false); }
});

$('#suspend-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const userId = new FormData(form).get('user_id');
  setBusy(form, true);
  setStatus(form, 'Suspending access and checking live sessions…');
  try {
    const response = await resultOrError(await api(`/api/users/${encodeURIComponent(userId)}/suspend`, { method: 'POST' }));
    const result = await response.json();
    const verification = result.remaining === null
      ? ' Access is blocked; live-session verification was unavailable.'
      : ` ${result.disconnected} session${result.disconnected === 1 ? '' : 's'} disconnected.`;
    setStatus(form, `Access suspended.${verification}`);
    toast(`VPN access suspended.${verification}`);
    setTimeout(() => location.reload(), 700);
  } catch (error) {
    setStatus(form, error.message, true);
    setBusy(form, false);
  }
});

$('#delete-form')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const userId = new FormData(form).get('user_id');
  setBusy(form, true);
  setStatus(form, 'Removing access and its managed device records…');
  try {
    await resultOrError(await api(`/api/users/${encodeURIComponent(userId)}`, { method: 'DELETE' }));
    setStatus(form, 'Access removed.');
    toast('VPN user and managed access removed.');
    setTimeout(() => location.reload(), 500);
  } catch (error) { setStatus(form, error.message, true); setBusy(form, false); }
});

async function runSetupPreflight() {
  const list = $('[data-setup-checks]');
  if (!list) return;
  list.innerHTML = '<li><i></i><span>Checking the connected router without making changes…</span></li>';
  try {
    const response = await resultOrError(await api('/api/setup-preflight'));
    const result = await response.json();
    const labels = { pass: 'Ready', fail: 'Needs attention', manual: 'Manual gate' };
    list.replaceChildren(...result.checks.map((check) => {
      const item = document.createElement('li');
      item.className = `setup-check ${check.status}`;
      item.innerHTML = '<i></i><span><strong></strong><small></small></span>';
      $('strong', item).textContent = `${labels[check.status] || 'Unknown'} · ${check.name}`;
      $('small', item).textContent = check.status === 'manual'
        ? 'Confirm this in WinBox before applying any reviewed plan.'
        : `RouterOS ${result.router.version} · ${result.router.architecture}`;
      return item;
    }));
  } catch (error) {
    list.innerHTML = '<li class="setup-check fail"><i></i><span><strong>Preflight unavailable</strong><small></small></span></li>';
    $('small', list).textContent = error.message;
  }
}

$('[data-setup-preflight]')?.addEventListener('click', runSetupPreflight);
$('[data-service-health-refresh]')?.addEventListener('click', refreshServiceHealth);

$('[data-setup-plan]')?.addEventListener('submit', async (event) => {
  event.preventDefault();
  const form = event.currentTarget;
  const values = Object.fromEntries(new FormData(form));
  setBusy(form, true);
  setStatus(form, 'Validating inputs and generating a review-only plan…');
  try {
    const response = await resultOrError(await api('/api/setup-plan', { method: 'POST', body: values }));
    const result = await response.json();
    const output = $('[data-setup-output]');
    $('[data-setup-plan-output]', output).textContent = result.plan;
    output.hidden = false;
    setStatus(form, 'Plan generated. Review every placeholder before any manual apply.');
  } catch (error) {
    setStatus(form, error.message, true);
  } finally {
    setBusy(form, false);
  }
});

$('[data-copy-setup]')?.addEventListener('click', async () => {
  const plan = $('[data-setup-plan-output]')?.textContent || '';
  if (!plan) return;
  try { await copyText(plan); toast('Review plan copied. It contains no credentials or secrets.'); }
  catch (_) { toast('Could not copy the plan automatically.', 'error'); }
});

document.addEventListener('click', (event) => {
  if (!event.target.closest('.action-menu')) $$('.action-menu[open]').forEach((item) => item.removeAttribute('open'));
});
document.addEventListener('visibilitychange', () => { if (!document.hidden) pollStatus(); });

showView(viewFromHash(), false);
seedCounters();
setTimeout(pollStatus, 1200);
setInterval(pollStatus, 5000);
