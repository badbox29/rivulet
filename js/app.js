/**
 * ============================================================
 * Rivulet — app.js
 * ============================================================
 * App-specific logic: data model, localStorage + Cloudflare Worker
 * sync, boot orchestration, and the UI (dashboard, streams, CRUD).
 * auth.js is the standalone, portable auth module — this file is the
 * host side that supplies its config via Auth.init() in boot().
 *
 * Account types (handled by auth.js): guest / token / google.
 * One-way upgrades: guest → token|google, token → google.
 * Worker contract is documented in AUTH-INTEGRATION.md.
 * ============================================================ */

'use strict';

// ─── Constants ────────────────────────────────────────────────────
const STORAGE_KEY         = 'riv_appdata';
const STORAGE_AUTH_KEY    = 'riv_google_id_token';
const STORAGE_DISMISS_KEY = 'riv_token_upgrade_dismissed';

const SYNC_THRESHOLD_MS      = 30 * 1000;
const SYNC_CHECK_INTERVAL_MS = 15 * 1000;

const CATEGORIES = ['Automotive', 'Cloud', 'Communication', 'Development', 'Education',
  'Entertainment', 'Family', 'Finance', 'Fitness', 'Food', 'Gaming', 'Health', 'Home',
  'Insurance', 'Music', 'News', 'Pets', 'Productivity', 'Security', 'Shopping', 'Travel',
  'Utilities', 'Other'];

const FREQUENCIES = [
  { id: 'weekly',    label: 'Weekly',    per: 'wk', toMonthly: a => a * 52 / 12 },
  { id: 'monthly',   label: 'Monthly',   per: 'mo', toMonthly: a => a },
  { id: 'quarterly', label: 'Quarterly', per: 'qt', toMonthly: a => a / 3 },
  { id: 'yearly',    label: 'Yearly',    per: 'yr', toMonthly: a => a / 12 },
];

const STATUSES = [
  { id: 'active',    label: 'Active' },
  { id: 'trial',     label: 'Trial' },
  { id: 'paused',    label: 'Paused' },
  { id: 'cancelled', label: 'Cancelled' },
];

const CURRENCIES = ['USD', 'EUR', 'GBP', 'CAD', 'AUD', 'JPY', 'INR', 'BRL', 'MXN'];

const LEAK_DAYS = 90;

// ─── App state ────────────────────────────────────────────────────
const App = {
  data: null,
  syncCheckTimer: null,
  filter: 'all',     // status filter
  search: '',
  editingId: null,   // id of subscription being edited, or null when adding
};

// ─── Data model ───────────────────────────────────────────────────
function defaultData() {
  return {
    authMethod:   'guest',
    userToken:    Auth.generateToken(),
    workerUrl:    '',
    linkedGoogle: null,
    firstName: '', lastName: '', username: '',
    subscriptions:  [],
    paymentMethods: [],
    settings: { currency: 'USD', flowView: 'monthly', reminderLeads: [7, 1], notifyBrowser: false },
    dismissedReminders: {},   // reminderId → date dismissed (re-surfaces next cycle)
    lastNotifyDate: '',       // YYYY-MM-DD of the last browser notification (once/day)
    lastSyncTime: 0, pendingSync: false, lastModified: Date.now(),
  };
}

function mergeData(raw) {
  const d = defaultData();
  if (!raw || typeof raw !== 'object') return d;
  return {
    ...d, ...raw,
    subscriptions:  Array.isArray(raw.subscriptions)  ? raw.subscriptions  : d.subscriptions,
    paymentMethods: Array.isArray(raw.paymentMethods) ? raw.paymentMethods : d.paymentMethods,
    dismissedReminders: (raw.dismissedReminders && typeof raw.dismissedReminders === 'object')
      ? raw.dismissedReminders : d.dismissedReminders,
    settings: (raw.settings && typeof raw.settings === 'object')
      ? { ...d.settings, ...raw.settings,
          reminderLeads: Array.isArray(raw.settings.reminderLeads) ? raw.settings.reminderLeads : d.settings.reminderLeads }
      : d.settings,
  };
}

// One subscription ("stream") record.
function newSubscription() {
  const now = Date.now();
  return {
    id: uid(), name: '', amount: 0, currency: App.data?.settings?.currency || 'USD',
    frequency: 'monthly', category: 'Other', nextChargeDate: '', autoRenews: true,
    paymentLabel: '', status: 'active', lastUsedDate: '', notes: '',
    taxIncluded: true, noticeDays: 0,
    priceHistory: [], createdAt: now, updatedAt: now,
  };
}

// ─── Small utilities ──────────────────────────────────────────────
const uid = () => (crypto.randomUUID ? crypto.randomUUID()
  : 'id-' + Date.now().toString(36) + '-' + Math.random().toString(16).slice(2));
const $  = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = s => String(s ?? '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

const ls = {
  get:    k => { try { const v = localStorage.getItem(k); return v ? JSON.parse(v) : null; } catch { return null; } },
  set:    (k, v) => { try { localStorage.setItem(k, JSON.stringify(v)); } catch (e) { console.error('[Rivulet] localStorage.set failed:', e); } },
  remove: k => { try { localStorage.removeItem(k); } catch {} },
};

function saveLocal() {
  try { localStorage.setItem(STORAGE_KEY, JSON.stringify(App.data)); }
  catch (e) { console.error('[Rivulet] saveLocal failed:', e); toast('⚠️ Could not save — storage may be full'); }
}

function markDirty() {
  App.data.pendingSync = true;
  App.data.lastModified = Date.now();
  saveLocal();
  updateSyncIndicator();
}

function updateSyncIndicator() {
  const el = $('#sync-indicator');
  if (el) el.style.display = (App.data?.pendingSync && getWorkerUrl()) ? '' : 'none';
}

// ─── Domain calculations ──────────────────────────────────────────
function freqOf(id)   { return FREQUENCIES.find(f => f.id === id) || FREQUENCIES[1]; }
function monthly(sub) { return freqOf(sub.frequency).toMonthly(Number(sub.amount) || 0); }
function isActive(sub){ return sub.status === 'active'; }

function activeMonthlyTotal() {
  return App.data.subscriptions.filter(isActive).reduce((sum, s) => sum + monthly(s), 0);
}

function formatMoney(n, currency = App.data.settings.currency) {
  const v = Number(n) || 0;
  try {
    return new Intl.NumberFormat(undefined, {
      style: 'currency', currency,
      minimumFractionDigits: Number.isInteger(v) ? 0 : 2,
      maximumFractionDigits: 2,
    }).format(v);
  } catch { return '$' + v.toFixed(2); }
}

function parseDate(str) {
  if (!str) return null;
  const [y, m, d] = str.split('-').map(Number);
  if (!y || !m || !d) return null;
  return new Date(y, m - 1, d);
}
function startOfToday() { const t = new Date(); t.setHours(0, 0, 0, 0); return t; }
function daysUntil(str) { const d = parseDate(str); if (!d) return null; return Math.round((d - startOfToday()) / 86400000); }
function daysSince(str) { const d = parseDate(str); if (!d) return null; return Math.round((startOfToday() - d) / 86400000); }

function isLeak(sub) {
  if (!isActive(sub) || !sub.lastUsedDate) return false;
  const since = daysSince(sub.lastUsedDate);
  return since != null && since > LEAK_DAYS;
}

function whenLabel(days) {
  if (days == null) return '';
  if (days < 0)  return `${Math.abs(days)}d overdue`;
  if (days === 0) return 'today';
  if (days === 1) return 'tomorrow';
  return `in ${days} days`;
}

// ─── Price increases & savings ────────────────────────────────────
function pctChange(from, to) { return from ? ((to - from) / from) * 100 : null; }

// latestIncrease(sub) — the most recent price-history step, if it was a rise.
function latestIncrease(sub) {
  const h = (sub.priceHistory || []).filter(p => p && typeof p.amount === 'number');
  if (h.length < 2) return null;
  const last = h[h.length - 1], prev = h[h.length - 2];
  if (last.amount > prev.amount) {
    return { from: prev.amount, to: last.amount, pct: pctChange(prev.amount, last.amount), date: last.date };
  }
  return null;
}
function recentIncrease(sub, withinDays = 90) {
  const inc = latestIncrease(sub);
  if (!inc) return null;
  const since = daysSince(inc.date);
  return (since == null || since <= withinDays) ? inc : null;
}

// Monthly cost currently going to leaks (active streams unused > LEAK_DAYS).
function leakMonthly() {
  return App.data.subscriptions.filter(isLeak).reduce((sum, s) => sum + monthly(s), 0);
}

// ─── Reminders engine ─────────────────────────────────────────────
// Surfaces what needs attention: upcoming renewals (by lead time), cancel-by
// deadlines (notice periods), trial endings, and recent price increases.
// Each reminder has a stable id within its billing cycle, so dismissing one
// hides it until the next cycle (when the date — and thus the id — changes).
const REMINDER_OVERDUE_GRACE = 14;  // days after a passed date we still nudge

function reminderDismissed(id) {
  return !!(App.data.dismissedReminders && App.data.dismissedReminders[id]);
}

function computeReminders() {
  const out   = [];
  const leads = (App.data.settings.reminderLeads || [7, 1]).slice().sort((a, b) => b - a);
  const maxLead = leads.length ? leads[0] : 7;
  const minLead = leads.length ? leads[leads.length - 1] : 1;
  const push = r => { if (!reminderDismissed(r.id)) out.push(r); };

  for (const s of App.data.subscriptions) {
    const name = s.name || 'Untitled';
    const amt  = formatMoney(s.amount, s.currency);

    // Upcoming renewal (active)
    if (s.status === 'active' && s.nextChargeDate) {
      const d = daysUntil(s.nextChargeDate);
      if (d != null && d >= 0 && d <= maxLead) {
        push({ id: `renewal:${s.id}:${s.nextChargeDate}`, subId: s.id, type: 'renewal',
          days: d, severity: d <= minLead ? 'due' : 'soon',
          title: `${name} renews ${whenLabel(d)}`, detail: amt });
      } else if (d != null && d < 0 && d >= -REMINDER_OVERDUE_GRACE && s.autoRenews) {
        push({ id: `renewal-passed:${s.id}:${s.nextChargeDate}`, subId: s.id, type: 'renewal',
          days: d, severity: 'overdue',
          title: `${name} renewal date has passed`, detail: 'Update the next charge date to keep totals accurate.' });
      }
    }

    // Cancel-by deadline (active + a notice period)
    if (s.status === 'active' && s.nextChargeDate && (s.noticeDays || 0) > 0) {
      const d = daysUntil(s.nextChargeDate);
      if (d != null) {
        const deadline = d - s.noticeDays;   // days until the cancel-by date
        if (deadline <= 7 && deadline >= -2) {
          push({ id: `notice:${s.id}:${s.nextChargeDate}`, subId: s.id, type: 'notice',
            days: deadline, severity: deadline <= 1 ? 'due' : 'soon',
            title: deadline < 0
              ? `${name}: cancel-by date has passed`
              : `${name}: cancel within ${deadline}d to avoid the charge`,
            detail: `Needs ${s.noticeDays}d notice before the ${amt} charge.` });
        }
      }
    }

    // Trial ending
    if (s.status === 'trial' && s.nextChargeDate) {
      const d = daysUntil(s.nextChargeDate);
      if (d != null && d >= 0 && d <= Math.max(maxLead, 7)) {
        push({ id: `trial:${s.id}:${s.nextChargeDate}`, subId: s.id, type: 'trial',
          days: d, severity: d <= minLead ? 'due' : 'soon',
          title: `${name} trial ends ${whenLabel(d)}`, detail: `Then bills ${amt}. Cancel before to avoid it.` });
      } else if (d != null && d < 0 && d >= -REMINDER_OVERDUE_GRACE) {
        push({ id: `trial-passed:${s.id}:${s.nextChargeDate}`, subId: s.id, type: 'trial',
          days: d, severity: 'overdue',
          title: `${name} trial period has ended`, detail: 'Update its status if it converted to a paid plan.' });
      }
    }

    // Recent price increase (any status)
    const inc = recentIncrease(s, 90);
    if (inc) {
      push({ id: `increase:${s.id}:${inc.date}`, subId: s.id, type: 'increase',
        days: null, severity: 'info',
        title: `${name} price went up`,
        detail: `${formatMoney(inc.from, s.currency)} → ${formatMoney(inc.to, s.currency)} (+${inc.pct.toFixed(0)}%)` });
    }
  }

  const rank = { overdue: 0, due: 1, soon: 2, info: 3 };
  out.sort((a, b) => (rank[a.severity] - rank[b.severity]) || ((a.days ?? 999) - (b.days ?? 999)));
  return out;
}

function dismissReminder(id) {
  App.data.dismissedReminders = App.data.dismissedReminders || {};
  App.data.dismissedReminders[id] = new Date().toISOString().slice(0, 10);
  markDirty();
  renderRemindersList();
  renderRemindersBadge();
  if (!Auth.isGuest()) pushToWorker();
}

// Browser notification for due/overdue items — once per day, only if enabled
// and permitted. Surfaced when the app is opened (no background push).
function maybeNotify() {
  if (!App.data.settings.notifyBrowser) return;
  if (typeof Notification === 'undefined' || Notification.permission !== 'granted') return;
  const today = new Date().toISOString().slice(0, 10);
  if (App.data.lastNotifyDate === today) return;
  const due = computeReminders().filter(r => r.severity === 'due' || r.severity === 'overdue');
  if (!due.length) return;
  App.data.lastNotifyDate = today; saveLocal();
  const title = due.length === 1 ? 'Rivulet reminder' : `Rivulet · ${due.length} reminders`;
  const body  = due.length === 1 ? due[0].title : due.slice(0, 3).map(r => r.title).join('\n');
  try {
    const n = new Notification(title, { body, tag: 'rivulet-reminders' });
    n.onclick = () => { window.focus(); openReminders(); n.close(); };
  } catch {}
}

// ─── Worker sync ──────────────────────────────────────────────────
function getWorkerUrl() { return App.data?.workerUrl || ''; }

async function pushToWorker() {
  const base = getWorkerUrl().replace(/\/+$/, '');
  if (!base) return false;
  const token = App.data?.userToken;
  if (!token) return false;
  const body = JSON.stringify(App.data);
  const headers = await Auth._authHeaders('PUT', token, body);
  try {
    const res = await fetch(`${base}/storage/${encodeURIComponent(token)}/profile`, {
      method: 'PUT', headers: { 'Content-Type': 'application/json', ...headers }, body,
    });
    if (res.ok) {
      App.data.pendingSync = false;
      App.data.lastSyncTime = Date.now();
      saveLocal(); updateSyncIndicator();
    } else { console.error(`[Rivulet] pushToWorker failed (${res.status})`); }
    return res.ok;
  } catch (e) { console.error('[Rivulet] pushToWorker network error:', e); return false; }
}

async function pullFromWorker() {
  const base = getWorkerUrl().replace(/\/+$/, '');
  if (!base) return null;
  const token = App.data?.userToken;
  if (!token) return null;
  const headers = await Auth._authHeaders('GET', token, '');
  try {
    const res = await fetch(`${base}/storage/${encodeURIComponent(token)}/profile`, { headers });
    if (res.status === 410) { App.data.authMethod = 'google'; saveLocal(); return null; }
    const migratedTo = res.headers.get('X-Token-Migrated');
    if (migratedTo) {
      const j = await res.json(); const remote = j.value ?? j;
      App.data = Auth.handlePullMigration(migratedTo, mergeData(remote));
      saveLocal(); return remote;
    }
    if (!res.ok) return null;
    const j = await res.json(); return j.value ?? j;
  } catch { return null; }
}

function shouldSync() {
  if (Auth.isGuest() || !getWorkerUrl() || !App.data.pendingSync) return false;
  return (Date.now() - (App.data.lastSyncTime || 0)) >= SYNC_THRESHOLD_MS;
}
async function maybeSync() { if (shouldSync()) await pushToWorker(); }
function startSyncPing() {
  if (App.syncCheckTimer) clearInterval(App.syncCheckTimer);
  App.syncCheckTimer = setInterval(maybeSync, SYNC_CHECK_INTERVAL_MS);
}
function bestEffortPushOnHide() {
  if (Auth.isGuest() || !getWorkerUrl() || !App.data.pendingSync) return;
  pushToWorker();
}
document.addEventListener('visibilitychange', () => { if (document.visibilityState === 'hidden') bestEffortPushOnHide(); });
window.addEventListener('beforeunload', bestEffortPushOnHide);

// merge two record arrays by id, newest updatedAt wins
function mergeById(remoteArr, localArr) {
  const byId = new Map();
  (remoteArr || []).forEach(r => { if (r && r.id != null) byId.set(r.id, r); });
  (localArr  || []).forEach(l => {
    if (!l || l.id == null) return;
    const r = byId.get(l.id);
    if (!r || (l.updatedAt || 0) >= (r.updatedAt || 0)) byId.set(l.id, l);
  });
  return [...byId.values()];
}

// ─── Auth callbacks ───────────────────────────────────────────────
async function onSignedIn(data, isNew) {
  App.data = mergeData(data); saveLocal(); renderApp();
  toast(isNew ? 'Welcome to Rivulet 🌊' : 'Welcome back — syncing your streams…');
  pushToWorker();
}
async function onGuestReady(data) { App.data = mergeData(data); saveLocal(); renderApp(); }

async function fetchGoogleClientId() {
  const base = getWorkerUrl().replace(/\/+$/, '');
  if (!base) return '';
  try {
    const res = await fetch(`${base}/auth/config`);
    if (!res.ok) return '';
    const data = await res.json();
    return data.googleClientId || '';
  } catch { return ''; }
}

// ─── Motion helpers ───────────────────────────────────────────────
function prefersReducedMotion() {
  return !!(window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches);
}

// Tween a number into el (e.g. the flow total) from its last shown value.
// First paint counts up from 0; later changes ease from the previous value.
function animateNumber(el, to, fmt, dur = 600) {
  const from = (typeof el._rivVal === 'number') ? el._rivVal : 0;
  el._rivVal = to;
  if (prefersReducedMotion() || from === to || typeof requestAnimationFrame === 'undefined') {
    el.textContent = fmt(to); return;
  }
  const start = (typeof performance !== 'undefined' ? performance.now() : Date.now());
  (function tick(now) {
    const t = Math.min(1, ((now || Date.now()) - start) / dur);
    const eased = 1 - Math.pow(1 - t, 3);           // easeOutCubic
    el.textContent = fmt(from + (to - from) * eased);
    if (t < 1) requestAnimationFrame(tick); else el.textContent = fmt(to);
  })(start);
}

// Tag freshly-rendered rows so CSS rises them into place, with a capped stagger.
function markEntering(container) {
  if (prefersReducedMotion()) return;
  const rows = container.children;
  for (let i = 0; i < rows.length; i++) {
    rows[i].classList.add('riv-enter');
    rows[i].style.animationDelay = `${Math.min(i, 12) * 28}ms`;
  }
}

// ─── Rendering ────────────────────────────────────────────────────
function renderApp() {
  const subs = App.data.subscriptions;
  const has = subs.length > 0;

  $('#empty-state').hidden = has;
  $('#hero').hidden = !has;
  $('#streams-section').hidden = !has;

  renderRemindersBadge();

  if (!has) { $('#upcoming-section').hidden = true; return; }

  renderHero();
  renderUpcoming();
  renderStreams();
}

// ─── Reminders UI ─────────────────────────────────────────────────
function renderRemindersBadge() {
  const n = computeReminders().length;
  const badge = $('#reminders-badge');
  if (!badge) return;
  badge.textContent = n > 9 ? '9+' : String(n);
  badge.style.display = n ? '' : 'none';
}

function openReminders() {
  renderRemindersList();
  openModal('modal-reminders');
}

function renderRemindersList() {
  const list = $('#reminders-list');
  if (!list) return;
  const items = computeReminders();
  if (!items.length) {
    list.innerHTML = `<p class="muted" style="padding:1.5rem 0;text-align:center;">You're all caught up — no reminders right now. 🌊</p>`;
    return;
  }
  list.innerHTML = items.map(r => `
    <div class="reminder-row sev-${r.severity}">
      <div class="reminder-body" data-sub="${esc(r.subId)}" role="button" tabindex="0">
        <div class="reminder-title">${esc(r.title)}</div>
        <div class="reminder-detail">${esc(r.detail)}</div>
      </div>
      <button class="btn btn-ghost btn-sm reminder-dismiss" data-id="${esc(r.id)}">Dismiss</button>
    </div>`).join('');

  $$('#reminders-list .reminder-body').forEach(body => {
    const open = () => { closeModal('modal-reminders'); openSubModal(body.dataset.sub); };
    body.addEventListener('click', open);
    body.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
  });
  $$('#reminders-list .reminder-dismiss').forEach(b =>
    b.addEventListener('click', e => { e.stopPropagation(); dismissReminder(b.dataset.id); }));

  markEntering(list);
}

function renderHero() {
  const period = App.data.settings.flowView;
  $$('.flow-toggle-btn').forEach(b => b.classList.toggle('is-active', b.dataset.period === period));

  const monthlyTotal = activeMonthlyTotal();
  const shown = period === 'annual' ? monthlyTotal * 12 : monthlyTotal;
  animateNumber($('#flow-amount'), shown, formatMoney);

  const subs = App.data.subscriptions;
  const activeCount = subs.filter(isActive).length;
  const renewWeek = subs.filter(s => isActive(s)).filter(s => { const d = daysUntil(s.nextChargeDate); return d != null && d >= 0 && d <= 7; }).length;
  const trials = subs.filter(s => s.status === 'trial').length;
  const leaks = subs.filter(isLeak).length;
  const reclaim = leakMonthly();
  const increases = subs.filter(s => recentIncrease(s, 90)).length;
  const other = period === 'annual'
    ? `${formatMoney(monthlyTotal)}/mo`
    : `${formatMoney(monthlyTotal * 12)}/year`;

  const bits = [
    `<b>${other.split('/')[0]}</b>/${other.split('/')[1]}`,
    `<b>${activeCount}</b> active ${activeCount === 1 ? 'stream' : 'streams'}`,
  ];
  if (renewWeek) bits.push(`<b>${renewWeek}</b> renew this week`);
  if (trials)    bits.push(`<b>${trials}</b> ${trials === 1 ? 'trial' : 'trials'}`);
  if (increases) bits.push(`<span class="leak-stat">${increases} price ${increases === 1 ? 'rise' : 'rises'}</span>`);
  if (leaks)     bits.push(`<span class="leak-stat">${leaks} ${leaks === 1 ? 'leak' : 'leaks'}${reclaim > 0 ? ` · reclaim ${formatMoney(reclaim)}/mo` : ''}</span>`);
  $('#flow-substats').innerHTML = bits.join(' · ');

  // Stream bars — active subs, widest = costliest, draining rightward.
  // Render at 0 width, then flow out to target so the dashboard fills like water.
  const ranked = subs.filter(isActive).map(s => ({ s, m: monthly(s) })).sort((a, b) => b.m - a.m).slice(0, 8);
  const max = ranked.length ? ranked[0].m : 1;
  const reduce = prefersReducedMotion();
  $('#flow-streams').innerHTML = ranked.map(({ s, m }) => {
    const target = Math.max(6, (m / max) * 100);
    return `
    <div class="stream-bar-row">
      <span class="stream-bar-name">${esc(s.name || 'Untitled')}</span>
      <div class="stream-bar-track">
        <div class="stream-bar-fill" data-w="${target.toFixed(2)}" style="width:${reduce ? target.toFixed(2) + '%' : '0%'};"></div>
      </div>
      <span class="stream-bar-amt">${formatMoney(m)}</span>
    </div>`;
  }).join('');
  if (!reduce) {
    requestAnimationFrame(() => $$('#flow-streams .stream-bar-fill').forEach(el => { el.style.width = el.dataset.w + '%'; }));
  }
}

function renderUpcoming() {
  const upcoming = App.data.subscriptions
    .filter(isActive)
    .map(s => ({ s, days: daysUntil(s.nextChargeDate) }))
    .filter(x => x.days != null && x.days >= 0 && x.days <= 30)
    .sort((a, b) => a.days - b.days);

  const section = $('#upcoming-section');
  if (!upcoming.length) { section.hidden = true; return; }
  section.hidden = false;

  const total = upcoming.reduce((sum, x) => sum + (Number(x.s.amount) || 0), 0);
  $('#upcoming-total').textContent = formatMoney(total);

  $('#upcoming-list').innerHTML = upcoming.map(({ s, days }) => {
    const d = parseDate(s.nextChargeDate);
    const day = d.getDate();
    const mon = d.toLocaleString(undefined, { month: 'short' });
    const soon = days <= 7;
    return `
      <li class="upcoming-row">
        <span class="upcoming-date"><span class="d">${day}</span><span class="m">${mon}</span></span>
        <span><span class="upcoming-name">${esc(s.name || 'Untitled')}</span><br>
          <span class="upcoming-when ${soon ? 'soon' : ''}">${whenLabel(days)}</span></span>
        <span class="upcoming-amt">${formatMoney(s.amount, s.currency)}</span>
      </li>`;
  }).join('');

  markEntering($('#upcoming-list'));
}

function renderStreams(animate = true) {
  const q = App.search.trim().toLowerCase();
  let rows = App.data.subscriptions.slice();

  if (App.filter !== 'all') rows = rows.filter(s => s.status === App.filter);
  if (q) rows = rows.filter(s => (s.name + ' ' + s.category).toLowerCase().includes(q));

  // active first, then by next charge proximity, then name
  rows.sort((a, b) => {
    if (isActive(a) !== isActive(b)) return isActive(a) ? -1 : 1;
    const da = daysUntil(a.nextChargeDate), db = daysUntil(b.nextChargeDate);
    if (da != null && db != null) return da - db;
    if (da != null) return -1; if (db != null) return 1;
    return (a.name || '').localeCompare(b.name || '');
  });

  const list = $('#streams-list');
  if (!rows.length) {
    list.innerHTML = `<p class="muted" style="padding:1rem 0;">No streams match.</p>`;
    return;
  }

  list.innerHTML = rows.map(s => {
    const f = freqOf(s.frequency);
    const days = daysUntil(s.nextChargeDate);
    const soon = days != null && days >= 0 && days <= 7;
    const pills = [];
    if (s.status === 'trial')     pills.push('<span class="pill pill-trial">Trial</span>');
    if (s.status === 'paused')    pills.push('<span class="pill pill-paused">Paused</span>');
    if (s.status === 'cancelled') pills.push('<span class="pill pill-cancelled">Cancelled</span>');
    if (isLeak(s))                pills.push('<span class="pill pill-leak">Leak</span>');

    const next = (isActive(s) && days != null)
      ? `<span class="stream-next ${soon ? 'soon' : ''}">${whenLabel(days)}</span>` : '';

    return `
      <div class="stream-row" data-id="${s.id}" role="button" tabindex="0">
        <div class="stream-main">
          <span class="stream-name">${esc(s.name || 'Untitled')}</span>
          ${pills.join('')}
        </div>
        <div class="stream-meta">
          <span class="stream-cat">${esc(s.category)}</span>
          ${s.paymentLabel ? `<span>· ${esc(s.paymentLabel)}</span>` : ''}
        </div>
        <div class="stream-right">
          <span class="stream-amt">${formatMoney(s.amount, s.currency)}<span class="per">/${f.per}</span></span>
          ${next}
        </div>
      </div>`;
  }).join('');

  $$('#streams-list .stream-row').forEach(row => {
    const open = () => openSubModal(row.dataset.id);
    row.addEventListener('click', open);
    row.addEventListener('keydown', e => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); open(); } });
  });

  if (animate) markEntering(list);
}

// ─── Subscription modal (add / edit) ──────────────────────────────
function fillSelect(el, items, getVal, getLabel) {
  el.innerHTML = items.map(it => `<option value="${getVal(it)}">${getLabel(it)}</option>`).join('');
}

function openSubModal(id = null) {
  App.editingId = id;
  const sub = id ? App.data.subscriptions.find(s => s.id === id) : newSubscription();
  if (!sub) return;

  fillSelect($('#sub-currency'), CURRENCIES, c => c, c => c);
  fillSelect($('#sub-frequency'), FREQUENCIES, f => f.id, f => f.label);
  fillSelect($('#sub-category'), CATEGORIES, c => c, c => c);
  fillSelect($('#sub-status'), STATUSES, s => s.id, s => s.label);

  $('#sub-modal-title').textContent = id ? 'Edit stream' : 'Add stream';
  $('#sub-name').value     = sub.name;
  $('#sub-amount').value    = sub.amount || '';
  $('#sub-currency').value  = sub.currency;
  $('#sub-frequency').value = sub.frequency;
  $('#sub-category').value  = sub.category;
  $('#sub-next-date').value = sub.nextChargeDate;
  $('#sub-status').value    = sub.status;
  $('#sub-payment').value   = sub.paymentLabel;
  $('#sub-lastused').value  = sub.lastUsedDate;
  $('#sub-notice').value    = sub.noticeDays || '';
  $('#sub-tax').checked      = sub.taxIncluded !== false;
  $('#sub-autorenew').checked = !!sub.autoRenews;
  $('#sub-notes').value     = sub.notes;
  $('#sub-status-msg').textContent = '';
  $('#sub-delete').style.display = id ? '' : 'none';

  openModal('modal-sub');
  $('#sub-name').focus();
}

function saveSubscription() {
  const name = $('#sub-name').value.trim();
  const amount = parseFloat($('#sub-amount').value);
  const msg = $('#sub-status-msg');
  if (!name)              { msg.textContent = 'Give the stream a name.'; return; }
  if (isNaN(amount) || amount < 0) { msg.textContent = 'Enter a valid amount.'; return; }

  const fields = {
    name, amount,
    currency:  $('#sub-currency').value,
    frequency: $('#sub-frequency').value,
    category:  $('#sub-category').value,
    nextChargeDate: $('#sub-next-date').value,
    status:    $('#sub-status').value,
    paymentLabel: $('#sub-payment').value.trim(),
    lastUsedDate: $('#sub-lastused').value,
    noticeDays: Math.max(0, parseInt($('#sub-notice').value, 10) || 0),
    taxIncluded: $('#sub-tax').checked,
    autoRenews: $('#sub-autorenew').checked,
    notes: $('#sub-notes').value.trim(),
    updatedAt: Date.now(),
  };

  if (App.editingId) {
    const sub = App.data.subscriptions.find(s => s.id === App.editingId);
    // record a price-history point if the amount changed
    if (sub && Number(sub.amount) !== amount) {
      sub.priceHistory = sub.priceHistory || [];
      sub.priceHistory.push({ date: new Date().toISOString().slice(0, 10), amount, note: '' });
    }
    Object.assign(sub, fields);
  } else {
    const sub = newSubscription();
    Object.assign(sub, fields);
    sub.priceHistory = [{ date: new Date().toISOString().slice(0, 10), amount, note: 'Initial' }];
    App.data.subscriptions.push(sub);
  }

  markDirty();
  closeModal('modal-sub');
  renderApp();
  toast(App.editingId ? 'Stream updated' : 'Stream added 🌊');
  App.editingId = null;
  if (!Auth.isGuest()) pushToWorker();
}

function deleteSubscription() {
  if (!App.editingId) return;
  App.data.subscriptions = App.data.subscriptions.filter(s => s.id !== App.editingId);
  markDirty();
  closeModal('modal-sub');
  renderApp();
  toast('Stream removed');
  App.editingId = null;
  if (!Auth.isGuest()) pushToWorker();
}

// ─── Modals + toast ───────────────────────────────────────────────
function openModal(id)  { $('#' + id)?.classList.add('open'); }
function closeModal(id) { $('#' + id)?.classList.remove('open'); }

function toast(msg) {
  const c = $('#toast-container'); if (!c) return;
  const el = document.createElement('div');
  el.className = 'toast'; el.textContent = msg;
  c.appendChild(el);
  setTimeout(() => el.remove(), 3600);
}

// ─── Settings ─────────────────────────────────────────────────────
function openSettings() {
  fillSelect($('#settings-currency'), CURRENCIES, c => c, c => c);
  $('#settings-currency').value = App.data.settings.currency;
  $('#settings-flowview').value = App.data.settings.flowView;
  $('#settings-notify').checked = !!App.data.settings.notifyBrowser;
  wireAuthSettings();
  openModal('modal-settings');
}

function wireAuthSettings() {
  Auth.renderSettingsSection();
  const workerEl = $('#settings-worker-url');
  if (workerEl) workerEl.value = App.data.workerUrl || '';
  const last = $('#settings-last-synced');
  if (last) last.textContent = App.data.lastSyncTime ? new Date(App.data.lastSyncTime).toLocaleString() : 'Never';
}

// ─── Backup ───────────────────────────────────────────────────────
function exportBackup() {
  const blob = new Blob([JSON.stringify(App.data, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `rivulet-backup-${new Date().toISOString().slice(0, 10)}.json`;
  a.click();
  URL.revokeObjectURL(url);
  toast('Backup exported');
}

async function importBackup(file) {
  try {
    const raw = JSON.parse(await file.text());
    App.data = mergeData(raw);
    saveLocal(); renderApp();
    closeModal('modal-settings');
    toast('Backup imported ✓');
    if (!Auth.isGuest()) pushToWorker();
  } catch { toast('⚠️ That file could not be read as a Rivulet backup'); }
}

// ─── Event wiring ─────────────────────────────────────────────────
function wireEvents() {
  $('#btn-settings').addEventListener('click', openSettings);
  $('#btn-reminders').addEventListener('click', openReminders);
  $('#btn-add').addEventListener('click', () => openSubModal());
  $('#btn-add-empty').addEventListener('click', () => openSubModal());

  $('#sub-save').addEventListener('click', saveSubscription);
  $('#sub-delete').addEventListener('click', deleteSubscription);

  // modal close buttons + overlay click + Esc
  $$('[data-close]').forEach(b => b.addEventListener('click', () => closeModal(b.dataset.close)));
  $$('.modal-overlay').forEach(ov => ov.addEventListener('click', e => { if (e.target === ov) ov.classList.remove('open'); }));
  document.addEventListener('keydown', e => { if (e.key === 'Escape') $$('.modal-overlay.open').forEach(m => m.classList.remove('open')); });

  // search
  $('#search').addEventListener('input', e => { App.search = e.target.value; renderStreams(false); });

  // status filters
  $$('#status-filters .chip').forEach(chip => chip.addEventListener('click', () => {
    $$('#status-filters .chip').forEach(c => c.classList.remove('is-active'));
    chip.classList.add('is-active');
    App.filter = chip.dataset.status;
    renderStreams();
  }));

  // flow period toggle
  $$('.flow-toggle-btn').forEach(b => b.addEventListener('click', () => {
    App.data.settings.flowView = b.dataset.period;
    saveLocal(); renderHero();
  }));

  // settings: preferences
  $('#settings-currency').addEventListener('change', e => { App.data.settings.currency = e.target.value; markDirty(); renderApp(); });
  $('#settings-flowview').addEventListener('change', e => { App.data.settings.flowView = e.target.value; saveLocal(); renderHero(); });
  $('#settings-notify').addEventListener('change', async e => {
    if (e.target.checked) {
      if (typeof Notification === 'undefined') { toast('This browser does not support notifications'); e.target.checked = false; return; }
      let perm = Notification.permission;
      if (perm === 'default') perm = await Notification.requestPermission();
      if (perm !== 'granted') { toast('Notifications are blocked — enable them in your browser settings'); e.target.checked = false; App.data.settings.notifyBrowser = false; markDirty(); return; }
      App.data.settings.notifyBrowser = true; markDirty(); toast('Browser reminders on');
    } else {
      App.data.settings.notifyBrowser = false; markDirty();
    }
  });

  // settings: backup
  $('#btn-export').addEventListener('click', exportBackup);
  $('#import-file').addEventListener('change', e => { if (e.target.files[0]) importBackup(e.target.files[0]); });

  // settings: account (auth)
  $('#settings-create-account').addEventListener('click', () => { closeModal('modal-settings'); Auth.showSetupFresh(); });
  $('#settings-worker-url').addEventListener('change', e => { App.data.workerUrl = e.target.value.trim().replace(/\/+$/, ''); saveLocal(); });
  $('#settings-sync-now-btn').addEventListener('click', async () => { const ok = await pushToWorker(); toast(ok ? 'Synced ✓' : 'Could not sync — check your connection'); wireAuthSettings(); });
  $('#settings-token-change').addEventListener('click', () => { closeModal('modal-settings'); Auth.showSetupLoadToken(); });
  $('#settings-upgrade-google-btn').addEventListener('click', () => { closeModal('modal-settings'); Auth.showGoogleUpgradeFlow(); });
  $('#settings-account-btn').addEventListener('click', () => { closeModal('modal-settings'); Auth.isGuest() ? Auth.showGuestSwitchConfirm() : Auth.showAccountSetup(); });
  $('#settings-token-copy').addEventListener('click', () => navigator.clipboard?.writeText(App.data.userToken || '').then(() => toast('Token copied')));
}

// ─── Boot ─────────────────────────────────────────────────────────
async function boot() {
  const stored = ls.get(STORAGE_KEY);
  App.data = stored ? mergeData(stored) : defaultData();

  const googleClientId = await fetchGoogleClientId();

  Auth.init({
    googleClientId,
    storageKey: STORAGE_KEY, storageAuthKey: STORAGE_AUTH_KEY, storageDismissKey: STORAGE_DISMISS_KEY,
    workerBase: getWorkerUrl,
    getData: () => App.data,
    setData: d => { App.data = d; saveLocal(); },
    mergeData, onSignedIn, onGuestReady,
    onSessionExpired: () => {},
    pushToWorker, startSyncPing,
    openModal, closeModal, toast,
    appName: 'Rivulet', appEmoji: '🌊',
  });

  wireEvents();

  if (!stored) { renderApp(); Auth.showAccountSetup(); return; }

  const tokenBeforePull = App.data.userToken;
  if (getWorkerUrl()) {
    const remote = await pullFromWorker();
    if (remote) {
      const subs = mergeById(remote.subscriptions, App.data.subscriptions);
      const pm   = mergeById(remote.paymentMethods, App.data.paymentMethods);
      App.data = mergeData(remote);
      App.data.subscriptions = subs;
      App.data.paymentMethods = pm;
      saveLocal();
    }
  }

  const ok = await Auth.bootCheck(tokenBeforePull);
  if (!ok) { renderApp(); return; }

  renderApp();
  updateSyncIndicator();
  if (!Auth.isGuest()) startSyncPing();
  maybeSync();
  maybeNotify();
}

document.addEventListener('DOMContentLoaded', boot);
