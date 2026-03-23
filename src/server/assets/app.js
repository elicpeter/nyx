// ── Nyx Scanner Web UI ───────────────────────────────────────────────────────

const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

// ── Icons (inline SVG, 18x18, stroke="currentColor") ────────────────────────

const ICONS = {
  overview: `<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="2" width="5.5" height="5.5" rx="1"/><rect x="10.5" y="2" width="5.5" height="5.5" rx="1"/><rect x="2" y="10.5" width="5.5" height="5.5" rx="1"/><rect x="10.5" y="10.5" width="5.5" height="5.5" rx="1"/></svg>`,
  findings: `<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M9 2L2 6v5c0 3.5 3 6 7 7 4-1 7-3.5 7-7V6L9 2z"/><path d="M9 6v4"/><circle cx="9" cy="12.5" r="0.5" fill="currentColor" stroke="none"/></svg>`,
  scans: `<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M14.5 9A5.5 5.5 0 1 1 9 3.5"/><polyline points="9 5 9 9 12 11"/></svg>`,
  rules: `<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M4 5h10"/><path d="M4 9h10"/><path d="M4 13h10"/><polyline points="2 4.5 2.8 5.5 4 4"/><polyline points="2 8.5 2.8 9.5 4 8"/><polyline points="2 12.5 2.8 13.5 4 12"/></svg>`,
  triage: `<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M10 2L4 3v9l6 4 6-4V3l-6-1z"/><path d="M10 6v4"/><circle cx="10" cy="12.5" r="0.5" fill="currentColor" stroke="none"/></svg>`,
  config: `<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><line x1="3" y1="5" x2="15" y2="5"/><line x1="3" y1="9" x2="15" y2="9"/><line x1="3" y1="13" x2="15" y2="13"/><circle cx="6" cy="5" r="1.5" fill="var(--bg-secondary)"/><circle cx="11" cy="9" r="1.5" fill="var(--bg-secondary)"/><circle cx="7" cy="13" r="1.5" fill="var(--bg-secondary)"/></svg>`,
  explorer: `<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M3 3v12h12"/><path d="M7 3v4h4V3"/><path d="M7 11v4h4v-4"/><path d="M11 7h4v4h-4"/></svg>`,
  debug: `<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="4 5 2 5 2 16 13 16 13 14"/><polyline points="6 2 16 2 16 12 6 12 6 2"/><path d="M9 5.5h4"/><path d="M9 8h4"/></svg>`,
  settings: `<svg viewBox="0 0 18 18" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><circle cx="9" cy="9" r="2.5"/><path d="M9 1.5v2M9 14.5v2M1.5 9h2M14.5 9h2M3.7 3.7l1.4 1.4M12.9 12.9l1.4 1.4M14.3 3.7l-1.4 1.4M5.1 12.9l-1.4 1.4"/></svg>`,
  folder: `<svg viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M2 3.5C2 2.95 2.45 2.5 3 2.5h2.5l1.5 1.5H11c.55 0 1 .45 1 1v5.5c0 .55-.45 1-1 1H3c-.55 0-1-.45-1-1V3.5z"/></svg>`,
  tag: `<svg viewBox="0 0 14 14" fill="none" stroke="currentColor" stroke-width="1.5" stroke-linecap="round" stroke-linejoin="round"><path d="M1.5 7.8V2.5c0-.6.4-1 1-1h5.3L13 6.7l-5.3 5.3L1.5 7.8z"/><circle cx="5" cy="5" r="0.8" fill="currentColor" stroke="none"/></svg>`,
};

// ── Navigation & Route Definitions ───────────────────────────────────────────

const NAV_SECTIONS = [
  { id: 'overview',  label: 'Overview',  path: '/',          icon: ICONS.overview, group: 'primary' },
  { id: 'findings',  label: 'Findings',  path: '/findings',  icon: ICONS.findings, group: 'primary' },
  { id: 'scans',     label: 'Scans',     path: '/scans',     icon: ICONS.scans,    group: 'primary' },
  { id: 'rules',     label: 'Rules',     path: '/rules',     icon: ICONS.rules,    group: 'primary' },
  { id: 'triage',    label: 'Triage',    path: '/triage',    icon: ICONS.triage,   group: 'primary' },
  { id: 'config',    label: 'Config',    path: '/config',    icon: ICONS.config,   group: 'secondary' },
  { id: 'explorer',  label: 'Explorer',  path: '/explorer',  icon: ICONS.explorer, group: 'secondary' },
  { id: 'debug',     label: 'Debug',     path: '/debug',     icon: ICONS.debug,    group: 'secondary' },
  { id: 'settings',  label: 'Settings',  path: '/settings',  icon: ICONS.settings, group: 'footer' },
];

const ROUTES = [
  { path: '/',                 section: 'overview', render: renderDashboard },
  { path: '/findings',         section: 'findings', render: renderFindings },
  { path: '/findings/:id',     section: 'findings', render: renderFindingDetail },
  { path: '/scans',            section: 'scans',    render: renderScans },
  { path: '/scans/compare/:left/:right', section: 'scans', render: renderScanCompare },
  { path: '/scans/:id',        section: 'scans',    render: renderScanDetail },
  { path: '/rules',            section: 'rules',    render: renderRules },
  { path: '/rules/:id',        section: 'rules',    render: renderRules },
  { path: '/triage',           section: 'triage',   render: renderTriage },
  { path: '/config',           section: 'config',   render: renderConfig },
  { path: '/explorer',         section: 'explorer', render: renderStub },
  { path: '/debug',            section: 'debug',    render: renderStub },
  { path: '/debug/cfg',        section: 'debug',    render: renderStub },
  { path: '/debug/ssa',        section: 'debug',    render: renderStub },
  { path: '/debug/call-graph', section: 'debug',    render: renderStub },
  { path: '/debug/taint',      section: 'debug',    render: renderStub },
  { path: '/settings',         section: 'settings', render: renderStub },
];

const SECTION_TITLES = {
  overview: 'Overview',
  findings: 'Findings',
  scans: 'Scans',
  rules: 'Rules',
  triage: 'Triage',
  config: 'Config',
  explorer: 'Explorer',
  debug: 'Debug',
  settings: 'Settings',
};

const ROUTE_TITLES = {
  '/debug/cfg':        'CFG Viewer',
  '/debug/ssa':        'SSA Viewer',
  '/debug/call-graph': 'Call Graph',
  '/debug/taint':      'Taint Debugger',
};

const STUB_DESCRIPTIONS = {
  '/triage':           'Review, classify, and prioritize findings with bulk actions and assignment workflows.',
  '/explorer':         'Browse the scanned codebase, view file trees, and inspect individual files with inline annotations.',
  '/debug':            'Inspect internal analysis state — control flow graphs, SSA IR, call graphs, and taint propagation.',
  '/debug/cfg':        'Visualize control flow graphs for individual functions with block-level detail.',
  '/debug/ssa':        'Inspect SSA intermediate representation including phi nodes, value numbering, and taint state.',
  '/debug/call-graph': 'Explore the inter-procedural call graph with SCC highlighting and topo-order visualization.',
  '/debug/taint':      'Step through taint propagation with per-instruction state snapshots and path tracking.',
  '/scans/:id':        'View detailed scan results, timing breakdown, and per-file analysis.',
  '/settings':         'Application settings and preferences. Visit Config for sources, sinks, and sanitizers. Visit Rules to manage analysis rules.',
};

// ── API helpers ──────────────────────────────────────────────────────────────

// AbortController for the current page render — aborted on every navigation
// so stale responses from a previous page cannot overwrite the new page.
let pageAbort = new AbortController();

function isAbortError(e) {
  return e.name === 'AbortError';
}

async function api(path, opts = {}) {
  const headers = { ...opts.headers };
  if (opts.body) {
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  }
  // Attach the page-level abort signal unless the caller opts out (signal: null)
  // or provides its own signal.
  const signal = opts.signal === null ? undefined : (opts.signal || pageAbort.signal);
  const res = await fetch(`/api${path}`, { ...opts, headers, signal });
  if (!res.ok) {
    const body = await res.json().catch(() => ({}));
    throw new Error(body.error || `HTTP ${res.status}`);
  }
  return res.json();
}

// ── State ────────────────────────────────────────────────────────────────────

let currentRoute = '/';
let appMeta = null;
let selectedFindings = new Set();
const fileCache = new Map();

// ── Router ───────────────────────────────────────────────────────────────────

function matchRoute(path) {
  for (const r of ROUTES) {
    const regex = new RegExp('^' + r.path.replace(/:(\w+)/g, '(?<$1>[^/]+)') + '$');
    const m = path.match(regex);
    if (m) return { ...r, params: m.groups || {} };
  }
  return null;
}

function navigate(path) {
  if (path === currentRoute) return;
  history.pushState(null, '', path);
  route(path);
}

// Generation counter — incremented on every route() call so SSE-triggered
// refreshes can detect they've been superseded and bail out.
let routeGeneration = 0;

function route(path) {
  // Abort any in-flight API requests from the previous page render.
  pageAbort.abort();
  pageAbort = new AbortController();
  routeGeneration++;
  // Cancel any pending SSE refresh so it doesn't fight this render.
  clearTimeout(_refreshTimer);

  currentRoute = path;
  const match = matchRoute(path);
  if (match) {
    updateSidebar(match.section);
    updateHeader(match);
    match.render($('#content'), match.params, match);
  } else {
    updateSidebar(null);
    updateHeader(null);
    render404($('#content'));
  }
}

// SSE-safe refresh: schedules a re-render of the current page after a short
// delay.  If the user navigates (or another refresh fires) before the timer
// expires, the pending refresh is cancelled so it never fights the user.
let _refreshTimer = null;
function scheduleRefresh() {
  clearTimeout(_refreshTimer);
  const gen = routeGeneration;
  _refreshTimer = setTimeout(() => {
    _refreshTimer = null;
    // Only fire if no navigation happened since we scheduled.
    if (routeGeneration === gen) route(currentRoute);
  }, 200);
}

// ── Sidebar Component ────────────────────────────────────────────────────────

function renderSidebar() {
  const sidebar = $('#sidebar');
  const primary = NAV_SECTIONS.filter(s => s.group === 'primary');
  const secondary = NAV_SECTIONS.filter(s => s.group === 'secondary');
  const footer = NAV_SECTIONS.filter(s => s.group === 'footer');

  const navItem = (s) =>
    `<li><a href="${s.path}" class="nav-link" data-section="${s.id}"><span class="nav-icon">${s.icon}</span><span>${s.label}</span></a></li>`;

  sidebar.innerHTML = `
    <div class="sidebar-header">
      <h1 class="logo">Nyx</h1>
      <span class="version" id="version"></span>
    </div>
    <ul class="nav-list">
      ${primary.map(navItem).join('')}
      <li><div class="nav-separator"></div></li>
      ${secondary.map(navItem).join('')}
    </ul>
    <div class="sidebar-footer">
      <ul class="nav-list" style="flex:0;padding-top:0">
        ${footer.map(navItem).join('')}
      </ul>
    </div>
    <div class="sidebar-meta" id="sidebar-meta">
      <div class="sidebar-meta-item" id="meta-root" title="">
        ${ICONS.folder}
        <span id="meta-root-text">—</span>
      </div>
      <div class="sidebar-meta-item">
        ${ICONS.tag}
        <span id="meta-version">—</span>
      </div>
      <div class="scan-indicator" id="scan-indicator">
        <span class="status-dot running"></span>
        <span>Scanning...</span>
      </div>
    </div>
  `;
}

function updateSidebar(sectionId) {
  $$('.nav-link', $('#sidebar')).forEach(el => {
    el.classList.toggle('active', el.dataset.section === sectionId);
  });
}

async function loadAppMeta() {
  try {
    const health = await api('/health', { signal: null });
    appMeta = health;
    const v = $('#version');
    if (v) v.textContent = `v${health.version}`;
    const metaRoot = $('#meta-root');
    const metaRootText = $('#meta-root-text');
    if (metaRoot && metaRootText) {
      metaRoot.title = health.scan_root;
      metaRootText.textContent = truncPath(health.scan_root, 22);
    }
    const metaVersion = $('#meta-version');
    if (metaVersion) metaVersion.textContent = `v${health.version}`;
  } catch (e) {
    // Non-critical, sidebar meta just stays as "—"
  }
}

// ── Header Bar Component ─────────────────────────────────────────────────────

function updateHeader(match) {
  const header = $('#header-bar');
  if (!header) return;

  const crumbs = buildBreadcrumbs(match);

  header.innerHTML = `
    <div class="header-left">
      <nav class="breadcrumbs">
        ${crumbs.map((c, i) => {
          if (i === crumbs.length - 1) {
            return `<span class="breadcrumb-current">${escHtml(c.label)}</span>`;
          }
          return `<a href="${c.path}" class="breadcrumb-link nav-link-internal">${escHtml(c.label)}</a><span class="breadcrumb-sep">/</span>`;
        }).join('')}
      </nav>
    </div>
    <div class="header-right">
      <input type="text" class="header-search-input" placeholder="Search... (/)" disabled title="Coming soon">
      <button class="btn btn-sm" disabled title="Coming soon">Export</button>
      <button class="btn btn-primary btn-sm" id="header-start-scan">Start Scan</button>
    </div>
  `;

  $('#header-start-scan')?.addEventListener('click', () => openNewScanModal());
}

function buildBreadcrumbs(match) {
  const crumbs = [{ label: 'Nyx', path: '/' }];
  if (!match) {
    crumbs.push({ label: 'Not Found', path: '#' });
    return crumbs;
  }

  const sectionTitle = SECTION_TITLES[match.section] || match.section;
  const sectionNav = NAV_SECTIONS.find(s => s.id === match.section);
  const sectionPath = sectionNav ? sectionNav.path : '/';

  crumbs.push({ label: sectionTitle, path: sectionPath });

  // Sub-page title for specific routes
  const routeTitle = ROUTE_TITLES[match.path];
  if (routeTitle) {
    crumbs.push({ label: routeTitle, path: match.path });
  } else if (match.params.id) {
    crumbs.push({ label: `#${match.params.id}`, path: currentRoute });
  }

  return crumbs;
}

// ── Stub Page Renderer ───────────────────────────────────────────────────────

function renderStub(el, params, match) {
  const title = ROUTE_TITLES[match.path] || SECTION_TITLES[match.section] || 'Page';
  const desc = STUB_DESCRIPTIONS[match.path] || STUB_DESCRIPTIONS[match.section] || 'This section is under development.';
  const sectionNav = NAV_SECTIONS.find(s => s.id === match.section);
  const icon = sectionNav ? sectionNav.icon : ICONS.overview;

  el.innerHTML = `
    <div class="stub-page">
      <div class="stub-icon">${icon}</div>
      <h2 class="stub-title">${escHtml(title)}</h2>
      <p class="stub-description">${escHtml(desc)}</p>
      <span class="stub-badge">Coming Soon</span>
    </div>
  `;
}

// ── 404 Page ─────────────────────────────────────────────────────────────────

function render404(el) {
  el.innerHTML = `
    <div class="stub-page">
      <h2 class="stub-title">Page Not Found</h2>
      <p class="stub-description">The page you're looking for doesn't exist.</p>
      <a href="/" class="btn btn-primary nav-link-internal" style="text-decoration:none">Go to Overview</a>
    </div>
  `;
}

// ── SVG Chart Helpers ─────────────────────────────────────────────────────────

function svgHorizontalBar(items, opts = {}) {
  if (!items || items.length === 0) {
    return '<div class="empty-state" style="padding:20px"><p>No data</p></div>';
  }
  const barH = opts.barHeight || 22;
  const gap = 4;
  const labelW = 110;
  const valueW = 45;
  const chartW = opts.width || 400;
  const barAreaW = chartW - labelW - valueW - 16;
  const totalH = items.length * (barH + gap);
  const maxVal = opts.maxValue || Math.max(...items.map(i => i.value), 1);

  let svg = `<svg viewBox="0 0 ${chartW} ${totalH}" width="100%" preserveAspectRatio="xMinYMin meet" xmlns="http://www.w3.org/2000/svg">`;
  items.forEach((item, i) => {
    const y = i * (barH + gap);
    const w = Math.max((item.value / maxVal) * barAreaW, 2);
    const color = item.color || 'var(--accent)';
    svg += `<text x="${labelW - 8}" y="${y + barH / 2 + 4}" text-anchor="end" font-size="11" font-family="var(--font)" fill="var(--text-secondary)">${escHtml(item.label)}</text>`;
    svg += `<rect x="${labelW}" y="${y + 2}" width="${w}" height="${barH - 4}" rx="3" fill="${color}" opacity="0.85"/>`;
    svg += `<text x="${labelW + barAreaW + 8}" y="${y + barH / 2 + 4}" text-anchor="start" font-size="11" font-family="var(--font-mono)" font-weight="600" fill="var(--text)">${item.value}</text>`;
  });
  svg += '</svg>';
  return `<div class="chart-container">${svg}</div>`;
}

function svgLineChart(points, opts = {}) {
  if (!points || points.length < 2) {
    return '<div class="empty-state" style="padding:20px"><p>Need multiple scans for trends</p></div>';
  }
  const W = opts.width || 400;
  const H = opts.height || 160;
  const pad = { top: 15, right: 15, bottom: 30, left: 40 };
  const plotW = W - pad.left - pad.right;
  const plotH = H - pad.top - pad.bottom;

  const maxVal = Math.max(...points.map(p => p.value), 1);
  const minVal = 0;
  const yRange = maxVal - minVal || 1;

  const xStep = plotW / Math.max(points.length - 1, 1);
  const coords = points.map((p, i) => ({
    x: pad.left + i * xStep,
    y: pad.top + plotH - ((p.value - minVal) / yRange) * plotH,
    label: p.label,
    value: p.value,
  }));

  const polyPoints = coords.map(c => `${c.x},${c.y}`).join(' ');
  const areaPoints = `${coords[0].x},${pad.top + plotH} ${polyPoints} ${coords[coords.length - 1].x},${pad.top + plotH}`;
  const color = opts.color || 'var(--accent)';

  let svg = `<svg viewBox="0 0 ${W} ${H}" width="100%" preserveAspectRatio="xMinYMin meet" xmlns="http://www.w3.org/2000/svg">`;
  // Grid lines
  const yTicks = 4;
  for (let i = 0; i <= yTicks; i++) {
    const y = pad.top + (i / yTicks) * plotH;
    const val = Math.round(maxVal - (i / yTicks) * yRange);
    svg += `<line x1="${pad.left}" y1="${y}" x2="${pad.left + plotW}" y2="${y}" stroke="var(--border-light)" stroke-width="1"/>`;
    svg += `<text x="${pad.left - 6}" y="${y + 3}" text-anchor="end" font-size="9" font-family="var(--font-mono)" fill="var(--text-tertiary)">${val}</text>`;
  }
  // Area fill
  svg += `<polygon points="${areaPoints}" fill="${color}" opacity="0.08"/>`;
  // Line
  svg += `<polyline points="${polyPoints}" fill="none" stroke="${color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`;
  // Dots
  coords.forEach(c => {
    svg += `<circle cx="${c.x}" cy="${c.y}" r="3" fill="${color}" stroke="var(--bg)" stroke-width="2"/>`;
  });
  // X-axis labels (show subset if many points)
  const maxLabels = 6;
  const step = Math.max(1, Math.ceil(coords.length / maxLabels));
  coords.forEach((c, i) => {
    if (i % step !== 0 && i !== coords.length - 1) return;
    const label = formatShortDate(c.label);
    svg += `<text x="${c.x}" y="${H - 4}" text-anchor="middle" font-size="9" font-family="var(--font)" fill="var(--text-tertiary)">${escHtml(label)}</text>`;
  });
  svg += '</svg>';
  return `<div class="chart-container">${svg}</div>`;
}

function formatShortDate(isoStr) {
  if (!isoStr) return '';
  try {
    const d = new Date(isoStr);
    return `${d.getMonth() + 1}/${d.getDate()} ${d.getHours()}:${String(d.getMinutes()).padStart(2, '0')}`;
  } catch { return ''; }
}

function renderStatCard(label, value, opts = {}) {
  let deltaHtml = '';
  if (opts.delta != null && opts.delta !== 0) {
    const dir = opts.delta > 0 ? 'up' : 'down';
    const arrow = opts.delta > 0 ? '&#9650;' : '&#9660;';
    deltaHtml = `<span class="stat-delta delta-${dir}">${arrow}&nbsp;${Math.abs(opts.delta)}</span>`;
  }
  const colorStyle = opts.color ? `color:${opts.color}` : '';
  const subtitle = opts.subtitle ? `<div class="stat-subtitle">${escHtml(opts.subtitle)}</div>` : '';
  return `
    <div class="overview-stat-card">
      <div class="stat-label">${escHtml(label)}</div>
      <div class="stat-value" style="${colorStyle}">${value}${deltaHtml}</div>
      ${subtitle}
    </div>`;
}

// ── Dashboard ────────────────────────────────────────────────────────────────

async function renderDashboard(el, params, match) {
  el.innerHTML = '<div class="loading">Loading overview...</div>';
  try {
    const [overview, trends] = await Promise.all([
      api('/overview'),
      api('/overview/trends').catch(() => []),
    ]);

    // ── Empty state ──
    if (overview.state === 'empty') {
      el.innerHTML = `
        <div class="overview-empty">
          ${ICONS.overview}
          <h2>Welcome to Nyx</h2>
          <p>Start your first scan to see security findings and analytics.</p>
          <button class="btn btn-primary" id="first-scan-btn">Start Scan</button>
        </div>`;
      $('#first-scan-btn', el)?.addEventListener('click', openNewScanModal);
      return;
    }

    // ── Fresh banner ──
    const freshBanner = overview.state === 'fresh' ? `
      <div class="overview-fresh-banner">
        <strong>Scan completed</strong>
        <span>${overview.total_findings} finding${overview.total_findings === 1 ? '' : 's'} detected${overview.latest_scan_duration_secs != null ? ' in ' + overview.latest_scan_duration_secs.toFixed(1) + 's' : ''}.</span>
        <a href="/findings" class="nav-link-internal">View all findings &rarr;</a>
      </div>` : '';

    // ── Stat cards ──
    const netDelta = overview.new_since_last - overview.fixed_since_last;
    const statCards = [
      renderStatCard('Total Findings', overview.total_findings, {
        delta: netDelta || null,
      }),
      renderStatCard('New', overview.new_since_last, { color: overview.new_since_last > 0 ? 'var(--sev-high)' : undefined }),
      renderStatCard('Fixed', overview.fixed_since_last, { color: overview.fixed_since_last > 0 ? 'var(--success)' : undefined }),
      renderStatCard('High Confidence', (overview.high_confidence_rate * 100).toFixed(0) + '%'),
      renderStatCard('Triage Coverage', (overview.triage_coverage * 100).toFixed(0) + '%'),
      renderStatCard('Scan Duration', overview.latest_scan_duration_secs != null
        ? overview.latest_scan_duration_secs.toFixed(1) + 's' : '-'),
    ].join('');

    // ── Charts ──
    const sevItems = ['HIGH', 'MEDIUM', 'LOW'].map(s => ({
      label: s.charAt(0) + s.slice(1).toLowerCase(),
      value: overview.by_severity[s] || 0,
      color: s === 'HIGH' ? '#e74c3c' : s === 'MEDIUM' ? '#e67e22' : '#3498db',
    }));

    const catItems = Object.entries(overview.by_category || {})
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([k, v]) => ({ label: k, value: v, color: '#5856d6' }));

    const langItems = Object.entries(overview.by_language || {})
      .sort((a, b) => b[1] - a[1])
      .slice(0, 8)
      .map(([k, v]) => ({ label: k, value: v, color: '#5856d6' }));

    const trendData = trends.map(t => ({ label: t.timestamp, value: t.total }));

    // ── Top tables ──
    function compactTable(items, nameLabel, countLabel, opts = {}) {
      if (!items || items.length === 0) return '<div class="empty-state" style="padding:16px"><p>No data</p></div>';
      const nameKey = opts.nameKey || 'name';
      const countKey = opts.countKey || 'count';
      return `<table><thead><tr><th>${escHtml(nameLabel)}</th><th>${escHtml(countLabel)}</th></tr></thead><tbody>
        ${items.map(item => {
          const name = item[nameKey];
          const displayName = opts.truncate ? truncPath(name, 45) : name;
          return `<tr${opts.clickAttr ? ` class="clickable" ${opts.clickAttr(item)}` : ''}>
            <td title="${escHtml(name)}">${escHtml(displayName)}</td>
            <td>${item[countKey]}</td>
          </tr>`;
        }).join('')}
      </tbody></table>`;
    }

    const topFilesHtml = compactTable(overview.top_files, 'File', 'Findings', {
      truncate: true,
      clickAttr: item => `data-file-path="${escHtml(item.name)}"`,
    });
    const topDirsHtml = compactTable(overview.top_directories, 'Directory', 'Findings', {
      truncate: true,
    });
    const topRulesHtml = compactTable(overview.top_rules, 'Rule', 'Findings');

    const recentScansHtml = overview.recent_scans.length === 0
      ? '<div class="empty-state" style="padding:16px"><p>No scans yet</p></div>'
      : `<table><thead><tr><th>Status</th><th>Duration</th><th>Findings</th><th>Time</th></tr></thead><tbody>
        ${overview.recent_scans.slice(0, 5).map(s => `<tr class="clickable" data-scan-id="${escHtml(s.id)}">
          <td><span class="status-dot ${s.status}"></span> ${escHtml(s.status)}</td>
          <td>${s.duration_secs != null ? s.duration_secs.toFixed(1) + 's' : '-'}</td>
          <td>${s.finding_count ?? '-'}</td>
          <td>${s.started_at ? new Date(s.started_at).toLocaleString() : '-'}</td>
        </tr>`).join('')}
      </tbody></table>`;

    // ── Insights ──
    const insightsHtml = overview.insights.length > 0 ? `
      <div class="overview-insights">
        <div class="card">
          <div class="card-header">Insights</div>
          <div class="insight-list">
            ${overview.insights.map(i => `
              <div class="insight-card insight-${i.severity}">
                <span>${escHtml(i.message)}</span>
                ${i.action_url ? `<a href="${escHtml(i.action_url)}" class="nav-link-internal">View &rarr;</a>` : ''}
              </div>`).join('')}
          </div>
        </div>
      </div>` : '';

    // ── Render ──
    el.innerHTML = `
      <div class="page-header"><h2>Overview</h2></div>
      ${freshBanner}
      <div class="overview-stat-grid">${statCards}</div>
      <div class="overview-chart-grid">
        <div class="card">
          <div class="card-header">Findings Over Time</div>
          ${svgLineChart(trendData)}
        </div>
        <div class="card">
          <div class="card-header">By Severity</div>
          ${svgHorizontalBar(sevItems)}
        </div>
        <div class="card">
          <div class="card-header">By Category</div>
          ${svgHorizontalBar(catItems)}
        </div>
        <div class="card">
          <div class="card-header">By Language</div>
          ${svgHorizontalBar(langItems)}
        </div>
      </div>
      <div class="overview-table-grid">
        <div class="card">
          <div class="card-header">Top Affected Files</div>
          ${topFilesHtml}
        </div>
        <div class="card">
          <div class="card-header">Top Directories</div>
          ${topDirsHtml}
        </div>
        <div class="card">
          <div class="card-header">Top Rules Triggered</div>
          ${topRulesHtml}
        </div>
        <div class="card">
          <div class="card-header">Recent Scans</div>
          ${recentScansHtml}
        </div>
      </div>
      ${insightsHtml}
    `;

    // ── Wire click handlers ──
    $$('[data-scan-id]', el).forEach(row => {
      row.addEventListener('click', () => navigate(`/scans/${row.dataset.scanId}`));
    });
    $$('[data-file-path]', el).forEach(row => {
      row.addEventListener('click', () => navigate(`/findings?search=${encodeURIComponent(row.dataset.filePath)}`));
    });
    $$('.nav-link-internal', el).forEach(a => {
      a.addEventListener('click', (e) => {
        e.preventDefault();
        navigate(a.getAttribute('href'));
      });
    });
  } catch (e) {
    if (isAbortError(e)) return;
    el.innerHTML = `<div class="error-state"><h3>Error loading overview</h3><p>${escHtml(e.message)}</p></div>`;
  }
}

// ── Findings URL State ───────────────────────────────────────────────────────

const FINDINGS_DEFAULTS = {
  page: '1', per_page: '50', sort_by: '', sort_dir: 'asc',
  severity: '', category: '', confidence: '', language: '',
  rule_id: '', status: '', search: '',
};

function getFindingsState() {
  const p = new URLSearchParams(location.search);
  const state = {};
  for (const key of Object.keys(FINDINGS_DEFAULTS)) {
    state[key] = p.get(key) || FINDINGS_DEFAULTS[key];
  }
  return state;
}

function setFindingsState(updates) {
  const state = { ...getFindingsState(), ...updates };
  const p = new URLSearchParams();
  for (const [k, v] of Object.entries(state)) {
    if (v && v !== FINDINGS_DEFAULTS[k]) p.set(k, v);
  }
  const qs = p.toString();
  const newUrl = '/findings' + (qs ? '?' + qs : '');
  history.pushState(null, '', newUrl);
  selectedFindings.clear();
  renderFindings($('#content'), {}, matchRoute('/findings'));
}

// ── Findings ─────────────────────────────────────────────────────────────────

async function renderFindings(el, params, match) {
  el.innerHTML = '<div class="loading">Loading findings...</div>';
  try {
    const state = getFindingsState();

    // Build API query params
    const urlParams = new URLSearchParams();
    urlParams.set('page', state.page);
    urlParams.set('per_page', state.per_page);
    if (state.sort_by) urlParams.set('sort_by', state.sort_by);
    if (state.sort_dir && state.sort_dir !== 'asc') urlParams.set('sort_dir', state.sort_dir);
    if (state.severity) urlParams.set('severity', state.severity);
    if (state.category) urlParams.set('category', state.category);
    if (state.confidence) urlParams.set('confidence', state.confidence);
    if (state.language) urlParams.set('language', state.language);
    if (state.rule_id) urlParams.set('rule_id', state.rule_id);
    if (state.status) urlParams.set('status', state.status);
    if (state.search) urlParams.set('search', state.search);

    const [data, filters] = await Promise.all([
      api(`/findings?${urlParams}`),
      api('/findings/filters').catch(() => null),
    ]);

    renderFullWidthFindings(el, data, filters, state);
  } catch (e) {
    if (isAbortError(e)) return;
    if (e.message.includes('404')) {
      el.innerHTML = '<div class="empty-state"><h3>No scan results yet</h3><p>Run a scan first to see findings.</p></div>';
    } else {
      el.innerHTML = `<div class="error-state"><h3>Error</h3><p>${escHtml(e.message)}</p></div>`;
    }
  }
}

function renderFullWidthFindings(el, data, filters, state) {
    const totalPages = Math.ceil(data.total / data.per_page) || 1;
    const page = data.page;
    const hasAnyFilter = state.severity || state.category || state.confidence
      || state.language || state.rule_id || state.status || state.search;

    const sortArrow = (col) => {
      if (state.sort_by !== col) return '';
      return `<span class="sort-arrow">${state.sort_dir === 'desc' ? '\u2193' : '\u2191'}</span>`;
    };
    const sortClass = (col) => 'sortable' + (state.sort_by === col ? ' active' : '');

    const buildSelect = (id, label, values, current) => {
      if (!values || values.length === 0) return '';
      const opts = values.map(v =>
        `<option value="${escHtml(v)}" ${current === v ? 'selected' : ''}>${escHtml(v)}</option>`
      ).join('');
      return `<select id="${id}"><option value="">All ${escHtml(label)}</option>${opts}</select>`;
    };

    el.innerHTML = `
      <div class="page-header">
        <h2>Findings</h2>
        <span class="filter-count">${data.total} finding${data.total !== 1 ? 's' : ''}${hasAnyFilter ? ' (filtered)' : ''}</span>
      </div>
      <div class="filter-bar">
        <input type="text" placeholder="Search findings... (/)" class="search-input" id="findings-search"
          value="${escHtml(state.search)}">
        ${filters ? buildSelect('filter-severity', 'Severities', filters.severities, state.severity) : ''}
        ${filters ? buildSelect('filter-confidence', 'Confidences', filters.confidences, state.confidence) : ''}
        ${filters ? buildSelect('filter-category', 'Categories', filters.categories, state.category) : ''}
        ${filters ? buildSelect('filter-language', 'Languages', filters.languages, state.language) : ''}
        ${filters ? buildSelect('filter-rule', 'Rules', filters.rules, state.rule_id) : ''}
        ${filters ? buildSelect('filter-status', 'Statuses', filters.statuses, state.status) : ''}
        ${hasAnyFilter ? '<button class="btn btn-sm btn-clear" id="clear-filters">Clear All</button>' : ''}
      </div>
      <div class="bulk-action-bar" id="bulk-bar">
        <span class="bulk-count" id="bulk-count">0 selected</span>
        <button class="btn btn-sm btn-bulk-triage" data-state="suppressed">Suppress</button>
        <button class="btn btn-sm btn-bulk-triage" data-state="false_positive">Mark FP</button>
        <button class="btn btn-sm btn-bulk-triage" data-state="accepted_risk">Accept Risk</button>
        <button class="btn btn-sm btn-bulk-triage" data-state="investigating">Investigating</button>
        <button class="btn btn-sm" id="bulk-suppress-pattern">Suppress by Pattern</button>
      </div>
      ${data.findings.length === 0
        ? '<div class="empty-state"><h3>No findings</h3><p>Run a scan to see results, or adjust your filters.</p></div>'
        : `<div class="table-wrap"><table>
          <thead><tr>
            <th class="col-checkbox"><input type="checkbox" id="select-all"></th>
            <th class="${sortClass('severity')}">Severity${sortArrow('severity')}</th>
            <th class="${sortClass('confidence')}">Confidence${sortArrow('confidence')}</th>
            <th class="${sortClass('rule_id')}">Rule${sortArrow('rule_id')}</th>
            <th class="${sortClass('category')}">Category${sortArrow('category')}</th>
            <th class="${sortClass('file')}">File${sortArrow('file')}</th>
            <th class="${sortClass('line')}">Line${sortArrow('line')}</th>
            <th class="${sortClass('language')}">Language${sortArrow('language')}</th>
            <th class="${sortClass('status')}">Status${sortArrow('status')}</th>
          </tr></thead>
          <tbody>
          ${data.findings.map(f => `<tr class="clickable${selectedFindings.has(f.index) ? ' selected' : ''}" data-finding="${f.index}" data-fingerprint="${f.fingerprint}">
            <td class="col-checkbox"><input type="checkbox" class="row-check" data-idx="${f.index}" ${selectedFindings.has(f.index) ? 'checked' : ''}></td>
            <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
            <td>${f.confidence ? `<span class="badge badge-conf-${f.confidence.toLowerCase()}">${f.confidence}</span>` : '-'}</td>
            <td>${escHtml(f.rule_id)}</td>
            <td>${escHtml(f.category)}</td>
            <td class="cell-path" title="${escHtml(f.path)}">${escHtml(truncPath(f.path))}</td>
            <td>${f.line}</td>
            <td>${f.language || '-'}</td>
            <td><span class="badge badge-triage-${f.triage_state || f.status}">${(f.triage_state || f.status).replace(/_/g, ' ')}</span></td>
          </tr>`).join('')}
          </tbody></table></div>
          <div class="pagination">
            <div class="pagination-left">
              <span>Per page:</span>
              <select id="page-size">
                ${[25,50,100].map(n => `<option value="${n}" ${parseInt(state.per_page)===n?'selected':''}>${n}</option>`).join('')}
              </select>
            </div>
            <div class="pagination-center">
              <button class="btn btn-sm" id="page-first" ${page<=1?'disabled':''}>First</button>
              <button class="btn btn-sm" id="page-prev" ${page<=1?'disabled':''}>Prev</button>
              <span>Page ${page} of ${totalPages}</span>
              <button class="btn btn-sm" id="page-next" ${page>=totalPages?'disabled':''}>Next</button>
              <button class="btn btn-sm" id="page-last" ${page>=totalPages?'disabled':''}>Last</button>
            </div>
            <div class="pagination-right">
              <span>${data.total} total</span>
            </div>
          </div>`
      }`;

    // ── Event listeners ──

    // Row click → navigate to detail page (skip if clicking checkbox)
    $$('[data-finding]', el).forEach(row => {
      row.addEventListener('click', (e) => {
        if (e.target.type === 'checkbox') return;
        navigate(`/findings/${row.dataset.finding}`);
      });
    });

    // Search with debounce
    $('#findings-search')?.addEventListener('input', debounce(e => {
      setFindingsState({ search: e.target.value, page: '1' });
    }, 300));

    // Filter dropdowns
    const filterMap = {
      'filter-severity': 'severity',
      'filter-confidence': 'confidence',
      'filter-category': 'category',
      'filter-language': 'language',
      'filter-rule': 'rule_id',
      'filter-status': 'status',
    };
    for (const [id, key] of Object.entries(filterMap)) {
      $(`#${id}`)?.addEventListener('change', e => {
        setFindingsState({ [key]: e.target.value, page: '1' });
      });
    }

    // Clear all filters
    $('#clear-filters')?.addEventListener('click', () => {
      setFindingsState({
        severity: '', category: '', confidence: '', language: '',
        rule_id: '', status: '', search: '', page: '1',
      });
    });

    // Sortable column headers
    $$('th.sortable', el).forEach(th => {
      th.addEventListener('click', () => {
        const cols = ['severity','confidence','rule_id','category','file','line','language','status'];
        const idx = Array.from(th.parentNode.children).indexOf(th) - 1; // minus checkbox col
        const col = cols[idx];
        if (!col) return;
        const newDir = state.sort_by === col && state.sort_dir === 'asc' ? 'desc' : 'asc';
        setFindingsState({ sort_by: col, sort_dir: newDir, page: '1' });
      });
    });

    // Row selection checkboxes
    const updateBulkBar = () => {
      const bar = $('#bulk-bar');
      const count = $('#bulk-count');
      if (bar) bar.classList.toggle('visible', selectedFindings.size > 0);
      if (count) count.textContent = `${selectedFindings.size} selected`;
    };

    $$('.row-check', el).forEach(cb => {
      cb.addEventListener('change', () => {
        const idx = parseInt(cb.dataset.idx);
        if (cb.checked) selectedFindings.add(idx);
        else selectedFindings.delete(idx);
        cb.closest('tr').classList.toggle('selected', cb.checked);
        updateBulkBar();
        // Update select-all state
        const allChecks = $$('.row-check', el);
        const selectAll = $('#select-all');
        if (selectAll) selectAll.checked = allChecks.length > 0 && allChecks.every(c => c.checked);
      });
    });

    $('#select-all')?.addEventListener('change', e => {
      $$('.row-check', el).forEach(cb => {
        cb.checked = e.target.checked;
        const idx = parseInt(cb.dataset.idx);
        if (e.target.checked) selectedFindings.add(idx);
        else selectedFindings.delete(idx);
        cb.closest('tr').classList.toggle('selected', e.target.checked);
      });
      updateBulkBar();
    });

    // Pagination
    $('#page-size')?.addEventListener('change', e => {
      setFindingsState({ per_page: e.target.value, page: '1' });
    });
    $('#page-first')?.addEventListener('click', () => setFindingsState({ page: '1' }));
    $('#page-prev')?.addEventListener('click', () => setFindingsState({ page: String(Math.max(1, page - 1)) }));
    $('#page-next')?.addEventListener('click', () => setFindingsState({ page: String(Math.min(totalPages, page + 1)) }));
    $('#page-last')?.addEventListener('click', () => setFindingsState({ page: String(totalPages) }));

    updateBulkBar();

    // Bulk triage action buttons
    $$('.btn-bulk-triage', el).forEach(btn => {
      btn.addEventListener('click', async () => {
        const fingerprints = [];
        $$('tr[data-fingerprint]', el).forEach(row => {
          const idx = parseInt(row.dataset.finding);
          if (selectedFindings.has(idx)) {
            fingerprints.push(row.dataset.fingerprint);
          }
        });
        if (fingerprints.length === 0) return;
        try {
          await api('/triage', {
            method: 'POST',
            body: JSON.stringify({ fingerprints, state: btn.dataset.state, note: '' }),
            signal: null,
          });
          selectedFindings.clear();
          renderFindings(el, params, match);
        } catch (err) {
          alert('Failed to update triage state: ' + err.message);
        }
      });
    });

    // Suppress by pattern button
    $('#bulk-suppress-pattern', el)?.addEventListener('click', () => {
      // Collect rule_ids and file paths from selected findings
      const selectedRows = [];
      $$('tr[data-fingerprint]', el).forEach(row => {
        const idx = parseInt(row.dataset.finding);
        if (selectedFindings.has(idx)) {
          const finding = data.findings.find(f => f.index === idx);
          if (finding) selectedRows.push(finding);
        }
      });
      if (selectedRows.length === 0) return;

      // Get unique rules and files
      const rules = [...new Set(selectedRows.map(f => f.rule_id))];
      const files = [...new Set(selectedRows.map(f => f.path))];

      // Build a simple modal for pattern selection
      const modal = document.createElement('div');
      modal.className = 'suppress-modal-overlay';
      modal.innerHTML = `
        <div class="suppress-modal">
          <h3>Suppress by Pattern</h3>
          <div class="suppress-options">
            ${rules.map(r => `<button class="btn btn-sm suppress-opt" data-by="rule" data-value="${escHtml(r)}">By rule: ${escHtml(r)}</button>`).join('')}
            ${files.map(f => `<button class="btn btn-sm suppress-opt" data-by="file" data-value="${escHtml(f)}">By file: ${escHtml(truncPath(f, 40))}</button>`).join('')}
          </div>
          <textarea id="suppress-note" placeholder="Note (optional)..." rows="2" style="width:100%;margin-top:var(--space-3)"></textarea>
          <div style="display:flex;gap:var(--space-2);margin-top:var(--space-3)">
            <button class="btn btn-sm" id="suppress-modal-cancel">Cancel</button>
          </div>
        </div>
      `;
      document.body.appendChild(modal);

      modal.querySelector('#suppress-modal-cancel').addEventListener('click', () => modal.remove());
      modal.addEventListener('click', (e) => { if (e.target === modal) modal.remove(); });

      modal.querySelectorAll('.suppress-opt').forEach(opt => {
        opt.addEventListener('click', async () => {
          const note = (modal.querySelector('#suppress-note')?.value || '').trim();
          try {
            await api('/triage/suppress', {
              method: 'POST',
              body: JSON.stringify({ by: opt.dataset.by, value: opt.dataset.value, note }),
              signal: null,
            });
            modal.remove();
            selectedFindings.clear();
            renderFindings($('#content'), params, match);
          } catch (err) {
            alert('Failed to add suppression rule: ' + err.message);
          }
        });
      });
    });
}

// ── Finding Detail Page ──────────────────────────────────────────────────────

async function renderFindingDetail(el, params, match) {
  const index = params.id;
  el.innerHTML = '<div class="loading">Loading finding...</div>';
  try {
    const f = await api(`/findings/${index}`);

    const sanitizerBadge = f.sanitizer_status
      ? `<span class="badge sanitizer-badge-${f.sanitizer_status}">${f.sanitizer_status === 'none' ? 'No sanitizers' : f.sanitizer_status === 'bypassed' ? 'Sanitizer bypassed' : 'Sanitized'}</span>`
      : '';

    const evidenceHtml = buildEvidenceHtml(f);
    const confidenceHtml = buildConfidenceHtml(f);
    const relatedHtml = buildRelatedHtml(f);
    const notesHtml = buildNotesHtml(f);
    const flowHtml = buildFlowHtml(f);

    el.innerHTML = `
      <div class="detail-panel">
        <button class="btn btn-sm" id="back-btn" style="margin-bottom:var(--space-4)">Back to Findings</button>
        <h2>${escHtml(f.rule_id)}</h2>
        <div class="badge-row">
          <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
          ${f.confidence ? `<span class="badge badge-conf-${f.confidence.toLowerCase()}">${f.confidence}</span>` : ''}
          <span class="badge">${escHtml(f.category)}</span>
          <span class="badge badge-triage-${f.triage_state || 'open'}">${(f.triage_state || 'open').replace(/_/g, ' ')}</span>
          ${sanitizerBadge}
        </div>
        <a href="#" class="file-location" id="open-code-viewer" data-path="${escHtml(f.path)}" data-line="${f.line}">${escHtml(f.path)}:${f.line}:${f.col}</a>

        <div class="triage-actions" data-fingerprint="${escHtml(f.fingerprint)}">
          ${f.triage_note ? `<div class="triage-current-note"><strong>Note:</strong> ${escHtml(f.triage_note)}</div>` : ''}
          <div class="triage-buttons">
            ${['open','investigating','false_positive','accepted_risk','suppressed','fixed']
              .filter(s => s !== (f.triage_state || 'open'))
              .map(s => `<button class="btn btn-sm btn-triage btn-triage-${s}" data-state="${s}">${s.replace(/_/g, ' ')}</button>`)
              .join('')}
          </div>
          <div class="triage-note-input" id="triage-note-form" style="display:none">
            <textarea id="triage-note-text" placeholder="Add a note (optional)..." rows="2"></textarea>
            <div class="triage-note-actions">
              <button class="btn btn-sm btn-primary" id="triage-confirm">Confirm</button>
              <button class="btn btn-sm" id="triage-cancel">Cancel</button>
            </div>
          </div>
        </div>

        ${f.message || (f.evidence && (f.evidence.source || f.evidence.sink)) ? `
          <div class="detail-section">
            <div class="section-toggle" data-section="why">
              <span class="toggle-arrow">&#9660;</span> Why Nyx Reported This
            </div>
            <div class="section-body" id="section-why">
              ${f.evidence && f.evidence.explanation ? `<p style="margin-bottom:var(--space-3);line-height:1.5">${escHtml(f.evidence.explanation)}</p>` : ''}
              ${f.message ? `<p style="margin-bottom:var(--space-3)">${escHtml(f.message)}</p>` : ''}
              ${f.evidence && f.evidence.source ? `<p class="evidence-note">Tainted data flows from <strong>${escHtml(f.evidence.source.kind)}</strong> at line ${f.evidence.source.line} to a dangerous operation.</p>` : ''}
              ${f.evidence && f.evidence.sink ? `<p class="evidence-note">Sink at line ${f.evidence.sink.line}${f.evidence.sink.snippet ? ': <code>' + escHtml(f.evidence.sink.snippet) + '</code>' : ''}</p>` : ''}
              ${f.guard_kind ? `<p class="evidence-note">Guard: ${escHtml(f.guard_kind)}</p>` : ''}
            </div>
          </div>` : ''}

        ${flowHtml ? `
          <div class="detail-section">
            <div class="section-toggle" data-section="flow">
              <span class="toggle-arrow">&#9660;</span> Taint Flow
            </div>
            <div class="section-body" id="section-flow">${flowHtml}</div>
          </div>` : ''}

        ${evidenceHtml ? `
          <div class="detail-section">
            <div class="section-toggle" data-section="evidence">
              <span class="toggle-arrow">&#9660;</span> Evidence
            </div>
            <div class="section-body" id="section-evidence">${evidenceHtml}</div>
          </div>` : ''}

        ${notesHtml ? `
          <div class="detail-section">
            <div class="section-toggle" data-section="notes">
              <span class="toggle-arrow">&#9660;</span> Analysis Notes
            </div>
            <div class="section-body" id="section-notes">${notesHtml}</div>
          </div>` : ''}

        ${confidenceHtml ? `
          <div class="detail-section">
            <div class="section-toggle" data-section="confidence">
              <span class="toggle-arrow">&#9660;</span> Confidence Reasoning
            </div>
            <div class="section-body" id="section-confidence">${confidenceHtml}</div>
          </div>` : ''}

        ${relatedHtml ? `
          <div class="detail-section">
            <div class="section-toggle" data-section="related">
              <span class="toggle-arrow">&#9660;</span> Related Findings
            </div>
            <div class="section-body" id="section-related">${relatedHtml}</div>
          </div>` : ''}

        ${f.labels.length > 0 ? `
          <div class="detail-section">
            <div class="section-toggle" data-section="labels">
              <span class="toggle-arrow">&#9660;</span> Labels
            </div>
            <div class="section-body" id="section-labels">
              <div class="label-list">
                ${f.labels.map(([k, v]) => `<span class="label-item"><span class="label-key">${escHtml(k)}:</span> <span class="label-value">${escHtml(v)}</span></span>`).join('')}
              </div>
            </div>
          </div>` : ''}

        ${f.code_context ? `
          <div class="detail-section">
            <div class="section-toggle" data-section="code-preview">
              <span class="toggle-arrow">&#9660;</span> Code Preview
            </div>
            <div class="section-body" id="section-code-preview">
              <div class="code-block">
                ${f.code_context.lines.map((line, i) => {
                  const lineNum = f.code_context.start_line + i;
                  const isHighlight = lineNum === f.code_context.highlight_line;
                  return `<div class="code-line${isHighlight ? ' highlight' : ''}"><span class="line-number">${lineNum}</span><span class="line-content">${escHtml(line)}</span></div>`;
                }).join('')}
              </div>
            </div>
          </div>` : ''}
      </div>`;

    // Back button
    $('#back-btn')?.addEventListener('click', () => navigate('/findings'));

    // File location → open code modal
    $('#open-code-viewer')?.addEventListener('click', (e) => {
      e.preventDefault();
      openCodeModal(f);
    });

    // Collapsible section toggles
    $$('.section-toggle', el).forEach(toggle => {
      toggle.addEventListener('click', () => {
        const sectionId = toggle.dataset.section;
        const body = $(`#section-${sectionId}`, el);
        const arrow = $('.toggle-arrow', toggle);
        if (body) body.classList.toggle('collapsed');
        if (arrow) arrow.classList.toggle('collapsed');
      });
    });

    // Flow step clicks → open code modal at that line
    $$('.flow-step', el).forEach(step => {
      step.addEventListener('click', () => {
        $$('.flow-step', el).forEach(s => s.classList.remove('active'));
        step.classList.add('active');
        openCodeModal({ path: step.dataset.path, line: parseInt(step.dataset.line), evidence: f.evidence, language: f.language });
      });
    });

    // Related finding clicks → navigate to that finding's detail page
    $$('.related-row', el).forEach(row => {
      row.addEventListener('click', () => navigate(`/findings/${row.dataset.finding}`));
    });

    // Triage action buttons
    let pendingTriageState = null;
    $$('.btn-triage', el).forEach(btn => {
      btn.addEventListener('click', () => {
        pendingTriageState = btn.dataset.state;
        const form = $('#triage-note-form', el);
        if (form) form.style.display = 'block';
        const ta = $('#triage-note-text', el);
        if (ta) { ta.value = ''; ta.focus(); }
      });
    });

    $('#triage-cancel', el)?.addEventListener('click', () => {
      pendingTriageState = null;
      const form = $('#triage-note-form', el);
      if (form) form.style.display = 'none';
    });

    $('#triage-confirm', el)?.addEventListener('click', async () => {
      if (!pendingTriageState) return;
      const note = ($('#triage-note-text', el)?.value || '').trim();
      try {
        await api('/triage', {
          method: 'POST',
          body: JSON.stringify({ fingerprints: [f.fingerprint], state: pendingTriageState, note }),
          signal: null,
        });
        // Re-render the finding detail to reflect the new state
        renderFindingDetail(el, params, match);
      } catch (err) {
        alert('Failed to update triage state: ' + err.message);
      }
    });

  } catch (e) {
    if (isAbortError(e)) return;
    el.innerHTML = `<div class="error-state"><h3>Finding not found</h3><p>${escHtml(e.message)}</p></div>`;
  }
}

function buildEvidenceHtml(f) {
  if (!f.evidence) return '';
  const cards = [];

  if (f.evidence.source) {
    const s = f.evidence.source;
    cards.push(`<div class="evidence-card">
      <div class="evidence-kind" style="color:var(--success)">Source</div>
      <div>${escHtml(s.path)}:${s.line}:${s.col}</div>
      ${s.snippet ? `<div class="evidence-snippet">${escHtml(s.snippet)}</div>` : ''}
    </div>`);
  }

  if (f.evidence.sink) {
    const s = f.evidence.sink;
    cards.push(`<div class="evidence-card">
      <div class="evidence-kind" style="color:var(--sev-high)">Sink</div>
      <div>${escHtml(s.path)}:${s.line}:${s.col}</div>
      ${s.snippet ? `<div class="evidence-snippet">${escHtml(s.snippet)}</div>` : ''}
    </div>`);
  }

  for (const g of (f.evidence.guards || [])) {
    cards.push(`<div class="evidence-card">
      <div class="evidence-kind" style="color:var(--accent)">Guard</div>
      <div>${escHtml(g.path)}:${g.line}:${g.col}</div>
      ${g.snippet ? `<div class="evidence-snippet">${escHtml(g.snippet)}</div>` : ''}
    </div>`);
  }

  for (const s of (f.evidence.sanitizers || [])) {
    cards.push(`<div class="evidence-card">
      <div class="evidence-kind" style="color:var(--sev-medium)">Sanitizer</div>
      <div>${escHtml(s.path)}:${s.line}:${s.col}</div>
      ${s.snippet ? `<div class="evidence-snippet">${escHtml(s.snippet)}</div>` : ''}
    </div>`);
  }

  if (f.evidence.state) {
    const st = f.evidence.state;
    cards.push(`<div class="evidence-card">
      <div class="evidence-kind">State: ${escHtml(st.machine)}</div>
      <div>${st.subject ? escHtml(st.subject) + ': ' : ''}${escHtml(st.from_state)} &rarr; ${escHtml(st.to_state)}</div>
    </div>`);
  }

  return cards.join('');
}

function buildNotesHtml(f) {
  if (!f.evidence || !f.evidence.notes || f.evidence.notes.length === 0) return '';
  const items = f.evidence.notes.map(note => {
    // Parse known note formats into readable text
    if (note.startsWith('source_kind:')) {
      const kind = note.split(':')[1];
      const readable = { UserInput: 'User Input', EnvironmentConfig: 'Environment/Config', Database: 'Database', FileSystem: 'File System', CaughtException: 'Caught Exception', Unknown: 'Unclassified' };
      return `Source type: ${readable[kind] || kind}`;
    }
    if (note.startsWith('hop_count:')) return `Path length: ${note.split(':')[1]} blocks`;
    if (note === 'uses_summary') return 'Uses cross-file summary';
    if (note === 'path_validated') return 'Path has validation guard';
    if (note.startsWith('cap_specificity:')) return `Cap specificity: ${note.split(':')[1]}`;
    if (note.startsWith('degraded:')) return `Degraded analysis: ${note.split(':')[1]}`;
    return note;
  });
  return `<ul style="list-style:disc;padding-left:20px;margin:0">${items.map(n => `<li class="evidence-note">${escHtml(n)}</li>`).join('')}</ul>`;
}

function buildConfidenceHtml(f) {
  if (!f.confidence) return '';
  let html = `<span class="badge badge-conf-${f.confidence.toLowerCase()}">${f.confidence}</span>`;
  if (f.rank_score != null) {
    html += ` <span style="margin-left:var(--space-2);font-size:var(--text-sm);color:var(--text-secondary)">Score: ${f.rank_score.toFixed(1)}</span>`;
  }
  if (f.rank_reason && f.rank_reason.length > 0) {
    html += '<div style="margin-top:var(--space-2)">';
    for (const [k, v] of f.rank_reason) {
      html += `<div class="evidence-note"><strong>${escHtml(k)}:</strong> ${escHtml(v)}</div>`;
    }
    html += '</div>';
  }
  // Confidence limiters
  const limiters = f.evidence && f.evidence.confidence_limiters;
  if (limiters && limiters.length > 0 && f.confidence !== 'High') {
    html += '<div style="margin-top:var(--space-3)"><strong style="font-size:var(--text-sm);color:var(--text-secondary)">Why not higher confidence?</strong>';
    html += '<ul class="confidence-limiters">';
    for (const l of limiters) {
      html += `<li>${escHtml(l)}</li>`;
    }
    html += '</ul></div>';
  }
  return html;
}

function buildRelatedHtml(f) {
  if (!f.related_findings || f.related_findings.length === 0) return '';
  return f.related_findings.map(r =>
    `<div class="related-row" data-finding="${r.index}">
      <span class="badge badge-${r.severity.toLowerCase()}">${r.severity.charAt(0)}</span>
      <span style="font-size:var(--text-xs)">${escHtml(r.rule_id)}</span>
      <span class="cell-path" style="font-size:var(--text-xs);max-width:200px">${escHtml(truncPath(r.path, 30))}:${r.line}</span>
    </div>`
  ).join('');
}

function buildFlowHtml(f) {
  if (!f.evidence || !f.evidence.flow_steps || f.evidence.flow_steps.length === 0) return '';

  const kindColors = {
    source: 'var(--success)',
    assignment: 'var(--accent)',
    call: 'var(--sev-medium)',
    phi: 'var(--text-tertiary)',
    sink: 'var(--sev-high)',
  };
  const kindLabels = {
    source: 'Source',
    assignment: 'Assign',
    call: 'Call',
    phi: 'Phi',
    sink: 'Sink',
  };

  const steps = f.evidence.flow_steps.map((s, i) => {
    const color = kindColors[s.kind] || 'var(--text-secondary)';
    const label = kindLabels[s.kind] || s.kind;
    const isLast = i === f.evidence.flow_steps.length - 1;
    return `<div class="flow-step${s.is_cross_file ? ' flow-step-cross-file' : ''}" data-path="${escHtml(s.file)}" data-line="${s.line}">
      <div class="flow-step-connector">
        <div class="flow-step-dot" style="background:${color}"></div>
        ${!isLast ? '<div class="flow-step-line"></div>' : ''}
      </div>
      <div class="flow-step-card">
        <div style="display:flex;align-items:center;gap:var(--space-2);margin-bottom:2px">
          <span class="flow-step-badge" style="color:${color}">${label}</span>
          <span style="font-size:var(--text-xs);color:var(--text-secondary)">#${s.step}</span>
          ${s.variable ? `<span style="font-size:var(--text-sm);font-family:var(--font-mono)">${escHtml(s.variable)}</span>` : ''}
          ${s.callee ? `<span style="font-size:var(--text-xs);color:var(--text-secondary)">${escHtml(s.callee)}</span>` : ''}
        </div>
        <div style="font-size:var(--text-xs);color:var(--text-tertiary)">${escHtml(s.file)}:${s.line}:${s.col}${s.function ? ` in ${escHtml(s.function)}` : ''}</div>
        ${s.snippet ? `<div class="flow-step-snippet">${escHtml(s.snippet)}</div>` : ''}
      </div>
    </div>`;
  }).join('');

  return `<div class="flow-timeline">${steps}</div>`;
}

// ── Code Viewer Modal ────────────────────────────────────────────────────────

async function openCodeModal(f) {
  // Create modal overlay
  const modal = document.createElement('div');
  modal.className = 'code-modal-overlay';
  modal.innerHTML = `
    <div class="code-modal">
      <div class="code-modal-header">
        <span class="code-modal-title">${escHtml(f.path)}</span>
        <button class="btn btn-sm code-modal-close" id="code-modal-close">Close</button>
      </div>
      <div class="code-modal-body">
        <div class="loading" style="padding:40px;text-align:center">Loading file...</div>
      </div>
    </div>`;
  document.body.appendChild(modal);

  // Close handlers
  const close = () => modal.remove();
  $('#code-modal-close', modal).addEventListener('click', close);
  modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
  const onKey = (e) => { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', onKey); } };
  document.addEventListener('keydown', onKey);

  try {
    let fileData = fileCache.get(f.path);
    if (!fileData) {
      fileData = await api(`/files?path=${encodeURIComponent(f.path)}`);
      fileCache.set(f.path, fileData);
    }

    const sourceLine = f.evidence?.source?.line;
    const sinkLine = f.evidence?.sink?.line;
    const findingLine = f.line;
    const lang = (f.language || '').toLowerCase();

    const body = $('.code-modal-body', modal);
    body.innerHTML = `<div class="code-viewer-body">${fileData.lines.map(l => {
      let cls = 'code-line';
      if (l.number === sourceLine) cls += ' highlight-source';
      else if (l.number === sinkLine) cls += ' highlight-sink';
      else if (l.number === findingLine) cls += ' highlight-finding';
      return `<div class="${cls}" data-line="${l.number}"><span class="line-number">${l.number}</span><span class="line-content">${highlightSyntax(escHtml(l.content), lang)}</span></div>`;
    }).join('')}</div>`;

    // Scroll to finding line
    requestAnimationFrame(() => {
      const target = $(`[data-line="${findingLine}"]`, modal);
      if (target) target.scrollIntoView({ block: 'center', behavior: 'smooth' });
    });
  } catch (e) {
    const body = $('.code-modal-body', modal);
    if (body) body.innerHTML = `<div class="error-state" style="padding:40px"><p>Could not load file: ${escHtml(e.message)}</p></div>`;
  }
}

// ── Syntax Highlighting ─────────────────────────────────────────────────────

const SYNTAX_RULES = {
  javascript: {
    keywords: /\b(const|let|var|function|return|if|else|for|while|do|switch|case|break|continue|new|this|class|extends|import|export|from|default|try|catch|finally|throw|async|await|yield|typeof|instanceof|in|of|null|undefined|true|false)\b/g,
    strings: /(["'`])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?)\b/gi,
  },
  typescript: null, // filled below
  python: {
    keywords: /\b(def|class|return|if|elif|else|for|while|import|from|as|try|except|finally|raise|with|yield|lambda|pass|break|continue|and|or|not|in|is|None|True|False|self|async|await|global|nonlocal)\b/g,
    strings: /("""[\s\S]*?"""|'''[\s\S]*?'''|"(?:[^"\\]|\\.)*"|'(?:[^'\\]|\\.)*')/g,
    comments: /(#.*$)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?)\b/gi,
  },
  go: {
    keywords: /\b(func|return|if|else|for|range|switch|case|default|break|continue|go|defer|select|chan|map|struct|interface|package|import|var|const|type|nil|true|false|make|new|append|len|cap|error)\b/g,
    strings: /(["'`])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?)\b/gi,
  },
  java: {
    keywords: /\b(public|private|protected|static|final|abstract|class|interface|extends|implements|return|if|else|for|while|do|switch|case|break|continue|new|this|super|try|catch|finally|throw|throws|import|package|void|int|long|double|float|boolean|char|byte|short|String|null|true|false|instanceof|synchronized|volatile|transient)\b/g,
    strings: /(["'])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?[lLfFdD]?)\b/g,
  },
  rust: {
    keywords: /\b(fn|let|mut|const|static|return|if|else|for|while|loop|match|break|continue|use|mod|pub|crate|self|super|struct|enum|impl|trait|where|type|as|in|ref|move|async|await|unsafe|extern|dyn|true|false|None|Some|Ok|Err|Self)\b/g,
    strings: /(["'])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?(?:_\d+)*[uif]?\d*)\b/g,
  },
  php: {
    keywords: /\b(function|return|if|else|elseif|for|foreach|while|do|switch|case|break|continue|class|extends|implements|new|public|private|protected|static|echo|print|require|include|use|namespace|try|catch|finally|throw|null|true|false|array|isset|empty|unset)\b/g,
    strings: /(["'])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|#.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?)\b/gi,
  },
  ruby: {
    keywords: /\b(def|end|class|module|return|if|elsif|else|unless|for|while|until|do|begin|rescue|ensure|raise|yield|block_given\?|require|include|extend|attr_accessor|attr_reader|attr_writer|self|nil|true|false|and|or|not|in|then|when|case)\b/g,
    strings: /(["'])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(#.*$)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?)\b/gi,
  },
  c: {
    keywords: /\b(int|char|float|double|void|long|short|unsigned|signed|const|static|extern|struct|union|enum|typedef|return|if|else|for|while|do|switch|case|break|continue|goto|sizeof|NULL|true|false|include|define|ifdef|ifndef|endif)\b/g,
    strings: /(["'])(?:(?!\1|\\).|\\.)*?\1/g,
    comments: /(\/\/.*$|\/\*[\s\S]*?\*\/)/gm,
    numbers: /\b(\d+\.?\d*(?:e[+-]?\d+)?[uUlLfF]*)\b/g,
  },
};
SYNTAX_RULES.typescript = SYNTAX_RULES.javascript;
SYNTAX_RULES['c++'] = SYNTAX_RULES.c;

function highlightSyntax(escapedHtml, lang) {
  const rules = SYNTAX_RULES[lang];
  if (!rules) return escapedHtml;

  // Tokenize: find all matches, sort by position, apply non-overlapping spans
  const tokens = [];
  const addTokens = (regex, cls) => {
    regex.lastIndex = 0;
    let m;
    while ((m = regex.exec(escapedHtml)) !== null) {
      tokens.push({ start: m.index, end: m.index + m[0].length, cls, text: m[0] });
    }
  };

  // Order matters: comments first (highest priority), then strings, then keywords/numbers
  addTokens(rules.comments, 'tok-comment');
  addTokens(rules.strings, 'tok-string');
  addTokens(rules.keywords, 'tok-keyword');
  addTokens(rules.numbers, 'tok-number');

  // Sort by start position
  tokens.sort((a, b) => a.start - b.start);

  // Remove overlapping tokens (earlier/higher-priority wins)
  const filtered = [];
  let lastEnd = 0;
  for (const t of tokens) {
    if (t.start >= lastEnd) {
      filtered.push(t);
      lastEnd = t.end;
    }
  }

  // Build result
  let result = '';
  let pos = 0;
  for (const t of filtered) {
    result += escapedHtml.slice(pos, t.start);
    result += `<span class="${t.cls}">${t.text}</span>`;
    pos = t.end;
  }
  result += escapedHtml.slice(pos);
  return result;
}


// ── Scans ────────────────────────────────────────────────────────────────────

async function renderScans(el, params, match) {
  el.innerHTML = '<div class="loading">Loading scans...</div>';
  try {
    const scans = await api('/scans');
    const selectedScans = new Set();

    // Show progress view if a scan is running
    const runningScans = scans.filter(s => s.status === 'running');
    const progressHtml = runningScans.length > 0 && window.activeScanProgress
      ? renderProgressView(window.activeScanProgress)
      : '';

    const relTime = (iso) => {
      if (!iso) return '-';
      const d = new Date(iso);
      const diff = Date.now() - d.getTime();
      if (diff < 60000) return 'just now';
      if (diff < 3600000) return `${Math.floor(diff/60000)}m ago`;
      if (diff < 86400000) return `${Math.floor(diff/3600000)}h ago`;
      return d.toLocaleDateString();
    };

    const completedScans = scans.filter(s => s.status === 'completed');

    el.innerHTML = `
      <div class="page-header">
        <h2>Scans</h2>
      </div>
      ${progressHtml}
      <div id="compare-bar" class="compare-select-bar" style="display:none">
        <span>Select exactly 2 completed scans to compare</span>
        <button class="btn btn-sm" id="compare-btn" disabled>Compare Selected</button>
      </div>
      ${scans.length === 0
        ? '<div class="empty-state"><h3>No scans yet</h3><p>Use the "Start Scan" button in the header to start your first scan.</p></div>'
        : `<div class="table-wrap"><table>
          <thead><tr>${completedScans.length >= 2 ? '<th style="width:32px"></th>' : ''}<th>Status</th><th>Root</th><th>Duration</th><th>Findings</th><th>Languages</th><th>Started</th></tr></thead>
          <tbody>
          ${scans.map(s => `<tr class="clickable" data-scan-id="${s.id}">
            ${completedScans.length >= 2 ? `<td>${s.status === 'completed' ? `<input type="checkbox" class="scan-compare-cb" data-cb-id="${s.id}" data-started="${s.started_at || ''}">` : ''}</td>` : ''}
            <td><span class="status-badge ${s.status}"><span class="status-dot ${s.status}"></span>${s.status}</span></td>
            <td style="font-family:var(--font-mono);font-size:0.82rem">${escHtml(truncPath(s.scan_root))}</td>
            <td>${s.duration_secs != null ? s.duration_secs.toFixed(2) + 's' : '-'}</td>
            <td>${s.finding_count ?? '-'}</td>
            <td>${(s.languages || []).map(l => `<span class="lang-badge">${escHtml(l)}</span>`).join('') || '-'}</td>
            <td>${relTime(s.started_at)}</td>
          </tr>`).join('')}
          </tbody></table></div>`
      }`;

    const updateCompareBar = () => {
      const bar = $('#compare-bar', el);
      const btn = $('#compare-btn', el);
      if (!bar || !btn) return;
      if (selectedScans.size > 0) {
        bar.style.display = 'flex';
        btn.disabled = selectedScans.size !== 2;
        bar.querySelector('span').textContent = selectedScans.size === 2
          ? '2 scans selected'
          : `Select ${2 - selectedScans.size} more completed scan${selectedScans.size === 0 ? 's' : ''}`;
      } else {
        bar.style.display = 'none';
      }
    };

    $$('.scan-compare-cb', el).forEach(cb => {
      cb.addEventListener('click', (e) => {
        e.stopPropagation();
        if (cb.checked) {
          if (selectedScans.size >= 2) {
            cb.checked = false;
            return;
          }
          selectedScans.add(cb.dataset.cbId);
        } else {
          selectedScans.delete(cb.dataset.cbId);
        }
        updateCompareBar();
      });
    });

    $('#compare-btn', el)?.addEventListener('click', () => {
      if (selectedScans.size !== 2) return;
      const ids = [...selectedScans];
      // Sort by started_at so left=older, right=newer
      const cbEls = $$('.scan-compare-cb', el);
      const startedMap = {};
      cbEls.forEach(cb => { startedMap[cb.dataset.cbId] = cb.dataset.started || ''; });
      ids.sort((a, b) => (startedMap[a] || '').localeCompare(startedMap[b] || ''));
      navigate(`/scans/compare/${ids[0]}/${ids[1]}`);
    });

    $$('[data-scan-id]', el).forEach(row => {
      row.addEventListener('click', (e) => {
        if (e.target.classList.contains('scan-compare-cb')) return;
        navigate(`/scans/${row.dataset.scanId}`);
      });
    });
  } catch (e) {
    if (isAbortError(e)) return;
    el.innerHTML = `<div class="error-state"><h3>Error</h3><p>${escHtml(e.message)}</p></div>`;
  }
}

// ── Scan Detail Page ─────────────────────────────────────────────────────────

async function renderScanDetail(el, params) {
  const id = params.id;
  el.innerHTML = '<div class="loading">Loading scan...</div>';
  try {
    const scan = await api(`/scans/${id}`);
    // Find previous completed scan for compare button
    let prevScanId = null;
    if (scan.status === 'completed') {
      try {
        const allScans = await api('/scans');
        const completed = allScans.filter(s => s.status === 'completed' && s.started_at);
        completed.sort((a, b) => (a.started_at || '').localeCompare(b.started_at || ''));
        const myIdx = completed.findIndex(s => s.id === id);
        if (myIdx > 0) prevScanId = completed[myIdx - 1].id;
      } catch { /* ignore */ }
    }
    let activeTab = 'summary';

    const renderTabs = () => {
      el.innerHTML = `
        <div style="display:flex;align-items:center;gap:var(--space-2);margin-bottom:var(--space-4)">
          <button class="btn btn-sm" id="back-to-scans">Back to Scans</button>
          ${prevScanId ? `<button class="btn btn-sm" id="compare-prev-btn" style="margin-left:auto">Compare with Previous</button>` : ''}
        </div>
        <div class="page-header">
          <h2>Scan Detail</h2>
          <span class="status-badge ${scan.status}"><span class="status-dot ${scan.status}"></span>${scan.status}</span>
        </div>
        <div class="scan-detail-tabs">
          <button class="scan-detail-tab ${activeTab === 'summary' ? 'active' : ''}" data-tab="summary">Summary</button>
          <button class="scan-detail-tab ${activeTab === 'findings' ? 'active' : ''}" data-tab="findings">Findings</button>
          <button class="scan-detail-tab ${activeTab === 'logs' ? 'active' : ''}" data-tab="logs">Logs</button>
          <button class="scan-detail-tab ${activeTab === 'metrics' ? 'active' : ''}" data-tab="metrics">Metrics</button>
        </div>
        <div id="scan-tab-content"></div>
      `;

      $('#back-to-scans')?.addEventListener('click', () => navigate('/scans'));
      $('#compare-prev-btn', el)?.addEventListener('click', () => {
        if (prevScanId) navigate(`/scans/compare/${prevScanId}/${id}`);
      });
      $$('.scan-detail-tab', el).forEach(tab => {
        tab.addEventListener('click', () => {
          activeTab = tab.dataset.tab;
          renderTabs();
        });
      });

      const content = $('#scan-tab-content', el);
      if (activeTab === 'summary') renderSummaryTab(content, scan, id);
      else if (activeTab === 'findings') renderFindingsTab(content, id);
      else if (activeTab === 'logs') renderLogsTab(content, id);
      else if (activeTab === 'metrics') renderMetricsTab(content, id, scan);
    };

    renderTabs();
  } catch (e) {
    if (isAbortError(e)) return;
    el.innerHTML = `<div class="error-state"><h3>Scan not found</h3><p>${escHtml(e.message)}</p></div>`;
  }
}

function renderSummaryTab(el, scan, id) {
  const fmtDate = (iso) => iso ? new Date(iso).toLocaleString() : '-';
  const duration = scan.duration_secs != null ? scan.duration_secs.toFixed(2) + 's' : '-';
  const langs = (scan.languages || []).join(', ') || '-';

  let timingHtml = '';
  if (scan.timing) {
    const t = scan.timing;
    const total = t.walk_ms + t.pass1_ms + t.call_graph_ms + t.pass2_ms + t.post_process_ms;
    if (total > 0) {
      const pct = (ms) => ((ms / total) * 100).toFixed(1);
      timingHtml = `
        <div class="card" style="margin-top:var(--space-4)">
          <div class="card-header">Timing Breakdown</div>
          <div class="timing-bar">
            <div class="timing-bar-segment walk" style="width:${pct(t.walk_ms)}%" title="Walk: ${t.walk_ms}ms"></div>
            <div class="timing-bar-segment pass1" style="width:${pct(t.pass1_ms)}%" title="Pass 1: ${t.pass1_ms}ms"></div>
            <div class="timing-bar-segment callgraph" style="width:${pct(t.call_graph_ms)}%" title="Call Graph: ${t.call_graph_ms}ms"></div>
            <div class="timing-bar-segment pass2" style="width:${pct(t.pass2_ms)}%" title="Pass 2: ${t.pass2_ms}ms"></div>
            <div class="timing-bar-segment postprocess" style="width:${pct(t.post_process_ms)}%" title="Post-process: ${t.post_process_ms}ms"></div>
          </div>
          <div class="timing-legend">
            <span class="timing-legend-item"><span class="timing-legend-dot" style="background:var(--sev-low)"></span> Walk ${t.walk_ms}ms</span>
            <span class="timing-legend-item"><span class="timing-legend-dot" style="background:var(--accent)"></span> Pass 1 ${t.pass1_ms}ms</span>
            <span class="timing-legend-item"><span class="timing-legend-dot" style="background:var(--sev-medium)"></span> Call Graph ${t.call_graph_ms}ms</span>
            <span class="timing-legend-item"><span class="timing-legend-dot" style="background:var(--success)"></span> Pass 2 ${t.pass2_ms}ms</span>
            <span class="timing-legend-item"><span class="timing-legend-dot" style="background:var(--text-tertiary)"></span> Post ${t.post_process_ms}ms</span>
          </div>
        </div>
      `;
    }
  }

  el.innerHTML = `
    <div class="scan-stat-grid">
      <div class="scan-stat-card">
        <div class="scan-stat-label">Files Scanned</div>
        <div class="scan-stat-value">${scan.files_scanned ?? '-'}</div>
      </div>
      <div class="scan-stat-card">
        <div class="scan-stat-label">Findings</div>
        <div class="scan-stat-value">${scan.finding_count ?? '-'}</div>
      </div>
      <div class="scan-stat-card">
        <div class="scan-stat-label">Duration</div>
        <div class="scan-stat-value">${duration}</div>
      </div>
      <div class="scan-stat-card">
        <div class="scan-stat-label">Languages</div>
        <div class="scan-stat-value" style="font-size:var(--text-base)">${langs}</div>
      </div>
    </div>

    <div class="card">
      <div class="card-header">Details</div>
      <table>
        <tr><td style="color:var(--text-secondary);width:140px">Scan ID</td><td style="font-family:var(--font-mono);font-size:var(--text-xs)">${escHtml(scan.id)}</td></tr>
        <tr><td style="color:var(--text-secondary)">Root</td><td style="font-family:var(--font-mono);font-size:var(--text-sm)">${escHtml(scan.scan_root)}</td></tr>
        <tr><td style="color:var(--text-secondary)">Engine</td><td>${escHtml(scan.engine_version || '-')}</td></tr>
        <tr><td style="color:var(--text-secondary)">Started</td><td>${fmtDate(scan.started_at)}</td></tr>
        <tr><td style="color:var(--text-secondary)">Finished</td><td>${fmtDate(scan.finished_at)}</td></tr>
        ${scan.error ? `<tr><td style="color:var(--text-secondary)">Error</td><td style="color:var(--sev-high)">${escHtml(scan.error)}</td></tr>` : ''}
      </table>
    </div>

    ${timingHtml}
  `;
}

async function renderFindingsTab(el, scanId) {
  el.innerHTML = '<div class="loading">Loading findings...</div>';
  try {
    const data = await api(`/scans/${scanId}/findings`);
    if (!data.findings || data.findings.length === 0) {
      el.innerHTML = '<div class="empty-state"><h3>No findings</h3><p>This scan produced no findings.</p></div>';
      return;
    }
    el.innerHTML = `
      <div class="table-wrap"><table>
        <thead><tr>
          <th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Confidence</th>
        </tr></thead>
        <tbody>
        ${data.findings.map(f => `<tr class="clickable" data-finding-idx="${f.index}">
          <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
          <td>${escHtml(f.rule_id)}</td>
          <td class="cell-path" title="${escHtml(f.path)}">${escHtml(truncPath(f.path))}</td>
          <td>${f.line}</td>
          <td>${f.confidence ? `<span class="badge badge-conf-${f.confidence.toLowerCase()}">${f.confidence}</span>` : '-'}</td>
        </tr>`).join('')}
        </tbody></table></div>
      <div style="margin-top:var(--space-2);font-size:var(--text-sm);color:var(--text-secondary)">
        Showing ${data.findings.length} of ${data.total} findings
      </div>
    `;
    $$('[data-finding-idx]', el).forEach(row => {
      row.addEventListener('click', () => navigate(`/findings/${row.dataset.findingIdx}`));
    });
  } catch (e) {
    if (isAbortError(e)) return;
    el.innerHTML = `<div class="error-state"><p>${escHtml(e.message)}</p></div>`;
  }
}

async function renderLogsTab(el, scanId) {
  el.innerHTML = '<div class="loading">Loading logs...</div>';
  let levelFilter = null;

  const render = async () => {
    try {
      const url = levelFilter ? `/scans/${scanId}/logs?level=${levelFilter}` : `/scans/${scanId}/logs`;
      const logs = await api(url);

      el.innerHTML = `
        <div class="log-filters">
          <button class="log-filter-btn ${!levelFilter ? 'active' : ''}" data-level="">All</button>
          <button class="log-filter-btn ${levelFilter === 'info' ? 'active' : ''}" data-level="info">Info</button>
          <button class="log-filter-btn ${levelFilter === 'warn' ? 'active' : ''}" data-level="warn">Warn</button>
          <button class="log-filter-btn ${levelFilter === 'error' ? 'active' : ''}" data-level="error">Error</button>
        </div>
        ${logs.length === 0
          ? '<div class="empty-state"><p>No log entries</p></div>'
          : `<div class="log-viewer">
            ${logs.map(l => `<div class="log-entry log-${l.level}">
              <span class="log-level ${l.level}">${l.level}</span>
              <span class="log-time">${new Date(l.timestamp).toLocaleTimeString()}</span>
              <span class="log-message">${escHtml(l.message)}${l.file_path ? ` <span style="color:var(--text-tertiary)">${escHtml(l.file_path)}</span>` : ''}</span>
            </div>`).join('')}
          </div>`
        }
      `;

      $$('.log-filter-btn', el).forEach(btn => {
        btn.addEventListener('click', () => {
          levelFilter = btn.dataset.level || null;
          render();
        });
      });
    } catch (e) {
      if (isAbortError(e)) return;
      el.innerHTML = `<div class="error-state"><p>${escHtml(e.message)}</p></div>`;
    }
  };
  render();
}

async function renderMetricsTab(el, scanId, scan) {
  // Try to get metrics from scan view first, then from API
  let metrics = scan.metrics;
  if (!metrics) {
    try {
      metrics = await api(`/scans/${scanId}/metrics`);
    } catch {
      // no metrics available
    }
  }

  if (!metrics) {
    el.innerHTML = '<div class="empty-state"><p>No metrics available for this scan.</p></div>';
    return;
  }

  const fmtNum = (n) => n != null ? n.toLocaleString() : '-';

  el.innerHTML = `
    <div class="metric-grid">
      <div class="metric-card">
        <div class="metric-card-label">CFG Nodes</div>
        <div class="metric-card-value">${fmtNum(metrics.cfg_nodes)}</div>
      </div>
      <div class="metric-card">
        <div class="metric-card-label">Call Edges</div>
        <div class="metric-card-value">${fmtNum(metrics.call_edges)}</div>
      </div>
      <div class="metric-card">
        <div class="metric-card-label">Functions Analyzed</div>
        <div class="metric-card-value">${fmtNum(metrics.functions_analyzed)}</div>
      </div>
      <div class="metric-card">
        <div class="metric-card-label">Summaries Reused</div>
        <div class="metric-card-value">${fmtNum(metrics.summaries_reused)}</div>
      </div>
      <div class="metric-card">
        <div class="metric-card-label">Unresolved Calls</div>
        <div class="metric-card-value">${fmtNum(metrics.unresolved_calls)}</div>
      </div>
    </div>
  `;
}

// ── Scan Comparison Page ─────────────────────────────────────────────────────

async function renderScanCompare(el, params) {
  const { left, right } = params;
  el.innerHTML = '<div class="loading">Loading comparison...</div>';
  try {
    const data = await api(`/scans/compare?left=${encodeURIComponent(left)}&right=${encodeURIComponent(right)}`);
    let activeTab = 'status';

    const fmtDate = (iso) => iso ? new Date(iso).toLocaleString() : '-';
    const shortId = (id) => id.length > 8 ? id.slice(0, 8) : id;

    const renderPage = () => {
      // Severity delta display
      const severities = ['HIGH', 'MEDIUM', 'LOW'];
      const deltaHtml = severities.map(s => {
        const d = data.summary.severity_delta[s] || 0;
        let cls = 'delta-zero';
        let prefix = '';
        if (d > 0) { cls = 'delta-positive'; prefix = '+'; }
        else if (d < 0) { cls = 'delta-negative'; }
        return `<span class="severity-delta-item">
          <span class="badge badge-${s.toLowerCase()}">${s}</span>
          <span class="${cls}">${prefix}${d}</span>
        </span>`;
      }).join('');

      el.innerHTML = `
        <button class="btn btn-sm" id="back-to-scans" style="margin-bottom:var(--space-4)">Back to Scans</button>
        <div class="page-header"><h2>Scan Comparison</h2></div>

        <div class="compare-header">
          <div class="compare-scan-pill">
            <span>Left</span>
            <span class="pill-id">${escHtml(shortId(data.left_scan.id))}</span>
            <span class="pill-count">${data.left_scan.finding_count} findings</span>
            <span style="color:var(--text-tertiary);font-size:var(--text-xs)">${fmtDate(data.left_scan.started_at)}</span>
          </div>
          <span class="compare-vs">vs</span>
          <div class="compare-scan-pill">
            <span>Right</span>
            <span class="pill-id">${escHtml(shortId(data.right_scan.id))}</span>
            <span class="pill-count">${data.right_scan.finding_count} findings</span>
            <span style="color:var(--text-tertiary);font-size:var(--text-xs)">${fmtDate(data.right_scan.started_at)}</span>
          </div>
        </div>

        <div class="compare-summary-grid">
          <div class="compare-card compare-card--new">
            <div class="compare-card-label">New</div>
            <div class="compare-card-value">${data.summary.new_count}</div>
          </div>
          <div class="compare-card compare-card--fixed">
            <div class="compare-card-label">Fixed</div>
            <div class="compare-card-value">${data.summary.fixed_count}</div>
          </div>
          <div class="compare-card compare-card--changed">
            <div class="compare-card-label">Changed</div>
            <div class="compare-card-value">${data.summary.changed_count}</div>
          </div>
          <div class="compare-card compare-card--unchanged">
            <div class="compare-card-label">Unchanged</div>
            <div class="compare-card-value">${data.summary.unchanged_count}</div>
          </div>
        </div>

        <div class="severity-delta">${deltaHtml}</div>

        <div class="scan-detail-tabs">
          <button class="scan-detail-tab ${activeTab === 'status' ? 'active' : ''}" data-cmp-tab="status">By Status</button>
          <button class="scan-detail-tab ${activeTab === 'rule' ? 'active' : ''}" data-cmp-tab="rule">By Rule</button>
          <button class="scan-detail-tab ${activeTab === 'file' ? 'active' : ''}" data-cmp-tab="file">By File</button>
        </div>
        <div id="compare-tab-content"></div>
      `;

      $('#back-to-scans', el)?.addEventListener('click', () => navigate('/scans'));
      $$('[data-cmp-tab]', el).forEach(tab => {
        tab.addEventListener('click', () => {
          activeTab = tab.dataset.cmpTab;
          renderPage();
        });
      });

      const content = $('#compare-tab-content', el);
      if (activeTab === 'status') renderCompareByStatus(content, data);
      else if (activeTab === 'rule') renderCompareByGroup(content, data, 'rule_id');
      else if (activeTab === 'file') renderCompareByGroup(content, data, 'path');
    };

    renderPage();
  } catch (e) {
    if (isAbortError(e)) return;
    el.innerHTML = `<div class="error-state"><h3>Comparison failed</h3><p>${escHtml(e.message)}</p></div>`;
  }
}

function renderCompareByStatus(el, data) {
  const sections = [
    { key: 'new', label: 'New Findings', badge: 'compare-badge--new', rowCls: 'compare-finding-row--new', items: data.new_findings },
    { key: 'fixed', label: 'Fixed Findings', badge: 'compare-badge--fixed', rowCls: 'compare-finding-row--fixed', items: data.fixed_findings },
    { key: 'changed', label: 'Changed Findings', badge: 'compare-badge--changed', rowCls: 'compare-finding-row--changed', items: data.changed_findings },
    { key: 'unchanged', label: 'Unchanged Findings', badge: 'compare-badge--unchanged', rowCls: 'compare-finding-row--unchanged', items: data.unchanged_findings },
  ];

  el.innerHTML = sections.map(sec => {
    if (sec.items.length === 0) return '';
    const collapsed = sec.key === 'unchanged';
    return `
      <div class="compare-section" data-section="${sec.key}">
        <div class="compare-section-header" data-toggle="${sec.key}">
          <span class="section-toggle ${collapsed ? 'collapsed' : ''}">&#9660;</span>
          <span class="${sec.badge}">${sec.key.toUpperCase()}</span>
          <span>${sec.label} (${sec.items.length})</span>
        </div>
        <div class="compare-section-body" ${collapsed ? 'style="display:none"' : ''} data-body="${sec.key}">
          ${sec.items.map(f => renderCompareRow(f, sec.rowCls, sec.key === 'changed')).join('')}
        </div>
      </div>
    `;
  }).join('');

  attachCompareListeners(el);
}

function renderCompareByGroup(el, data, groupField) {
  // Merge all findings into one list with status tags
  const all = [];
  data.new_findings.forEach(f => all.push({ ...f, _status: 'new' }));
  data.fixed_findings.forEach(f => all.push({ ...f, _status: 'fixed' }));
  data.changed_findings.forEach(f => all.push({ ...f, _status: 'changed' }));
  data.unchanged_findings.forEach(f => all.push({ ...f, _status: 'unchanged' }));

  // Group by field
  const groups = {};
  all.forEach(f => {
    const key = f[groupField] || f.finding?.[groupField] || '(unknown)';
    if (!groups[key]) groups[key] = [];
    groups[key].push(f);
  });

  const groupKeys = Object.keys(groups).sort();
  el.innerHTML = groupKeys.map(key => {
    const items = groups[key];
    const counts = { new: 0, fixed: 0, changed: 0, unchanged: 0 };
    items.forEach(f => counts[f._status]++);
    const summary = [
      counts.new > 0 ? `+${counts.new}` : '',
      counts.fixed > 0 ? `-${counts.fixed}` : '',
      counts.changed > 0 ? `~${counts.changed}` : '',
    ].filter(Boolean).join(' ') || `${counts.unchanged} unchanged`;

    return `
      <div class="compare-section">
        <div class="compare-group-header" data-toggle="${escHtml(key)}">
          <span class="section-toggle">&#9660;</span>
          <span style="font-family:var(--font-mono);font-size:var(--text-xs)">${escHtml(key)}</span>
          <span class="compare-group-summary">${summary}</span>
        </div>
        <div class="compare-section-body" data-body="${escHtml(key)}">
          ${items.map(f => {
            const rowCls = `compare-finding-row--${f._status}`;
            return renderCompareRow(f, rowCls, f._status === 'changed');
          }).join('')}
        </div>
      </div>
    `;
  }).join('');

  attachCompareListeners(el);
}

function renderCompareRow(f, rowCls, showChanges) {
  const finding = f.finding || f;
  const sevBadge = `<span class="badge badge-${(finding.severity || '').toLowerCase()}">${finding.severity || '-'}</span>`;
  const confBadge = finding.confidence ? `<span class="badge badge-conf-${finding.confidence.toLowerCase()}">${finding.confidence}</span>` : '';

  let changesHtml = '';
  if (showChanges && f.changes && f.changes.length > 0) {
    changesHtml = f.changes.map(c =>
      `<span class="compare-delta-inline">${escHtml(c.field)}: ${escHtml(c.old_value)} <span class="delta-arrow">&rarr;</span> ${escHtml(c.new_value)}</span>`
    ).join(' ');
  }

  return `
    <div class="compare-finding-row ${rowCls}" data-finding-idx="${finding.index}">
      ${sevBadge}
      <span style="font-size:var(--text-xs)">${escHtml(finding.rule_id || '')}</span>
      <span class="finding-path" title="${escHtml(finding.path || '')}">${escHtml(truncPath(finding.path || ''))}</span>
      <span style="font-size:var(--text-xs);color:var(--text-secondary)">L${finding.line || '-'}</span>
      ${confBadge}
      ${changesHtml}
    </div>
  `;
}

function attachCompareListeners(el) {
  // Toggle sections
  $$('[data-toggle]', el).forEach(header => {
    header.addEventListener('click', () => {
      const key = header.dataset.toggle;
      const body = $(`[data-body="${key}"]`, el);
      const toggle = $('.section-toggle', header);
      if (!body) return;
      const visible = body.style.display !== 'none';
      body.style.display = visible ? 'none' : '';
      if (toggle) toggle.classList.toggle('collapsed', visible);
    });
  });

  // Click findings to navigate
  $$('.compare-finding-row[data-finding-idx]', el).forEach(row => {
    row.addEventListener('click', () => navigate(`/findings/${row.dataset.findingIdx}`));
  });
}

// ── New Scan Modal ───────────────────────────────────────────────────────────

function openNewScanModal() {
  const modal = document.createElement('div');
  modal.className = 'scan-modal-overlay';
  const defaultRoot = appMeta?.scan_root || '';

  modal.innerHTML = `
    <div class="scan-modal">
      <h3>Start New Scan</h3>
      <div class="scan-modal-form">
        <div class="form-group">
          <label>Scan Root</label>
          <input type="text" id="scan-root-input" value="${escHtml(defaultRoot)}" placeholder="/path/to/project">
        </div>
        <div class="scan-modal-actions">
          <button class="btn btn-sm" id="scan-modal-cancel">Cancel</button>
          <button class="btn btn-primary btn-sm" id="scan-modal-start">Start Scan</button>
        </div>
      </div>
    </div>
  `;
  document.body.appendChild(modal);

  const close = () => modal.remove();
  $('#scan-modal-cancel', modal).addEventListener('click', close);
  modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
  const onKey = (e) => { if (e.key === 'Escape') { close(); document.removeEventListener('keydown', onKey); } };
  document.addEventListener('keydown', onKey);

  $('#scan-modal-start', modal).addEventListener('click', async () => {
    const root = $('#scan-root-input', modal).value.trim();
    try {
      const body = root && root !== defaultRoot
        ? JSON.stringify({ scan_root: root })
        : undefined;
      await api('/scans', { method: 'POST', body, signal: null });
      close();
      navigate('/scans');
    } catch (e) {
      if (isAbortError(e)) return;
      alert(e.message);
    }
  });
}

// ── Scan Progress View ───────────────────────────────────────────────────────

function renderProgressView(data) {
  const stages = ['discovering', 'parsing', 'analyzing', 'complete'];
  const stageLabels = { discovering: 'Discovering', parsing: 'Parsing', analyzing: 'Analyzing', complete: 'Complete' };
  const currentIdx = stages.indexOf(data.stage);

  const total = data.files_discovered || 1;
  const processed = data.stage === 'parsing' ? data.files_parsed
    : data.stage === 'analyzing' ? data.files_analyzed
    : data.stage === 'complete' ? total : 0;
  const pct = Math.min(100, (processed / total) * 100);
  const elapsed = data.elapsed_ms ? (data.elapsed_ms / 1000).toFixed(1) + 's' : '-';

  return `
    <div class="scan-progress">
      <div class="scan-progress-header">
        <h3>Scan in Progress</h3>
        <span style="font-size:var(--text-sm);color:var(--text-secondary)">${elapsed} elapsed</span>
      </div>
      <div class="stage-pipeline">
        ${stages.map((s, i) => {
          const cls = i < currentIdx ? 'done' : i === currentIdx ? 'active' : '';
          return `<div class="stage-step ${cls}">
            <div class="stage-dot"></div>
            <span class="stage-label">${stageLabels[s]}</span>
          </div>`;
        }).join('')}
      </div>
      <div class="progress-bar"><div class="progress-bar-fill" style="width:${pct}%"></div></div>
      <div class="progress-stats">
        <span>${processed} / ${data.files_discovered || 0} files</span>
        <span>${pct.toFixed(0)}%</span>
      </div>
      ${data.current_file ? `<div class="progress-current-file">${escHtml(truncPath(data.current_file, 80))}</div>` : ''}
    </div>
  `;
}

function updateProgressDisplay(data) {
  // Update inline progress if visible on current page
  const existing = document.querySelector('.scan-progress');
  if (existing) {
    const temp = document.createElement('div');
    temp.innerHTML = renderProgressView(data);
    existing.replaceWith(temp.firstElementChild);
  }
}

// ── Triage ───────────────────────────────────────────────────────────────────

// Persistent filter state across re-renders within the same page visit
let _triageFilter = 'all';

async function renderTriage(el, params, match) {
  el.innerHTML = '<div class="loading">Loading triage data...</div>';
  try {
    const [firstPage, auditData, suppressionData, syncStatus] = await Promise.all([
      api('/findings?per_page=5000'),
      api('/triage/audit?per_page=100'),
      api('/triage/suppress'),
      api('/triage/sync-status'),
    ]);

    let findings = firstPage.findings || [];
    const totalFindings = firstPage.total || findings.length;
    if (totalFindings > findings.length) {
      const pages = Math.ceil(totalFindings / 5000);
      const remaining = [];
      for (let p = 2; p <= pages; p++) {
        remaining.push(api(`/findings?per_page=5000&page=${p}`));
      }
      const results = await Promise.all(remaining);
      for (const r of results) {
        findings = findings.concat(r.findings || []);
      }
    }
    const auditEntries = auditData.entries || [];
    const suppressionRules = suppressionData.rules || [];

    // Compute summary stats
    const allStates = ['open', 'investigating', 'false_positive', 'accepted_risk', 'suppressed', 'fixed'];
    const stateCounts = {};
    allStates.forEach(s => stateCounts[s] = 0);
    findings.forEach(f => {
      const ts = f.triage_state || 'open';
      stateCounts[ts] = (stateCounts[ts] || 0) + 1;
    });
    const totalCount = findings.length;
    const needsAttention = (stateCounts['open'] || 0) + (stateCounts['investigating'] || 0);

    // Severity breakdown for open findings
    const openBySev = {};
    ['High', 'Medium', 'Low'].forEach(sev => {
      openBySev[sev] = findings.filter(f => (f.triage_state || 'open') === 'open' && f.severity === sev).length;
    });

    // Top rules among open findings
    const openRuleCounts = {};
    findings.filter(f => (f.triage_state || 'open') === 'open').forEach(f => {
      openRuleCounts[f.rule_id] = (openRuleCounts[f.rule_id] || 0) + 1;
    });
    const topRules = Object.entries(openRuleCounts).sort((a, b) => b[1] - a[1]).slice(0, 5);

    // Filter findings by current _triageFilter
    const activeFilter = _triageFilter;
    const filtered = activeFilter === 'all'
      ? findings
      : activeFilter === 'needs_attention'
        ? findings.filter(f => { const ts = f.triage_state || 'open'; return ts === 'open' || ts === 'investigating'; })
        : findings.filter(f => (f.triage_state || 'open') === activeFilter);

    // Triage actions appropriate for each state
    function triageActionsFor(f) {
      const ts = f.triage_state || 'open';
      const btns = [];
      if (ts === 'open') {
        btns.push({ state: 'investigating', label: 'Investigate' });
        btns.push({ state: 'false_positive', label: 'FP' });
        btns.push({ state: 'suppressed', label: 'Suppress' });
        btns.push({ state: 'accepted_risk', label: 'Accept' });
      } else if (ts === 'investigating') {
        btns.push({ state: 'false_positive', label: 'FP' });
        btns.push({ state: 'suppressed', label: 'Suppress' });
        btns.push({ state: 'accepted_risk', label: 'Accept' });
        btns.push({ state: 'fixed', label: 'Fixed' });
        btns.push({ state: 'open', label: 'Reopen' });
      } else {
        btns.push({ state: 'open', label: 'Reopen' });
        btns.push({ state: 'investigating', label: 'Investigate' });
      }
      return btns.map(b =>
        `<button class="btn btn-sm btn-triage-quick btn-triage-${b.state}" data-fp="${f.fingerprint}" data-state="${b.state}">${b.label}</button>`
      ).join('');
    }

    const stateLabel = s => s.replace(/_/g, ' ');

    el.innerHTML = `
      <div class="triage-page">
        <!-- Summary cards row -->
        <div class="triage-summary-row">
          <div class="triage-summary-card triage-card-clickable ${activeFilter === 'all' ? 'triage-card-active' : ''}" data-filter="all">
            <div class="triage-card-count">${totalCount}</div>
            <div class="triage-card-label">Total</div>
          </div>
          <div class="triage-summary-card triage-card-clickable triage-card-attention ${activeFilter === 'needs_attention' ? 'triage-card-active' : ''}" data-filter="needs_attention">
            <div class="triage-card-count">${needsAttention}</div>
            <div class="triage-card-label">Needs Attention</div>
          </div>
          ${allStates.map(s => `
            <div class="triage-summary-card triage-card-clickable ${activeFilter === s ? 'triage-card-active' : ''}" data-filter="${s}">
              <div class="triage-card-count">${stateCounts[s] || 0}</div>
              <div class="triage-card-label"><span class="badge badge-triage-${s}">${stateLabel(s)}</span></div>
            </div>
          `).join('')}
        </div>

        <!-- Open findings breakdown -->
        ${(stateCounts['open'] || 0) > 0 ? `
        <div class="triage-open-summary">
          <div class="triage-open-severity">
            <span class="triage-open-label">Open by severity:</span>
            ${['High', 'Medium', 'Low'].map(sev =>
              `<span class="triage-sev-pill"><span class="badge badge-${sev.toLowerCase()}">${sev}</span> ${openBySev[sev]}</span>`
            ).join('')}
          </div>
          ${topRules.length > 0 ? `
          <div class="triage-top-rules">
            <span class="triage-open-label">Top open rules:</span>
            ${topRules.map(([rule, count]) =>
              `<span class="triage-rule-pill"><code>${escHtml(rule)}</code> <span class="triage-rule-count">${count}</span></span>`
            ).join('')}
          </div>` : ''}
        </div>` : ''}

        <!-- Tabs and sync controls -->
        <div class="triage-tabs-row">
          <div class="triage-tabs">
            <button class="triage-tab active" data-tab="findings">Findings (${filtered.length})</button>
            <button class="triage-tab" data-tab="rules">Suppression Rules (${suppressionRules.length})</button>
            <button class="triage-tab" data-tab="audit">Audit Log (${auditEntries.length})</button>
          </div>
          <div class="triage-sync-controls">
            ${syncStatus.sync_enabled ? (() => {
              if (syncStatus.file_exists) {
                return `<span class="triage-sync-status"><span class="triage-sync-dot synced"></span> .nyx/triage.json (${syncStatus.decisions} decisions)</span>`;
              } else {
                return '<span class="triage-sync-status"><span class="triage-sync-dot unsynced"></span> No sync file</span>';
              }
            })() : '<span class="triage-sync-status"><span class="triage-sync-dot unsynced"></span> Sync disabled</span>'}
            <button class="btn btn-sm" id="triage-export" title="Save triage decisions to .nyx/triage.json for team sharing via git">Export</button>
            ${syncStatus.file_exists ? `<button class="btn btn-sm" id="triage-import" title="Load triage decisions from .nyx/triage.json">Import</button>` : ''}
          </div>
        </div>

        <!-- Findings tab -->
        <div class="triage-tab-content" id="tab-findings">
          ${filtered.length === 0
            ? `<div class="empty-state"><h3>No findings${activeFilter !== 'all' ? ' in this state' : ''}</h3>
               <p>${activeFilter === 'all' ? 'Run a scan to see results.' : 'Click a different state card above to see other findings.'}</p></div>`
            : `<div class="table-wrap"><table>
                <thead><tr>
                  <th>State</th><th>Severity</th><th>Confidence</th><th>Rule</th><th>File</th><th>Line</th><th>Actions</th>
                </tr></thead>
                <tbody>
                ${filtered.slice(0, 200).map(f => `<tr>
                  <td><span class="badge badge-triage-${f.triage_state || 'open'}">${stateLabel(f.triage_state || 'open')}</span></td>
                  <td><span class="badge badge-${(f.severity || '').toLowerCase()}">${f.severity || '-'}</span></td>
                  <td>${f.confidence ? `<span class="badge badge-conf-${f.confidence.toLowerCase()}">${f.confidence}</span>` : '-'}</td>
                  <td>${escHtml(f.rule_id)}</td>
                  <td class="cell-path" title="${escHtml(f.path)}">${escHtml(truncPath(f.path, 35))}</td>
                  <td>${f.line}</td>
                  <td class="triage-quick-actions">
                    ${triageActionsFor(f)}
                    <a href="/findings/${f.index}" class="btn btn-sm nav-link-internal">View</a>
                  </td>
                </tr>`).join('')}
                </tbody></table></div>
                ${filtered.length > 200 ? `<p class="triage-truncation-note">Showing first 200 of ${filtered.length} findings. Use the state cards above to narrow down.</p>` : ''}`
          }
        </div>

        <!-- Suppression Rules tab -->
        <div class="triage-tab-content" id="tab-rules" style="display:none">
          ${suppressionRules.length === 0
            ? '<div class="empty-state"><h3>No suppression rules</h3><p>Suppress findings by pattern from the Findings page bulk actions, or from individual finding detail pages.</p></div>'
            : `<div class="table-wrap"><table>
                <thead><tr><th>Type</th><th>Pattern</th><th>State</th><th>Note</th><th>Created</th><th></th></tr></thead>
                <tbody>
                ${suppressionRules.map(r => `<tr>
                  <td><span class="badge">${escHtml(r.suppress_by)}</span></td>
                  <td><code>${escHtml(r.match_value)}</code></td>
                  <td><span class="badge badge-triage-${r.state}">${stateLabel(r.state)}</span></td>
                  <td>${escHtml(r.note || '-')}</td>
                  <td style="font-size:var(--text-xs);white-space:nowrap">${escHtml(r.created_at ? r.created_at.substring(0, 10) : '-')}</td>
                  <td><button class="btn btn-sm btn-danger btn-delete-rule" data-rule-id="${r.id}">Delete</button></td>
                </tr>`).join('')}
                </tbody></table></div>`
          }
        </div>

        <!-- Audit Log tab -->
        <div class="triage-tab-content" id="tab-audit" style="display:none">
          ${auditEntries.length === 0
            ? '<div class="empty-state"><h3>No audit entries yet</h3><p>Every triage action will be logged here with a timestamp and state transition.</p></div>'
            : `<div class="table-wrap"><table class="triage-audit-table">
                <thead><tr><th>Time</th><th>Fingerprint</th><th>Action</th><th>Transition</th><th>Note</th></tr></thead>
                <tbody>
                ${auditEntries.map(e => `<tr>
                  <td style="font-size:var(--text-xs);white-space:nowrap">${escHtml(e.timestamp ? e.timestamp.substring(0, 19).replace('T', ' ') : '-')}</td>
                  <td style="font-size:var(--text-xs)"><code title="${escHtml(e.fingerprint)}">${escHtml(e.fingerprint.substring(0, 12))}</code></td>
                  <td><span class="badge">${escHtml(e.action)}</span></td>
                  <td>
                    <span class="badge badge-triage-${e.previous_state}">${stateLabel(e.previous_state)}</span>
                    <span class="triage-arrow">&rarr;</span>
                    <span class="badge badge-triage-${e.new_state}">${stateLabel(e.new_state)}</span>
                  </td>
                  <td style="font-size:var(--text-xs)">${escHtml(e.note || '-')}</td>
                </tr>`).join('')}
                </tbody></table></div>`
          }
        </div>
      </div>
    `;

    // ── Event wiring ──────────────────────────────────────────────────────

    // Clickable state cards → filter
    $$('.triage-card-clickable', el).forEach(card => {
      card.addEventListener('click', () => {
        _triageFilter = card.dataset.filter;
        renderTriage(el, params, match);
      });
    });

    // Tab switching
    $$('.triage-tab', el).forEach(tab => {
      tab.addEventListener('click', () => {
        $$('.triage-tab', el).forEach(t => t.classList.remove('active'));
        $$('.triage-tab-content', el).forEach(c => c.style.display = 'none');
        tab.classList.add('active');
        const target = $(`#tab-${tab.dataset.tab}`, el);
        if (target) target.style.display = 'block';
      });
    });

    // Quick triage buttons
    $$('.btn-triage-quick', el).forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          await api('/triage', {
            method: 'POST',
            body: JSON.stringify({ fingerprints: [btn.dataset.fp], state: btn.dataset.state, note: '' }),
            signal: null,
          });
          renderTriage(el, params, match);
        } catch (err) {
          alert('Failed to update triage state: ' + err.message);
        }
      });
    });

    // Delete suppression rule
    $$('.btn-delete-rule', el).forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          await api(`/triage/suppress?id=${btn.dataset.ruleId}`, { method: 'DELETE', signal: null });
          renderTriage(el, params, match);
        } catch (err) {
          alert('Failed to delete rule: ' + err.message);
        }
      });
    });

    // Export triage to .nyx/triage.json
    $('#triage-export', el)?.addEventListener('click', async () => {
      try {
        const result = await api('/triage/export', { method: 'POST', signal: null });
        renderTriage(el, params, match);
        alert(`Exported ${result.exported} decisions and ${result.suppression_rules} suppression rules to .nyx/triage.json\n\nCommit this file to share triage decisions with your team.`);
      } catch (err) {
        alert('Export failed: ' + err.message);
      }
    });

    // Import triage from .nyx/triage.json
    $('#triage-import', el)?.addEventListener('click', async () => {
      try {
        const result = await api('/triage/import', { method: 'POST', signal: null });
        renderTriage(el, params, match);
        alert(`Imported ${result.imported} of ${result.total_in_file} decisions from .nyx/triage.json`);
      } catch (err) {
        alert('Import failed: ' + err.message);
      }
    });

  } catch (e) {
    if (isAbortError(e)) return;
    el.innerHTML = `<div class="error-state"><h3>Error loading triage data</h3><p>${escHtml(e.message)}</p></div>`;
  }
}

// ── Settings ─────────────────────────────────────────────────────────────────

// ── Rules Page ────────────────────────────────────────────────────────────────

async function renderRules(el, params, match) {
  el.innerHTML = '<div class="loading">Loading rules...</div>';
  try {
    const rules = await api('/rules');

    const langs = [...new Set(rules.map(r => r.language))].sort();
    const kinds = ['source', 'sanitizer', 'sink'];

    let selectedId = match.params?.id || null;

    function renderPage() {
      const selectedRule = selectedId ? rules.find(r => r.id === selectedId) : null;

      el.innerHTML = `
        <div class="page-header"><h2>Rules</h2>
          <span style="color:var(--text-secondary);font-size:var(--text-sm);margin-left:var(--space-3)">${rules.length} rules</span>
        </div>
        <div class="rules-layout">
          <div class="rules-list-panel">
            <div class="rules-filters">
              <select id="rules-lang-filter">
                <option value="">All Languages</option>
                ${langs.map(l => `<option value="${escHtml(l)}">${escHtml(l)}</option>`).join('')}
              </select>
              <select id="rules-kind-filter">
                <option value="">All Kinds</option>
                ${kinds.map(k => `<option value="${escHtml(k)}">${escHtml(k)}</option>`).join('')}
              </select>
              <label style="display:flex;align-items:center;gap:4px;font-size:var(--text-sm)">
                <input type="checkbox" id="rules-custom-only"> Custom only
              </label>
              <input type="text" id="rules-search" placeholder="Search matchers..." style="flex:1;min-width:100px">
            </div>
            <div id="rules-table-wrap">
              ${renderRulesTable(rules, selectedId)}
            </div>
          </div>
          <div class="rules-detail-panel" id="rules-detail">
            ${selectedRule ? renderRuleDetail(selectedRule) : '<div class="empty-state" style="padding:40px"><p>Select a rule to view details</p></div>'}
          </div>
        </div>
      `;

      bindAll();
    }

    function selectRule(id) {
      selectedId = id;
      history.replaceState(null, '', id ? '/rules/' + encodeURIComponent(id) : '/rules');

      // Update detail panel without full re-render
      const detail = $('#rules-detail');
      const rule = id ? rules.find(r => r.id === id) : null;
      if (detail) {
        detail.innerHTML = rule
          ? renderRuleDetail(rule)
          : '<div class="empty-state" style="padding:40px"><p>Select a rule to view details</p></div>';
        bindDetailActions();
      }

      // Update selected row highlight
      $$('.rule-row', el).forEach(row => {
        row.classList.toggle('selected', row.dataset.ruleId === id);
      });
    }

    function bindDetailActions() {
      $('#clone-rule-btn')?.addEventListener('click', async () => {
        if (!selectedId) return;
        try {
          await api('/rules/clone', { method: 'POST', signal: null, body: JSON.stringify({ rule_id: selectedId }) });
          renderRules(el, params, match);
        } catch (e) { if (!isAbortError(e)) alert('Error: ' + e.message); }
      });

      $('#detail-toggle-btn')?.addEventListener('click', async () => {
        if (!selectedId) return;
        try {
          await api('/rules/' + encodeURIComponent(selectedId) + '/toggle', { method: 'POST', signal: null });
          renderRules(el, params, match);
        } catch (e) { if (!isAbortError(e)) alert('Error: ' + e.message); }
      });
    }

    function applyFilters() {
      const lang = $('#rules-lang-filter').value;
      const kind = $('#rules-kind-filter').value;
      const customOnly = $('#rules-custom-only').checked;
      const search = $('#rules-search').value.toLowerCase();

      const filtered = rules.filter(r => {
        if (lang && r.language !== lang) return false;
        if (kind && r.kind !== kind) return false;
        if (customOnly && !r.is_custom) return false;
        if (search && !r.matchers.some(m => m.toLowerCase().includes(search)) && !r.title.toLowerCase().includes(search)) return false;
        return true;
      });

      const wrap = $('#rules-table-wrap');
      if (wrap) wrap.innerHTML = renderRulesTable(filtered, selectedId);
      bindTableRows();
    }

    function bindTableRows() {
      $$('.rule-row', el).forEach(row => {
        row.addEventListener('click', (e) => {
          if (e.target.closest('.rule-toggle')) return;
          selectRule(row.dataset.ruleId);
        });
      });

      $$('.rule-toggle', el).forEach(toggle => {
        toggle.addEventListener('click', async (e) => {
          e.stopPropagation();
          try {
            await api('/rules/' + encodeURIComponent(toggle.dataset.ruleId) + '/toggle', { method: 'POST', signal: null });
            renderRules(el, params, match);
          } catch (e) { if (!isAbortError(e)) alert('Error: ' + e.message); }
        });
      });
    }

    function bindAll() {
      $('#rules-lang-filter')?.addEventListener('change', applyFilters);
      $('#rules-kind-filter')?.addEventListener('change', applyFilters);
      $('#rules-custom-only')?.addEventListener('change', applyFilters);
      $('#rules-search')?.addEventListener('input', debounce(applyFilters, 200));
      bindTableRows();
      bindDetailActions();
    }

    renderPage();

  } catch (e) {
    if (isAbortError(e)) return;
    el.innerHTML = `<div class="error-state"><h3>Error</h3><p>${escHtml(e.message)}</p></div>`;
  }
}

function renderRulesTable(rules, selectedId) {
  if (rules.length === 0) {
    return '<div class="empty-state" style="padding:20px"><p>No rules match filters</p></div>';
  }
  return `<table class="rules-table">
    <colgroup>
      <col class="col-toggle">
      <col><!-- title: takes remaining space -->
      <col class="col-lang">
      <col class="col-kind">
      <col class="col-cap">
      <col class="col-finds">
    </colgroup>
    <thead><tr>
      <th></th><th>Title</th><th>Lang</th><th>Kind</th><th>Cap</th><th>Finds</th>
    </tr></thead>
    <tbody>
    ${rules.map(r => `<tr class="rule-row${r.id === selectedId ? ' selected' : ''}${!r.enabled ? ' rule-disabled' : ''}" data-rule-id="${escHtml(r.id)}">
      <td><button class="rule-toggle${r.enabled ? ' toggle-on' : ' toggle-off'}" data-rule-id="${escHtml(r.id)}" title="${r.enabled ? 'Disable' : 'Enable'}">${r.enabled ? 'On' : 'Off'}</button></td>
      <td class="col-title-cell"><span class="rule-title-text">${escHtml(r.title)}${r.is_custom ? ' <span class="badge-custom">custom</span>' : ''}${r.is_gated ? ' <span class="badge-builtin">gated</span>' : ''}</span></td>
      <td>${escHtml(r.language)}</td>
      <td><span class="badge badge-${r.kind}">${escHtml(r.kind)}</span></td>
      <td>${escHtml(r.cap)}</td>
      <td>${r.finding_count}</td>
    </tr>`).join('')}
    </tbody>
  </table>`;
}

function renderRuleDetail(rule) {
  return `
    <div class="rule-detail-card">
      <h3>${escHtml(rule.title)}</h3>
      <div class="rule-detail-grid">
        <div class="rule-detail-label">ID</div>
        <div><code style="font-size:var(--text-xs);word-break:break-all">${escHtml(rule.id)}</code></div>
        <div class="rule-detail-label">Language</div>
        <div>${escHtml(rule.language)}</div>
        <div class="rule-detail-label">Kind</div>
        <div><span class="badge badge-${rule.kind}">${escHtml(rule.kind)}</span></div>
        <div class="rule-detail-label">Capability</div>
        <div>${escHtml(rule.cap)}</div>
        <div class="rule-detail-label">Case Sensitive</div>
        <div>${rule.case_sensitive ? 'Yes' : 'No'}</div>
        <div class="rule-detail-label">Status</div>
        <div>${rule.enabled
          ? '<span style="color:var(--success)">Enabled</span>'
          : '<span style="color:var(--text-tertiary)">Disabled</span>'}</div>
        <div class="rule-detail-label">Findings</div>
        <div>${rule.finding_count}${rule.suppression_rate > 0 ? ` (${(rule.suppression_rate * 100).toFixed(0)}% suppressed)` : ''}</div>
      </div>
      ${rule.is_custom ? '<div style="margin-top:var(--space-3)"><span class="badge-custom">Custom Rule</span></div>' : ''}
      ${rule.is_gated ? '<div style="margin-top:var(--space-3)"><span class="badge-builtin">Gated Sink</span></div>' : ''}
      <div style="margin-top:var(--space-4)">
        <div class="rule-detail-label" style="margin-bottom:var(--space-2)">Matchers</div>
        <div>${rule.matchers.map(m => `<code class="matcher-tag">${escHtml(m)}</code>`).join(' ')}</div>
      </div>
      <div style="margin-top:var(--space-5);display:flex;gap:var(--space-2)">
        <button class="btn btn-sm" id="detail-toggle-btn">${rule.enabled ? 'Disable' : 'Enable'}</button>
        ${!rule.is_custom ? `<button class="btn btn-primary btn-sm" id="clone-rule-btn">Clone to Custom</button>` : ''}
      </div>
    </div>
  `;
}

// ── Config Page ───────────────────────────────────────────────────────────────

const LANG_OPTIONS = ['javascript', 'typescript', 'python', 'go', 'java', 'c', 'cpp', 'php', 'ruby', 'rust'];
const CAP_OPTIONS = ['all', 'env_var', 'html_escape', 'shell_escape', 'url_encode', 'json_parse', 'file_io', 'sql_query', 'deserialize', 'ssrf', 'code_exec', 'crypto'];

async function renderConfig(el, params, match) {
  el.innerHTML = '<div class="loading">Loading configuration...</div>';
  try {
    const [config, sources, sinks, sanitizers, terminators, profiles] = await Promise.all([
      api('/config'),
      api('/config/sources'),
      api('/config/sinks'),
      api('/config/sanitizers'),
      api('/config/terminators'),
      api('/config/profiles'),
    ]);

    el.innerHTML = `
      <div class="page-header"><h2>Config</h2></div>

      ${renderConfigSection('General', 'config-general', `
        <div class="detail-meta">
          <div><strong>Analysis Mode:</strong> ${escHtml(config.scanner?.mode || 'full')}</div>
          <div><strong>Min Severity:</strong> ${escHtml(config.scanner?.min_severity || 'Low')}</div>
          <div><strong>Max File Size:</strong> ${config.scanner?.max_file_size_mb ? config.scanner.max_file_size_mb + ' MB' : 'unlimited'}</div>
          <div><strong>Excluded Dirs:</strong> ${escHtml((config.scanner?.excluded_directories || []).join(', '))}</div>
          <div><strong>Excluded Exts:</strong> ${escHtml((config.scanner?.excluded_extensions || []).join(', '))}</div>
          <div><strong>Attack Surface Ranking:</strong> ${config.output?.attack_surface_ranking ? 'Enabled' : 'Disabled'}</div>
        </div>
        <div style="margin-top:var(--space-4);padding-top:var(--space-3);border-top:1px solid var(--border)">
          <div class="toggle-inline">
            <input type="checkbox" id="triage-sync-toggle" ${config.server?.triage_sync ? 'checked' : ''}>
            <label for="triage-sync-toggle"><strong>Triage Sync</strong> &mdash; Auto-sync triage decisions to <code>.nyx/triage.json</code> for git-based team sharing</label>
          </div>
        </div>
      `)}

      ${renderConfigSection('Custom Sources', 'config-sources', renderLabelTable(sources, 'source'))}
      ${renderConfigSection('Custom Sinks', 'config-sinks', renderLabelTable(sinks, 'sink'))}
      ${renderConfigSection('Custom Sanitizers', 'config-sanitizers', renderLabelTable(sanitizers, 'sanitizer'))}

      ${renderConfigSection('Terminators', 'config-terminators', `
        <div class="inline-form" id="add-term-form">
          <div class="form-group">
            <label>Language</label>
            <select id="term-lang" style="width:140px">
              <option value="">Select...</option>
              ${LANG_OPTIONS.map(l => `<option value="${l}">${escHtml(l)}</option>`).join('')}
            </select>
          </div>
          <div class="form-group">
            <label>Function Name</label>
            <input type="text" id="term-name" placeholder="process.exit">
          </div>
          <button class="btn btn-primary btn-sm" id="add-term-btn">Add Terminator</button>
        </div>
        <div class="table-wrap">
          ${terminators.length === 0 ? '<div class="empty-state" style="padding:12px"><p>No terminators configured</p></div>' :
            `<table><thead><tr><th>Language</th><th>Name</th><th></th></tr></thead><tbody>
            ${terminators.map((t, i) => `<tr>
              <td>${escHtml(t.lang)}</td>
              <td style="font-family:var(--font-mono)">${escHtml(t.name)}</td>
              <td><button class="btn btn-danger btn-sm delete-term" data-idx="${i}">Remove</button></td>
            </tr>`).join('')}
            </tbody></table>`}
        </div>
      `)}

      ${renderConfigSection('Profiles', 'config-profiles', `
        <div class="table-wrap">
          ${profiles.length === 0 ? '<div class="empty-state" style="padding:12px"><p>No profiles configured</p></div>' :
            `<table><thead><tr><th>Name</th><th>Type</th><th>Settings</th><th></th></tr></thead><tbody>
            ${profiles.map(p => `<tr>
              <td><strong>${escHtml(p.name)}</strong></td>
              <td>${p.is_builtin ? '<span class="badge-builtin">built-in</span>' : '<span class="badge-custom">custom</span>'}</td>
              <td style="font-size:var(--text-xs);max-width:300px;overflow:hidden;text-overflow:ellipsis">${escHtml(JSON.stringify(p.settings))}</td>
              <td>
                <button class="btn btn-sm activate-profile" data-name="${escHtml(p.name)}">Activate</button>
                ${!p.is_builtin ? `<button class="btn btn-danger btn-sm delete-profile" data-name="${escHtml(p.name)}">Delete</button>` : ''}
              </td>
            </tr>`).join('')}
            </tbody></table>`}
        </div>
        <div class="inline-form" style="margin-top:12px">
          <div class="form-group">
            <label>Profile Name</label>
            <input type="text" id="profile-name" placeholder="my_profile">
          </div>
          <button class="btn btn-primary btn-sm" id="save-profile-btn">Save Current as Profile</button>
        </div>
      `)}
    `;

    // ── Section collapse ──
    $$('.config-section-header', el).forEach(header => {
      header.addEventListener('click', () => {
        const body = header.nextElementSibling;
        if (body) body.classList.toggle('collapsed');
        header.classList.toggle('collapsed');
      });
    });

    // ── Triage sync toggle ──
    $('#triage-sync-toggle')?.addEventListener('change', async (e) => {
      try {
        await api('/config/triage-sync', {
          method: 'POST', signal: null,
          body: JSON.stringify({ enabled: e.target.checked }),
        });
      } catch (err) { if (!isAbortError(err)) alert('Error: ' + err.message); }
    });

    // ── Source/Sink/Sanitizer add/delete ──
    bindLabelActions(el, 'source', 'sources', params, match);
    bindLabelActions(el, 'sink', 'sinks', params, match);
    bindLabelActions(el, 'sanitizer', 'sanitizers', params, match);

    // ── Terminators ──
    $('#add-term-btn')?.addEventListener('click', async () => {
      const lang = $('#term-lang').value.trim();
      const name = $('#term-name').value.trim();
      if (!lang || !name) return;
      try {
        await api('/config/terminators', { method: 'POST', signal: null, body: JSON.stringify({ lang, name }) });
        renderConfig(el, params, match);
      } catch (e) { if (!isAbortError(e)) alert('Error: ' + e.message); }
    });

    $$('.delete-term', el).forEach(btn => {
      btn.addEventListener('click', async () => {
        const t = terminators[btn.dataset.idx];
        try {
          await api('/config/terminators', { method: 'DELETE', signal: null, body: JSON.stringify(t) });
          renderConfig(el, params, match);
        } catch (e) { if (!isAbortError(e)) alert('Error: ' + e.message); }
      });
    });

    // ── Profiles ──
    $$('.activate-profile', el).forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          await api('/config/profiles/' + encodeURIComponent(btn.dataset.name) + '/activate', { method: 'POST', signal: null });
          renderConfig(el, params, match);
        } catch (e) { if (!isAbortError(e)) alert('Error: ' + e.message); }
      });
    });

    $$('.delete-profile', el).forEach(btn => {
      btn.addEventListener('click', async () => {
        try {
          await api('/config/profiles/' + encodeURIComponent(btn.dataset.name), { method: 'DELETE', signal: null });
          renderConfig(el, params, match);
        } catch (e) { if (!isAbortError(e)) alert('Error: ' + e.message); }
      });
    });

    $('#save-profile-btn')?.addEventListener('click', async () => {
      const name = $('#profile-name').value.trim();
      if (!name) { $('#profile-name').classList.add('input-error'); return; }
      try {
        await api('/config/profiles', { method: 'POST', signal: null, body: JSON.stringify({ name, settings: {} }) });
        renderConfig(el, params, match);
      } catch (e) { if (!isAbortError(e)) alert('Error: ' + e.message); }
    });

  } catch (e) {
    if (isAbortError(e)) return;
    el.innerHTML = `<div class="error-state"><h3>Error</h3><p>${escHtml(e.message)}</p></div>`;
  }
}

function renderConfigSection(title, id, content) {
  return `
    <div class="config-section" id="${id}">
      <div class="config-section-header"><span class="config-collapse-arrow">&#9660;</span> <strong>${escHtml(title)}</strong></div>
      <div class="config-section-body">${content}</div>
    </div>
  `;
}

function renderLabelTable(entries, kind) {
  const builtins = entries.filter(e => e.is_builtin);
  const custom = entries.filter(e => !e.is_builtin);

  return `
    <div class="inline-form add-label-form" data-kind="${kind}">
      <div class="form-group">
        <label>Language</label>
        <select class="label-lang" style="width:140px">
          <option value="">Select...</option>
          ${LANG_OPTIONS.map(l => `<option value="${l}">${escHtml(l)}</option>`).join('')}
        </select>
      </div>
      <div class="form-group">
        <label>Matcher</label>
        <input type="text" class="label-matcher" placeholder="functionName">
      </div>
      <div class="form-group">
        <label>Capability</label>
        <select class="label-cap">
          ${CAP_OPTIONS.map(c => `<option value="${c}">${escHtml(c)}</option>`).join('')}
        </select>
      </div>
      <button class="btn btn-primary btn-sm add-label-btn" data-kind="${kind}">Add ${kind}</button>
    </div>
    <div class="table-wrap" style="margin-top:8px">
      ${entries.length === 0 ? `<div class="empty-state" style="padding:12px"><p>No ${kind} rules</p></div>` :
        `<table class="label-table"><thead><tr><th>Language</th><th>Matchers</th><th>Cap</th><th></th></tr></thead><tbody>
        ${builtins.map(e => `<tr class="label-builtin">
          <td>${escHtml(e.lang)}</td>
          <td style="font-family:var(--font-mono)">${escHtml(e.matchers.join(', '))}</td>
          <td>${escHtml(e.cap)}</td>
          <td><span class="badge-builtin">built-in</span></td>
        </tr>`).join('')}
        ${custom.map((e, i) => `<tr>
          <td>${escHtml(e.lang)}</td>
          <td style="font-family:var(--font-mono)">${escHtml(e.matchers.join(', '))}</td>
          <td>${escHtml(e.cap)}</td>
          <td><button class="btn btn-danger btn-sm delete-label-btn" data-kind="${kind}" data-idx="${i}">Remove</button></td>
        </tr>`).join('')}
        </tbody></table>`}
    </div>
  `;
}

function bindLabelActions(el, kind, endpoint, params, match) {
  // Scope to the specific section
  const forms = $$('.add-label-form[data-kind="' + kind + '"]', el);
  forms.forEach(form => {
    const addBtn = form.querySelector('.add-label-btn');
    if (!addBtn) return;
    addBtn.addEventListener('click', async () => {
      const lang = form.querySelector('.label-lang').value.trim();
      const matcher = form.querySelector('.label-matcher').value.trim();
      const cap = form.querySelector('.label-cap').value;
      if (!lang || !matcher) return;
      try {
        await api('/config/' + endpoint, {
          method: 'POST', signal: null,
          body: JSON.stringify({ lang, matchers: [matcher], cap, case_sensitive: false, is_builtin: false }),
        });
        renderConfig(el, params, match);
      } catch (e) { if (!isAbortError(e)) alert('Error: ' + e.message); }
    });
  });

  $$('.delete-label-btn[data-kind="' + kind + '"]', el).forEach(btn => {
    btn.addEventListener('click', async () => {
      // Find the custom entries for this kind from the table
      const row = btn.closest('tr');
      const cells = row.querySelectorAll('td');
      const lang = cells[0].textContent.trim();
      const matchers = cells[1].textContent.trim().split(', ');
      const cap = cells[2].textContent.trim();
      try {
        await api('/config/' + endpoint, {
          method: 'DELETE', signal: null,
          body: JSON.stringify({ lang, matchers, cap, case_sensitive: false, is_builtin: false }),
        });
        renderConfig(el, params, match);
      } catch (e) { if (!isAbortError(e)) alert('Error: ' + e.message); }
    });
  });
}

// ── Actions ──────────────────────────────────────────────────────────────────

// ── SSE ──────────────────────────────────────────────────────────────────────

window.activeScanProgress = null;

function connectSSE() {
  const es = new EventSource('/api/events');

  es.addEventListener('scan_completed', () => {
    window.activeScanProgress = null;
    setScanIndicator(false);
    scheduleRefresh();
  });

  es.addEventListener('scan_started', () => {
    setScanIndicator(true);
    if (currentRoute === '/scans' || currentRoute === '/') {
      scheduleRefresh();
    }
  });

  es.addEventListener('scan_failed', () => {
    window.activeScanProgress = null;
    setScanIndicator(false);
    scheduleRefresh();
  });

  es.addEventListener('scan_progress', (e) => {
    try {
      const outer = JSON.parse(e.data);
      const data = outer.data || outer;
      window.activeScanProgress = data;
      if (currentRoute === '/scans' || currentRoute.startsWith('/scans/')) {
        updateProgressDisplay(data);
      }
      updateScanIndicatorProgress(data);
    } catch { /* ignore parse errors */ }
  });

  es.addEventListener('config_changed', () => {
    if (currentRoute === '/settings' || currentRoute === '/config' || currentRoute.startsWith('/rules')) scheduleRefresh();
  });

  es.onerror = () => {
    es.close();
    setTimeout(connectSSE, 3000);
  };
}

function setScanIndicator(visible) {
  const indicator = $('#scan-indicator');
  if (indicator) {
    indicator.classList.toggle('visible', visible);
  }
}

function updateScanIndicatorProgress(data) {
  const indicator = $('#scan-indicator');
  if (!indicator) return;
  indicator.classList.add('visible');
  const span = indicator.querySelector('span:last-child');
  if (span) {
    const stage = data.stage || 'scanning';
    const pct = data.files_discovered > 0
      ? Math.round(((data.files_parsed || 0) / data.files_discovered) * 100)
      : 0;
    span.textContent = `${stage} ${pct}%`;
  }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function truncPath(p, maxLen = 60) {
  if (!p) return '';
  if (p.length <= maxLen) return p;
  return '...' + p.slice(-(maxLen - 3));
}

function escHtml(s) {
  if (s == null) return '';
  const d = document.createElement('div');
  d.textContent = String(s);
  return d.innerHTML;
}

function debounce(fn, ms) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => fn(...args), ms);
  };
}

// ── Keyboard Shortcuts ───────────────────────────────────────────────────────

document.addEventListener('keydown', e => {
  if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'TEXTAREA') return;

  if (e.key === '/') {
    e.preventDefault();
    const search = $('#findings-search');
    if (search) search.focus();
    else navigate('/findings');
  }
});

// ── Init ─────────────────────────────────────────────────────────────────────

renderSidebar();
loadAppMeta();
connectSSE();

window.addEventListener('popstate', () => {
  const path = location.pathname;
  if (path === '/findings' && currentRoute === '/findings') {
    // Same page, different query — just re-render findings
    selectedFindings.clear();
    renderFindings($('#content'), {}, matchRoute('/findings'));
  } else {
    route(path);
  }
});

// Click handler for nav links and internal navigation
document.addEventListener('click', e => {
  const link = e.target.closest('.nav-link, .nav-link-internal');
  if (link && link.getAttribute('href')) {
    e.preventDefault();
    navigate(link.getAttribute('href'));
  }
});

route(location.pathname);
