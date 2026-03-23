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
  { path: '/scans/:id',        section: 'scans',    render: renderScanDetail },
  { path: '/rules',            section: 'rules',    render: renderStub },
  { path: '/rules/:id',        section: 'rules',    render: renderStub },
  { path: '/triage',           section: 'triage',   render: renderStub },
  { path: '/config',           section: 'config',   render: renderStub },
  { path: '/explorer',         section: 'explorer', render: renderStub },
  { path: '/debug',            section: 'debug',    render: renderStub },
  { path: '/debug/cfg',        section: 'debug',    render: renderStub },
  { path: '/debug/ssa',        section: 'debug',    render: renderStub },
  { path: '/debug/call-graph', section: 'debug',    render: renderStub },
  { path: '/debug/taint',      section: 'debug',    render: renderStub },
  { path: '/settings',         section: 'settings', render: renderSettings },
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
  '/rules':            'Define and manage custom taint analysis rules for sources, sinks, and sanitizers across all supported languages.',
  '/rules/:id':        'View and edit rule details.',
  '/triage':           'Review, classify, and prioritize findings with bulk actions and assignment workflows.',
  '/config':           'Configure scan settings, language options, and analysis parameters.',
  '/explorer':         'Browse the scanned codebase, view file trees, and inspect individual files with inline annotations.',
  '/debug':            'Inspect internal analysis state — control flow graphs, SSA IR, call graphs, and taint propagation.',
  '/debug/cfg':        'Visualize control flow graphs for individual functions with block-level detail.',
  '/debug/ssa':        'Inspect SSA intermediate representation including phi nodes, value numbering, and taint state.',
  '/debug/call-graph': 'Explore the inter-procedural call graph with SCC highlighting and topo-order visualization.',
  '/debug/taint':      'Step through taint propagation with per-instruction state snapshots and path tracking.',
  '/scans/:id':        'View detailed scan results, timing breakdown, and per-file analysis.',
};

// ── API helpers ──────────────────────────────────────────────────────────────

async function api(path, opts = {}) {
  const headers = { ...opts.headers };
  if (opts.body) {
    headers['Content-Type'] = headers['Content-Type'] || 'application/json';
  }
  const res = await fetch(`/api${path}`, { ...opts, headers });
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

function route(path) {
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
    const health = await api('/health');
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

// ── Dashboard ────────────────────────────────────────────────────────────────

async function renderDashboard(el, params, match) {
  el.innerHTML = '<div class="loading">Loading dashboard...</div>';
  try {
    const [health, summary, scans] = await Promise.all([
      api('/health'),
      api('/findings/summary').catch(() => null),
      api('/scans'),
    ]);

    const high = summary?.by_severity?.HIGH || 0;
    const medium = summary?.by_severity?.MEDIUM || 0;
    const low = summary?.by_severity?.LOW || 0;
    const total = summary?.total || 0;

    el.innerHTML = `
      <div class="page-header">
        <h2>Dashboard</h2>
      </div>
      <div class="card-grid">
        <div class="card">
          <div class="card-header">Total Findings</div>
          <div class="card-value">${total}</div>
        </div>
        <div class="card">
          <div class="card-header">High</div>
          <div class="card-value" style="color:var(--sev-high)">${high}</div>
        </div>
        <div class="card">
          <div class="card-header">Medium</div>
          <div class="card-value" style="color:var(--sev-medium)">${medium}</div>
        </div>
        <div class="card">
          <div class="card-header">Low</div>
          <div class="card-value" style="color:var(--sev-low)">${low}</div>
        </div>
      </div>
      <div class="card" style="margin-bottom:16px">
        <div class="card-header">Scan Root</div>
        <div style="font-family:var(--font-mono);font-size:0.85rem">${escHtml(health.scan_root)}</div>
      </div>
      <div class="card">
        <div class="card-header">Recent Scans</div>
        ${scans.length === 0 ? '<div class="empty-state" style="padding:20px"><h3>No scans yet</h3><p>Click "New Scan" to start</p></div>' :
          `<table><thead><tr><th>Status</th><th>Duration</th><th>Findings</th><th>Time</th></tr></thead><tbody>
          ${scans.slice(0, 5).map(s => `<tr class="clickable" data-scan-id="${s.id}">
            <td><span class="status-dot ${s.status}"></span>${s.status}</td>
            <td>${s.duration_secs != null ? s.duration_secs.toFixed(1) + 's' : '-'}</td>
            <td>${s.finding_count ?? '-'}</td>
            <td>${s.started_at ? new Date(s.started_at).toLocaleString() : '-'}</td>
          </tr>`).join('')}
          </tbody></table>`
        }
      </div>`;

    $$('[data-scan-id]', el).forEach(row => {
      row.addEventListener('click', () => navigate(`/scans/${row.dataset.scanId}`));
    });
  } catch (e) {
    el.innerHTML = `<div class="error-state"><h3>Error loading dashboard</h3><p>${escHtml(e.message)}</p></div>`;
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
        <button class="btn btn-sm" disabled title="Coming in Phase 7">Suppress</button>
        <button class="btn btn-sm" disabled title="Coming in Phase 7">Mark FP</button>
        <button class="btn btn-sm" disabled title="Coming in Phase 7">Export</button>
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
          ${data.findings.map(f => `<tr class="clickable${selectedFindings.has(f.index) ? ' selected' : ''}" data-finding="${f.index}">
            <td class="col-checkbox"><input type="checkbox" class="row-check" data-idx="${f.index}" ${selectedFindings.has(f.index) ? 'checked' : ''}></td>
            <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
            <td>${f.confidence ? `<span class="badge badge-conf-${f.confidence.toLowerCase()}">${f.confidence}</span>` : '-'}</td>
            <td>${escHtml(f.rule_id)}</td>
            <td>${escHtml(f.category)}</td>
            <td class="cell-path" title="${escHtml(f.path)}">${escHtml(truncPath(f.path))}</td>
            <td>${f.line}</td>
            <td>${f.language || '-'}</td>
            <td><span class="badge badge-status-${f.status}">${f.status}</span></td>
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
          <span class="badge badge-status-${f.status}">${f.status}</span>
          ${sanitizerBadge}
        </div>
        <a href="#" class="file-location" id="open-code-viewer" data-path="${escHtml(f.path)}" data-line="${f.line}">${escHtml(f.path)}:${f.line}:${f.col}</a>

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

  } catch (e) {
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

    el.innerHTML = `
      <div class="page-header">
        <h2>Scans</h2>
      </div>
      ${progressHtml}
      ${scans.length === 0
        ? '<div class="empty-state"><h3>No scans yet</h3><p>Use the "Start Scan" button in the header to start your first scan.</p></div>'
        : `<div class="table-wrap"><table>
          <thead><tr><th>Status</th><th>Root</th><th>Duration</th><th>Findings</th><th>Languages</th><th>Started</th></tr></thead>
          <tbody>
          ${scans.map(s => `<tr class="clickable" data-scan-id="${s.id}">
            <td><span class="status-badge ${s.status}"><span class="status-dot ${s.status}"></span>${s.status}</span></td>
            <td style="font-family:var(--font-mono);font-size:0.82rem">${escHtml(truncPath(s.scan_root))}</td>
            <td>${s.duration_secs != null ? s.duration_secs.toFixed(2) + 's' : '-'}</td>
            <td>${s.finding_count ?? '-'}</td>
            <td>${(s.languages || []).map(l => `<span class="lang-badge">${escHtml(l)}</span>`).join('') || '-'}</td>
            <td>${relTime(s.started_at)}</td>
          </tr>`).join('')}
          </tbody></table></div>`
      }`;

    $$('[data-scan-id]', el).forEach(row => {
      row.addEventListener('click', () => navigate(`/scans/${row.dataset.scanId}`));
    });
  } catch (e) {
    el.innerHTML = `<div class="error-state"><h3>Error</h3><p>${escHtml(e.message)}</p></div>`;
  }
}

// ── Scan Detail Page ─────────────────────────────────────────────────────────

async function renderScanDetail(el, params) {
  const id = params.id;
  el.innerHTML = '<div class="loading">Loading scan...</div>';
  try {
    const scan = await api(`/scans/${id}`);
    let activeTab = 'summary';

    const renderTabs = () => {
      el.innerHTML = `
        <button class="btn btn-sm" id="back-to-scans" style="margin-bottom:var(--space-4)">Back to Scans</button>
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
      await api('/scans', { method: 'POST', body });
      close();
      navigate('/scans');
    } catch (e) {
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

// ── Settings ─────────────────────────────────────────────────────────────────

async function renderSettings(el, params, match) {
  el.innerHTML = '<div class="loading">Loading settings...</div>';
  try {
    const [rules, terminators] = await Promise.all([
      api('/config/rules'),
      api('/config/terminators'),
    ]);

    el.innerHTML = `
      <div class="page-header"><h2>Settings</h2></div>

      <div class="settings-section">
        <h3>Custom Rules</h3>
        <div class="inline-form" id="add-rule-form">
          <div class="form-group">
            <label>Language</label>
            <select id="rule-lang" style="width:140px">
              <option value="">Select...</option>
              <option value="javascript">JavaScript</option>
              <option value="typescript">TypeScript</option>
              <option value="python">Python</option>
              <option value="go">Go</option>
              <option value="java">Java</option>
              <option value="c">C</option>
              <option value="cpp">C++</option>
              <option value="php">PHP</option>
              <option value="ruby">Ruby</option>
              <option value="rust">Rust</option>
            </select>
          </div>
          <div class="form-group">
            <label>Matcher</label>
            <input type="text" id="rule-matcher" placeholder="functionName">
          </div>
          <div class="form-group">
            <label>Kind</label>
            <select id="rule-kind">
              <option value="source">Source</option>
              <option value="sanitizer">Sanitizer</option>
              <option value="sink">Sink</option>
            </select>
          </div>
          <div class="form-group">
            <label>Capability</label>
            <select id="rule-cap">
              <option value="all">all</option>
              <option value="env_var">env_var</option>
              <option value="html_escape">html_escape</option>
              <option value="shell_escape">shell_escape</option>
              <option value="url_encode">url_encode</option>
              <option value="json_parse">json_parse</option>
              <option value="file_io">file_io</option>
              <option value="sql_query">sql_query</option>
              <option value="deserialize">deserialize</option>
              <option value="ssrf">ssrf</option>
              <option value="code_exec">code_exec</option>
              <option value="crypto">crypto</option>
            </select>
          </div>
          <button class="btn btn-primary btn-sm" id="add-rule-btn">Add Rule</button>
        </div>
        <div class="table-wrap">
          ${rules.length === 0 ? '<div class="empty-state" style="padding:20px"><p>No custom rules configured</p></div>' :
            `<table><thead><tr><th>Language</th><th>Matchers</th><th>Kind</th><th>Capability</th><th></th></tr></thead><tbody>
            ${rules.map((r, i) => `<tr>
              <td>${escHtml(r.lang)}</td>
              <td style="font-family:var(--font-mono)">${escHtml(r.matchers.join(', '))}</td>
              <td><span class="badge">${escHtml(r.kind)}</span></td>
              <td>${escHtml(r.cap)}</td>
              <td><button class="btn btn-danger btn-sm delete-rule" data-idx="${i}">Remove</button></td>
            </tr>`).join('')}
            </tbody></table>`
          }
        </div>
      </div>

      <div class="settings-section">
        <h3>Terminators</h3>
        <div class="inline-form" id="add-term-form">
          <div class="form-group">
            <label>Language</label>
            <select id="term-lang" style="width:140px">
              <option value="">Select...</option>
              <option value="javascript">JavaScript</option>
              <option value="typescript">TypeScript</option>
              <option value="python">Python</option>
              <option value="go">Go</option>
              <option value="java">Java</option>
              <option value="c">C</option>
              <option value="cpp">C++</option>
              <option value="php">PHP</option>
              <option value="ruby">Ruby</option>
              <option value="rust">Rust</option>
            </select>
          </div>
          <div class="form-group">
            <label>Function Name</label>
            <input type="text" id="term-name" placeholder="process.exit">
          </div>
          <button class="btn btn-primary btn-sm" id="add-term-btn">Add Terminator</button>
        </div>
        <div class="table-wrap">
          ${terminators.length === 0 ? '<div class="empty-state" style="padding:20px"><p>No custom terminators configured</p></div>' :
            `<table><thead><tr><th>Language</th><th>Name</th><th></th></tr></thead><tbody>
            ${terminators.map((t, i) => `<tr>
              <td>${escHtml(t.lang)}</td>
              <td style="font-family:var(--font-mono)">${escHtml(t.name)}</td>
              <td><button class="btn btn-danger btn-sm delete-term" data-idx="${i}">Remove</button></td>
            </tr>`).join('')}
            </tbody></table>`
          }
        </div>
      </div>
    `;

    // Add rule
    $('#add-rule-btn')?.addEventListener('click', async () => {
      const lang = $('#rule-lang').value.trim();
      const matcher = $('#rule-matcher').value.trim();
      const kind = $('#rule-kind').value;
      const cap = $('#rule-cap').value;
      if (!lang || !matcher) {
        if (!lang) $('#rule-lang').classList.add('input-error');
        if (!matcher) $('#rule-matcher').classList.add('input-error');
        return;
      }
      $('#rule-lang').classList.remove('input-error');
      $('#rule-matcher').classList.remove('input-error');
      try {
        await api('/config/rules', {
          method: 'POST',
          body: JSON.stringify({ lang, matchers: [matcher], kind, cap }),
        });
        renderSettings(el, params, match);
      } catch (e) { alert('Error: ' + e.message); }
    });

    // Delete rule
    $$('.delete-rule', el).forEach(btn => {
      btn.addEventListener('click', async () => {
        const r = rules[btn.dataset.idx];
        try {
          await api('/config/rules', {
            method: 'DELETE',
            body: JSON.stringify(r),
          });
          renderSettings(el, params, match);
        } catch (e) { alert('Error: ' + e.message); }
      });
    });

    // Add terminator
    $('#add-term-btn')?.addEventListener('click', async () => {
      const lang = $('#term-lang').value.trim();
      const name = $('#term-name').value.trim();
      if (!lang || !name) {
        if (!lang) $('#term-lang').classList.add('input-error');
        if (!name) $('#term-name').classList.add('input-error');
        return;
      }
      $('#term-lang').classList.remove('input-error');
      $('#term-name').classList.remove('input-error');
      try {
        await api('/config/terminators', {
          method: 'POST',
          body: JSON.stringify({ lang, name }),
        });
        renderSettings(el, params, match);
      } catch (e) { alert('Error: ' + e.message); }
    });

    // Delete terminator
    $$('.delete-term', el).forEach(btn => {
      btn.addEventListener('click', async () => {
        const t = terminators[btn.dataset.idx];
        try {
          await api('/config/terminators', {
            method: 'DELETE',
            body: JSON.stringify(t),
          });
          renderSettings(el, params, match);
        } catch (e) { alert('Error: ' + e.message); }
      });
    });

  } catch (e) {
    el.innerHTML = `<div class="error-state"><h3>Error</h3><p>${escHtml(e.message)}</p></div>`;
  }
}

// ── Actions ──────────────────────────────────────────────────────────────────

// ── SSE ──────────────────────────────────────────────────────────────────────

window.activeScanProgress = null;

function connectSSE() {
  const es = new EventSource('/api/events');

  es.addEventListener('scan_completed', () => {
    window.activeScanProgress = null;
    setScanIndicator(false);
    route(currentRoute);
  });

  es.addEventListener('scan_started', () => {
    setScanIndicator(true);
    if (currentRoute === '/scans' || currentRoute === '/') {
      route(currentRoute);
    }
  });

  es.addEventListener('scan_failed', () => {
    window.activeScanProgress = null;
    setScanIndicator(false);
    route(currentRoute);
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
    if (currentRoute === '/settings') route(currentRoute);
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
