// ── Nyx Scanner Web UI ───────────────────────────────────────────────────────

const $ = (sel, ctx = document) => ctx.querySelector(sel);
const $$ = (sel, ctx = document) => [...ctx.querySelectorAll(sel)];

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
let findingsPage = 1;
let findingsFilters = {};

// ── Router ───────────────────────────────────────────────────────────────────

function navigate(path) {
  if (path === currentRoute) return;
  history.pushState(null, '', path);
  route(path);
}

function route(path) {
  currentRoute = path;
  updateNav();
  const content = $('#content');

  if (path === '/') return renderDashboard(content);
  if (path === '/findings') return renderFindings(content);
  if (path.startsWith('/findings/')) return renderFindingDetail(content, path.split('/')[2]);
  if (path === '/scans') return renderScans(content);
  if (path === '/settings') return renderSettings(content);

  content.innerHTML = '<div class="empty-state"><h3>Page not found</h3></div>';
}

function updateNav() {
  $$('.nav-link').forEach(el => {
    const r = el.dataset.route;
    el.classList.toggle('active', r === currentRoute || (r !== '/' && currentRoute.startsWith(r)));
  });
}

// ── Dashboard ────────────────────────────────────────────────────────────────

async function renderDashboard(el) {
  el.innerHTML = '<div class="loading">Loading dashboard...</div>';
  try {
    const [health, summary, scans] = await Promise.all([
      api('/health'),
      api('/findings/summary').catch(() => null),
      api('/scans'),
    ]);

    $('#version').textContent = `v${health.version}`;

    const high = summary?.by_severity?.HIGH || 0;
    const medium = summary?.by_severity?.MEDIUM || 0;
    const low = summary?.by_severity?.LOW || 0;
    const total = summary?.total || 0;

    el.innerHTML = `
      <div class="page-header">
        <h2>Dashboard</h2>
        <button class="btn btn-primary" id="scan-btn">New Scan</button>
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
        <div style="font-family:var(--font-mono);font-size:0.85rem">${health.scan_root}</div>
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

    $('#scan-btn')?.addEventListener('click', startScan);
    $$('[data-scan-id]', el).forEach(row => {
      row.addEventListener('click', () => navigate('/scans'));
    });
  } catch (e) {
    el.innerHTML = `<div class="error-state"><h3>Error loading dashboard</h3><p>${e.message}</p></div>`;
  }
}

// ── Findings ─────────────────────────────────────────────────────────────────

async function renderFindings(el) {
  el.innerHTML = '<div class="loading">Loading findings...</div>';
  try {
    const params = new URLSearchParams();
    params.set('page', findingsPage);
    params.set('per_page', '50');
    for (const [k, v] of Object.entries(findingsFilters)) {
      if (v) params.set(k, v);
    }

    const data = await api(`/findings?${params}`);

    el.innerHTML = `
      <div class="page-header">
        <h2>Findings</h2>
        <span style="color:var(--text-secondary)">${data.total} total</span>
      </div>
      <div class="filter-bar">
        <input type="text" placeholder="Search findings... (/)" class="search-input" id="findings-search"
          value="${findingsFilters.search || ''}">
        <select id="filter-severity">
          <option value="">All Severities</option>
          <option value="HIGH" ${findingsFilters.severity==='HIGH'?'selected':''}>High</option>
          <option value="MEDIUM" ${findingsFilters.severity==='MEDIUM'?'selected':''}>Medium</option>
          <option value="LOW" ${findingsFilters.severity==='LOW'?'selected':''}>Low</option>
        </select>
        <select id="filter-category">
          <option value="">All Categories</option>
          <option value="Security" ${findingsFilters.category==='Security'?'selected':''}>Security</option>
          <option value="Reliability" ${findingsFilters.category==='Reliability'?'selected':''}>Reliability</option>
          <option value="Quality" ${findingsFilters.category==='Quality'?'selected':''}>Quality</option>
        </select>
      </div>
      ${data.findings.length === 0
        ? '<div class="empty-state"><h3>No findings</h3><p>Run a scan to see results, or adjust your filters.</p></div>'
        : `<div class="table-wrap"><table>
          <thead><tr><th>Severity</th><th>Rule</th><th>File</th><th>Line</th><th>Confidence</th></tr></thead>
          <tbody>
          ${data.findings.map(f => `<tr class="clickable" data-finding="${f.index}">
            <td><span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span></td>
            <td>${f.rule_id}</td>
            <td style="font-family:var(--font-mono);font-size:0.82rem">${truncPath(f.path)}</td>
            <td>${f.line}</td>
            <td>${f.confidence || '-'}</td>
          </tr>`).join('')}
          </tbody></table></div>
          <div class="pagination">
            ${findingsPage > 1 ? '<button class="btn btn-sm" id="prev-page">Prev</button>' : ''}
            <span>Page ${data.page} of ${Math.ceil(data.total / data.per_page) || 1}</span>
            ${data.page * data.per_page < data.total ? '<button class="btn btn-sm" id="next-page">Next</button>' : ''}
          </div>`
      }`;

    // Event listeners
    $$('[data-finding]', el).forEach(row => {
      row.addEventListener('click', () => navigate(`/findings/${row.dataset.finding}`));
    });
    $('#findings-search')?.addEventListener('input', debounce(e => {
      findingsFilters.search = e.target.value;
      findingsPage = 1;
      renderFindings(el);
    }, 300));
    $('#filter-severity')?.addEventListener('change', e => {
      findingsFilters.severity = e.target.value;
      findingsPage = 1;
      renderFindings(el);
    });
    $('#filter-category')?.addEventListener('change', e => {
      findingsFilters.category = e.target.value;
      findingsPage = 1;
      renderFindings(el);
    });
    $('#prev-page')?.addEventListener('click', () => { findingsPage--; renderFindings(el); });
    $('#next-page')?.addEventListener('click', () => { findingsPage++; renderFindings(el); });
  } catch (e) {
    if (e.message.includes('404')) {
      el.innerHTML = '<div class="empty-state"><h3>No scan results yet</h3><p>Run a scan first to see findings.</p></div>';
    } else {
      el.innerHTML = `<div class="error-state"><h3>Error</h3><p>${e.message}</p></div>`;
    }
  }
}

// ── Finding Detail ───────────────────────────────────────────────────────────

async function renderFindingDetail(el, index) {
  el.innerHTML = '<div class="loading">Loading finding...</div>';
  try {
    const f = await api(`/findings/${index}`);

    el.innerHTML = `
      <div class="detail-header">
        <button class="btn btn-sm" id="back-btn" style="margin-bottom:12px">Back to Findings</button>
        <h2>${f.rule_id}</h2>
        <div class="detail-meta">
          <span class="badge badge-${f.severity.toLowerCase()}">${f.severity}</span>
          <span>${f.category}</span>
          <span style="font-family:var(--font-mono)">${f.path}:${f.line}:${f.col}</span>
          ${f.confidence ? `<span>Confidence: ${f.confidence}</span>` : ''}
          ${f.rank_score != null ? `<span>Score: ${f.rank_score.toFixed(1)}</span>` : ''}
        </div>
      </div>
      ${f.message ? `<div class="detail-section"><h3>Message</h3><p>${escHtml(f.message)}</p></div>` : ''}
      ${f.labels.length > 0 ? `
        <div class="detail-section">
          <h3>Evidence Labels</h3>
          <div class="label-list">
            ${f.labels.map(([k, v]) => `<span class="label-item"><span class="label-key">${escHtml(k)}:</span> <span class="label-value">${escHtml(v)}</span></span>`).join('')}
          </div>
        </div>` : ''}
      ${f.code_context ? `
        <div class="detail-section">
          <h3>Code</h3>
          <div class="code-block">
            ${f.code_context.lines.map((line, i) => {
              const lineNum = f.code_context.start_line + i;
              const isHighlight = lineNum === f.code_context.highlight_line;
              return `<div class="code-line${isHighlight ? ' highlight' : ''}"><span class="line-number">${lineNum}</span><span class="line-content">${escHtml(line)}</span></div>`;
            }).join('')}
          </div>
        </div>` : ''}
    `;

    $('#back-btn')?.addEventListener('click', () => navigate('/findings'));
  } catch (e) {
    el.innerHTML = `<div class="error-state"><h3>Finding not found</h3><p>${e.message}</p></div>`;
  }
}

// ── Scans ────────────────────────────────────────────────────────────────────

async function renderScans(el) {
  el.innerHTML = '<div class="loading">Loading scans...</div>';
  try {
    const scans = await api('/scans');

    el.innerHTML = `
      <div class="page-header">
        <h2>Scans</h2>
        <button class="btn btn-primary" id="scan-btn">New Scan</button>
      </div>
      ${scans.length === 0
        ? '<div class="empty-state"><h3>No scans yet</h3><p>Click "New Scan" to start your first scan.</p></div>'
        : `<div class="table-wrap"><table>
          <thead><tr><th>Status</th><th>Root</th><th>Duration</th><th>Findings</th><th>Started</th><th>Error</th></tr></thead>
          <tbody>
          ${scans.map(s => `<tr>
            <td><span class="status-dot ${s.status}"></span>${s.status}</td>
            <td style="font-family:var(--font-mono);font-size:0.82rem">${truncPath(s.scan_root)}</td>
            <td>${s.duration_secs != null ? s.duration_secs.toFixed(2) + 's' : '-'}</td>
            <td>${s.finding_count ?? '-'}</td>
            <td>${s.started_at ? new Date(s.started_at).toLocaleString() : '-'}</td>
            <td style="color:var(--sev-high)">${s.error || ''}</td>
          </tr>`).join('')}
          </tbody></table></div>`
      }`;

    $('#scan-btn')?.addEventListener('click', startScan);
  } catch (e) {
    el.innerHTML = `<div class="error-state"><h3>Error</h3><p>${e.message}</p></div>`;
  }
}

// ── Settings ─────────────────────────────────────────────────────────────────

async function renderSettings(el) {
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
              <td>${r.lang}</td>
              <td style="font-family:var(--font-mono)">${r.matchers.join(', ')}</td>
              <td><span class="badge">${r.kind}</span></td>
              <td>${r.cap}</td>
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
              <td>${t.lang}</td>
              <td style="font-family:var(--font-mono)">${t.name}</td>
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
        renderSettings(el);
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
          renderSettings(el);
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
        renderSettings(el);
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
          renderSettings(el);
        } catch (e) { alert('Error: ' + e.message); }
      });
    });

  } catch (e) {
    el.innerHTML = `<div class="error-state"><h3>Error</h3><p>${e.message}</p></div>`;
  }
}

// ── Actions ──────────────────────────────────────────────────────────────────

async function startScan() {
  try {
    await api('/scans', { method: 'POST' });
    navigate('/scans');
  } catch (e) {
    alert(e.message);
  }
}

// ── SSE ──────────────────────────────────────────────────────────────────────

function connectSSE() {
  const es = new EventSource('/api/events');

  es.addEventListener('scan_completed', () => {
    // Auto-refresh current view
    route(currentRoute);
  });

  es.addEventListener('scan_started', () => {
    if (currentRoute === '/scans' || currentRoute === '/') {
      route(currentRoute);
    }
  });

  es.addEventListener('scan_failed', () => {
    route(currentRoute);
  });

  es.addEventListener('config_changed', () => {
    if (currentRoute === '/settings') route(currentRoute);
  });

  es.onerror = () => {
    es.close();
    setTimeout(connectSSE, 3000);
  };
}

// ── Helpers ──────────────────────────────────────────────────────────────────

function truncPath(p) {
  if (p.length <= 60) return p;
  return '...' + p.slice(-57);
}

function escHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
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

window.addEventListener('popstate', () => route(location.pathname));

// Click handler for nav links
document.addEventListener('click', e => {
  const link = e.target.closest('.nav-link');
  if (link) {
    e.preventDefault();
    navigate(link.getAttribute('href'));
  }
});

connectSSE();
route(location.pathname);
