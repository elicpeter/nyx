#!/usr/bin/env node
/**
 * Capture stills + a demo GIF of the Nyx dashboard for the README/docs.
 *
 * The demo source is embedded below (V1_SERVER + V2_SERVER) so the
 * storyboard is reproducible from this file alone.  V1 has 4 endpoints
 * and yields ~6 findings (one of them a 5-hop CMDi taint flow that
 * the GIF drills into); V2 keeps only that flow so scan #2 has fewer
 * findings than scan #1 and the overview trend chart shows a
 * downward slope.
 *
 * Phases:
 *   1. setup        — write V1 to SCAN_ROOT, ensure server reachable
 *   2. gif (opt)    — record the storyboard against a fresh DB; this
 *                     also drives scan #1 via the UI
 *   3. scan #1      — if --gif didn't run, kick off scan #1 via API
 *   4. stills/p1    — capture pages whose content benefits from many
 *                     findings (findings list, finding detail)
 *   5. patch+scan2  — overwrite SCAN_ROOT with V2 + run scan #2 via API
 *   6. stills/p2    — capture pages whose content benefits from a
 *                     two-scan history (overview trend, scans list,
 *                     scan detail) plus the static-ish ones
 *                     (triage, explorer, rules, config)
 *   7. frame        — composite the brand purple gradient around every
 *                     captured PNG via scripts/frame-screenshots.py
 *
 * Prerequisites (script asserts each before starting):
 *   - playwright installed (npx playwright)
 *   - ffmpeg on PATH (palette-based GIF conversion)
 *   - python3 + Pillow on PATH (frame compositing)
 *   - nyx serve running on $NYX_URL (default http://127.0.0.1:9876)
 *   - the served scan root is empty of prior scans (system DB wiped)
 *
 * Usage:
 *   node scripts/capture-screenshots.mjs --stills   # PNGs only
 *   node scripts/capture-screenshots.mjs --gif      # GIF only
 *   node scripts/capture-screenshots.mjs --all      # both, in one orchestrated run
 *
 * Output (under assets/screenshots/):
 *   demo.gif                       (~25–30s walkthrough)
 *   overview.png                   (mirror of docs/serve-overview.png; used by README)
 *   docs/serve-overview.png        (overview after scan #2 — trend going down)
 *   docs/serve-findings-list.png   (post-scan-#1 list with multiple highs)
 *   docs/serve-finding-detail.png  (5-hop taint flow visualizer)
 *   docs/serve-triage.png
 *   docs/serve-explorer.png
 *   docs/serve-scans.png
 *   docs/serve-scan-detail.png
 *   docs/serve-rules.png
 *   docs/serve-config.png
 */
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import {
  copyFileSync,
  existsSync,
  mkdirSync,
  rmSync,
  unlinkSync,
  writeFileSync,
} from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';

const URL_BASE  = process.env.NYX_URL  || 'http://127.0.0.1:9876';
const SCAN_ROOT = process.env.SCAN_ROOT || '/tmp/nyx-demo-app';
const OUT_DIR   = process.env.OUT_DIR  || '/Users/elipeter/nyx/assets/screenshots';
const FRAMER    = process.env.FRAMER   || '/Users/elipeter/nyx/scripts/frame-screenshots.py';
const VIEW = { width: 1440, height: 900 };
const COLOR_SCHEME = 'light';

const args = new Set(process.argv.slice(2));
const wantStills = args.has('--stills') || args.has('--all');
const wantGif    = args.has('--gif')    || args.has('--all');
if (!wantStills && !wantGif) {
  console.error('usage: capture-screenshots.mjs [--stills|--gif|--all]');
  process.exit(2);
}

mkdirSync(join(OUT_DIR, 'docs'), { recursive: true });

// Demo source ----------------------------------------------------------------

const V1_SERVER = `import express from 'express';
import { exec } from 'child_process';
import fs from 'fs';

const app = express();
app.use(express.json());

// Lookup endpoint. Multi-hop CMDi: req.params.user → trim → flag → cmd → exec.
app.get('/lookup/:user', (req, res) => {
  const raw = req.params.user;
  const cleaned = raw.trim();
  const flag = \`--user=\${cleaned}\`;
  const cmd = \`whois \${flag} --verbose\`;
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
});

// SSRF: req.query.url → fetch.
app.get('/proxy', async (req, res) => {
  const target = req.query.url;
  const response = await fetch(target);
  const body = await response.text();
  res.send(body);
});

// Path traversal / unsafe file read.
app.get('/file', (req, res) => {
  const requested = req.query.path;
  const body = fs.readFileSync(requested, 'utf8');
  res.send(body);
});

// Login endpoint with weak (Math.random) session id.
app.post('/login', (req, res) => {
  const sid = Math.random().toString(36).slice(2);
  res.cookie('sid', sid).json({ ok: true });
});

app.listen(3000);
`;

const V2_SERVER = `import express from 'express';
import { exec } from 'child_process';

const app = express();
app.use(express.json());

// Lookup endpoint. Multi-hop CMDi: req.params.user → trim → flag → cmd → exec.
app.get('/lookup/:user', (req, res) => {
  const raw = req.params.user;
  const cleaned = raw.trim();
  const flag = \`--user=\${cleaned}\`;
  const cmd = \`whois \${flag} --verbose\`;
  exec(cmd, (err, stdout) => {
    res.send(stdout);
  });
});

app.listen(3000);
`;

const PACKAGE_JSON = `{ "name": "nyx-demo-app", "version": "1.0.0", "type": "module", "main": "src/server.js" }
`;

const AUTH_JS = `import jwt from 'jsonwebtoken';
const SECRET = 'super-secret-key';
export function sign(p) { return jwt.sign(p, SECRET); }
export function verify(t) { return jwt.verify(t, SECRET); }
`;

function writeDemo(variant) {
  mkdirSync(join(SCAN_ROOT, 'src'), { recursive: true });
  writeFileSync(join(SCAN_ROOT, 'package.json'), PACKAGE_JSON);
  writeFileSync(
    join(SCAN_ROOT, 'src/server.js'),
    variant === 'v2' ? V2_SERVER : V1_SERVER,
  );
  const authPath = join(SCAN_ROOT, 'src/auth.js');
  if (variant === 'v1') writeFileSync(authPath, AUTH_JS);
  if (variant === 'v2' && existsSync(authPath)) unlinkSync(authPath);
}

// Server helpers -------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchJson(path) {
  const res = await fetch(URL_BASE + path);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

async function csrfToken() {
  const r = await fetch(URL_BASE + '/api/session');
  return (await r.json()).csrf_token;
}

async function waitForServer() {
  for (let i = 0; i < 30; i++) {
    try { await fetchJson('/api/health'); return; } catch { await sleep(250); }
  }
  throw new Error(`nyx serve not reachable at ${URL_BASE}, start it first`);
}

async function startScanViaApi(token) {
  const res = await fetch(URL_BASE + '/api/scans', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': token },
    body: '{}',
  });
  if (!res.ok && res.status !== 409) {
    throw new Error(`POST /api/scans: ${res.status} ${await res.text()}`);
  }
}

async function waitForScanComplete(prevScanId, timeoutMs = 90_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const overview = await fetchJson('/api/overview').catch(() => null);
    if (
      overview?.latest_scan_id &&
      overview.state !== 'empty' &&
      overview.latest_scan_id !== prevScanId
    ) {
      await sleep(400);
      return overview;
    }
    await sleep(400);
  }
  throw new Error('scan did not complete within deadline');
}

async function currentScanId() {
  const overview = await fetchJson('/api/overview').catch(() => null);
  return overview?.latest_scan_id ?? null;
}

// Storyboard helpers ---------------------------------------------------------

async function findFirstTaintRow(page) {
  return page.locator('tbody tr').filter({ hasText: 'taint-' }).first();
}

// Stills ---------------------------------------------------------------------

async function captureStillsAfterScan1(page) {
  console.error('[stills/p1] findings list');
  await page.goto(URL_BASE + '/findings');
  await page.waitForSelector('tbody tr', { timeout: 15_000 });
  await sleep(1500);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-findings-list.png') });

  console.error('[stills/p1] finding detail (5-hop CMDi)');
  const row = await findFirstTaintRow(page);
  await row.click();
  await page.waitForURL(/\/findings\/\d+/, { timeout: 10_000 });
  await sleep(2200); // flow visualizer animation
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-finding-detail.png') });
}

async function captureStillsAfterScan2(page) {
  console.error('[stills/p2] overview (with 2-scan trend)');
  await page.goto(URL_BASE + '/');
  await page
    .waitForSelector('.health-score-card, [class*="health"]', { timeout: 10_000 })
    .catch(() => {});
  await sleep(1800);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-overview.png') });

  console.error('[stills/p2] triage');
  await page.goto(URL_BASE + '/triage');
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await sleep(1500);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-triage.png') });

  console.error('[stills/p2] explorer');
  await page.goto(URL_BASE + '/explorer');
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await sleep(2000);
  // Open the file with findings if visible — makes the screenshot
  // representative of the explorer's value (highlighted source +
  // sink marker).  Best-effort: skip silently if selector misses.
  const fileNode = page
    .locator('.file-tree, [class*="file-tree"]')
    .locator('text=server.js')
    .first();
  if (await fileNode.count()) {
    await fileNode.click().catch(() => {});
    await sleep(1500);
  }
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-explorer.png') });

  console.error('[stills/p2] scans list');
  await page.goto(URL_BASE + '/scans');
  await page.waitForSelector('tbody tr', { timeout: 10_000 }).catch(() => {});
  await sleep(1500);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-scans.png') });

  console.error('[stills/p2] scan detail');
  const firstScan = page.locator('tbody tr').first();
  if (await firstScan.count()) {
    await firstScan.click();
    await page.waitForURL(/\/scans\/\d+/, { timeout: 10_000 }).catch(() => {});
    await sleep(1800);
    await page.screenshot({ path: join(OUT_DIR, 'docs/serve-scan-detail.png') });
  }

  console.error('[stills/p2] rules');
  await page.goto(URL_BASE + '/rules');
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await sleep(1800);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-rules.png') });

  console.error('[stills/p2] config');
  await page.goto(URL_BASE + '/config');
  await page.waitForLoadState('domcontentloaded').catch(() => {});
  await sleep(1800);
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-config.png') });
}

// GIF storyboard -------------------------------------------------------------

async function captureGifFrames(page) {
  console.error('[gif] scene 1: empty dashboard');
  await page.goto(URL_BASE + '/');
  await page.waitForSelector('text=Run your first scan');
  await sleep(2200);

  console.error('[gif] scene 2: open Start Scan modal');
  await page.click('header button:has-text("Start Scan"), .header button:has-text("Start Scan"), button:has-text("Start Scan")');
  await page.waitForSelector('.scan-modal');
  await sleep(1200);

  console.error('[gif] scene 3: confirm scan');
  await page.click('.scan-modal button.btn-primary');
  await page.waitForURL('**/scans', { timeout: 10_000 }).catch(() => {});
  await waitForScanComplete(null);

  console.error('[gif] scene 4: back to overview, scroll');
  await page.goto(URL_BASE + '/');
  await page
    .waitForSelector('.health-score-card, [class*="health"]', { timeout: 10_000 })
    .catch(() => {});
  await sleep(1800);
  await page.evaluate(() => window.scrollBy({ top: 360, behavior: 'smooth' }));
  await sleep(1500);
  await page.evaluate(() => window.scrollBy({ top: 360, behavior: 'smooth' }));
  await sleep(1500);
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(800);

  console.error('[gif] scene 5: navigate to Findings');
  await page.click('a.nav-link:has-text("Findings"), .sidebar a:has-text("Findings")');
  await page.waitForURL('**/findings', { timeout: 10_000 });
  await page.waitForSelector('tbody tr', { timeout: 10_000 });
  await sleep(1500);

  console.error('[gif] scene 6: click the 5-hop taint finding');
  const taintRow = await findFirstTaintRow(page);
  await taintRow.click();
  await page.waitForURL(/\/findings\/\d+/, { timeout: 10_000 });
  await sleep(2500);
  await page.evaluate(() => window.scrollBy({ top: 240, behavior: 'smooth' }));
  await sleep(1500);

  console.error('[gif] scene 7: open the collapsed sections');
  for (const title of ['Evidence', 'Analysis Notes', 'Confidence Reasoning']) {
    const toggle = page.locator(`.section-toggle:has-text("${title}")`).first();
    if (await toggle.count()) {
      await toggle.scrollIntoViewIfNeeded();
      await sleep(400);
      await toggle.click();
      await sleep(900);
    }
  }
  await sleep(800);

  console.error('[gif] scene 8: triage status dropdown');
  await page.evaluate(() => window.scrollTo({ top: 0, behavior: 'smooth' }));
  await sleep(900);
  const statusBtn = page.locator('.status-trigger').first();
  if (await statusBtn.count()) {
    await statusBtn.click().catch(() => {});
    await sleep(1500);
    await page.keyboard.press('Escape').catch(() => {});
    await sleep(500);
  }

  console.error('[gif] scene 9: debug call graph (final visual)');
  await page.goto(URL_BASE + '/debug/call-graph');
  await page.waitForSelector('text=Project scope', { timeout: 15_000 }).catch(() => {});
  await sleep(3500);
}

async function convertWebmToGif(webm, gifOut) {
  const palette = '/tmp/nyx-demo-palette.png';
  console.error('[gif] generating palette');
  execFileSync('ffmpeg', [
    '-y', '-ss', '1.0', '-i', webm,
    '-vf', 'fps=15,scale=1440:-1:flags=lanczos,palettegen',
    palette,
  ], { stdio: 'inherit' });
  console.error('[gif] palette → gif');
  execFileSync('ffmpeg', [
    '-y', '-ss', '1.0', '-i', webm, '-i', palette,
    '-lavfi', 'fps=15,scale=1440:-1:flags=lanczos [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle',
    gifOut,
  ], { stdio: 'inherit' });
}

// Frame phase ----------------------------------------------------------------

const FRAMED_PNGS = [
  'docs/serve-overview.png',
  'docs/serve-findings-list.png',
  'docs/serve-finding-detail.png',
  'docs/serve-triage.png',
  'docs/serve-explorer.png',
  'docs/serve-scans.png',
  'docs/serve-scan-detail.png',
  'docs/serve-rules.png',
  'docs/serve-config.png',
];

function applyFrames() {
  const paths = FRAMED_PNGS.map((p) => join(OUT_DIR, p)).filter((p) => existsSync(p));
  if (paths.length === 0) return;
  console.error(`[frame] applying purple gradient frame to ${paths.length} pngs`);
  execFileSync('python3', [FRAMER, ...paths], { stdio: 'inherit' });
  // Mirror the framed serve-overview.png to the top-level path the
  // README links.  All other top-level pngs are unused per a grep
  // across docs/* and README.md, so we don't generate them.
  const src = join(OUT_DIR, 'docs/serve-overview.png');
  const dst = join(OUT_DIR, 'overview.png');
  if (existsSync(src)) {
    copyFileSync(src, dst);
    console.error(`[frame] mirrored serve-overview.png → overview.png`);
  }
}

// Main -----------------------------------------------------------------------

async function main() {
  await waitForServer();

  console.error('[setup] writing v1 demo to', SCAN_ROOT);
  writeDemo('v1');

  const browser = await chromium.launch({ headless: true });

  try {
    if (wantGif) {
      const videoDir = '/tmp/nyx-demo-video';
      if (existsSync(videoDir)) rmSync(videoDir, { recursive: true });
      mkdirSync(videoDir, { recursive: true });

      const ctx = await browser.newContext({
        viewport: VIEW,
        colorScheme: COLOR_SCHEME,
        recordVideo: { dir: videoDir, size: VIEW },
      });
      await ctx.addInitScript(() => {
        try { localStorage.setItem('theme', 'light'); } catch {}
      });
      const page = await ctx.newPage();
      await captureGifFrames(page);
      await page.close();
      await ctx.close();

      const fs = await import('node:fs');
      const files = fs.readdirSync(videoDir).filter((f) => f.endsWith('.webm'));
      if (files.length === 0) throw new Error('no webm captured');
      await convertWebmToGif(join(videoDir, files[0]), join(OUT_DIR, 'demo.gif'));
    } else if (wantStills) {
      // --stills only: GIF didn't run, so we drive scan #1 ourselves.
      console.error('[setup] running scan #1 (v1) via API');
      const token = await csrfToken();
      const before = await currentScanId();
      await startScanViaApi(token);
      await waitForScanComplete(before);
    }

    if (wantStills) {
      const ctx = await browser.newContext({ viewport: VIEW, colorScheme: COLOR_SCHEME });
      await ctx.addInitScript(() => {
        try { localStorage.setItem('theme', 'light'); } catch {}
      });
      const page = await ctx.newPage();

      // Phase 1: capture pages that benefit from many findings.
      await captureStillsAfterScan1(page);

      // Patch demo to v2 + run scan #2 silently to populate the
      // trend chart with two data points (second one smaller).
      console.error('[setup] patching demo to v2 + running scan #2 via API');
      writeDemo('v2');
      const token = await csrfToken();
      const before = await currentScanId();
      await startScanViaApi(token);
      await waitForScanComplete(before);

      // Phase 2: capture pages whose value depends on the trend or
      // are independent of the scan history.
      await captureStillsAfterScan2(page);

      await ctx.close();

      // Frame phase — composite the brand purple gradient around
      // every captured PNG, then mirror serve-overview.png to the
      // top-level path the README references.
      applyFrames();
    }
  } finally {
    await browser.close();
  }

  console.error('done');
}

main().catch((e) => {
  console.error('FAIL:', e);
  process.exit(1);
});
