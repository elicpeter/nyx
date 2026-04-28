#!/usr/bin/env node
/**
 * Capture stills + a demo GIF of the Nyx dashboard for the README.
 *
 * Prerequisites (script asserts each before starting):
 *   - playwright installed (npx playwright)
 *   - ffmpeg on PATH (palette-based GIF conversion)
 *   - nyx serve running on $NYX_URL (default http://127.0.0.1:9876)
 *   - the served scan root has *no prior scans* — the GIF storyboard
 *     deliberately starts in the empty state and triggers a fresh
 *     scan via the UI's "Start Scan" modal.
 *
 * Usage:
 *   node scripts/capture-screenshots.mjs --stills        # only PNGs
 *   node scripts/capture-screenshots.mjs --gif           # only the GIF
 *   node scripts/capture-screenshots.mjs --all           # both
 *
 * Output:
 *   assets/screenshots/overview.png
 *   assets/screenshots/docs/serve-overview.png
 *   assets/screenshots/finding-detail.png
 *   assets/screenshots/triage.png
 *   assets/screenshots/demo.gif
 */
import { chromium } from 'playwright';
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import process from 'node:process';

const URL_BASE  = process.env.NYX_URL  || 'http://127.0.0.1:9876';
const SCAN_ROOT = process.env.SCAN_ROOT || '/Users/elipeter/oss/ripgrep';
const OUT_DIR   = process.env.OUT_DIR  || '/Users/elipeter/nyx/assets/screenshots';
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

// Wait helpers ---------------------------------------------------------------

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function fetchJson(path) {
  const res = await fetch(URL_BASE + path);
  if (!res.ok) throw new Error(`${path}: ${res.status}`);
  return res.json();
}

async function csrfToken() {
  const r = await fetch(URL_BASE + '/api/session');
  const data = await r.json();
  return data.csrf_token;
}

async function waitForServer() {
  for (let i = 0; i < 30; i++) {
    try {
      await fetchJson('/api/health');
      return;
    } catch {
      await sleep(250);
    }
  }
  throw new Error(`nyx serve not reachable at ${URL_BASE}, start it first`);
}

async function waitForScanComplete(timeoutMs = 60_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const overview = await fetchJson('/api/overview').catch(() => null);
    if (overview?.latest_scan_id && overview.state !== 'empty') return overview;
    await sleep(500);
  }
  throw new Error('scan did not complete within deadline');
}

// Storyboard -----------------------------------------------------------------

async function captureStills(page) {
  console.error('[stills] empty overview');
  await page.goto(URL_BASE + '/');
  await page.waitForSelector('text=Run your first scan', { timeout: 10_000 });
  await page.screenshot({ path: join(OUT_DIR, 'docs/empty-overview.png') });

  console.error('[stills] triggering scan via Start Scan modal');
  await page.click('button:has-text("Start Scan")');
  await page.waitForSelector('text=Start New Scan');
  // Modal pre-fills scan root from /api/health.scan_root.  We set it
  // from outside (via NYX_SCAN_ROOT in the serve invocation) so we
  // can leave the field as default.
  await page.click('.scan-modal button.btn-primary');
  // Tolerate either: nav to /scans (newer build) or stays on /
  await page.waitForLoadState('domcontentloaded').catch(() => {});

  console.error('[stills] waiting for scan to complete');
  await waitForScanComplete();

  console.error('[stills] populated overview');
  await page.goto(URL_BASE + '/');
  await page.waitForSelector('.health-score-card, [class*="health"]', { timeout: 10_000 }).catch(() => {});
  await sleep(1000); // let charts animate in
  await page.screenshot({ path: join(OUT_DIR, 'overview.png') });
  await page.screenshot({ path: join(OUT_DIR, 'docs/serve-overview.png') });

  console.error('[stills] finding detail');
  await page.goto(URL_BASE + '/findings');
  // Click the first row with a HIGH or MEDIUM severity badge.
  const firstRow = page.locator('tbody tr, [role="row"]').first();
  await firstRow.click();
  await page.waitForURL(/\/findings\/\d+/, { timeout: 10_000 });
  await sleep(1500); // flow visualiser animation
  await page.screenshot({ path: join(OUT_DIR, 'finding-detail.png') });

  console.error('[stills] triage page');
  await page.goto(URL_BASE + '/triage');
  await sleep(800);
  await page.screenshot({ path: join(OUT_DIR, 'triage.png') });
}

async function captureGifFrames(page, framesDir) {
  // Driver records video; we extract frames via ffmpeg afterwards.
  // Playwright's per-context video gives us a webm of the whole
  // session at viewport size.
  console.error('[gif] scene 1: empty overview');
  await page.goto(URL_BASE + '/');
  await page.waitForSelector('text=Run your first scan');
  await sleep(2000);

  console.error('[gif] scene 2-3: trigger scan, wait for completion');
  await page.click('button:has-text("Start Scan")');
  await page.waitForSelector('text=Start New Scan');
  await sleep(800);
  await page.click('.scan-modal button.btn-primary');
  await page.waitForURL('**/scans');
  await waitForScanComplete();

  console.error('[gif] scene 4: navigate to overview and hover Health');
  await page.goto(URL_BASE + '/');
  await sleep(2000);
  // Best-effort: hover the Health card if we can locate it.
  const healthCard = page.locator('text=/Health/i').first();
  if (await healthCard.count()) {
    await healthCard.hover();
  }
  await sleep(2000);

  console.error('[gif] scene 5: top files card');
  await page.evaluate(() => window.scrollBy(0, 400));
  await sleep(1500);

  console.error('[gif] scene 6-7: drill into a finding');
  await page.goto(URL_BASE + '/findings');
  await sleep(800);
  const firstRow = page.locator('tbody tr, [role="row"]').first();
  await firstRow.click();
  await page.waitForURL(/\/findings\/\d+/);
  await sleep(3500);

  console.error('[gif] scene 8: triage dropdown');
  const triageSelector = page.locator('select, [role="combobox"]').first();
  if (await triageSelector.count()) {
    await triageSelector.click().catch(() => {});
    await sleep(800);
  }
  await sleep(1500);

  console.error('[gif] scene 9-10: back to overview');
  await page.goto(URL_BASE + '/');
  await sleep(2500);
}

async function convertWebmToGif(webm, gifOut) {
  const palette = '/tmp/nyx-demo-palette.png';
  console.error('[gif] generating palette');
  execFileSync('ffmpeg', [
    '-y', '-i', webm,
    '-vf', 'fps=15,scale=1440:-1:flags=lanczos,palettegen',
    palette,
  ], { stdio: 'inherit' });
  console.error('[gif] palette → gif');
  execFileSync('ffmpeg', [
    '-y', '-i', webm, '-i', palette,
    '-lavfi', 'fps=15,scale=1440:-1:flags=lanczos [x]; [x][1:v] paletteuse=dither=bayer:bayer_scale=5:diff_mode=rectangle',
    gifOut,
  ], { stdio: 'inherit' });
}

// Main -----------------------------------------------------------------------

async function main() {
  await waitForServer();

  const browser = await chromium.launch({ headless: true });
  try {
    if (wantStills) {
      const ctx = await browser.newContext({ viewport: VIEW, colorScheme: COLOR_SCHEME });
      // Pin theme via localStorage so the React theme context picks
      // it up on first render rather than chasing the system default.
      await ctx.addInitScript(() => {
        try { localStorage.setItem('theme', 'light'); } catch {}
      });
      const page = await ctx.newPage();
      await captureStills(page);
      await ctx.close();
    }

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
      await captureGifFrames(page, videoDir);
      await page.close();
      await ctx.close();
      // Find the recorded webm.
      const fs = await import('node:fs');
      const files = fs.readdirSync(videoDir).filter((f) => f.endsWith('.webm'));
      if (files.length === 0) throw new Error('no webm captured');
      const webm = join(videoDir, files[0]);
      await convertWebmToGif(webm, join(OUT_DIR, 'demo.gif'));
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
