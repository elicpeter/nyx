# scripts

Local helpers for repo-wide checks and a couple of one-off tools.

| Script                   | What it does                                                                                  |
| ------------------------ | --------------------------------------------------------------------------------------------- |
| `fix.sh`                 | Apply all auto-fixes (clippy, fmt, eslint, prettier), then run tests.                         |
| `check.sh`               | Verify only (no fixes). Mirrors the GitHub Actions CI workflow.                               |
| `cached-cargo-test.sh`   | Wrap `cargo test` with a source-hash cache; concurrent invocations of the same args share one run. |
| `capture-screenshots.mjs`| Capture the README stills and demo GIF from a running `nyx serve`. Needs Playwright and ffmpeg. |

Fixers stream their output (so you can see what changed); tests run quietly and
only show output if they fail. Both scripts print a green/red summary at the end
and exit non-zero if any step failed.

## Usage

```bash
./scripts/fix.sh                # fix everything + run tests
./scripts/fix.sh --no-tests     # just apply fixes
./scripts/fix.sh --rust-only    # skip frontend
./scripts/fix.sh --frontend-only

./scripts/check.sh              # verify everything (CI-equivalent)
./scripts/check.sh --rust-only
```

Scripts can be run from any directory; they resolve the repo root from their
own location.

## Cached cargo test

Wraps `cargo test`. The first run executes normally and records its output
keyed by a hash of the source tree. Later runs with the same args and an
unchanged tree return the cached output. Concurrent callers share a single
cargo run via a mkdir lock.

```bash
./scripts/cached-cargo-test.sh --lib
./scripts/cached-cargo-test.sh --tests
FORCE_CARGO=1 ./scripts/cached-cargo-test.sh --lib   # bypass cache
```

Use it for full-suite invocations. Narrow per-test runs (`cargo test
some_function`) are fast on their own and just clutter the cache.

## Capture screenshots

Regenerates `assets/screenshots/*.png` and `assets/screenshots/demo.gif` for
the README. Requires Playwright and ffmpeg on PATH, plus a running `nyx
serve` on `$NYX_URL` (default `http://127.0.0.1:9876`). The served scan root
must have no prior scans. The GIF storyboard starts in the empty state and
triggers a fresh scan through the UI.

```bash
node scripts/capture-screenshots.mjs --stills   # only PNGs
node scripts/capture-screenshots.mjs --gif      # only the GIF
node scripts/capture-screenshots.mjs --all      # both
```
