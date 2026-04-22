# Nyx 0.5.0 Pre-Release Plan

This plan closes the findings from the 0.5.0 release-readiness audit. It is
organized as ten self-contained phases, each sized to fit comfortably in a
single Claude Code session. Every phase restates the project context so it
can be handed to a fresh session with the prompt:

> "Implement Phase N from PRE_RELEASE_PLAN.md"

and have everything needed to execute without reading the audit.

## Phase summary

| Phase | Title                                         | Blocks release | Est. session size |
|-------|-----------------------------------------------|----------------|-------------------|
| 0     | Release-engineering unblock                   | Yes            | 30–60 min         |
| 1     | Server / UI security hardening                | Yes            | 1 session (full)  |
| 2a    | Engine correctness — must-fix                 | Yes            | 1 session         |
| 2b    | Engine correctness — precision fallbacks      | Yes            | 1 session         |
| 2c    | Engine correctness — optional polish          | No             | ½ session         |
| 3     | Documentation honesty                         | Yes            | ½ session         |
| 4a    | Robustness integration tests                  | Yes            | 1 session         |
| 4b    | Precision coverage (SCC + FP guard fixtures)  | Yes            | 1 session         |
| 5     | Hot-path `.unwrap()` cleanup                  | Yes (partial)  | ½–1 session       |
| 6     | Release tagging and publish                   | Yes (final)    | ½ session         |

Recommended order: 0 first. Then 1, 2a, 2b, 3, 4a, 4b, 5 in any order that
suits staffing (they are mostly independent once 0 is done; 4a/4b depend on
fixes from 1/2a/2b landing first so tests exercise them). 2c can be done
any time or deferred post-release. 6 last, after everything else is green.

**Deferred (not in this plan, safe for post-release):** submodule extraction
of `cfg.rs` and `taint/ssa_transfer.rs`, macOS/Windows CI jobs, legacy
`FuncSummary` path removal, GitHub issue/PR templates, CODEOWNERS, SARIF
schema-conformance tests, Laravel ORM modeling for PHP, Rust match-arm
guard support, full project-wide `.unwrap()` audit.

---

## Shared project context

**Every phase below re-inlines this block. Skip down to the phase you want.**

Nyx is a multi-language static security scanner written in Rust (target: Rust
2024 edition, builds on Rust 1.85+). The repo is at `/Users/elipeter/nyx`.
The current release branch is `release/0.5.0`. The default branch is `master`.

The binary is `nyx`; the crate is `nyx-scanner`. License is GPL-3.0-or-later.

Core architecture:
- Tree-sitter frontend across 10 languages (JS, TS, Python, Go, Java, Ruby,
  PHP, Rust, C, C++).
- Per-file AST → CFG (petgraph) → SSA IR → taint analysis with `Cap` bitflags.
- Two-pass scan: pass 1 extracts `FuncSummary` + `SsaFuncSummary` per file and
  persists to SQLite (via r2d2 pool); pass 2 runs taint with a `GlobalSummaries`
  merged view.
- Call graph (`src/callgraph.rs`) drives SCC-based topo batching in pass 2.
- Optional local web UI (axum, default feature `serve`) with a React frontend.
- Optional SMT solving via the `smt` Cargo feature (gates on Z3).

Key source files:
- `src/cfg.rs` — AST→CFG construction (~9k lines)
- `src/ssa/lower.rs` — Cytron phi insertion + SSA lowering
- `src/taint/ssa_transfer.rs` — SSA-level taint transfer (~7.5k lines)
- `src/taint/domain.rs` — `VarTaint`, `SmallBitSet`, `PredicateSummary`
- `src/taint/path_state.rs` — predicate classification
- `src/commands/scan.rs` — scan orchestration (both scan paths)
- `src/database.rs` — SQLite layer, incremental indexing
- `src/callgraph.rs` — call graph + SCC analysis
- `src/summary/` — `FuncSummary` / `SsaFuncSummary` types
- `src/labels/` — per-language source/sanitizer/sink rules
- `src/server/` — axum HTTP server (only compiled with `serve` feature)
- `frontend/` — React UI, served as static assets
- `src/walk.rs` — filesystem walker
- `src/output.rs` — JSON/SARIF serialization

Tests live in `tests/` (integration) and inline `#[test]` blocks in `src/`.
Fixtures live in `tests/fixtures/`. Expectations are `.expect.json` per
fixture. Benchmark corpus is `tests/benchmark/ground_truth.json`.

CI runs on Linux only (`.github/workflows/ci.yml`). Release artifacts for
Linux/macOS/Windows are produced by `.github/workflows/release-build.yml`.
Supply-chain policy is declared in `deny.toml` (cargo-deny).

**When in doubt about any engine invariant, prefer the SSA-based path over
legacy fallback.** MEMORY.md documents the architecture in detail.

---

## Phase 0 — Release-engineering unblock

**Status:** Not started
**Estimated effort:** 30–60 minutes
**Blocks release:** Yes
**Depends on:** Nothing

### Project context

(See "Shared project context" at the top of this document.)

### Why this phase exists

Three supply-chain / release-hygiene defects currently prevent a credible
0.5.0 tag:

1. `deny.toml` fails to parse under current cargo-deny. The CI
   license/advisory gate is silently not running. Verified with
   `cargo deny check` on cargo-deny 0.18.3 — it errors with
   `error: expected a <bare-gnu-license>` on lines containing
   `"GPL-3.0-only"`, `"GPL-3.0-or-later"`, `"GPL-2.0-or-later"`,
   `"LGPL-3.0-only"`, `"LGPL-3.0-or-later"`. cargo-deny's license grammar
   rejects the suffixed SPDX forms in favor of bare names.
2. `Cargo.toml` depends on `dashmap = "7.0.0-rc2"`. Shipping a public release
   against an RC of a concurrent map is a supply-chain red flag and will be
   caught by any downstream `cargo audit`.
3. `SECURITY.md` "Supported Versions" table still lists 0.4.x as latest.
   Needs updating so users know 0.5.x is the current line.

(`CHANGELOG.md` also still has everything under `## [Unreleased]`. That gets
fixed in Phase 6 at tag time, not now.)

### Files you will touch

- `deny.toml`
- `Cargo.toml`
- `Cargo.lock` (regenerated, not hand-edited)
- `SECURITY.md`

### Files you MUST NOT touch

- Anything under `src/`
- Anything under `tests/`
- `CHANGELOG.md` (that is Phase 6)

### Tasks

1. **Fix `deny.toml`.** In the `[licenses] allow = [...]` array, remove
   suffixed SPDX identifiers and keep only bare forms:
   - Remove `"LGPL-3.0-only"` (keep existing `"LGPL-3.0"`)
   - Remove `"LGPL-3.0-or-later"`
   - Remove `"GPL-3.0-only"` (keep existing `"GPL-3.0"`)
   - Remove `"GPL-3.0-or-later"`
   - Replace `"GPL-2.0-or-later"` with `"GPL-2.0"`

   If any bare form is missing, add it. Do not remove any other license
   identifiers.

2. **Downgrade `dashmap`.** In `Cargo.toml`, change `dashmap = "7.0.0-rc2"` to
   the latest stable `6.x` release. Verify the version exists on crates.io.
   Regenerate `Cargo.lock` via `cargo build` (or `cargo update -p dashmap`).
   Do not touch other dependency versions.

   If the dashmap 7 API is needed somewhere (unlikely for 6→7 in a concurrent
   map crate), fix call sites minimally. Do not rewrite usage.

3. **Update `SECURITY.md`.** The "Supported Versions" section currently shows
   `0.4.x` as the latest supported line. Add a `0.5.x` row marked as current
   and demote `0.4.x` to "critical fixes only" or equivalent. Keep wording
   consistent with the existing table.

### Verification

```bash
cargo deny check                      # must exit 0
cargo build --all-features            # must succeed
cargo test --workspace                # must pass
cargo tree --depth 1 | grep -Ei 'alpha|beta|rc[0-9]'  # must return no lines
```

### Definition of done

- [ ] `cargo deny check` exits 0 locally.
- [ ] `cargo build --all-features` and `cargo test --workspace` both pass.
- [ ] `cargo tree --depth 1` contains no pre-release version strings.
- [ ] `SECURITY.md` lists 0.5.x as a current supported line.
- [ ] No changes outside the four files listed in "Files you will touch".

---

## Phase 1 — Server / UI security hardening

**Status:** Not started
**Estimated effort:** 1 full session
**Blocks release:** Yes
**Depends on:** Phase 0 (so CI can verify changes)

### Project context

(See "Shared project context" at the top of this document.)

Additional context for this phase: Nyx ships a local HTTP UI behind the
`serve` Cargo feature (default on). The server is built with axum, binds to
`127.0.0.1` by default, exposes REST endpoints for config, findings, scans,
and events, and serves a compiled React frontend from
`src/server/assets/dist/`. The frontend is built by `build.rs` from the
`frontend/` directory.

Even though the server is loopback-only, the threat model in `SECURITY.md`
explicitly includes "untrusted input to Nyx process" — i.e., a malicious repo
being scanned. Finding messages, file paths, and source snippets flow from
the analyzer to the UI, so XSS and header hygiene matter.

### Why this phase exists

Seven concrete issues found in the security audit:

1. **RwLock poisoning.** `src/server/routes/config.rs` and possibly others
   call `.read().unwrap()` / `.write().unwrap()` on a shared `RwLock`. A
   single panic while a lock is held permanently poisons it and every
   subsequent request to that endpoint panics. A malicious scan can brick the
   server.
2. **Missing security headers.** `src/server/app.rs` does not set
   `X-Frame-Options`, `Content-Security-Policy`, `X-Content-Type-Options`, or
   `Referrer-Policy`. Even on loopback, absence weakens defense in depth.
3. **Symlink containment.** `src/walk.rs:139-145` only validates path
   containment when `follow_symlinks=true`. When `follow=false` (the default),
   a pre-existing symlink in the scan tree can surface paths outside the
   scan root in certain walker paths. A scanner must canonicalize
   unconditionally.
4. **Unbounded request bodies.** No `DefaultBodyLimit` layer on the router.
   A rogue client could send a multi-GB body to `/api/config` and OOM.
5. **Finding-message XSS surface.** Finding `message` / `path` / snippet
   fields flow into the UI. The frontend escapes code lines in
   `CodeViewer.tsx`, but there is no server-side guarantee that `message`
   and `path` are safe to render, and the full frontend has not been audited
   for raw-HTML insertion.
6. **SARIF leaks absolute paths.** `src/output.rs:119-122` falls back to the
   absolute path when `strip_prefix(scan_root)` fails. That leaks home dirs.
7. **Test-only SQL helper ships in release binary.** `src/database.rs:422`
   has a test helper that formats a table name into a SQL string. Gate it.

### Files you will touch

- `src/server/routes/config.rs` (and any other route file with RwLock
  `.unwrap()` calls — grep first)
- `src/server/app.rs` (or wherever the Router is built)
- `src/server/routes/events.rs` (known `.unwrap()` at line 19)
- `src/walk.rs`
- `src/output.rs`
- `src/database.rs` (cfg-gate for test helper)
- `frontend/src/**/*.tsx` (XSS audit only; likely no edits needed)
- `src/server/models.rs` (server-side escaping if needed)
- `tests/` — new tests listed below

### Files you MUST NOT touch

- Engine code under `src/cfg.rs`, `src/ssa/`, `src/taint/`, `src/symex/`,
  `src/abstract_interp/`, `src/constraint/`, `src/summary/`,
  `src/callgraph.rs`
- `src/commands/scan.rs` (unless a test requires it)
- Anything under `tests/fixtures/`

### Tasks

1. **Eliminate RwLock `.unwrap()`.** Grep the entire `src/server/` tree for
   `.read().unwrap()` and `.write().unwrap()` on any state lock. For each:
   replace with a
   `.map_err(|_| (StatusCode::INTERNAL_SERVER_ERROR, "config lock unavailable"))?`
   (or an `IntoResponse`-returning helper). Alternatively, if you want to
   remove the poisoning category entirely, switch the underlying lock to
   `parking_lot::RwLock`, which cannot be poisoned. Pick one approach and
   apply it consistently. Do not mix.

   Known starting points:
   - `src/server/routes/config.rs:54-527` (~15+ sites)
   - `src/server/routes/events.rs:19` (check
     `unwrap_or_default()` is the intended fallback; if not, log and
     return `None`)

2. **Add security-header middleware** in the router build in
   `src/server/app.rs`. Use `tower_http::set_header::SetResponseHeaderLayer`.
   Add:
   - `X-Frame-Options: DENY`
   - `X-Content-Type-Options: nosniff`
   - `Referrer-Policy: no-referrer`
   - `Content-Security-Policy: default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'`

   If the React build requires inline scripts, you may need `'unsafe-inline'`
   in `script-src` initially — prefer a nonce. Document the choice in a
   one-line comment above the layer.

3. **Add a body size limit.** In the same router, add
   `.layer(DefaultBodyLimit::max(50 * 1024 * 1024))`.

4. **Fix symlink containment** in `src/walk.rs:139-145`. Current code:
   ```rust
   let path_allowed = canonical_root.as_ref().is_none_or(|root| {
       if follow {
           path_stays_within_root(root, e.path()).unwrap_or(false)
       } else {
           true
       }
   });
   ```
   Change to unconditional:
   ```rust
   let path_allowed = canonical_root.as_ref().is_none_or(|root| {
       path_stays_within_root(root, e.path()).unwrap_or(false)
   });
   ```
   Add a unit test: temp dir with a symlink pointing to `/tmp/outside_root`.
   Scan with `follow_symlinks=false` and `=true`; in both cases the outside
   path must be excluded.

5. **Fix SARIF absolute-path leak** in `src/output.rs:119-122`. Replace the
   `unwrap_or_else` fallback with either (a) return an error, or (b) emit a
   deterministic token like `"<out-of-root>"` and log a warning. Do not ship
   absolute paths in SARIF.

6. **Gate the test-only SQL helper.** Wrap the function at
   `src/database.rs:422` in `#[cfg(test)]`. Verify non-test code does not
   call it first.

7. **XSS audit of frontend.** Run:
   ```bash
   rg -n 'dangerouslySetInnerHTML|innerHTML' frontend/src
   ```
   For each occurrence, confirm the input is a safe literal or already
   escaped. If any takes a value derived from a finding (`message`, `path`,
   `rule_id`, code snippets) without explicit escaping, replace with plain
   text or route through an escape helper.

   Belt-and-suspenders: in `src/server/models.rs` when building `FindingView`
   (or equivalent), consider an explicit `html_escape` pass on `message` and
   `path`. Pick one layer (frontend or backend) and document it; avoid
   double-escaping.

8. **Add a poison-recovery test.** Start the server in a test harness. Send
   a request to a config route instrumented to panic. Catch the 500. Send a
   follow-up legitimate request and assert it returns 200 (not another
   panic from a poisoned lock).

### Verification

```bash
cargo test --all-features --workspace
cargo build --release --all-features
# Start the server in one terminal:
cargo run --release --features serve -- serve --port 9700
# In another terminal:
curl -sI http://127.0.0.1:9700/ | grep -E 'X-Frame-Options|X-Content-Type|Content-Security-Policy|Referrer-Policy'
# All four headers should be present.
rg -n '\.read\(\)\.unwrap\(\)|\.write\(\)\.unwrap\(\)' src/server/  # zero
rg -n 'dangerouslySetInnerHTML|innerHTML' frontend/src              # zero or annotated
```

### Definition of done

- [ ] `cargo test --all-features --workspace` passes.
- [ ] All four security headers visible in live `curl -I`.
- [ ] Zero `.read().unwrap()` / `.write().unwrap()` on `RwLock` in
      `src/server/`.
- [ ] Symlink containment test passes with both `follow=true` and `=false`.
- [ ] SARIF output for a file outside scan root contains no absolute path.
- [ ] Poison-recovery test passes.
- [ ] `rg dangerouslySetInnerHTML` in `frontend/src` returns zero, or each
      is annotated.
- [ ] `src/database.rs:422` helper is `#[cfg(test)]`-gated.

---

## Phase 2a — Engine correctness: must-fix

**Status:** Not started
**Estimated effort:** 1 session
**Blocks release:** Yes
**Depends on:** Phase 0

### Project context

(See "Shared project context" at the top of this document.)

Additional context: Nyx's taint engine is SSA-only (legacy `TaintTransfer`
was removed in an earlier engine phase; do not resurrect it). All taint
analysis flows through `src/taint/ssa_transfer.rs` using `SsaTaintState`
over an `SsaBody` produced by `src/ssa/lower.rs`. Cross-file context comes
from `GlobalSummaries`. Pass 2 of the scan does SCC-based topo batching of
files and runs a fixed-point within each SCC batch up to
`MAX_SCC_FIXPOINT_ITERS` iterations with a hard safety cap at
`SCC_FIXPOINT_SAFETY_CAP = 64` (in `src/commands/scan.rs`).

Findings are deduplicated and ranked before output in `src/commands/scan.rs`
and `src/rank.rs`.

### Why this phase exists

Three correctness defects that a user can hit with normal code:

1. **Dedup key omits sink caps.** `src/commands/scan.rs:340-428` groups
   findings by `(path, line, severity)`. Two different sinks on the same line
   (e.g., `sink_sql(x); sink_shell(x);`) collapse to one finding. Real vulns
   are being dropped under the name "dedup."
2. **SSA phi-arity assertion is debug-only and uses `<=`.**
   `src/ssa/lower.rs:1331` — an SSA body with fewer phi operands than
   predecessors is unsound, but release builds will happily lower it.
3. **SCC safety-cap silently emits unconverged findings.**
   `src/commands/scan.rs:498` — on hitting the 64-iteration cap, findings
   are still emitted as if converged. No user signal.

### Files you will touch

- `src/commands/scan.rs`
- `src/ssa/lower.rs`
- `src/evidence.rs` (or wherever the Diag struct lives — may need a
  confidence/note field)
- `tests/fixtures/dedup/same_line_different_sinks/` (new)
- `tests/scc_convergence_tests.rs` (new test case)
- `tests/ssa_equivalence_tests.rs` (new test case) or an inline test in
  `src/ssa/lower.rs`

### Files you MUST NOT touch

- `src/taint/` — Phase 2b territory
- `src/labels/` — Phase 2b territory
- `src/database.rs` — Phase 2c / 5
- `src/server/` — Phase 1
- `frontend/`

### Tasks

#### Task 2a.1 — Dedup key includes sink caps

In `src/commands/scan.rs:340-428`, locate `deduplicate_taint_flows` (or the
equivalent grouping function). Change the grouping tuple from
`(path, line, severity)` to `(path, line, severity, sink_cap_bits)` where
`sink_cap_bits` is the `u16` returned by the resolved sink `Cap`.

Add a fixture `tests/fixtures/dedup/same_line_different_sinks/` with:
- A small Python file containing `sink_sql(x); sink_shell(x)` both on one
  line after a tainted source.
- An `.expect.json` asserting **two** findings on that line, with
  `must_not_match` guarding against regression to a single finding.

Register the fixture in the existing fixture-driven test harness (grep
`tests/integration_tests.rs` or equivalent for how other `tests/fixtures/*`
dirs are wired up).

#### Task 2a.2 — SSA phi-arity is a release assertion

In `src/ssa/lower.rs` around line 1331 (`debug_assert_phi_operand_counts`):

- Promote from `debug_assert_*!` to `assert_*!` so it runs in release.
- Change the comparison from `operands.len() <= preds.len()` to strict
  equality (`==`). An SSA body with fewer phi operands than block
  predecessors is unsound.
- Ensure the assertion message prints enough context (function name, block
  id, phi value id, observed and expected operand counts) to debug if it
  ever triggers.

Add a test in `src/ssa/lower.rs` (or `tests/ssa_equivalence_tests.rs`):
build a tiny CFG with exception edges where a catch block is the join point
of both an exception predecessor and a normal control flow predecessor.
Lower it and assert the phi at the catch block has exactly two operands.

**Do not** add a "fallback" that silently pads phi operand counts. If the
assertion fires, it is a real SSA-lowering bug to fix elsewhere.

#### Task 2a.3 — SCC cap emits tagged findings

In `src/commands/scan.rs` around line 498 (`SCC_FIXPOINT_SAFETY_CAP`):

- On cap-hit, still emit the findings computed at the cap.
- For each such finding, set `confidence = Low` (or equivalent — see
  `src/evidence.rs` or the Diag type) and append a diagnostic note:
  `"SCC did not converge within N iterations; results may be imprecise"`.
- Log a single `tracing::warn!` per batch, not per finding.

If the Diag struct does not currently support a confidence field or note
field, add one rather than overloading severity. Check whether
`Diag.evidence` already supports attached notes.

Add a test in `tests/scc_convergence_tests.rs`: construct a synthetic SCC
fixture that requires more than 64 iterations. Assert (a) findings still
return and (b) they carry the low-confidence tag / note.

### Verification

```bash
cargo test --workspace --all-features
cargo test --test scc_convergence_tests
cargo test --test ssa_equivalence_tests
cargo bench --bench scan_bench -- --save-baseline post-phase-2a
# F1 must stay within tolerance (see tests/benchmark_test.rs).

cargo build --release --all-features
# The phi-arity assertion now compiles in release; confirm no panic on
# the normal corpus run:
cargo test --release --test ssa_equivalence_tests
```

### Definition of done

- [ ] Dedup fixture: two same-line, different-sink findings both surface.
- [ ] `src/ssa/lower.rs` phi-arity is a release `assert!` with `==`.
- [ ] Exception-edge phi test passes.
- [ ] SCC cap test: findings still emit but carry a low-confidence tag
      and/or note.
- [ ] Benchmark F1 regression within allowed tolerance.
- [ ] `tests/ssa_equivalence_tests.rs` no-panic corpus still passes on all
      265+ fixtures.

---

## Phase 2b — Engine correctness: precision fallbacks

**Status:** Not started
**Estimated effort:** 1 session
**Blocks release:** Yes (well, strongly recommended)
**Depends on:** Phase 0

### Project context

(See "Shared project context" at the top of this document.)

Additional context: path-sensitive taint uses predicates (classified in
`src/taint/path_state.rs`) tracked in `SsaTaintState.predicates`, backed by
a `SmallBitSet` in `src/taint/domain.rs` (64-slot u64 bitset — silently
drops ids ≥ 64). Gated sinks (sinks whose danger depends on an argument
like the first arg of `setAttribute` being `"onclick"`) are classified in
`src/labels/mod.rs` via `classify_gated_sink` against `GATED_REGISTRY`.

### Why this phase exists

Three precision defects that silently lose soundness or precision:

1. **`SmallBitSet` silent 64-variable cliff.** `src/taint/domain.rs` —
   predicate insertions beyond id 63 are dropped with no warning, metric, or
   log. Large functions silently lose path sensitivity.
2. **Predicate classification fallback over-validates.**
   `src/taint/path_state.rs:402-450` — when target extraction fails for a
   multi-arg validator like `validate(x, limit)`, all condition vars are
   marked validated. Should fall back to `Unknown`.
3. **Gated sink "unknown activation" is treated as "not gated at all."**
   `src/labels/mod.rs` `classify_gated_sink` returns `None` when it cannot
   constant-eval the activation arg. Result: the sink is unmarked. Should
   treat as "possibly dangerous."

### Files you will touch

- `src/taint/domain.rs`
- `src/taint/path_state.rs`
- `src/taint/ssa_transfer.rs` (only to verify `ALL_ARGS` handling in
  `collect_tainted_sink_vars`)
- `src/labels/mod.rs`
- `tests/fixtures/predicate/multi_arg_validator/` (2 new fixtures)
- `tests/fixtures/gated_sinks/dynamic_activation/` (1 new fixture)

### Files you MUST NOT touch

- `src/commands/scan.rs` — Phase 2a
- `src/ssa/lower.rs` — Phase 2a
- `src/database.rs` — Phase 2c / 5
- `src/server/` — Phase 1
- `frontend/`

### Tasks

#### Task 2b.1 — `SmallBitSet` capacity observability

In `src/taint/domain.rs`, locate `SmallBitSet::insert` (around lines
28-130).

- When an id ≥ 64 is ignored, emit a `tracing::debug!` with the id and a
  stable feature tag (e.g., `target: "nyx::predicate_bitset"`) so operators
  can filter.
- Add a module-level doc comment explaining the 64-element limit and the
  implications: predicate tracking for variables beyond id 63 is dropped;
  path-sensitivity degrades gracefully to no-op rather than failing loudly.
- If a per-scan metric counter already exists in the codebase (grep
  `metrics::counter!` or similar), bump it. If not, skip — do not introduce
  a metrics framework in this phase.

No behavior change. Pure observability.

#### Task 2b.2 — Predicate classification conservative fallback

In `src/taint/path_state.rs:402-450` (`classify_condition_with_target`),
find the branch where target extraction fails for a multi-arg validator
call.

Current behavior: returns `(kind, None)`, and upstream code treats all
condition vars as validated.

Fix: when the call has >1 args and target extraction failed, return
`(PredicateKind::Unknown, None)`. This treats the validator's effect as
opaque — safer than assuming every condition var is validated.

Add two fixtures in `tests/fixtures/predicate/multi_arg_validator/`:
- `tainted_arg_validated.py`: `if validate(x, 100): sink(x)` where `x` is
  tainted. Expect the path is correctly recognized as validated (the
  target was extractable). Finding count: 0.
- `wrong_arg_validated.py`: `if validate(limit, x): sink(x)` where `x` is
  tainted and `limit` is being validated. Expect the path is **not**
  validated. Finding count: 1.

If current target-extraction logic already handles `validate(x, 100)`
correctly, keep that path working — only change the fallback behavior for
the ambiguous case.

#### Task 2b.3 — Gated-sink "unknown activation" is conservative

In `src/labels/mod.rs` `classify_gated_sink` (and its registry-lookup
pathway), when the activation-arg constant-eval returns `None`, change the
return from `None` (treat as ungated) to `Some((label, ALL_ARGS))` — the
sink is active and all argument positions are possibly dangerous.

"ALL_ARGS" means: `(0..arity).collect::<Vec<_>>()` in place of the usual
explicit payload-args slice. Downstream `collect_tainted_sink_vars` in
`src/taint/ssa_transfer.rs` must be able to handle the "all args" case
(grep to confirm).

Add one JS fixture in `tests/fixtures/gated_sinks/dynamic_activation/`:
`setAttribute(x, y)` where `x` is a tainted variable (not a string
literal), `y` is tainted. Expect: finding on the call.

### Verification

```bash
cargo test --workspace --all-features
cargo test --test integration_tests  # picks up new fixtures
cargo bench --bench scan_bench -- --save-baseline post-phase-2b
# F1 must stay within tolerance. This phase may increase true-positive
# count slightly (gated-sink conservatism); that is expected and fine.

# Verify SmallBitSet observability fires:
RUST_LOG=nyx::predicate_bitset=debug cargo test --test integration_tests 2>&1 | grep 'predicate_bitset'
# (May be empty if no test function has >64 predicates; that is fine.)
```

### Definition of done

- [ ] `SmallBitSet` emits a debug-level log when an id ≥ 64 is dropped.
- [ ] Predicate classification: both new multi-arg-validator fixtures pass.
- [ ] Gated-sink fixture: dynamic-activation `setAttribute(x, y)` produces
      a finding.
- [ ] Benchmark F1 regression within allowed tolerance.

---

## Phase 2c — Engine correctness: optional polish

**Status:** Not started
**Estimated effort:** ½ session (may defer post-release)
**Blocks release:** No
**Depends on:** Phase 0

### Project context

(See "Shared project context" at the top of this document.)

Additional context: Nyx has k=1 context-sensitive inline analysis in
`src/taint/ssa_transfer.rs`. The cache key `ArgTaintSig` encodes per-arg
cap bits but excludes source-origin identity — so two callers with
identical caps but different source origins collide, and the cached
origin-attribution is whichever caller computed first. Separately, the DB
schema version mismatch in `src/database.rs` aborts the scan instead of
offering a rebuild path.

### Why this phase exists

Two items the audit flagged as "MAY, time-permitting." Neither is a
blocker. Include them if you have slack; otherwise defer.

1. **Inline-cache key `ArgTaintSig` excludes origins.**
   `src/taint/ssa_transfer.rs:408-425` — two call sites with identical caps
   but different source origins collide. Cached origin-attribution is
   non-deterministic across callers.
2. **DB engine-version mismatch aborts scan.** `src/database.rs` — CI/CD
   pipelines die loudly rather than rebuild.

### Files you will touch

- `src/taint/ssa_transfer.rs` (doc comment or minor fix)
- `src/database.rs`
- `src/cli.rs` (if adding a flag)
- `docs/configuration.md` (doc the new behavior)

### Files you MUST NOT touch

- Anything in Phases 1, 2a, 2b, 3, 4a, 4b territory.

### Tasks

#### Task 2c.1 — Inline-cache provenance note

In `src/taint/ssa_transfer.rs:408-425` around `ArgTaintSig` and
`InlineCache`:

**Simplest fix:** add a module-level comment explaining that cached origin
attribution is non-deterministic across callers with identical caps but
different origins. Document that the engine prefers cap-based correctness
over origin-attribution stability.

**More-invasive fix (only if the simple path is not acceptable):** include
a truncated origin hash in the cache key. This increases cache misses and
memory. Measure impact on benchmark wall-clock before adopting.

Pick one. If the simple path is chosen, grep for all sites that read a
cached `InlineResult` and verify none assume origin determinism.

#### Task 2c.2 — DB engine-version auto-rebuild

In `src/database.rs` `check_engine_version` (approximately line 332):

Current behavior: abort with error.

Fix: add a `--rebuild-db` CLI flag (in `src/cli.rs`) that, when passed,
deletes and re-creates the DB on mismatch. Default remains "abort on
mismatch" so surprises are still visible.

Alternative: accept a `NYX_REBUILD_DB=1` env var. Either is fine. Document
in `docs/configuration.md` under an "Upgrading" section.

### Verification

```bash
cargo test --workspace --all-features

# Manual test of DB auto-rebuild:
cargo run --release -- scan --index on /some/dir
# Bump the engine version string in src/database.rs temporarily.
cargo run --release -- scan --index on /some/dir  # should abort
cargo run --release -- scan --index on --rebuild-db /some/dir  # should succeed
# Revert the version bump.
```

### Definition of done

- [ ] Inline-cache origin behavior is documented (or fixed with a test).
- [ ] DB engine-version mismatch has a rebuild path (flag or env var).
- [ ] `docs/configuration.md` documents the rebuild behavior.

---

## Phase 3 — Documentation honesty

**Status:** Not started
**Estimated effort:** ½ session
**Blocks release:** Yes
**Depends on:** Phases 2a/2b (so any metric updates reflect final behavior)

### Project context

(See "Shared project context" at the top of this document.)

Additional context: Nyx's documentation lives in the repo root (`README.md`,
`CHANGELOG.md`, `SECURITY.md`, `CONTRIBUTING.md`) and under `docs/`
(index, cli, configuration, detectors, installation, language-maturity,
output, quickstart, rules/). The `docs/language-maturity.md` file is the
current source of truth for per-language capability — it is unusually
honest and should be preserved. The README is less accurate in two
specific places.

### Why this phase exists

The audit identified:

1. **README contradicts itself on cross-file analysis.** `README.md:29`
   lists "Cross-file taint tracking" as a headline feature. `README.md:343`
   then correctly clarifies the implementation is "intra-procedural with
   cross-file function summaries; it does not perform full inter-procedural
   analysis." Same document, opposite impressions.
2. **C and C++ F1 numbers lack scope context.** The README implies C/C++
   are comparable to Stable tier based on F1. In reality their rule set
   ships with only 2 sanitizers and 5 sinks each — no SQL, no code
   execution, no deserialization.
3. **PHP is labeled Beta but Laravel-specific patterns are not modeled.**
4. **Benchmark metrics presented without corpus framing.** "91.1 / 99.4 /
   95.1%" reads as absolute truth. It is 262-case-corpus-specific.
5. **Advanced analysis features documented only in CHANGELOG.md.**
   Symbolic execution, constraint solving, abstract interpretation,
   context-sensitive analysis, and their env-var toggles
   (`NYX_SYMEX`, `NYX_CONSTRAINT`, `NYX_ABSTRACT_INTERP`,
   `NYX_CONTEXT_SENSITIVE`) are not in `docs/configuration.md` or
   elsewhere user-facing.
6. **"Typically scans large repositories in seconds"** (README:46) — vague
   claim with no corpus or hardware reference.

### Files you will touch

- `README.md`
- `docs/index.md`
- `docs/configuration.md`
- `docs/language-maturity.md` (only if Phase 2 moved any F1 number)
- `docs/advanced-analysis.md` (new file)

### Files you MUST NOT touch

- Source under `src/`
- Tests under `tests/`
- `CHANGELOG.md` (Phase 6)

### Tasks

1. **Fix the cross-file headline** in `README.md:29`. Replace the existing
   "Cross-file taint tracking" bullet with something like:

   > Cross-file taint via conservative function summaries — intra-procedural
   > analysis with cross-file call resolution through summarized
   > capabilities. Not full inter-procedural analysis.

   Adjust to the document's voice. The headline must be consistent with
   the detail at README:343.

2. **Add the C/C++ scope caveat.** In the README's language-support
   section, for C and C++:

   > C and C++ support currently covers command injection, buffer overflow,
   > format string, file I/O, SSRF, and basic path traversal only. SQL
   > injection, code execution, and deserialization rules are not yet
   > implemented. For comprehensive C/C++ coverage, pair Nyx with
   > clang-tidy, the Clang Static Analyzer, or Infer.

3. **Add the PHP Laravel caveat.** In the PHP entry:

   > PHP support is production-ready for plain PHP. Laravel-specific ORM,
   > validation, and middleware patterns are not comprehensively modeled.
   > Laravel codebases should pair Nyx with Psalm or PHPStan.

4. **Qualify benchmark metrics.** Wherever numbers like "91.1 / 99.4 /
   95.1%" appear, append " on our 262-case benchmark corpus
   (`tests/benchmark/ground_truth.json`)." If the corpus size changed in
   recent commits, update (count entries in ground_truth.json).

5. **Replace the vague speed claim** at README:46. Either cite a specific
   measurement (from `tests/benchmark/RESULTS.md` if available) or drop
   the claim. Do not invent numbers.

6. **Create `docs/advanced-analysis.md`** with sections for:

   - **Abstract interpretation** — interval + string prefix/suffix
     domains; env var `NYX_ABSTRACT_INTERP=0` disables.
   - **Context-sensitive analysis** — k=1 inline analysis with caching;
     env var `NYX_CONTEXT_SENSITIVE=0` disables.
   - **Symbolic execution** — witness generation for taint flows; env var
     disables (verify actual env var name in `src/symex/mod.rs`).
   - **Constraint solving** — path constraint propagation with optional
     SMT (via `smt` Cargo feature); env var `NYX_CONSTRAINT=0` disables.

   One paragraph per feature: what it does, why it helps, how to turn it
   off, known limitations. Link to relevant source modules.

7. **Link the new doc from `docs/index.md`** under an "Advanced" heading.

8. **Update `docs/language-maturity.md`** only if Phase 2 changed any
   per-language F1 number. Re-run `cargo test --test benchmark_test
   --ignored -- --nocapture` and update if the numbers shifted. Otherwise
   leave it alone — it is already honest.

### Verification

```bash
# README internal consistency:
rg -n 'cross-file|interprocedural|inter-procedural' README.md
# Headline and detail must agree.

# Every env var in CHANGELOG must appear in user-facing docs:
for var in NYX_ABSTRACT_INTERP NYX_CONTEXT_SENSITIVE NYX_SYMEX NYX_CONSTRAINT; do
  echo "=== $var ==="
  rg -n "$var" docs/ README.md
done
# Each should return at least one hit outside CHANGELOG.md.

# Link check:
rg -n 'docs/advanced-analysis' docs/index.md  # must return a hit
```

### Definition of done

- [ ] README headline on cross-file is consistent with the detail
      paragraph.
- [ ] C, C++, and PHP blocks in README each carry the scope caveat.
- [ ] Benchmark numbers framed with "on our N-case corpus."
- [ ] Vague "scans in seconds" claim is cited or removed.
- [ ] `docs/advanced-analysis.md` exists with one section per feature.
- [ ] `docs/index.md` links to the new page.
- [ ] Every CHANGELOG env var appears in `docs/configuration.md` or
      `docs/advanced-analysis.md`.
- [ ] `docs/language-maturity.md` reflects current benchmark numbers.

---

## Phase 4a — Robustness integration tests

**Status:** Not started
**Estimated effort:** 1 session
**Blocks release:** Yes
**Depends on:** Phase 1 (symlink fix), Phase 2a (SCC cap behavior)

### Project context

(See "Shared project context" at the top of this document.)

Additional test-suite context: integration tests live in `tests/`. Fixture
tests load from `tests/fixtures/`. The expectations schema supports
`expected`, `must_match: bool`, `must_not_match`, `max_count`.

CLI testing in this project uses `assert_cmd` + `predicates` (already in
dev-dependencies). Tempdir helpers use `tempfile` (also in dev-deps).

### Why this phase exists

The audit identified categorically-missing test classes for user-facing
robustness:

1. **No panic-recovery test.** Config flag `enable_panic_recovery = true`
   exists; behavior unverified.
2. **No concurrent-scan test.** `worker_threads > 1` is production default;
   thread-safety of shared state is untested.
3. **No CLI argument validation tests.** `--config <missing>`,
   `--output <unwritable>`, `--max-file-size-mb -1`, conflicting flags —
   all untested.
4. **No malformed-config tests.** Invalid TOML/YAML should produce clear
   errors; untested.
5. **No DB-corruption recovery test.** Index mode can be fed a corrupted
   SQLite file; behavior undefined.
6. **No symlink-loop test.** Infinite loop potential.

### Files you will touch

- `tests/panic_recovery_tests.rs` (new)
- `tests/concurrent_scan_tests.rs` (new)
- `tests/cli_validation_tests.rs` (new)
- `tests/malformed_config_tests.rs` (new)
- `tests/db_corruption_tests.rs` (new)
- `tests/hostile_input_tests.rs` (extend)
- `src/ast.rs` (tiny `#[cfg(test)]` panic-injection hook, if chosen)

### Files you MUST NOT touch

- Non-test source under `src/` (except a tiny `#[cfg(test)]` hook).
- Existing fixtures under `tests/fixtures/`.
- `tests/scc_convergence_tests.rs` — that's Phase 4b.

### Tasks

#### Task 4a.1 — Panic-recovery test

Create `tests/panic_recovery_tests.rs`. Injection strategy options:
- (a) tiny `#[cfg(test)]`-gated hook in `src/ast.rs`:
  `if path.ends_with("__PANIC__.py") { panic!("injected"); }`
- (b) a Cargo feature `test-panic-injection` for cleaner isolation.

Test body:
- Temp dir with `normal.py` (clean) and `__PANIC__.py` (triggers injected
  panic).
- Run `scan_filesystem_with_observer` with `enable_panic_recovery = true`.
- Assert scan completes without propagating the panic.
- Assert findings from `normal.py` still return.
- Run again with `enable_panic_recovery = false`; assert the panic
  surfaces (or errors cleanly — assert current behavior explicitly).

If `enable_panic_recovery` is not yet honored config, either wire it up in
this phase or assert current default-safe behavior and file a follow-up.

#### Task 4a.2 — Concurrent-scan safety test

Create `tests/concurrent_scan_tests.rs`:
- Temp dir with ~10 source files across languages.
- Spawn two threads via `std::thread::spawn`, each running a scan over
  the same directory.
- Join both. Assert both succeed and produce identical (sorted) finding
  sets.

If the two scans must not share a DB file, document why. If they can,
assert the DB is not corrupted (reopen and query).

#### Task 4a.3 — CLI argument validation tests

Create `tests/cli_validation_tests.rs` using `assert_cmd` + `predicates`.
Minimum cases:

1. `nyx scan --config /nonexistent/file.toml /tmp/scan-dir` exits nonzero
   with "config" and the path in stderr.
2. `nyx scan --output /unwritable/dir/out.json /tmp/scan-dir` (tempdir +
   chmod to simulate) exits nonzero.
3. `nyx scan --max-file-size-mb 0 /tmp/scan-dir` exits nonzero (if 0 is
   disallowed; if allowed, test a negative value).
4. `nyx scan --severity BOGUS /tmp/scan-dir` exits nonzero with valid
   severities listed.
5. `nyx scan --format unknown /tmp/scan-dir` exits nonzero.

Adapt arg names to match `src/cli.rs`.

#### Task 4a.4 — Malformed config tests

Create `tests/malformed_config_tests.rs`. Write malformed TOML to a
tempdir, run `nyx scan --config <that> <scan-dir>`:

1. Syntactically invalid TOML (`foo = [[`). Must not panic; exit nonzero
   with a parse-error message referencing the file.
2. Valid TOML but wrong type (`worker_threads = "auto"` when int expected).
   Must exit nonzero with a type-mismatch message.
3. Unknown top-level section. Assert current behavior (warn-and-continue
   or error) explicitly.

#### Task 4a.5 — DB-corruption recovery test

Create `tests/db_corruption_tests.rs`:

1. Temp dir with a few source files.
2. Run `scan_with_index_parallel` to populate `.nyx/` DB.
3. Corrupt the main SQLite file (write random bytes to the first 100
   bytes, or truncate to 0).
4. Run the scan again.
5. Assert: either clear error + nonzero exit, or auto-rebuild + success.
   Whichever is current behavior, assert it.

If Phase 2c Task 2c.2 added auto-rebuild, test that path.

#### Task 4a.6 — Symlink-loop test

Extend `tests/hostile_input_tests.rs` with `symlink_loop_does_not_hang`:

- Tempdir with `a/` and symlink `a/self -> ../a` (self-referencing).
- Run `nyx scan` with `follow_symlinks = true`.
- Assert scan completes within 10 seconds (use `recv_timeout` or
  equivalent).

If `follow_symlinks = false` is default, test both cases.

### Verification

```bash
cargo test --test panic_recovery_tests
cargo test --test concurrent_scan_tests
cargo test --test cli_validation_tests
cargo test --test malformed_config_tests
cargo test --test db_corruption_tests
cargo test --test hostile_input_tests symlink_loop
cargo test --workspace --all-features
```

### Definition of done

- [ ] All five new test files exist and pass.
- [ ] Symlink-loop test completes within a 10-second timeout.
- [ ] Full `cargo test --workspace --all-features` passes.

---

## Phase 4b — Precision coverage (SCC + FP guard fixtures)

**Status:** Not started
**Estimated effort:** 1 session
**Blocks release:** Yes
**Depends on:** Phase 2a (SCC behavior), Phase 2b (fallback behavior)

### Project context

(See "Shared project context" at the top of this document.)

Additional context: FP-guard fixtures are `.expect.json` files that assert
specific rule IDs must **not** fire at specific locations. They are the
primary mechanism protecting against false-positive regressions as rules
evolve. Today only ~29% of fixtures use `must_match: false` or
`must_not_match` — target for release is meaningfully higher.

`tests/scc_convergence_tests.rs` contains existing convergence tests but
with loose iteration bounds (e.g., `iters >= 4 && iters < 32`). These
don't catch regressions within that wide band.

### Why this phase exists

Two specific test-suite precision gaps:

1. **SCC tests assert `iters >= 4 && iters < 32`** — a regression to
   20-iter convergence would still pass. Also: "finding exists"
   assertions pass even if FP count doubles.
2. **FP guard fixture ratio is ~29%.** Need ~20 new fixtures covering the
   most likely FP categories.

### Files you will touch

- `tests/scc_convergence_tests.rs`
- `tests/fixtures/fp_guards/` (new directory tree with ~20 fixtures)
- Existing `.expect.json` files (optional tightening)

### Files you MUST NOT touch

- Non-test source under `src/`.
- New integration test files from Phase 4a.

### Tasks

#### Task 4b.1 — Tighten SCC test assertions

In `tests/scc_convergence_tests.rs`, locate existing bounds like
`assert!(iters >= 4 && iters < 32)`.

- Replace with the actual expected value per fixture
  (e.g., `assert_eq!(iters, 6)` or `assert!(iters <= 8)`).
- If the exact count is hard to pin down, at minimum cut the upper bound
  to something that would regress if optimization broke (e.g., 32 → 12).
- Change "finding is found" assertions (`findings.iter().any(...)`) to
  full expectation validation using the same `validate_expectations`
  helper used elsewhere in the fixture harness (grep how
  `tests/integration_tests.rs` does it).

#### Task 4b.2 — FP guard fixture expansion (target ~20 fixtures)

Create `tests/fixtures/fp_guards/` with subdirectories per category. Each
subdir contains one source file and one `.expect.json` with an empty
`expected` list plus `must_not_match` entries for likely regression rule
IDs.

Suggested categories (allocate ~4 fixtures each):

1. **Sanitizer edge cases** — escaped HTML with various encodings; shell
   escape with edge-case chars; URL encoding with unicode.
2. **Type-driven suppressions** — tainted int passed to a function where
   the abstract domain proved `[0, 255]`; int port bound via
   `socket.bind(("127.0.0.1", port))` where `port` is range-constrained.
3. **Struct-field isolation** —
   `obj.safe_field = user_input; sink(obj.unsafe_field)` must not fire
   for `obj.unsafe_field` taint.
4. **Cross-call-site specialization** — function called once with tainted
   arg (produces finding) and once with sanitized arg (must not); verify
   the summary does not spuriously mark the sanitized call as tainted.
5. **Framework-safe patterns** — Rails `sanitize(html)`, Express
   `res.json(obj)` (not a direct XSS sink), Flask `escape(x)`.

For each fixture, add `must_not_match` entries targeting the specific
rule IDs that would fire if the FP protection regresses. Grep
`tests/fixtures/` for existing `.expect.json` to match schema conventions.

Register the new fixture tree with the fixture-driven integration test
(usually a walker in `tests/integration_tests.rs` that globs
`tests/fixtures/**/*.expect.json` — confirm).

### Verification

```bash
cargo test --test scc_convergence_tests
cargo test --test integration_tests  # picks up new FP fixtures
cargo test --workspace --all-features

# Count FP-guard fixtures before/after:
rg -c 'must_not_match' tests/fixtures/ | wc -l   # target: +~20
rg -c '"must_match": false' tests/fixtures/ | wc -l
```

### Definition of done

- [ ] SCC tests use `validate_expectations` and have tight iteration
      bounds.
- [ ] At least 20 new FP-guard fixtures across the five categories.
- [ ] Each new fixture has `must_not_match` entries for the specific rule
      IDs it guards.
- [ ] `rg must_not_match tests/fixtures/` count increases by ~20+.
- [ ] `cargo test --workspace --all-features` passes.

---

## Phase 5 — Hot-path `.unwrap()` cleanup

**Status:** Not started
**Estimated effort:** ½–1 session
**Blocks release:** Partial — the worst offenders must be fixed; broader
cleanup can defer.
**Depends on:** Phase 0

### Project context

(See "Shared project context" at the top of this document.)

Additional context: Nyx uses a typed error hierarchy in `src/errors.rs`
(`NyxError` enum, `NyxResult<T>` alias, `From` impls for `std::io::Error`,
`rusqlite::Error`, etc.). The intent is structured errors — but
`src/database.rs` alone contains 241 `.unwrap()` / `.expect()` calls, and
parallel rayon loops in `src/commands/scan.rs` also rely on them. A single
`.unwrap()` panic in a rayon worker kills the worker thread and can
produce non-deterministic results or scan failures under hostile input.

### Why this phase exists

Fix only the `.unwrap()` sites most likely to fire on hostile or malformed
input. Full cleanup is a post-release refactor.

### Files you will touch

- `src/database.rs`
- `src/commands/scan.rs`
- `src/patterns/mod.rs`
- `src/errors.rs` (possibly a new variant)

### Files you MUST NOT touch

- Engine internals: `src/ssa/`, `src/taint/`, `src/cfg.rs`,
  `src/abstract_interp/`, `src/constraint/`, `src/symex/`. Those have their
  own `panic!()` calls that are part of a larger refactor — out of scope.
- `src/server/` — Phase 1 territory.
- Test code.

### Tasks

1. **Target `src/database.rs:849, 928, 1451` and nearby lines.** These are
   the highest-impact unwraps the audit flagged:
   - Line 849: `std::fs::read(path).unwrap_or_default()` in an AST-only
     scan loop.
   - Line 928: `analyse_file_fused(...).unwrap_or_else(...)` in Pass 1.
   - Line 1451: `.unwrap()` accessing the DB pool in a transaction.

   For each: convert to `.map_err(|e| NyxError::from(e))?`, or use
   `.inspect_err(|e| tracing::warn!(...))` + fallback for non-critical
   paths where continuation with defaults is legitimate.

2. **Parallel scan loops in `src/commands/scan.rs`.** In the rayon
   `flat_map_iter().collect()` (pass 1) and `map().try_reduce()`
   (pass 2) closures, replace `.unwrap()` on per-file analysis with:
   - Logged failure + skip-file-and-continue for parse errors.
   - Propagated `NyxError` for systemic failures (DB unavailable, OOM).

   Use `NyxError::Msg` sparingly; prefer named variants.

3. **`src/patterns/mod.rs:296-310` pattern registry load.** The registry
   is `Lazy::new()` initialized; an invalid tree-sitter query panics.
   Wrap in `catch_unwind` or return a `Result`, and on failure emit a
   diagnostic error + fall back to an empty registry for that language.
   Do not fail the entire scan because one language pattern is malformed.

4. **Update `src/errors.rs`** only if a new variant is needed. Prefer
   reusing existing variants.

### Out of scope (explicitly)

- Every other `.unwrap()` in the codebase.
- `src/symex/`, `src/constraint/`, `src/output.rs` panics — planned for
  post-release refactor.

### Verification

```bash
cargo test --workspace --all-features
# Stress test: run against a deliberately hostile input set.
cargo run --release -- scan tests/fixtures/hostile_input/ 2>&1 | tee /tmp/stress.log
# Expected: scan completes; per-file errors are logged but the process does
# not crash.

rg -c '\.unwrap\(\)' src/database.rs
# Target: meaningfully lower than 241 (aim for ~200 or better).
```

### Definition of done

- [ ] The three specific `src/database.rs` lines no longer `.unwrap()` on
      potentially-failing values.
- [ ] Parallel scan loops in `src/commands/scan.rs` do not `.unwrap()` on
      per-file analysis results.
- [ ] `src/patterns/mod.rs` registry load does not panic on a malformed
      pattern.
- [ ] `cargo test --workspace --all-features` passes.
- [ ] Hostile-input smoke test completes without crash.

---

## Phase 6 — Release tagging and publish

**Status:** Not started
**Estimated effort:** ½ session
**Blocks release:** Yes (final gate)
**Depends on:** Phases 0, 1, 2a, 2b, 3, 4a, 4b, 5 all complete and green.
Phase 2c is optional.

### Project context

(See "Shared project context" at the top of this document.)

Additional context: `.github/workflows/release-build.yml` produces binaries
for Linux x86_64, Linux aarch64, macOS x86_64, macOS aarch64, Windows
x86_64, bundled with `THIRDPARTY-LICENSES.html` (generated at build time
by `cargo about`) and `LICENSE`. The GitHub Action `elicpeter/nyx@<tag>`
uses `action.yml` + `action-scripts/download.sh`.

### Why this phase exists

Final release hygiene: date the CHANGELOG, tune release-profile flags,
produce checksums, cut the tag, let the release-build workflow run.

### Files you will touch

- `CHANGELOG.md`
- `Cargo.toml` (add `[profile.release]`)
- `.github/workflows/release-build.yml` (add checksum + tag-guard steps)
- `action.yml` (only if pinning guidance is needed)

### Files you MUST NOT touch

- Anything else. No last-minute source changes in the tag commit.

### Tasks

1. **Date the CHANGELOG.** Rename `## [Unreleased]` to
   `## [0.5.0] - YYYY-MM-DD` (today). Add a fresh empty `## [Unreleased]`
   section above it. Read through every bullet and verify it matches what
   actually shipped. Remove anything that didn't.

2. **Add `[profile.release]` to `Cargo.toml`:**

   ```toml
   [profile.release]
   opt-level = 3
   lto = "thin"
   codegen-units = 1
   strip = true
   ```

   Build and smoke-test:
   ```bash
   cargo build --release --all-features
   ls -lh target/release/nyx
   ./target/release/nyx --version
   ```

3. **Add checksum generation to `release-build.yml`.** After "Package
   artifacts" and before upload, add:

   ```yaml
   - name: Generate checksums
     shell: bash
     run: |
       cd dist
       if command -v sha256sum >/dev/null 2>&1; then
         sha256sum nyx-* > SHA256SUMS
       else
         shasum -a 256 nyx-* > SHA256SUMS
       fi
   ```

   Include `dist/SHA256SUMS` in the `softprops/action-gh-release` file list.

4. **Verify tag matches Cargo.toml version.** Add at the top of
   `release-build.yml`:

   ```yaml
   - name: Verify tag matches Cargo.toml version
     run: |
       tag="${GITHUB_REF_NAME#v}"
       cargo_ver=$(grep -m1 '^version' Cargo.toml | cut -d'"' -f2)
       if [[ "$tag" != "$cargo_ver" ]]; then
         echo "Tag $tag does not match Cargo.toml version $cargo_ver"
         exit 1
       fi
   ```

5. **Cut the tag** (only after all prior phases are merged to the release
   branch):

   ```bash
   git checkout release/0.5.0
   git pull
   git status  # must be clean
   git tag -a v0.5.0 -m "Release 0.5.0"
   git push origin v0.5.0
   ```

   Watch `release-build.yml`. If any platform fails, diagnose before
   deleting/recreating the tag. **Do not force-push the tag.**

6. **Publish to crates.io** (confirm with repo owner first):

   ```bash
   cargo publish --dry-run
   cargo publish
   ```

7. **Update `action.yml` documentation.** In the README's "GitHub Actions
   usage" section, emphasize pinning:

   ```yaml
   - uses: elicpeter/nyx@v0.5.0
     with:
       version: 'v0.5.0'
   ```

   Documentation-only; `action.yml` itself does not need to change.

### Verification

```bash
# Pre-tag:
cargo build --release --all-features
cargo test --workspace --all-features
cargo deny check
ls -lh target/release/nyx   # smaller binary thanks to LTO+strip

# Post-tag (once workflow completes):
curl -LO https://github.com/elicpeter/nyx/releases/download/v0.5.0/SHA256SUMS
curl -LO https://github.com/elicpeter/nyx/releases/download/v0.5.0/nyx-aarch64-apple-darwin.zip
shasum -a 256 -c SHA256SUMS   # verify downloaded files

# Smoke-test the action in a test repo using elicpeter/nyx@v0.5.0.
```

### Definition of done

- [ ] `CHANGELOG.md` has `## [0.5.0] - <date>` with an accurate bullet
      list.
- [ ] `Cargo.toml` has a `[profile.release]` block; release binary is
      LTO-enabled, stripped, measurably smaller.
- [ ] `release-build.yml` generates and uploads `SHA256SUMS`.
- [ ] `release-build.yml` fails fast if the tag ≠ `Cargo.toml` version.
- [ ] Tag `v0.5.0` is pushed; workflow green for all five platforms.
- [ ] Release artifacts include `SHA256SUMS`.
- [ ] `cargo deny check` green at the release commit.

---

## Final pre-ship checklist

Before announcing:

- [ ] All ten phases' "Definition of done" lists are fully checked
      (Phase 2c optional).
- [ ] `cargo test --workspace --all-features` green on a clean checkout.
- [ ] `cargo deny check` green.
- [ ] Benchmark regression gate green.
- [ ] README is internally consistent; no cross-file contradiction remains.
- [ ] `docs/language-maturity.md` reflects current behavior.
- [ ] GitHub release page shows binaries + `SHA256SUMS`.
- [ ] `cargo install nyx-scanner` from a fresh machine works end-to-end.
- [ ] `nyx serve` on a fresh machine shows a working UI with security
      headers present.

If any item fails, do not announce. Fix, cut 0.5.1 or re-tag, try again.
