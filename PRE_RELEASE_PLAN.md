# Nyx 0.5.0 Pre-Release Plan

This document is a self-contained plan to take Nyx from "conditionally ready" to "ship-ready" for the public 0.5.0 release. It is structured so a fresh Claude Code session can be told **"Implement Phase X from PRE_RELEASE_PLAN.md"** and have everything needed to do that phase end to end.

The plan addresses 26 issues identified in the release readiness audit, plus two engineering goals:

- **Core engine correctness**: Acceptable → Strong
- **Interprocedural analysis**: Acceptable → Strong

---

## How to use this document

Each phase below is sized for one focused Claude Code session (roughly 2–6 hours of sustained work). Phases are roughly ordered so earlier phases unblock later ones, but most are independent. Where a phase depends on another, the dependency is called out explicitly under **Dependencies**.

Each phase has the same structure:

- **Goal**: one sentence
- **Issues addressed**: which audit issue numbers this closes
- **Why this matters**: short context, mainly so a fresh session understands the stakes
- **Files to read first**: read these before touching code so you have working context
- **Tasks**: numbered, concrete actions
- **Acceptance criteria**: how you know the phase is done
- **Tests**: what tests to add or change
- **Notes**: anything else (gotchas, dependencies, open decisions)

When in doubt about scope: do exactly what the phase asks, add tests for it, do not add adjacent improvements. Adjacent improvements have their own phases.

---

## Project context (read this once before starting any phase)

Nyx is a multi-language static security scanner in Rust. The repo root is `/Users/elipeter/nyx`. Key facts:

- **Cargo crate**: `nyx-scanner`, version `0.5.0` (in `Cargo.toml`), edition `2024` (valid in Rust 1.85+, do not change to 2021).
- **Binary**: `nyx` (`src/main.rs`), library `nyx_scanner` (`src/lib.rs`).
- **Default features**: `serve` (Axum-based local web UI). The `smt` feature is opt-in (Z3).
- **License**: GPL-3.0-or-later.
- **Branch context**: current branch is `release/0.5.0`. `master` is the main branch.

### Module map (key files)

```
src/
  cfg.rs              ~10K lines   AST → CFG, all 10 languages, anonymous fn span IDs (uses start_byte)
  ast.rs              ~1.8K        AST entry, run_rules_on_file, parse timeout integration
  callgraph.rs        ~1.5K        CallGraph, CallGraphAnalysis (Tarjan SCC + topological)
  database.rs         ~3K          rusqlite r2d2 pool, summaries persistence, indexed parity
  cli.rs              CLI flags via clap; user-facing flag set
  main.rs / lib.rs    Both must register the same modules — keep them in sync
  output.rs           Console / JSON / SARIF 2.1.0 emission
  walk.rs             ignore-crate-based walker, symlink revalidation, max_file_size gating
  fmt.rs              Formatting helpers (1.3K)
  rank.rs             Attack-surface ranking (deterministic ordering)
  errors.rs           NyxError enum, ConfigError with structured metadata

  ssa/
    lower.rs          ~2.1K        AST/CFG → SSA, dominance frontiers, Cytron phi insertion
    type_facts.rs     ~1.4K        TypeKind inference, constructor → type mapping
    heap.rs           ~1.1K        HeapObjectId (= SsaValue), points-to analysis
    invariants.rs     SSA structural invariant checks
    const_prop.rs     Constant propagation, ConstLattice::parse (also used by symex)

  taint/
    mod.rs            ~1K          Two-pass driver, JS/TS two-level solve, dedup at L219-227
    ssa_transfer.rs   ~9K          SsaTaintTransfer / SsaTaintState / inline cache (k=1)
                                   MAX_ORIGINS=4 at line 34
    path_state.rs     ~1.4K        PredicateKind, classify_condition_with_target
    domain.rs         VarTaint, TaintOrigin, SmallBitSet, PredicateSummary
    backwards.rs      Demand-driven backwards taint, off by default

  abstract_interp/    Interval + StringFact domains, AbstractDomain trait
  symex/              Symbolic execution: value, transfer, executor, witness, strings, smt, loops, interproc
  cfg_analysis/       CFG structural rules (auth gaps, unguarded sinks, leaks)
  state/              Resource lifecycle / auth state machines
  labels/             Per-language source/sanitizer/sink rule tables (one .rs per language + mod.rs)
                      mod.rs (~1.9K) hosts GATED_REGISTRY, classify_gated_sink, classify_all
  summary/            FuncSummary / SsaFuncSummary / GlobalSummaries / merge_summaries()
  server/             Axum local server (feature-gated)
    security.rs       LocalServerSecurity: Host header + CSRF + Origin enforcement
    app.rs            Router, CSP, security headers
    routes/           HTTP route handlers
  commands/
    scan.rs           ~3.4K        Scan orchestration, two-pass driver
                                   SCC_FIXPOINT_SAFETY_CAP=64 at line 626
                                   SCC_FIXPOINT_CAP_OVERRIDE for tests at line 649
                                   last_scc_max_iterations() observable at line 639
    serve.rs          nyx serve subcommand
  utils/
    config.rs         ~1.5K        Config loader, validation
    path.rs           Centralized repo-path canonicalization (used by walker, server, file routes)
    analysis_options.rs  Engine knob defaults

tests/
  benchmark/          ground_truth.json (~264 cases), RESULTS.md
  fixtures/           ~93 fixture directories with expectations.json
  scc_convergence_tests.rs    Gold-standard adversarial test pattern
  ssa_equivalence_tests.rs    Lowering determinism, optimization idempotence
  hostile_input_tests.rs, panic_recovery_tests.rs, db_corruption_tests.rs
  perf_tests.rs       NYX_CI_BENCH=1 wall-clock budget enforcement
  benchmark_test.rs   benchmark_evaluation regression gate
```

### Engine knobs (env vars and CLI flags)

- `NYX_CONTEXT_SENSITIVE` — k=1 inline analysis (default on)
- `NYX_BACKWARDS` / `--backwards-analysis` — demand-driven backwards taint (default off)
- `NYX_ABSTRACT_INTERP` — interval/string abstract interpretation (default on)
- CLI engine toggles in `src/cli.rs` (~lines 195–249): symex, cross_file_symex, symex_interproc, smt, parse_timeout_ms, abstract_interp, context_sensitive, constraint_solving, backwards_analysis

### Build and test commands

```
cargo build --release
cargo nextest run --all-features                            # full test suite
cargo test --release --all-features --test benchmark_test -- --ignored --nocapture benchmark_evaluation
NYX_CI_BENCH=1 cargo test --release --all-features --test perf_tests -- --nocapture
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --all -- --check
cargo deny check advisories licenses bans sources
```

### Conventions

- No emojis in code, comments, or docs.
- Edits should preserve existing patterns; don't refactor opportunistically.
- Add tests for every behavior change, especially regression tests for "silent precision loss" issues.
- When changing user-facing strings (CLI help, errors), update `docs/` in the same commit.
- When changing config schema, update both `default-nyx.conf` and `docs/configuration.md`.

---

## Phase index

1. **Documentation contradictions and release hygiene** — pure docs/config alignment, fast wins
2. **CI cross-platform and release engineering** — macOS/Windows CI, checksums, CodeQL scoping, third-party licenses
3. **EngineNote provenance system** — foundation for "no silent precision loss"
4. **JS/TS pass-2 convergence cap** — fix the hardcoded 3-iteration bug, add regression test
5. **Inline-cache origin attribution** — interprocedural correctness fix
6. **Anonymous function structural identity** — replace byte-offset disambig
7. **Dedup correctness and alternative paths** — preserve distinct flows
8. **Engine fragility test coverage** — closures, async, containers, determinism, edit-and-rescan
9. **C/C++ tier reframe and engine knob surfacing** — honest labeling + UX banner + `--profile`
10. **Negative test tightening** — convert noise_budget to forbidden_findings
11. **Cross-function container identity (interprocedural strength)** — heap propagation through summaries
12. **Catch-block CFG invariants and Switch terminator** — kill known SSA fragility
13. **Real-CVE replay corpus** — benchmark credibility boost
14. **Code health refactors** — split cfg.rs and ssa_transfer.rs (post-release safe)

After Phase 1–8 complete, the release blockers are cleared. After Phase 9–13 complete, both engineering goals (core engine and interprocedural strength) are met. Phase 14 is post-release cleanup.

---

# Phase 1: Documentation contradictions and release hygiene

## Goal
Eliminate every documentation/configuration contradiction identified in the audit, plus the small Cargo metadata fixes. No code logic changes.

## Issues addressed
1, 2, 12, 13, 14, 18, 19, 20, 24, 25

## Why this matters
A user installing 0.5.0 today hits at least one contradiction immediately (state-analysis default vs docs). Multiple "Done" claims in the Roadmap are stronger than the implementation justifies. The CHANGELOG has no `[0.5.0]` section, so the version they install ships with no release notes. These are credibility issues, not technical issues, but they are cheap to fix and unacceptable to ship without.

## Files to read first
- `README.md`
- `CHANGELOG.md` (head only)
- `default-nyx.conf`
- `docs/configuration.md`
- `docs/detectors/state.md`
- `Cargo.toml`
- `action.yml`

## Tasks

### 1.1 — Audit state engine maturity, then resolve `enable_state_analysis` default contradiction

The contradiction:
- `src/utils/config.rs:236` and `:596` set the code default to `true`.
- `default-nyx.conf:62` ships `enable_state_analysis = true`.
- `README.md:197–201` marks all five state findings `(opt-in)`.
- `README.md:344` says "Optional resource lifecycle and auth state analysis (disabled by default)".
- `README.md:352` says "State analysis ... is disabled by default; enable with `scanner.enable_state_analysis = true`".
- `docs/configuration.md:65` lists default as `false`.
- `docs/detectors/state.md:7` says "State analysis is opt-in".

The code says on; the docs say off. Both are internally consistent — the question is which side is correct for 0.5.0. Don't pick by fiat; do the audit below and let it decide.

**Audit the state engine** before deciding. Read these files:

- `src/state/transfer.rs` (~970 lines) — `DefaultTransfer` for resource lifecycle
- `src/state/engine.rs` (~510 lines) — generic `run_forward`, lattice plumbing
- `src/state/facts.rs` (~760 lines) — fact computation
- `src/state/domain.rs` (~330 lines) — state domain definitions
- `src/state/lattice.rs` (~115 lines)
- `src/state/symbol.rs` (~260 lines)
- `src/state/mod.rs`
- `src/cfg_analysis/rules.rs` — state-related rules (search `state-`)
- `src/evidence.rs:292–296` — confidence levels assigned to state findings
- `tests/state_tests.rs` — direct test coverage
- All other tests that set `cfg.scanner.enable_state_analysis = true` (currently `tests/common/mod.rs:16`, `tests/abstract_transfer_tests.rs:339`, `tests/cross_file_context_tests.rs:57,165`, `tests/cross_file_body_loading_tests.rs:31`)
- `tests/benchmark/ground_truth.json` — search for cases that expect or forbid `state-*` rule IDs

Use these criteria to judge readiness for default-on:

1. **Test coverage**: Does `tests/state_tests.rs` plus any state-touching cross-file/integration tests exercise:
   - All five state finding kinds (`state-use-after-close`, `state-double-close`, `state-resource-leak`, `state-resource-leak-possible`, `state-unauthed-access`)?
   - At least one acquire/release pair per language that has them defined (per README: malloc/free, fopen/fclose, Lock/Unlock; per CHANGELOG: Python `open`/`.close`, `socket`/`.close`, etc.)?
   - Negative cases (must-not-fire) for safe code, including early-return + cleanup, conditional cleanup, and cleanup-in-finally?
   - Cross-file flows where the resource crosses a function boundary?
2. **Benchmark behavior**: Run `cargo test --release --all-features --test benchmark_test -- --ignored --nocapture benchmark_evaluation` twice, once with `enable_state_analysis = true` and once with `false`. Record:
   - The delta in total findings (count and per-rule breakdown).
   - Whether any benchmark case flips from TP to FP (or vice versa) when state analysis toggles. Look at `tests/benchmark/results/latest.json` after each run.
   - Whether F1 / Precision / Recall move materially. The benchmark is rule-level; state findings should not appear unless a benchmark case explicitly expects them.
3. **Performance impact**: Run `NYX_CI_BENCH=1 cargo test --release --all-features --test perf_tests -- --nocapture` with state analysis on and off on the same fixture set. State analysis is a separate forward-dataflow pass on top of taint; if it adds more than ~30% wall clock on any fixture, that is a meaningful default-on cost.
4. **Open issues / TODOs**: Search the state code for `TODO`, `FIXME`, `XXX`, `HACK`, `unimplemented!`, `todo!`, and `panic!`. Count them and read each in context. A few stale TODOs are fine; many open invariants or `unimplemented!` arms suggest the engine is not finished.
5. **Confidence calibration**: `src/evidence.rs:292–296` assigns High confidence to use-after-close, double-close, unauthed-access; Medium to resource-leak; Low to resource-leak-possible. Spot-check a handful of state findings on real fixtures and judge whether the assigned confidence matches reality (i.e., are the High-confidence ones actually low-FP?).
6. **Noise on real code**: Pick 2–3 fixture directories under `tests/fixtures/` that are NOT state-specific (e.g., a couple of cross_file_* dirs). Scan with state analysis on. Count state findings produced and judge whether they are useful or noise.

Write a brief audit summary (in the PR description, not as a committed file) covering each criterion and its finding.

**Then make the decision based on the audit:**

- **If the audit concludes default-on is justified** (good test coverage, no benchmark regressions, acceptable perf cost, low noise on non-state fixtures, confidence levels well-calibrated):
  - Keep `default-nyx.conf:62` as `enable_state_analysis = true`.
  - Keep `src/utils/config.rs:236` and `:596` as `true`.
  - **Update the docs to match**:
    - `README.md:197–201`: remove the `(opt-in)` parenthetical from each row in the table; consider replacing with `(default on)` or just removing the qualifier entirely.
    - `README.md:344`: change "Optional resource lifecycle and auth state analysis (disabled by default)" to "Resource lifecycle and auth state analysis (enabled by default; disable with `scanner.enable_state_analysis = false`)".
    - `README.md:352`: change to "State analysis (`use-after-close`, `double-close`, `resource-leak`, `unauthenticated-access`) is enabled by default; disable with `scanner.enable_state_analysis = false`".
    - `docs/configuration.md:65`: change default from `false` to `true`.
    - `docs/detectors/state.md:7`: change "State analysis is opt-in" to "State analysis is enabled by default; opt out with `scanner.enable_state_analysis = false`".
  - Add a one-line CHANGELOG entry under 0.5.0 (the section created in Task 1.2): `**Changed**: state analysis is now enabled by default. Disable with \`scanner.enable_state_analysis = false\` if you only want taint findings.`

- **If the audit concludes default-on is not justified** (gaps in test coverage, benchmark noise, perf cost, FP-prone, or unfinished code paths):
  - Change `default-nyx.conf:62` to `enable_state_analysis = false`.
  - Change `src/utils/config.rs:236` and `:596` from `true` to `false`. Verify that `tests/common/mod.rs:16` and the other test setups that currently rely on the default still work (they explicitly set it to `true`, so they should be unaffected).
  - Leave the docs as they are (they already say opt-in).
  - Document the audit findings briefly in `docs/detectors/state.md` under a new "Maturity" subsection so the reasoning is recorded.

Either outcome is acceptable; the goal is consistency between what the code does and what the docs say, with an honest engineering reason for the chosen default.

### 1.2 — CHANGELOG `[0.5.0]` section
- `CHANGELOG.md` currently has only `## [Unreleased]`.
- Move all current `Unreleased` content under a new section `## [0.5.0] - YYYY-MM-DD` (use today's date in the format YYYY-MM-DD).
- Above that, add a fresh empty `## [Unreleased]` section with `### Added`, `### Changed`, `### Fixed`, `### Removed` empty subheadings.
- Add a top-of-section note to 0.5.0: `**Note**: 0.5.0 introduces an SSA-based taint engine and major cross-file improvements. If you upgrade and see new false positives or regressions on cross-file flows, please open an issue with a minimal reproduction.`

### 1.3 — Move "nyx serve" out of Roadmap
- `README.md:440` lists "`nyx serve` local UI, smart file-watch re-scan, richer artifact browsing, interactive trace inspection" under Roadmap.
- `nyx serve` is shipped (verify: `Cargo.toml:31` has `default = ["serve"]`; `src/commands/serve.rs` is implemented).
- Remove "`nyx serve` local UI" from the Roadmap row. Keep "smart file-watch re-scan, richer artifact browsing, interactive trace inspection" if those remain unimplemented.
- Add a new section in the README, between "Architecture in Brief" and "Status", called **"What's New in 0.5.0"** that calls out: SSA-based taint engine, cross-file SCC fixed-point with parameter-granularity points-to summaries, demand-driven backwards taint (opt-in), and the local web UI (`nyx serve`).

### 1.4 — Reword "Path-sensitive analysis: Done"
- `README.md` Roadmap row currently: `Path-sensitive analysis | Done | Track path predicates and conditional constraints. Detect infeasible paths and validation-only-in-one-branch patterns. Monotone predicate summaries with contradiction pruning.`
- The implementation is per-predecessor phi merging plus classified condition predicates — predicate-aware, not full path-sensitive.
- Reword to: `Predicate-aware analysis | Done | Per-predecessor phi merging with classified condition predicates. Validation-only-in-one-branch detection via PredStates. Symbolic / SMT path-sensitive variants are opt-in.`

### 1.5 — Honest framing of the 95.1% F1 number
- Under `### Detection Accuracy` in README, after the metric table, add a paragraph (one paragraph, not a section):

> **What these numbers mean.** The benchmark corpus is 264 synthetic mini-fixtures (20–120 LOC each), curated for known-good and known-bad cases. F1 numbers are reported per language in the Language Maturity matrix; the aggregate hides per-tier variance (Rust ≈ 76%, C/C++ ≈ 80–86%, Python/TS ≈ 100%). The benchmark uses `allowed_alternative_rule_ids` to credit findings under any of several semantically equivalent rule IDs, which softens precision compared to a strict-rule-only scoring. Real-world repositories with framework-specific idioms (Django middleware, Spring DI, async runtimes, ORMs) will produce different numbers; treat 95.1% as a regression-protection floor on this corpus, not a general accuracy claim.

### 1.6 — Document the GitHub Action
- `action.yml` exists but `README.md` does not mention it.
- Add a `### Use in CI` subsection under "Quick Start" or before the Configuration section with:

```yaml
- name: Scan with Nyx
  uses: elicpeter/nyx@v0.5.0
  with:
    format: sarif
    fail-on: MEDIUM
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: nyx-results.sarif
```

- List the inputs/outputs the action exposes (read `action.yml` to confirm names).

### 1.7 — Add `rust-version` to Cargo.toml
- `[package]` section in `Cargo.toml` has no `rust-version` field.
- README claims MSRV 1.85.
- Add: `rust-version = "1.85"`.

### 1.8 — Tighten Cargo.toml `exclude` list
- Current `exclude` includes: `assets/`, `frontend/node_modules/`, `.github/`, `CLAUDE.md`, `.claude/`, `.idea/`, `tests/`, `benches/`, `examples/`, `docs/`.
- Add: `.DS_Store`, `.nyx/`, `.z3-trace`, `target/`.
- Run `cargo package --list 2>&1 | head -100` and verify no junk is included.

### 1.9 — Z3 licensing note
- In the README `## License` section, add a one-line note after the GPL-3.0 statement:

> The optional `smt` feature bundles the Z3 SMT solver (MIT-licensed). Distributors of binaries built with `--features smt` should include Z3's license in their attribution.

### 1.10 — Complete `default-nyx.conf` engine documentation
- The CLI exposes more knobs (`--symex`, `--cross-file-symex`, `--symex-interproc`, `--smt`, `--backwards-analysis`, `--abstract-interp`, `--context-sensitive`, `--constraint-solving`, `--parse-timeout-ms`) than `default-nyx.conf` documents.
- Read `src/cli.rs` lines 180–260 to enumerate the full set.
- Add an `[analysis.engine]` section to `default-nyx.conf` that documents every knob with its default value and a one-sentence comment. Include the env-var equivalents in the comment where applicable (e.g., `# env: NYX_BACKWARDS=1`).

## Acceptance criteria
- `enable_state_analysis = false` in `default-nyx.conf`; verify `cargo run -- scan --help` does not enable state analysis without an explicit flag.
- `CHANGELOG.md` has a `[0.5.0] - <date>` section and a fresh empty `[Unreleased]` section above it.
- `README.md` contains the "What's New in 0.5.0" section, has Roadmap reworded, and contains the F1 framing paragraph.
- `Cargo.toml` has `rust-version = "1.85"` and the expanded `exclude` list.
- `default-nyx.conf` contains a complete `[analysis.engine]` section.
- `cargo build --release && cargo test --all-features` still passes.

## Tests
- No new tests required — these are doc/config edits.
- Run the existing test suite to confirm nothing broke.

## Notes
- Do not bump the version number; we are still 0.5.0.
- Do not change actual default *values* in code (`src/utils/config.rs`), unless `enable_state_analysis`'s default there is `true` — in which case flip it to `false` and check that `tests/` does not depend on it being on by default. If anything breaks, those tests should explicitly opt in.

---

# Phase 2: CI cross-platform and release engineering

## Goal
Make the CI matrix match the binary distribution (Linux + macOS + Windows), checksum release artifacts, scope CodeQL honestly, and ship third-party license attribution.

## Issues addressed
4, 8, 9, 26

## Why this matters
README §Installation distributes binaries for `x86_64-unknown-linux-gnu`, `x86_64-pc-windows-msvc`, `x86_64-apple-darwin`, and `aarch64-apple-darwin`. CI today is `ubuntu-latest` only on every job. A security tool whose binaries are not tested on the platforms it ships to is not credible. Likewise, distributing binaries with no checksum is a trust gap inappropriate for a security tool. CodeQL on Rust with `build-mode: none` overstates the protection.

## Files to read first
- `.github/workflows/ci.yml`
- `.github/workflows/codeql.yml`
- `.github/workflows/release-build.yml`
- `Cargo.toml` (for feature names)
- `about.toml` and `about.hbs` (cargo-about config)

## Tasks

### 2.1 — Add cross-platform smoke test job to `ci.yml`
- Add a new job `cross-platform-smoke`:

```yaml
  cross-platform-smoke:
    name: cross-platform-smoke
    strategy:
      fail-fast: false
      matrix:
        os: [macos-latest, windows-latest]
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: stable
          cache: true
      - uses: taiki-e/install-action@nextest
      - name: Build
        run: cargo build --release --all-features
      - name: Smoke tests
        run: cargo nextest run --all-features --test integration_tests --test pattern_tests --test cli_validation_tests
```

- Pick a *subset* of integration tests that doesn't require Linux-specific paths or tools. The three tests above are the safest choices; verify they don't have `#[cfg(target_os = "linux")]` skips before committing.
- If a test fails on macOS or Windows, *do not skip it* — investigate and either fix or add a justified skip comment.

### 2.2 — Scope CodeQL to frontend; add `cargo audit` for Rust
- Edit `.github/workflows/codeql.yml`. Remove Rust from the matrix (CodeQL Rust support is `build-mode: none` only, query-based, no real dataflow).
- Keep JavaScript/TypeScript scanning scoped to `frontend/`.
- Create a new job in `ci.yml` (or new `audit.yml` workflow):

```yaml
  cargo-audit:
    name: cargo-audit
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: stable
      - uses: taiki-e/install-action@cargo-audit
      - run: cargo audit --deny warnings
```

- Note: `cargo deny check advisories` already exists in CI, so `cargo audit` is redundant. Choose one; prefer `cargo deny` since it is already wired. In that case, do not add `cargo-audit`; instead remove the redundant claim about "CodeQL covers Rust" if it appears in any docs.

### 2.3 — SHA256SUMS for release artifacts
- Edit `.github/workflows/release-build.yml`.
- After all binaries are built and zipped, add a step to generate `SHA256SUMS`:

```yaml
      - name: Generate checksums
        if: runner.os == 'Linux'
        run: |
          cd release-artifacts
          sha256sum *.zip > SHA256SUMS
          cat SHA256SUMS
      - name: Upload checksums
        if: runner.os == 'Linux'
        uses: actions/upload-artifact@v4
        with:
          name: checksums
          path: release-artifacts/SHA256SUMS
```

- Then in the `softprops/action-gh-release` step, ensure `SHA256SUMS` is included in the `files:` list.
- Update the README installation section to reference checksum verification:

```bash
# Verify checksum after download
sha256sum -c SHA256SUMS --ignore-missing
```

### 2.4 — Generate and commit `THIRD_PARTY_LICENSES.md`
- `about.toml` and `about.hbs` already configure `cargo-about`.
- Run `cargo install cargo-about --locked` (one-time).
- Run `cargo about generate about.hbs > THIRD_PARTY_LICENSES.html` and convert to a Markdown-friendly form, OR if the existing template produces HTML, generate `THIRD_PARTY_LICENSES.md` instead by adapting the template.
- Commit the generated file at the repo root.
- Add a CI step to `ci.yml` that regenerates and verifies the file is up to date:

```yaml
  third-party-licenses:
    name: third-party-licenses
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions-rust-lang/setup-rust-toolchain@v1
        with:
          toolchain: stable
      - run: cargo install cargo-about --locked
      - name: Regenerate license attribution
        run: cargo about generate about.hbs > /tmp/THIRD_PARTY_LICENSES.html
      - name: Diff against committed file
        run: diff -u THIRD_PARTY_LICENSES.html /tmp/THIRD_PARTY_LICENSES.html
```

- Add to `README.md`: a one-line link near the License section: "See `THIRD_PARTY_LICENSES.html` for the full third-party attribution."

## Acceptance criteria
- A CI run on a fresh PR shows new green jobs: `cross-platform-smoke (macos-latest)`, `cross-platform-smoke (windows-latest)`, `third-party-licenses`.
- `release-build.yml` produces a `SHA256SUMS` file alongside the binaries.
- `THIRD_PARTY_LICENSES.html` (or `.md`) exists at the repo root.
- `.github/workflows/codeql.yml` does not list Rust as a target (or has it gated to a comment explaining the limitation).

## Tests
- The new CI jobs are themselves the test. Push to a feature branch and confirm green before merging.

## Notes
- macOS and Windows runners are slower and more expensive. Scope the smoke test tightly — three integration test files is enough to catch path-handling, tree-sitter, and serialization regressions.
- Do not attempt to run the full benchmark on Windows; cross-platform parity for the benchmark is not a release requirement.
- If `cargo about` produces only HTML and a Markdown version is desired, write a small post-processing script in `scripts/` rather than fighting the template.

---

# Phase 3: EngineNote provenance system

## Goal
Add a single mechanism to tag findings with engine-side provenance notes ("we hit a budget cap, so this result may be incomplete"), and wire every silent cap site to use it. This is the foundation for several later phases.

## Issues addressed
5, 21

## Why this matters
The audit's #1 engine concern is "silent precision loss." Today, when the worklist iteration budget is hit, when origins exceed `MAX_ORIGINS = 4`, when path-env constraints exceed their internal cap, when SSA lowering bails to an empty body, when the parse timeout fires — the user sees no signal. They cannot tell "Nyx found nothing because nothing was there" from "Nyx ran out of budget and stopped looking." This phase adds a uniform `EngineNote` mechanism so every cap site is observable. Phases 4 (JS/TS pass-2 cap) and 12 (Switch terminator) reuse this infrastructure.

## Files to read first
- `src/taint/ssa_transfer.rs` — search for `MAX_ORIGINS`, `MAX_WORKLIST`, look for any `if iter > N { break; }` patterns
- `src/taint/mod.rs` — search for the dedup at line 219–227
- `src/output.rs` — see how Findings are serialized to JSON and SARIF
- `src/ast.rs` lines 34–60 — parse timeout handling
- `src/commands/scan.rs` lines 626–660 — how `SCC_FIXPOINT_SAFETY_CAP` is observed (model for new code)
- One Finding struct definition (search for `pub struct Finding` in `src/`)

## Tasks

### 3.1 — Define the `EngineNote` enum
- Create `src/engine_notes.rs` (or co-locate in `src/output.rs` if you prefer), containing:

```rust
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum EngineNote {
    /// The taint worklist hit its iteration budget before converging.
    WorklistCapped { iterations: u32 },
    /// Origin tracking was truncated when a value exceeded MAX_ORIGINS.
    OriginsTruncated { dropped: u32 },
    /// JS/TS pass-2 in-file global propagation hit its iteration cap.
    InFileFixpointCapped { iterations: u32 },
    /// Cross-file SCC fixpoint hit SCC_FIXPOINT_SAFETY_CAP.
    CrossFileFixpointCapped { iterations: u32 },
    /// SSA lowering produced an empty body (parse failure or unsupported AST shape).
    SsaLoweringBailed { reason: String },
    /// Tree-sitter parse exceeded the configured timeout.
    ParseTimeout { timeout_ms: u32 },
    /// Predicate state was widened to top to maintain monotonicity.
    PredicateStateWidened,
    /// Path-environment constraints exceeded internal cap; widened to top.
    PathEnvCapped,
    /// Inline cache reused a cached body summary; the original origins were re-attributed.
    /// (Informational; not a confidence reduction.)
    InlineCacheReused,
}

impl EngineNote {
    /// True if this note indicates the engine may have missed information
    /// (i.e., findings are potentially under-reported).
    pub fn lowers_confidence(&self) -> bool {
        !matches!(self, EngineNote::InlineCacheReused)
    }
}
```

- Register the module in `src/lib.rs` and `src/main.rs` — both must declare it.

### 3.2 — Add `engine_notes: Vec<EngineNote>` to `Finding`
- Find the `Finding` struct (search `pub struct Finding` in `src/`).
- Add a field: `pub engine_notes: SmallVec<[EngineNote; 2]>` (use `SmallVec` since most findings will have zero notes; the codebase already uses `smallvec`).
- Add `#[serde(default, skip_serializing_if = "SmallVec::is_empty")]` so JSON output omits the field when empty (cleaner output, no breaking JSON change for callers).
- Add a builder method `Finding::with_note(mut self, note: EngineNote) -> Self`.
- Update the `Finding::new` or constructor to default `engine_notes` to empty.

### 3.3 — Attach notes to findings at every cap site
For each cap site below, after the cap is hit, identify the findings produced from the affected analysis context and tag them with the corresponding note. The pattern should be: collect notes during analysis into a per-body or per-file `Vec<EngineNote>`, then attach to all findings produced from that scope at emission time.

Cap sites to wire:

- **`src/taint/ssa_transfer.rs`**: search for the worklist loop. When the iteration budget is hit, push `EngineNote::WorklistCapped`. There is one main worklist in `run_ssa_taint_full()`; smaller per-block iteration loops do not need wiring.
- **`src/taint/ssa_transfer.rs:34` (`MAX_ORIGINS = 4`)**: every site that drops origins because the cap was hit (search for `MAX_ORIGINS` — there are ~20 sites). These should not each push a note (too noisy); instead, set a per-body flag the first time it happens, and emit one note for the body.
- **`src/commands/scan.rs:626`**: when `SCC_FIXPOINT_SAFETY_CAP` is hit. Push `EngineNote::CrossFileFixpointCapped` to all findings produced from any file in that SCC.
- **`src/ssa/lower.rs`**: when SSA lowering bails (returns an empty body or errors out). Push `EngineNote::SsaLoweringBailed { reason }`. Currently the failure path returns empty findings; we want to keep it that way but at least surface "we tried and gave up" via a note attached to a synthetic informational finding (or, if there are no findings, log a TRACE — see Phase 3.5 below).
- **`src/ast.rs`**: when the parse timeout fires. Push `EngineNote::ParseTimeout`. Currently this likely produces zero findings for the file; wire a synthetic informational finding with the note (severity `Info`) so it surfaces in JSON output.

For Phase 4 (JS/TS pass-2 cap), the note is `InFileFixpointCapped`. Defining the variant here lets Phase 4 just emit it.

### 3.4 — JSON and SARIF emission
- `src/output.rs`: ensure `engine_notes` flows through to JSON output. Since it's `serde::Serialize` with `skip_serializing_if`, this should be automatic for JSON.
- For SARIF, add a property bag entry per finding. SARIF supports `properties` on `result` objects. Add:

```rust
if !finding.engine_notes.is_empty() {
    result["properties"] = json!({
        "engine_notes": finding.engine_notes,
        "confidence_capped": finding.engine_notes.iter().any(EngineNote::lowers_confidence),
    });
}
```

- For console output (`src/fmt.rs`): when verbose mode is on, append a one-line note count to each affected finding (e.g., `[capped: 1 note]`). Do not change non-verbose output (compatibility).

### 3.5 — `parse_timeout_ms = 0` footgun
- In `src/utils/config.rs`, locate the deserializer or validator for `parse_timeout_ms`.
- If it is `0` after config merge, emit a startup `tracing::warn!` log: `"parse_timeout_ms = 0 disables tree-sitter parse timeout entirely; this is unsafe for untrusted input."`
- Do not reject `0` (some users may genuinely want it disabled, e.g., testing huge generated code). Just make it loud.

## Acceptance criteria
- `Finding` struct has `engine_notes: SmallVec<[EngineNote; 2]>`.
- JSON output of a contrived test case where the worklist cap is forced to 1 contains `"engine_notes": [{"kind": "worklist_capped", ...}]`.
- SARIF output of the same test case has `result.properties.engine_notes` and `result.properties.confidence_capped: true`.
- Setting `parse_timeout_ms = 0` in config produces a startup WARN log.
- `cargo nextest run --all-features` passes.

## Tests
- New file: `tests/engine_notes_tests.rs`.
- Add `nyx_scanner::commands::scan::set_scc_fixpoint_cap_override(1)` style test helpers if not already present (the SCC code already has `SCC_FIXPOINT_CAP_OVERRIDE`, so the pattern exists). Add similar test-only override helpers for the worklist cap, JS/TS pass-2 cap (lands in Phase 4), and origins cap.
- Test cases:
  - Force worklist cap to 1 on a fixture that needs more iterations; verify `engine_notes` contains `WorklistCapped`.
  - Force origins cap to 1 on a fixture with two distinct sources merging; verify `OriginsTruncated`.
  - Force SCC cap to 1 on `tests/fixtures/cross_file_*` SCC fixture; verify `CrossFileFixpointCapped` on findings.
  - Set `parse_timeout_ms = 0` in a config and verify the WARN log appears (use `tracing-test` crate or capture stderr).
- Update `tests/ssa_equivalence_tests.rs::scan_is_stable_across_runs` if needed to confirm `engine_notes` remain deterministic across runs.

## Notes
- The override-pattern from `SCC_FIXPOINT_CAP_OVERRIDE` (`src/commands/scan.rs:649`) is the model: a global `AtomicUsize` defaulting to 0 (= use real cap), set by tests, read everywhere.
- Do not bump severity based on `engine_notes`; that's a policy decision that belongs in `rank.rs`. For now, just surface the notes.
- Design choice: notes can be deduplicated within a Finding's `engine_notes` (same kind shouldn't appear twice). Implement a `merge_notes(&mut self, other: EngineNote)` helper.
- When introducing the `EngineNote` system, ensure ranking (`rank.rs`) is unchanged. Confidence-capped findings still rank by their natural score; downstream consumers can filter by the `confidence_capped` SARIF property if they want.

---

# Phase 4: JS/TS pass-2 convergence cap

## Goal
Lift the hardcoded `max_iterations = 3` in JS/TS in-file pass-2 propagation to a real safety cap with an observable, an override hook, a regression test, and an `EngineNote` when the cap is hit. Mirror exactly the SCC pattern at `src/commands/scan.rs:626`.

## Issues addressed
3

## Why this matters
This is the single most material engine correctness risk identified in the audit. JS/TS in-file pass-2 silently stops after 3 rounds of global propagation, regardless of whether the lattice has converged. A real Express app with 4+ chained top-level bindings can drop findings with no warning. The cross-file SCC code already does this correctly with `SCC_FIXPOINT_SAFETY_CAP = 64`; the in-file analog has never been brought up to the same standard.

## Dependencies
- Phase 3 must be complete (uses `EngineNote::InFileFixpointCapped`).

## Files to read first
- `src/taint/mod.rs` lines 170–230 (the analyse-multi-body driver) and lines 460–600 (the iteration loop in `analyse_multi_body`)
- `src/commands/scan.rs` lines 620–680 (the SCC cap pattern to copy)
- `tests/scc_convergence_tests.rs` (the regression test pattern to copy)

## Tasks

### 4.1 — Replace hardcoded 3 with safety cap and override hook
In `src/taint/mod.rs`, near the top (or in a new sibling module if cleaner):

```rust
const JS_TS_PASS2_SAFETY_CAP: usize = 64;

static JS_TS_PASS2_CAP_OVERRIDE: AtomicUsize = AtomicUsize::new(0);
static LAST_JS_TS_PASS2_ITERATIONS: AtomicUsize = AtomicUsize::new(0);

#[doc(hidden)]
pub fn set_js_ts_pass2_cap_override(cap: usize) {
    JS_TS_PASS2_CAP_OVERRIDE.store(cap, Ordering::Relaxed);
}

fn js_ts_pass2_cap() -> usize {
    let o = JS_TS_PASS2_CAP_OVERRIDE.load(Ordering::Relaxed);
    if o == 0 { JS_TS_PASS2_SAFETY_CAP } else { o }
}

pub fn last_js_ts_pass2_iterations() -> usize {
    LAST_JS_TS_PASS2_ITERATIONS.load(Ordering::Relaxed)
}
```

- Replace the hardcoded `3` at `src/taint/mod.rs:181` with `js_ts_pass2_cap()`.
- After the iteration loop, store the actual iteration count into `LAST_JS_TS_PASS2_ITERATIONS`.

### 4.2 — Detect and emit `EngineNote::InFileFixpointCapped`
- The current iteration loop `for _round in 0..max_iterations.saturating_sub(1)` should detect convergence (no state change) and break early.
- If the loop completes without breaking *and* `max_iterations > 1`, the cap was hit. Add an `EngineNote::InFileFixpointCapped { iterations }` to all findings produced from this file.

### 4.3 — Regression test
Create `tests/js_ts_pass2_convergence_tests.rs`. Mirror `tests/scc_convergence_tests.rs::scc_deep_cycle_requires_multi_iter_convergence`:

- Build a fixture file with 5+ chained top-level globals where taint must propagate through each in turn:

```javascript
// tests/fixtures/js_ts_pass2_deep_chain/main.js
const tainted = process.env.USER_INPUT;
const stage1 = transform1(tainted);
const stage2 = transform2(stage1);
const stage3 = transform3(stage2);
const stage4 = transform4(stage3);
require('child_process').exec(stage4);

function transform1(x) { return x + ":1"; }
function transform2(x) { return x + ":2"; }
function transform3(x) { return x + ":3"; }
function transform4(x) { return x + ":4"; }
```

- The test: run a scan with `set_js_ts_pass2_cap_override(2)` (forces too few iterations); assert no taint finding is produced. Then with `set_js_ts_pass2_cap_override(64)` (default); assert finding *is* produced. Then assert `last_js_ts_pass2_iterations() >= 4`.
- Add a second test that asserts `EngineNote::InFileFixpointCapped` is attached when `set_js_ts_pass2_cap_override(2)` is used and a finding is produced (you may need to tweak the fixture to ensure *some* finding survives even when capped).

### 4.4 — Optional: surface as config knob
- Add `analysis.engine.in_file_fixpoint_cap = 64` to `default-nyx.conf` and document it.
- Wire through `src/utils/config.rs` to call `set_js_ts_pass2_cap_override` at startup if user overrides.
- Skip this if the test override is sufficient and the user-facing knob feels premature; the safety cap default of 64 is generous and unlikely to need tuning.

## Acceptance criteria
- `src/taint/mod.rs` no longer has a hardcoded literal `3` for `max_iterations`; instead reads from `js_ts_pass2_cap()`.
- `tests/js_ts_pass2_convergence_tests.rs` exists and passes.
- An `EngineNote::InFileFixpointCapped` is emitted when the cap is actually hit (verify via test).
- `last_js_ts_pass2_iterations()` returns a sensible value after a scan.
- `cargo nextest run --all-features` passes.

## Tests
- See 4.3 above. Mirror `tests/scc_convergence_tests.rs` exactly.

## Notes
- This phase is small but high-value. Do not expand scope.
- The 5-stage chain in the fixture is deliberate: the current cap of 3 can fully propagate a 3-stage chain (stage1 → stage2 → stage3) but not a 4+ stage chain. Verify the fixture actually fails with `set_js_ts_pass2_cap_override(3)`.
- If the iteration loop happens to converge early on the contrived fixture (e.g., all 5 transforms become tainted in iteration 1 because of how worklist visits happen), redesign the fixture to require sequential propagation. This is the same care `tests/scc_convergence_tests.rs` takes for cross-file.

---

# Phase 5: Inline-cache origin attribution

## Goal
Fix the inline analysis cache so that two call sites with the same argument capability shape but different taint origins do not get conflated. Currently the cache key is caps-only (`ArgTaintSig`), so a cached return-taint is reused with the wrong origin attribution.

## Issues addressed
7

## Why this matters
Findings that name the wrong source file/line are a credibility-killer. Users see a finding pointing to file A line 12 when the actual source is in file B line 47, dismiss it as a false positive, and lose trust in everything else the tool reports. This bug is hard to catch from output alone; a fixture is the only safe regression guard.

## Dependencies
- Phase 3 (uses `EngineNote::InlineCacheReused` for informational tagging — optional but recommended).

## Files to read first
- `src/taint/ssa_transfer.rs` — search for `ArgTaintSig`, `InlineCache`, `inline_analyse_callee`, `build_arg_taint_sig`. The cache infrastructure is concentrated in one region.
- The memory record at `~/.claude/projects/-Users-elipeter-nyx/memory/` for context-sensitive analysis (Phase 11 in the project history) is useful.

## Tasks

### 5.1 — Choose attribution strategy
Two options:

**Option A**: Include origins in cache key. Change `ArgTaintSig` from `SmallVec<[(usize, u16); 4]>` to `SmallVec<[(usize, u16, OriginSetHash); 4]>` where `OriginSetHash` is a `u64` hash of the sorted origin set. Pro: correct by construction. Con: cache hit rate drops since different origins miss.

**Option B**: Strip origins from cached value, re-attribute at apply time. Cache the *structural* return taint (caps, sanitization, validation). At apply time, the call-site origins are *unioned* into the returned taint (capped at `MAX_ORIGINS`). Pro: high cache hit rate preserved. Con: requires careful refactoring.

**Recommended**: Option B. The cache value already conceptually answers "given an argument shape, what taint shape exits?" — origin attribution is a separate question answered from call-site context.

### 5.2 — Implement Option B
- Find the cache value type (search for `InlineResult` or similar struct that the `InlineCache: HashMap<(String, ArgTaintSig), InlineResult>` stores).
- The cached `InlineResult.return_taint` likely has a `SmallVec<[TaintOrigin; 4]>` field per value. Strip origins from the cached value: store `0` or empty origin sets in the cache entry.
- At cache-hit application time (in `inline_analyse_callee` after the cache lookup), iterate over the returned taint values and union the *call site's* corresponding argument origins into them, capped at `MAX_ORIGINS`.
- The mapping is: callee return-taint references callee `Param(i)` values. The call-site origins for that parameter come from the call site's actual argument taint at position `i`. Union those origins into the returned taint.

### 5.3 — Add fixture proving the fix
Create `tests/fixtures/inline_cache_origin_attribution/`:

```javascript
// app.js
function exec_helper(cmd) {
    require('child_process').exec(cmd);
}

const sourceA = process.env.USER_INPUT;     // Source A
exec_helper(sourceA);                        // Call site 1

const sourceB = require('fs').readFileSync('/etc/foo'); // Source B
exec_helper(sourceB);                        // Call site 2
```

Expected:
- Two `taint-unsanitised-flow` findings: one with source line for `sourceA` (env), one with source line for `sourceB` (fs).
- Currently (before fix), both findings might attribute to whichever source the cache happened to capture first (typically `sourceA`).

`expectations.json`:

```json
{
  "required_findings": [
    {
      "id_prefix": "taint-",
      "file": "app.js",
      "source_line": 5,
      "sink_line": 3
    },
    {
      "id_prefix": "taint-",
      "file": "app.js",
      "source_line": 8,
      "sink_line": 3
    }
  ]
}
```

(If the fixture loader does not support `source_line` matching, extend it to do so — origin attribution correctness cannot be tested otherwise.)

### 5.4 — Add a verification test
- `tests/inline_cache_origin_tests.rs`:
  - Run the scan on the new fixture.
  - Collect all findings.
  - Group by sink line; for each sink, verify the source line matches the expected source for that call site (not whichever source was cached first).
  - Assert the cache was actually hit (write a debug counter or check via the cache size after the scan if accessible).

### 5.5 — Optional: tag cache reuse with `EngineNote::InlineCacheReused`
- For findings whose return-taint came from a cache hit, push `InlineCacheReused`.
- This is informational (not confidence-lowering). It exists for transparency: a user can tell which findings benefited from cache reuse and audit them more carefully.
- Skip this if it bloats output noticeably; it's a nice-to-have.

## Acceptance criteria
- `tests/fixtures/inline_cache_origin_attribution/` exists and the test in `tests/inline_cache_origin_tests.rs` passes.
- Manual inspection of JSON output for the fixture shows two findings with two distinct source attributions.
- `cargo nextest run --all-features` passes.

## Tests
- The new fixture and test described above.
- Sanity: existing context-sensitive tests in `tests/cross_file_context_tests.rs` should continue to pass.

## Notes
- Be careful with `MAX_ORIGINS` truncation: when unioning call-site origins into cached return-taint, if the union exceeds 4, truncate via the same logic the rest of the codebase uses (search `MAX_ORIGINS` in `ssa_transfer.rs` for the truncation pattern). When truncation happens, push `EngineNote::OriginsTruncated` (defined in Phase 3).
- This phase moves interprocedural analysis a meaningful step toward Strong: cross-call attribution is now correct.

---

# Phase 6: Anonymous function structural identity

## Goal
Replace byte-offset-based anonymous-function disambiguation with a structurally stable identifier (depth-first index of nested function definitions within the file). This eliminates a class of incremental-rescan bugs where adding a line above an anonymous function shifts its identity and breaks cross-file callback bindings or summary reuse.

## Issues addressed
11

## Why this matters
Anonymous functions are pervasive in JS, TS, Python, and Ruby. A summary persisted in the SQLite index references `FuncKey` with `disambig = Some(start_byte)`. Edit one line above the function and the byte offset changes — even if the function itself is unchanged. The next scan loads stale callback bindings or fails to look up summaries for unchanged code. Today this is masked because the file's blake3 hash changes invalidate the file's own summaries, but cross-file callers may still reference the stale FuncKey.

## Files to read first
- `src/cfg.rs` lines 312–360 — `LocalFuncSummary.disambig`, `BodyMeta.func_key`
- `src/cfg.rs` — search for all uses of `start_byte()` for anonymous function naming. Confirmed sites at lines 663, 2482, 2493, 3515 produce `<anon@{start_byte}>` strings; the disambig itself comes from `start_byte` elsewhere (search `disambig` and trace).
- `src/symbol/` — `FuncKey` definition
- `src/database.rs` — how `FuncKey` is serialized to/from SQLite (search for `FuncKey` writes and reads)
- `tests/indexed_parity_tests.rs` — existing parity coverage

## Tasks

### 6.1 — Define structural index
For each function body in a file, assign a structural ID:

- Walk the AST in tree-sitter pre-order (or in the same order CFG is built) and number every function/method/lambda/arrow/anonymous-function node starting from 0.
- Within a single file, each function gets a unique `(parent_path, sibling_index)` or simply a flat depth-first ordinal `u32`.

Recommended representation: a flat depth-first ordinal. Not robust to function reordering within a file, but neither is byte offset; both are unstable under refactor of identical magnitude. The improvement is robustness against *unrelated* edits (e.g., inserting a line above the function does not change its DFS index).

### 6.2 — Replace `disambig` semantics
- Change `LocalFuncSummary.disambig` from `Option<u32>` (byte offset) to `Option<StructuralId>` where `StructuralId` is a wrapper around `u32` representing the DFS index.
- Update every site that constructs `disambig`:
  - `src/cfg.rs` — find every place that produces `<anon@{start_byte}>` strings, and the corresponding place that builds `FuncKey` with `disambig = Some(start_byte)`. Replace with the DFS index.
- Update display: change `<anon@{n}>` rendering to `<anon#{dfs_index}>` (or similar) for clarity. The `<anon@{byte}>` strings appear in user-visible output; pick a format that does not look like a byte offset.

### 6.3 — Database migration
- The on-disk SQLite index stores serialized `FuncKey`s with byte-offset disambigs. Existing indexes are now invalid.
- Add a schema version bump in `src/database.rs`. When opening a DB whose schema version is older, *clear the summaries tables* (re-extract on next scan).
- Document in CHANGELOG that 0.5.0 invalidates pre-0.5.0 indexes (they will be silently rebuilt).

### 6.4 — Edit-and-rescan parity test
Create `tests/incremental_index_tests.rs`:

- Write a small JS file with an anonymous function inside another function:

```javascript
function outer() {
    return function (x) { return require('child_process').exec(x); };
}
const handler = outer();
handler(process.env.INPUT);
```

- Step 1: scan with index enabled into a tempdir. Capture findings.
- Step 2: insert a blank line at the top of the file (shifts byte offsets but does not change semantics).
- Step 3: scan again with the same index. Capture findings.
- Assert: findings from step 1 and step 3 are equivalent (same rule IDs, same source/sink line numbers — the line numbers themselves shift by 1 in step 3, account for that).
- The bug surface: in step 3, the inner anonymous function's `disambig` should match step 1's structural ID (not the new byte offset). Cross-file callback bindings should resolve identically.

### 6.5 — Verify cross-file callback resolution
Add a multi-file fixture where File A defines `function (x) { ... }` and exports it, File B imports and calls it. Edit File A to add a comment line above the function. Rescan; assert the cross-file taint flow still resolves.

## Acceptance criteria
- `LocalFuncSummary.disambig` no longer represents a byte offset.
- `tests/incremental_index_tests.rs` passes both the local edit-and-rescan and the cross-file callback resolution tests.
- Existing `tests/indexed_parity_tests.rs` tests still pass.
- `cargo nextest run --all-features` passes.
- A pre-0.5.0 SQLite index is silently rebuilt rather than producing wrong answers.

## Tests
- `tests/incremental_index_tests.rs` (new).
- Verify `tests/indexed_parity_tests.rs` still passes unchanged.

## Notes
- This phase has some breadth (touches many cfg.rs sites). Use `grep -n "start_byte" src/cfg.rs | grep -i "anon\|disambig"` to enumerate all relevant sites before starting.
- The user-visible `<anon@{start_byte}>` strings appear in finding messages. Changing them is a minor compatibility change for downstream consumers parsing finding messages; document in CHANGELOG.
- If full DFS-index implementation is too invasive, an interim improvement is: hash the function body's tree-sitter S-expression as the disambig. This is stable against unrelated file edits but unstable against the function's own edits (acceptable: editing the function should invalidate its summary).
- This phase moves interprocedural analysis another step toward Strong: callback bindings are now stable across reasonable refactors.

---

# Phase 7: Dedup correctness and alternative paths

## Goal
Prevent the dedup at `src/taint/mod.rs:219–227` from collapsing distinct flows that happen to share `(body_id, sink, source)`. Preserve at least one validated and one unvalidated flow when both exist; preserve distinct paths through different intermediate variables.

## Issues addressed
6

## Why this matters
Today, the dedup keeps only one finding per `(body_id, sink_index, source_index)` tuple, preferring `path_validated=true`. If a real exploit exists on an unguarded branch and a sibling branch is properly guarded, the guarded finding wins and the exploit is silently masked. There is no test that asserts the desired behavior; this is a correctness blind spot.

## Dependencies
- Phase 3 (optional: tag merged findings with a note).

## Files to read first
- `src/taint/mod.rs` lines 200–250 (sort and dedup region)
- The `Finding` struct definition (must understand all fields)
- `src/symex/witness.rs` — does the witness system already produce a unique-per-path identifier?
- `src/rank.rs` — to understand how ranking interacts with dedup

## Tasks

### 7.1 — Understand the existing dedup and decide policy
Re-read the current dedup:

```rust
all_findings.sort_by_key(|f| (f.body_id.0, f.sink.index(), f.source.index(), !f.path_validated));
all_findings.dedup_by_key(|f| (f.body_id, f.sink, f.source));
```

This keeps the *first* element after sorting. The sort puts `path_validated=true` first (because `!true == false < !false == true`), so the dedup keeps the validated one, dropping the unvalidated one.

Policy decision (recommended):

- **Always keep both**: if there exist findings to the same `(body_id, sink, source)` with both `path_validated=true` and `path_validated=false`, keep both as distinct findings, but link them via a new field `Finding.alternative_paths: Vec<FindingId>` (or a simpler `Finding.has_alternatives: bool`).
- **Same validation status, multiple distinct flows**: dedup these into one finding only if they are truly identical. Use a richer dedup key that includes the witness path hash if available, otherwise the intermediate-variables sequence.

### 7.2 — Implement richer dedup key
- If `src/symex/witness.rs` produces a stable hash per witness path, include it in the dedup key.
- If not, derive a path hash from the SSA value sequence between source and sink. This is stable for a given file/scan.
- New dedup key: `(body_id, sink, source, path_validated, path_hash)`.
- Two findings with the same (body, sink, source, path_validated) but different `path_hash` are kept as distinct.
- Two findings with the same (body, sink, source) but different `path_validated` are kept as distinct.

### 7.3 — Surface alternatives in output
- For two findings A and B with the same (body, sink, source) but different `path_validated`, mark them in the output:
  - JSON: add `"alternative_finding_ids": [...]` to each.
  - SARIF: add to `result.properties.relatedFindings`.
  - Console: print as a single "primary" finding with `... and 1 alternative path` annotation; add a verbose mode that expands the alternatives.

### 7.4 — Regression fixture
Create `tests/fixtures/dedup_alternative_paths/`:

```javascript
// app.js
const input = process.env.USER_INPUT;

function handler(req) {
    if (isWhitelisted(req)) {
        require('child_process').exec(input);   // validated (after isWhitelisted)
    } else {
        require('child_process').exec(input);   // unvalidated
    }
}

handler({});
```

`expectations.json`:

```json
{
  "required_findings": [
    { "id_prefix": "taint-", "sink_line": 6, "path_validated": true },
    { "id_prefix": "taint-", "sink_line": 8, "path_validated": false }
  ]
}
```

(If the expectations loader does not check `path_validated`, extend it.)

### 7.5 — Test
`tests/dedup_alternative_paths_tests.rs`:

- Scan the fixture.
- Assert both findings are present.
- Assert they reference each other via `alternative_finding_ids` (or whichever linking mechanism you implemented).

## Acceptance criteria
- The dedup at `src/taint/mod.rs:219–227` no longer drops distinct-path findings.
- `tests/dedup_alternative_paths_tests.rs` passes.
- `cargo nextest run --all-features` passes; existing tests not broken.
- Manual review: spot-check a benchmark fixture where multiple flows reach the same sink — verify the new behavior is sane and not a noise explosion.

## Tests
- New fixture and test as above.
- Run benchmark gate locally (`cargo test --release --all-features --test benchmark_test -- --ignored --nocapture benchmark_evaluation`); confirm precision/recall do not regress below floors.

## Notes
- The benchmark may temporarily dip in precision because previously-merged duplicate findings now surface as separate findings. If the floor is breached, decide whether to (a) tighten the dedup further (require distinct *path_hash*, not just distinct path_validated) or (b) lower the floor and document.
- The "alternative paths" framing is the user-facing story: this is not a regression in noise, it is a reveal of previously-hidden complexity. Document in CHANGELOG.

---

# Phase 8: Engine fragility test coverage

## Goal
Add regression test fixtures for entire categories of taint flow that are currently absent from the test suite: closures capturing tainted state, async/await patterns, container-element taint, cross-thread determinism, and edit-and-rescan parity.

## Issues addressed
17

## Why this matters
The engine *may* handle closures, async, and containers correctly today (or it may not — there is no way to tell without tests). The audit identified these as "missing categories of tests." Adding them now serves two purposes: (1) catch latent bugs before users do, (2) protect against future regressions when refactoring.

## Dependencies
- Phase 6 (for the edit-and-rescan test, ideally).

## Files to read first
- `tests/fixtures/` — browse to understand the fixture layout convention
- `tests/cross_file_context_tests.rs` — for the structural pattern of running fixtures from a test
- `tests/concurrent_scan_tests.rs` — for the determinism testing pattern

## Tasks

### 8.1 — Closure capture fixtures
For each stable-tier language (Python, JS, TS), add a fixture:

**JS arrow nested capture** (`tests/fixtures/closure_capture_js/`):
```javascript
function makeHandler() {
    const tainted = process.env.USER_INPUT;
    return (req) => {
        require('child_process').exec(tainted);
    };
}
const h = makeHandler();
h({});
```
Expected: `taint-unsanitised-flow` finding from env source to exec sink.

**Python nested def** (`tests/fixtures/closure_capture_py/`):
```python
import os, subprocess
def make_handler():
    tainted = os.environ["USER_INPUT"]
    def handler(req):
        subprocess.run(tainted, shell=True)
    return handler

h = make_handler()
h({})
```
Expected: similar finding.

**TS arrow with type annotation** (`tests/fixtures/closure_capture_ts/`):
Similar to the JS case but with explicit types.

For each fixture, write `expectations.json` with the required finding.

### 8.2 — Async/await fixtures
**JS Promise chain** (`tests/fixtures/async_promise_chain_js/`):
```javascript
fetch('/api')
    .then(res => res.text())
    .then(text => process.env.PREFIX + text)
    .then(combined => require('child_process').exec(combined));
```
Expected: finding from env source through promise chain to exec sink. (If the engine cannot handle this today, document the missing finding in `expectations.json` as a forbidden expectation but in the fixture's README.md as "known gap" — the test then asserts current behavior, and a future improvement that produces the finding will need to update the expectations.)

**Python asyncio** (`tests/fixtures/async_python/`):
```python
import asyncio, os, subprocess
async def fetch_and_exec():
    cmd = os.environ["CMD"]
    await asyncio.sleep(0)
    subprocess.run(cmd, shell=True)
asyncio.run(fetch_and_exec())
```

**Rust async** (`tests/fixtures/async_rust/`): similar pattern with `tokio::process::Command` (note: per `docs/language-maturity.md`, Tokio process variants are not yet covered for Rust — document as known gap).

### 8.3 — Container-element taint fixtures
**Python list element** (`tests/fixtures/container_taint_py/`):
```python
import os, subprocess
items = []
items.append(os.environ["INPUT"])
subprocess.run(items[0], shell=True)
```

**JS array element** (`tests/fixtures/container_taint_js/`):
```javascript
const items = [];
items.push(process.env.INPUT);
require('child_process').exec(items[0]);
```

If the engine does not handle these today (heap aliasing limitation noted in the audit), document them as known gaps and assert current behavior; do not block the phase on fixing the underlying engine — that is Phase 11.

### 8.4 — Per-thread-count determinism test
Create `tests/determinism_threads_tests.rs`:

```rust
#[test]
fn scan_is_deterministic_across_thread_counts() {
    let fixture = "tests/fixtures/cross_file_js_sqli";  // or similar non-trivial fixture
    let mut findings_by_threads: Vec<(usize, Vec<Finding>)> = Vec::new();

    for &threads in &[1, 2, 4, 8] {
        let scan = run_scan_with_threads(fixture, threads);
        findings_by_threads.push((threads, scan.findings));
    }

    let baseline = &findings_by_threads[0].1;
    for (threads, findings) in &findings_by_threads[1..] {
        assert_eq!(
            normalize(findings),
            normalize(baseline),
            "thread count {} produced different findings than 1-thread baseline",
            threads
        );
    }
}

fn normalize(findings: &[Finding]) -> Vec<Finding> {
    let mut sorted = findings.to_vec();
    sorted.sort_by(|a, b| {
        (a.path.as_str(), a.line, a.column, a.rule_id.as_str())
            .cmp(&(b.path.as_str(), b.line, b.column, b.rule_id.as_str()))
    });
    sorted
}
```

The `run_scan_with_threads` helper should set the worker thread count via the existing config knob (`scanner.worker_threads` per `default-nyx.conf`).

### 8.5 — Edit-and-rescan parity test
Already specified in Phase 6 (Task 6.4); confirm it exists.

## Acceptance criteria
- All eight new fixtures exist with `expectations.json` matching current engine behavior.
- The determinism test passes.
- `cargo nextest run --all-features` passes.

## Tests
- The new fixtures themselves are the tests (loaded by the existing fixture-runner test infrastructure).
- The new `tests/determinism_threads_tests.rs` is the determinism test.

## Notes
- The point of this phase is *coverage*, not fixing latent bugs. If a fixture reveals a bug, document it in the fixture's `README.md` as a known gap and codify the current (possibly wrong) behavior in `expectations.json`. Bugs revealed here become inputs to Phase 11 (container identity) or future work.
- Use `forbidden_findings: []` and `required_findings: [...]` to keep expectations strict — do not use `noise_budget` for these new fixtures.

---

# Phase 9: C/C++ tier reframe and engine knob surfacing

## Goal
Two related deliverables: (1) honestly reframe C/C++ as "Preview" rather than "Experimental" with a CLI banner on first scan; (2) consolidate the scattered engine flags into a `--profile {fast,balanced,deep}` shortcut and add `nyx scan --explain-engine`.

## Issues addressed
10, 15

## Why this matters
"Experimental" suggests "rough edges"; the actual C/C++ reality is "structurally cannot find common bug classes." Pointer aliasing, function pointers, array-element taint, and STL containers are not modeled. Users who scan a C codebase and see clean output will assume safety; they shouldn't.

The engine has 8+ env-var/CLI knobs (`NYX_BACKWARDS`, `NYX_ABSTRACT_INTERP`, `--symex`, `--cross-file-symex`, `--symex-interproc`, `--smt`, `--backwards-analysis`, `--context-sensitive`, `--constraint-solving`). No user can reason about which to enable. A `--profile` umbrella + an `--explain-engine` command makes the matrix tractable.

## Files to read first
- `docs/language-maturity.md`
- `src/labels/c.rs`, `src/labels/cpp.rs`
- `src/cli.rs`
- `default-nyx.conf`
- `src/utils/analysis_options.rs`

## Tasks

### 9.1 — Relabel C and C++ from "Experimental" to "Preview"
- In `README.md`, the Languages tier table: change C/C++ from "Experimental" to "Preview". Update the description: "Pattern-only coverage. Pointer aliasing, function pointers, array-element taint, and STL container flows are not modeled. Suitable for finding obvious unsafe API uses; do not use as a sole SAST gate. Pair with clang-tidy / Clang Static Analyzer / Infer."
- Same change in `docs/language-maturity.md`.
- Keep Rust as "Experimental" (the framing is appropriate; the gap is type-system understanding, not coverage).

### 9.2 — First-scan banner for Preview-tier languages
- In `src/commands/scan.rs`, after the scan completes (or before, after file enumeration), check if any C or C++ files were scanned.
- If so, print to stderr (once, not per-file):

```
warning: Nyx is in Preview for C/C++. Pointer aliasing, function pointers,
array-element taint, and STL container flows are not modeled. Findings are
a starting point for review; pair with clang-tidy or Clang Static Analyzer
for production gates.
```

- Suppress the banner when `--quiet` is set or when `output.quiet` is true in config.
- Suppress when output format is `json` or `sarif` (banner is for human consumption).

### 9.3 — `--profile {fast,balanced,deep}` umbrella
In `src/cli.rs`, add a new top-level flag:

```rust
/// Shortcut for engine analysis depth. Overrides individual engine knobs.
#[arg(long, value_enum)]
profile: Option<EngineProfile>,
```

Where:

- `fast`: AST + CFG + basic taint. Disables: symex, abstract-interp, context-sensitive, backwards-analysis, smt.
- `balanced` (default): AST + CFG + SSA taint + abstract-interp + context-sensitive (k=1). Disables: symex, smt, backwards.
- `deep`: everything in balanced + symex + backwards + cross-file symex + interproc symex. Still disables `smt` (z3 is a heavy dep).

Implement by setting the corresponding `analysis_options` fields when a profile is chosen, before individual flags are applied. Individual flags override the profile (so `--profile fast --backwards-analysis` enables backwards on top of fast).

### 9.4 — `nyx scan --explain-engine`
Add a CLI flag `--explain-engine` (boolean) that prints the effective engine configuration and exits without scanning:

```
Effective engine configuration:
  Profile: balanced (default)
  AST patterns:           on
  CFG construction:       on
  CFG analysis:           on
  Taint (SSA):            on
  Abstract interpretation: on   (NYX_ABSTRACT_INTERP, default on)
  Context sensitivity:    on   (NYX_CONTEXT_SENSITIVE, default on, k=1)
  Symbolic execution:     off  (--symex)
  Cross-file symex:       off  (--cross-file-symex)
  Interproc symex:        off  (--symex-interproc)
  Backwards taint:        off  (--backwards-analysis or NYX_BACKWARDS=1)
  SMT (Z3):               off  (--smt, requires --features smt)
  State analysis:         off  (scanner.enable_state_analysis, default off after Phase 1)
  Auth analysis:          on   (scanner.enable_auth_analysis, default on)
  Parse timeout:          10000 ms  (--parse-timeout-ms, 0 disables)
```

### 9.5 — Documentation
- Update `default-nyx.conf` to document `[analysis.profile]` (or just `analysis.profile = "balanced"` at top of `[analysis.engine]`).
- Update `docs/cli.md` with the new flags.
- Update `docs/configuration.md` accordingly.

## Acceptance criteria
- Running `nyx scan` against a directory containing a `.c` file prints the C/C++ Preview banner once.
- `nyx scan --quiet` suppresses the banner.
- `nyx scan --explain-engine` prints the effective engine config and exits 0 without scanning.
- `nyx scan --profile fast` produces fewer findings on a known fixture than `--profile deep`.
- README and `docs/language-maturity.md` use the "Preview" label for C/C++ with the explicit gap list.
- `cargo nextest run --all-features` passes.

## Tests
- `tests/cli_validation_tests.rs`: add a test that `--explain-engine` exits 0 with a non-empty stdout.
- `tests/cli_validation_tests.rs`: add a test that `--profile` accepts valid values and rejects invalid ones.
- `tests/integration_tests.rs` or new file: add a scan-with-c-file test that asserts the banner appears in stderr (use `assert_cmd`).

## Notes
- The banner text wording matters for credibility. Land it conservatively; do not name competitors disparagingly.
- `--profile deep` is the only place backwards taint is on by default. This is a meaningful change in behavior; document in CHANGELOG.

---

# Phase 10: Negative test tightening

## Goal
Audit every `tests/fixtures/` directory whose `expectations.json` uses `noise_budget` (a permissive cap on total findings) and convert to hard `forbidden_findings` lists where the fixture is meant to be a "must-not-fire" negative test.

## Issues addressed
16

## Why this matters
A "safe code" fixture that allows up to 5 high-severity findings via `noise_budget` is not asserting precision. A regression that doubles false positives on that fixture passes silently as long as it stays under the cap. The benchmark uses tighter `forbidden_findings` lists; legacy fixtures should be brought up to that standard, particularly for cross-file safe-flow fixtures.

## Files to read first
- A handful of `tests/fixtures/*/expectations.json` to understand the existing schema
- `tests/benchmark/ground_truth.json` to compare against the tighter pattern
- The fixture loader code (search `noise_budget` and `forbidden_findings` in `src/` and `tests/`)

## Tasks

### 10.1 — Inventory
- Run: `grep -l "noise_budget" tests/fixtures/*/expectations.json` and list every fixture using it.
- For each, read the fixture source and the `noise_budget` value.
- Categorize:
  - **Safe-code fixture (no findings expected)**: must be tightened. Convert `noise_budget` to `required_findings: []` and `forbidden_findings: [{"id_prefix": "..."}]` with explicit prefixes.
  - **Realistic-app fixture (some findings expected, exact count varies)**: keep `noise_budget` but document why in a fixture-local `README.md`.
  - **Stale / abandoned fixture**: consider deletion if it provides no signal.

### 10.2 — Convert safe fixtures
For each safe fixture:

- Replace:
  ```json
  "noise_budget": { "max_total_findings": 10, "max_high_findings": 5 }
  ```
- With:
  ```json
  "required_findings": [],
  "forbidden_findings": [
      { "id_prefix": "taint-" },
      { "id_prefix": "cfg-unguarded-sink" }
  ]
  ```
  (Add prefixes that are relevant to what the fixture is testing.)

- If the fixture currently produces some findings (because the engine has known false positives), either:
  - Add those known-FP findings to `required_findings` so the test pins the current state and a future fix breaks the test (loud), OR
  - Document the known FPs in a fixture-local `README.md` as a tracked gap, and leave a tighter `noise_budget` (e.g., `max_total_findings: 2`).

### 10.3 — Document remaining `noise_budget` uses
- Any fixture still using `noise_budget` after the audit must have a `README.md` explaining why.

### 10.4 — Cross-file safe fixtures
- Pay special attention to `tests/fixtures/cross_file_*` directories that are meant to be safe (e.g., `cross_file_js_html_sanitized`).
- These should have hard `forbidden_findings` lists, since their entire reason for existence is "the engine should NOT fire on this sanitized-correctly cross-file flow."

## Acceptance criteria
- Every safe-code fixture has tight expectations (`required_findings: []` or specific findings, with `forbidden_findings` listing relevant rule prefixes).
- Every remaining use of `noise_budget` has a fixture-local `README.md` justifying it.
- `cargo nextest run --all-features` passes.
- Run the benchmark gate; verify no regression in P/R/F1 numbers.

## Tests
- The fixtures are themselves the tests; ensure the fixture loader still passes them.

## Notes
- This phase is largely mechanical but requires judgment per fixture. Budget time accordingly.
- If a fixture's engine output cannot be made stable enough to assert specific findings (e.g., source/sink line numbers shift across runs), that's a determinism bug — file an issue separately rather than working around it.

---

# Phase 11: Cross-function container identity (interprocedural strength)

## Goal
Strengthen the heap-aliasing model so taint flows correctly through factory functions and helpers that produce or consume containers (lists, dicts, vectors, maps). This is the largest single step toward "Strong" interprocedural analysis.

## Issues addressed
- Engine fragility item 3 (heap aliasing best-effort across function boundaries)
- The container-taint fixtures from Phase 8 (8.3) become passing tests after this phase

## Why this matters
Container-routed taint is one of the most common real-world patterns ("input goes into a list, list gets passed to a helper, helper iterates and calls a sink"). Today, the engine tracks container identity intra-procedurally (good), but cross-procedural identity relies on `param_container_to_return` summaries plus name-pattern dotted-name fallbacks. This loses precision in many real cases.

## Dependencies
- Phase 5 (origin attribution) makes the container-flow attribution correct.
- Phase 8 (container fixtures) provides the regression tests.

## Files to read first
- `src/ssa/heap.rs` (1.1K lines) — `HeapObjectId`, `points_to`, `classify_container_op`
- `src/summary/mod.rs` — `FuncSummary`, `SsaFuncSummary`, look for `param_container_to_return` / points-to summary fields
- `src/taint/ssa_transfer.rs` — search for `param_container_to_return` and `points_to` to find usage sites
- The memory file `project_cf6_landed.md` (CF-6 parameter-granularity points-to summaries)

## Tasks

### 11.1 — Audit current cross-fn container handling
- Identify every site that consumes `param_container_to_return` (or whatever the cross-fn container summary field is called).
- Identify every site that uses the dotted-name fallback (search `dot_pos` in `heap.rs`).
- Build a list of cases where container identity is lost crossing a function boundary.

### 11.2 — Strengthen `PointsToSummary`
- Per memory record, `PointsToSummary` exists on `SsaFuncSummary` with parameter-granularity.
- Verify it captures: "if param `i` is a container, what does it point to internally? Does the function store into it? What does the function return — is the return value an alias of param `i`?"
- Add fields if missing:
  - `param_container_aliases: HashMap<usize, ContainerAlias>` — for each parameter that is a container, record what aliases the function creates (assignments to other parameters, returns, etc.).
  - `param_container_taint_to_return: SmallVec<[(usize, FlowKind); 4]>` — for each container parameter, record whether taint stored into it flows to the return value.

### 11.3 — Apply summaries at call sites
- In `src/taint/ssa_transfer.rs`, when resolving a call:
  - If the callee summary indicates `param_container_taint_to_return` for arg position `i`, propagate the container's element taint at the call site to the return value's container.
  - If the callee summary indicates `param_container_aliases`, update the call-site points-to to reflect the alias.

### 11.4 — Test fixtures
The container fixtures from Phase 8 (`tests/fixtures/container_taint_py/`, `tests/fixtures/container_taint_js/`) should now pass with `required_findings` listing the expected taint flow.

Add new cross-file container fixtures:

**Factory pattern** (`tests/fixtures/cross_file_container_factory/`):
```javascript
// factory.js
export function makeBag() { return []; }
export function fillBag(bag, val) { bag.push(val); return bag; }

// app.js
import { makeBag, fillBag } from './factory.js';
const bag = makeBag();
fillBag(bag, process.env.INPUT);
require('child_process').exec(bag[0]);
```

Expected: `taint-unsanitised-flow` from env to exec via cross-file factory + filler.

### 11.5 — Receiver-fallback robustness fixture
Per the audit's engine fragility item 7 (receiver-fallback for zero-arg method calls):

`tests/fixtures/receiver_chain_taint_java/`:
```java
// Tainted receiver flowing through chained no-arg builder methods
String tainted = System.getenv("INPUT");
String result = tainted.trim().toLowerCase();
Runtime.getRuntime().exec(result);
```

Expected: finding should fire (verify the fix doesn't introduce a false negative here; the existing receiver-fallback may already handle this — the fixture pins the behavior).

### 11.6 — Callback rename/alias regression
Per the audit's engine fragility item 8 (callback bindings name-keyed):

`tests/fixtures/cross_file_callback_alias/`:
```javascript
// helpers.js
export function dangerous(x) { require('child_process').exec(x); }

// app.js
import { dangerous } from './helpers.js';
const f = dangerous;
const g = f;
g(process.env.INPUT);
```

Expected: finding via the alias chain. If the engine cannot resolve `g → f → dangerous`, document as known limitation; otherwise add as `required_finding`.

## Acceptance criteria
- Container fixtures from Phase 8 (`container_taint_py`, `container_taint_js`) now have `required_findings` populated and the tests pass.
- New `cross_file_container_factory` fixture passes.
- New `receiver_chain_taint_java` fixture pins current behavior.
- New `cross_file_callback_alias` fixture either passes or documents the gap.
- `cargo nextest run --all-features` passes.
- Benchmark gate passes (`cargo test --release ... benchmark_evaluation`); precision/recall do not regress below floors.

## Tests
- See above. Run `cargo nextest run --test cross_file_container_*`.

## Notes
- This phase is engineering-heavy. Do not expand scope into "fix all heap aliasing." The goal is "container identity propagates through documented summary edges."
- If `PointsToSummary` is already rich enough but the application logic in `ssa_transfer.rs` is missing, that is the cheaper fix path.
- This phase is the load-bearing piece for moving interprocedural analysis from Acceptable → Strong.

---

# Phase 12: Catch-block CFG invariants and Switch terminator

## Goal
Two engine-correctness improvements: (1) add an SSA-lowering invariant that every catch-labeled block is either reachable via normal flow OR via an exception edge; (2) introduce `Terminator::Switch(SmallVec<[BlockId; 4]>)` to replace the current cascade-of-If lowering for switch statements.

## Issues addressed
- Engine fragility item 5 (catch-block reachability silently over-widened)
- Engine fragility item 6 (Switch lowered as cascade, loses precision)

## Why this matters
Today's "give orphan blocks all definitions" fallback is sound for taint reachability (no false negatives) but masks CFG-builder bugs. Adding the invariant assertion catches "we forgot to construct an exception edge to this catch block" early instead of letting it manifest as silent false negatives in resource-cleanup findings.

Switch lowering as cascaded If statements works for taint but loses precision for predicate solving and abstract interpretation. A real `Terminator::Switch` enables better analysis of large switches in Go, Rust, and Java.

## Files to read first
- `src/ssa/lower.rs` (~2.1K) — `form_blocks`, the orphan handling at lines ~1264–1310, exception edge stripping at lines ~245–257
- `src/cfg.rs` — search `Switch` to see how switch statements are currently constructed
- The memory file `project_switch_cfg.md` for context on the cascade workaround

## Tasks

### 12.1 — Catch-block reachability invariant
In `src/ssa/lower.rs`, after block formation but before phi insertion:

- Identify every block whose label is `catch` (or whose corresponding CFG node is a catch).
- For each, verify: it is reachable from the function entry via the (filtered) normal-flow CFG OR it is the target of at least one entry in `exception_edges`.
- If neither, this is a CFG construction bug. Behavior:
  - In debug builds (`#[cfg(debug_assertions)]`): `panic!` with a descriptive message identifying the file, function, and orphan block.
  - In release builds: emit `tracing::warn!` and proceed with the current "all definitions" fallback. Push `EngineNote::SsaLoweringBailed { reason: "catch_block_orphan: <details>" }` to all findings from this body.

### 12.2 — Add invariant test
In `src/ssa/invariants.rs`, add a public `pub fn check_catch_block_reachability(body: &SsaBody) -> Result<(), InvariantError>` and call it from the existing invariant pipeline.

In `tests/ssa_equivalence_tests.rs`, add a test that constructs a synthetic CFG with an orphan catch block and asserts the invariant fires (in a controlled way that doesn't panic the test process — use the release-build code path or a feature-flagged "do-not-panic" mode).

### 12.3 — `Terminator::Switch` variant
In `src/ssa/ir.rs` (or wherever `Terminator` is defined), add:

```rust
pub enum Terminator {
    // ... existing variants ...
    Switch {
        scrutinee: SsaValue,
        targets: SmallVec<[BlockId; 4]>,
        default: BlockId,
    },
}
```

### 12.4 — Construct Switch in lowering
- In `src/ssa/lower.rs`, find the cascade-of-If construction for switch statements (likely in or near the language-specific switch handling).
- When the source CFG indicates a switch, emit `Terminator::Switch` instead of an If cascade.
- The cascade fallback should remain for languages whose switch semantics include fall-through (C, C++, Java with non-arrow switch). For these, document why the cascade is preserved (in a code comment), or model fall-through as additional Switch targets.

### 12.5 — Update consumers
- `src/taint/ssa_transfer.rs` — handle the new terminator variant. For taint, all targets receive the same input state (no branch-aware narrowing yet); the abstract-interp / predicate logic can later use the scrutinee value.
- `src/abstract_interp/` — the new variant can refine intervals on the scrutinee per-target if literal cases are involved (optional refinement; can be a follow-up).
- `src/symex/` — handle the new variant; for symex, each target gets a path constraint `scrutinee == case_value`.

### 12.6 — Tests
- `tests/fixtures/large_switch_go/`: a Go switch with 6+ cases dispatching to different sinks. Verify findings fire correctly per case.
- `tests/fixtures/switch_fall_through_c/`: a C switch with explicit fall-through. Verify the cascade fallback still works.

## Acceptance criteria
- `cargo nextest run --all-features` passes.
- The new catch-block invariant test passes (asserts the invariant fires in a controlled scenario).
- The Switch terminator works for at least one language (Go is easiest; Java/Rust if time permits).
- `tests/ssa_equivalence_tests.rs::ssa_lowering_is_deterministic` still passes.

## Tests
- New invariant test in `tests/ssa_equivalence_tests.rs`.
- New fixtures under `tests/fixtures/`.

## Notes
- This phase is the most complex. If time runs out, ship the catch-block invariant alone; the Switch terminator can be a follow-up.
- The Switch terminator change ripples through every consumer of `Terminator`. Use the compiler errors as a checklist.
- Do not change CFG construction at the AST → CFG layer for switch — only the SSA lowering layer. This keeps the change localized.

---

# Phase 13: Real-CVE replay corpus

## Goal
Add a small corpus of real (historical, patched) CVEs as benchmark cases — at least one per stable-tier language. This dramatically strengthens the credibility of the published F1 numbers.

## Issues addressed
- Audit's "no real-repo validation" gap
- Strengthens benchmark realism (audit's #18 framing)

## Why this matters
Today's benchmark corpus is 264 synthetic mini-fixtures (20–120 LOC each). The audit specifically calls out: "A 95% F1 on toy fixtures is not equivalent to 95% F1 on a real Django project." Adding even a small real-CVE corpus turns the benchmark from "regression protection on toy code" into "regression protection that demonstrably catches real historical bugs."

## Files to read first
- `tests/benchmark/ground_truth.json`
- `tests/benchmark/RESULTS.md`
- `tests/benchmark_test.rs`

## Tasks

### 13.1 — Pick CVEs
Choose 1–3 real CVEs per stable-tier language. Criteria:
- Public, with a known patch.
- Small enough to extract a 50–500 LOC excerpt that captures the vulnerable pattern.
- The vulnerability class is one Nyx is supposed to detect (taint to a sink that has a corresponding rule).
- License of the original code is permissive (MIT, BSD, Apache 2.0). For copyleft code (GPL), include only the minimal vulnerable function with an attribution header.

Suggested starter set:
- **Python**: a Django CVE involving `RawSQL` or `extra(where=...)` with user input.
- **JavaScript**: a node.js CVE involving `child_process.exec` with concatenated user input.
- **TypeScript**: an Express middleware CVE involving an unsanitized header in a redirect or HTML response.

### 13.2 — Extract minimal reproducers
For each CVE:
- Create `tests/benchmark/cve_corpus/<lang>/<cve_id>/`.
- `vulnerable.{py,js,ts}`: the minimal extracted vulnerable code, with the source attribution and CVE link in a header comment.
- `patched.{py,js,ts}`: the minimal patched version.

### 13.3 — Wire into ground truth
- Add entries to `tests/benchmark/ground_truth.json`:
  - For each `vulnerable.*`: expected rule ID, expected sink line, `provenance: "real_cve"`, `notes: "CVE-XXXX-YYYY: <one-line description>"`.
  - For each `patched.*`: `forbidden_rule_ids: [...]` to assert the patched version does not fire.

### 13.4 — Update RESULTS.md
- Add a section "Real-CVE Corpus" listing each included CVE with its detection status.
- Compute and publish per-CVE precision/recall.

### 13.5 — README acknowledgement
Add a sentence under §Detection Accuracy:

> The corpus also includes <N> real historical CVEs across <M> languages; per-CVE results are tracked in `tests/benchmark/RESULTS.md` under "Real-CVE Corpus."

## Acceptance criteria
- At least 3 real CVEs in the corpus (1 per stable language).
- Each CVE's vulnerable file produces a Nyx finding mapping to the documented rule.
- Each CVE's patched file produces no relevant finding.
- `cargo test --release --all-features --test benchmark_test -- --ignored --nocapture benchmark_evaluation` passes.

## Tests
- The benchmark test (`benchmark_evaluation`) is the test.

## Notes
- Be cautious about license attribution. GPL'd source extracted into this repo (also GPL) is fine but include a header. MIT/BSD: include the original license header alongside Nyx's GPL.
- If a chosen CVE is not detected by current Nyx, that's a finding — either pick a different CVE, or document as a known gap and use the patched version as the assertion ("Nyx does not yet detect CVE-X but should not regress on the patched version").
- Keep the extracted code minimal — do not commit a full vulnerable application. The corpus is for regression protection, not for demonstrating the CVE end-to-end.

---

# Phase 14: Code health refactors (post-release safe)

## Goal
Split the two largest files in the codebase (`src/cfg.rs` at 10K LOC, `src/taint/ssa_transfer.rs` at 9K LOC) into per-concern submodules. This improves maintainability without changing behavior.

## Issues addressed
22, 23

## Why this matters
A 10K-line file is a contributor barrier and a refactoring landmine. Splitting it does not reduce defect risk in the short term, but materially improves long-term maintainability. This phase is explicitly post-release-safe — it can ship in 0.5.1 or 0.6.

## Files to read first
- `src/cfg.rs` — scan the file's top-level structure (sections, language-specific functions)
- `src/taint/ssa_transfer.rs` — same

## Tasks

### 14.1 — Split `src/cfg.rs`
Suggested split:

```
src/cfg/
  mod.rs              Public types: NodeInfo, EdgeKind, FuncSummaries, FuncKey aliases (~500 lines)
  builder.rs          Top-level build_cfg orchestration, push_node, edge construction (~1500 lines)
  python.rs           Python-specific AST → CFG handlers
  javascript.rs       JS-specific
  typescript.rs       TS-specific (or shared with JS via composition)
  java.rs             Java-specific
  go.rs               Go-specific
  ruby.rs             Ruby-specific
  php.rs              PHP-specific
  c.rs                C-specific
  cpp.rs              C++-specific
  rust.rs             Rust-specific
  shared.rs           Cross-language helpers (call extraction, span manipulation, etc.)
```

- Move language-specific functions into the per-language file.
- Keep public types in `mod.rs` so external `use crate::cfg::{NodeInfo, ...}` continues to work.
- Verify no behavior change: `cargo nextest run --all-features` must pass identically.

### 14.2 — Split `src/taint/ssa_transfer.rs`
Suggested split:

```
src/taint/ssa_transfer/
  mod.rs              SsaTaintTransfer, run_ssa_taint, run_ssa_taint_full (entry points)
  state.rs            SsaTaintState, lattice ops (join, leq), origin merging
  transfer.rs         transfer_inst, transfer_block, per-op handling
  inline.rs           InlineCache, ArgTaintSig, inline_analyse_callee, callback_bindings
  events.rs           SsaTaintEvent → Finding conversion (ssa_events_to_findings)
  helpers.rs          Small utility functions (try_curl_url_propagation, etc.)
```

- The 5K-line `tests.rs` sibling can stay or be split into per-concern test files.

### 14.3 — Behavior parity
- Run the full test suite and benchmark gate before and after.
- Diff the JSON output of a benchmark scan before and after — should be byte-identical.

## Acceptance criteria
- `src/cfg.rs` and `src/taint/ssa_transfer.rs` no longer exist as monolithic files (they are now directories).
- All public APIs unchanged.
- `cargo nextest run --all-features` passes.
- Benchmark gate produces identical numbers.
- `cargo clippy --all-targets --all-features -- -D warnings` passes.

## Tests
- Behavior parity is the test. No new tests required.

## Notes
- This is a high-risk-of-merge-conflict phase. Do it on a branch with no other in-flight work, merge fast.
- Resist any "while I'm here" cleanups. Keep the diff to pure file moves and mechanical renames.
- Defer to after the 0.5.0 release if there is any time pressure.

---

## Closing notes

After Phases 1–8 are complete, the audit's blockers and high-priority issues are closed. After Phases 9–13, the engineering quality goals (Strong core engine and Strong interprocedural analysis) are met. Phase 14 is post-release maintenance.

A reasonable shipping order:

- **Pre-0.5.0 release**: Phases 1, 2, 3, 4, 5, 9 (the doc/release blockers + the two highest-impact engine fixes + the C/C++ honesty)
- **0.5.1 patch release**: Phases 6, 7, 8, 10 (correctness and test depth, can land hot after 0.5.0)
- **0.6 minor release**: Phases 11, 12, 13 (the larger engine work and benchmark depth)
- **Maintenance**: Phase 14

If forced to ship 0.5.0 with only Phase 1 and Phase 4 done, that addresses the two true blockers (documentation contradictions + the silent JS/TS cap) at minimum acceptable cost.
