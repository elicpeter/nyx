# State Analysis: Default-On Implementation Plan

> Goal: Make state analysis (resource lifecycle + auth state tracking) trustworthy
> enough to enable by default for all full scans.
>
> Each phase is scoped to one Claude Code session. Phases are ordered by
> precision impact — the biggest sources of user-facing false positives are
> fixed first.

---

## Current State (as of audit, 2026-03-24)

**Verdict: NOT YET default-ready.**

Key blockers:
1. False positives on idiomatic cleanup patterns (Python `with`, Go `defer`,
   Java try-with-resources, Rust RAII, C++ smart pointers)
2. Auth condition detection uses substring matching — overfires
3. No tests for `state-unauthed-access` in the basic test suite
4. Console output does not render `StateEvidence` fields
5. No benchmark data for state analysis overhead
6. Only 31% of real-world expect.json assertions are hard (`must_match: true`)

Architecture that is already solid:
- Genuine monotone dataflow engine with bounded lattices and two-phase worklist
- Full pipeline integration (gate, conversion, ranking, confidence, SARIF)
- All 10 languages have resource pair definitions
- 28 integration tests + 18 unit tests + 40 real-world fixtures

---

## Phase 1 — Auth Analysis Hardening

**Problem:** The auth condition matcher at `transfer.rs:202` uses
`cond_lower.contains(matcher)`, which is simple substring matching. This means
`if (not_is_authenticated)` or `if (cached_is_authenticated_flag != null)`
both match `"is_authenticated"` and spuriously elevate auth level. Combined
with prefix-based web handler detection (`api_version_string()` matches
`api_*`), this produces High-severity, High-confidence false positives —
the most damaging kind.

Additionally, `state-unauthed-access` has **zero tests** in `state_tests.rs`.
The only coverage is the `rust_web_app` integration fixture (which validates
`min_count: 3`, not exact findings).

### Deliverables

1. **Fix auth condition matching** (`src/state/transfer.rs:199-203`)
   - Replace `cond_lower.contains(&m)` with word-boundary-aware matching
   - Approach: split condition text on non-identifier characters, check if any
     token matches the auth matcher exactly (or via suffix, like
     `callee_matches()` already does for call nodes)
   - Ensure `if (!is_authenticated)` with `condition_negated = true` still
     correctly skips elevation (already handled, but add test)

2. **Tighten web handler detection** (`src/state/facts.rs:228-233`)
   - `serve_*` and `process_*` are weak prefixes — require web parameter
     confirmation for these (currently `strong_name` skips the param check)
   - Only `handle_*`, `route_*`, `api_*` should be strong names
   - Consider: require at least one parameter from the web-params list for
     all handler prefixes, removing the "strong name" bypass entirely

3. **Add auth test suite** (`tests/state_tests.rs`)
   - Positive: function named `handle_request(req)` with `exec(cmd)` call
     and no auth check → expect `state-unauthed-access`
   - Positive: same function with `is_authenticated()` call before sink → no
     finding
   - Negative: function named `process_batch()` with no web params → no finding
     (not a web handler)
   - Negative: `if (!is_authenticated)` → should NOT elevate (negated)
   - Negative: function named `main()` → no finding (excluded)
   - FP regression: `api_version_string()` → no finding (no web params,
     no privileged sink)

4. **Add auth test fixtures** (`tests/fixtures/state/`)
   - `auth_unprotected_handler.rs` — handler with shell exec, no auth
   - `auth_protected_handler.rs` — handler with auth check before exec
   - `auth_not_a_handler.py` — `process_data()` with no web params
   - `auth_negated_condition.js` — `if (!is_authenticated)` should not elevate

### Success Criteria
- All new tests pass
- `state-unauthed-access` has ≥6 dedicated test assertions (positive + negative)
- No substring-matching FPs possible in condition text

### Key Files
- `src/state/transfer.rs` — condition matching logic (lines 186-224)
- `src/state/facts.rs` — web entrypoint detection (lines 215-261)
- `tests/state_tests.rs` — test suite
- `tests/fixtures/state/` — fixture directory

---

## Phase 2 — Python `with` and Java Try-With-Resources Suppression

**Problem:** Python `with open(f) as f:` and Java
`try (var s = new FileInputStream(...))` are the standard resource management
patterns in their respective languages. The state engine sees the acquire
call but has no model for the implicit cleanup, producing false
`state-resource-leak` findings. The `with_statement.expect.json` fixture
already documents 3 of 4 expected findings as "noise."

### Approach

The CFG builder processes `with_item` as `Kind::CallWrapper` and
`try_with_resources_statement` resources as sequential predecessors to the try
body. Neither adds any cleanup metadata. The fix is to mark acquisition nodes
that occur inside auto-cleanup scopes.

### Deliverables

1. **Add `auto_cleanup` field to `NodeInfo`** (`src/cfg.rs`)
   - `auto_cleanup: bool` — true when this node's defined variable will be
     automatically cleaned up by the language runtime (context manager,
     try-with-resources)
   - Default: `false`

2. **Set `auto_cleanup` for Python `with_item`** (`src/cfg.rs`)
   - In the `Kind::CallWrapper` handler (around line 1086), when the parent
     AST node is `with_item` / `with_clause` / `with_statement`, set
     `auto_cleanup = true` on the resulting call node
   - Implementation: thread parent kind through `build_sub()`, or inspect the
     tree-sitter parent of the current node

3. **Set `auto_cleanup` for Java try-with-resources** (`src/cfg.rs`)
   - In `build_try()` (around line 2324), when processing the `resources`
     field of `try_with_resources_statement`, set `auto_cleanup = true` on
     resource declaration nodes

4. **Suppress leaks for `auto_cleanup` variables** (`src/state/facts.rs`)
   - In `extract_findings()` leak detection (lines 75-140), skip variables
     whose acquisition node has `auto_cleanup = true`
   - Implementation: build a `HashSet<SymbolId>` of auto-cleanup variables
     by scanning CFG nodes where `auto_cleanup == true && defines.is_some()`,
     then exclude those symbols from leak reporting

5. **Update test expectations**
   - `python_with_statement` test: change from "known limitation" to "correctly
     suppressed"
   - `with_statement.expect.json`: remove noise entries, keep real leak in else
     branch
   - Add new fixture: `python_with_nested.py` — nested `with` blocks with one
     real leak outside `with`
   - Add new fixture: `java_try_with_resources.java` — TWR with one safe and
     one unsafe function

### Success Criteria
- Python `with open(f) as f:` produces zero state-resource-leak findings
- Java TWR produces zero state-resource-leak findings for resources in the
  resource clause
- Real leaks outside `with`/TWR blocks are still detected
- All existing tests still pass

### Key Files
- `src/cfg.rs` — NodeInfo struct, `build_sub()`, `build_try()`
- `src/state/facts.rs` — `extract_findings()` leak detection
- `tests/state_tests.rs` — Python tests
- `src/labels/python.rs` — `with_statement` → `Kind::Block` mapping
- `src/labels/java.rs` — `try_with_resources_statement` → `Kind::Try` mapping

---

## Phase 3 — Go `defer` Suppression

**Problem:** Go's `defer f.Close()` is the standard resource cleanup pattern.
The CFG currently maps `defer_statement` to `Kind::Block`, processing its
children sequentially. This means `defer f.Close()` marks `f` as CLOSED at
the defer statement's position, not at function exit. This causes:
- `state-use-after-close` FP: any use of `f` after the `defer` line
- Incorrect leak semantics: `f` appears closed mid-function instead of at exit

This is a different problem from Phase 2 — `defer` doesn't suppress the close,
it *repositions* it to function exit.

### Approach

Mark close calls inside `defer` blocks so the state analysis can handle them
specially: don't mark the variable as CLOSED immediately, but do suppress leak
findings for it at function exit.

### Deliverables

1. **Add `in_defer: bool` to `NodeInfo`** (`src/cfg.rs`)
   - True when this node is inside a `defer_statement`
   - Default: `false`

2. **Set `in_defer` during CFG construction** (`src/cfg.rs`)
   - In `build_sub()`, when the current AST node kind is `defer_statement`
     (Go), set a flag that propagates to all child nodes
   - Implementation: add `in_defer: bool` parameter to `build_sub()` or use a
     thread-local/context field. Set it when entering `defer_statement`,
     clear when leaving.

3. **Handle deferred closes in state transfer** (`src/state/transfer.rs`)
   - In the release detection logic (lines 109-136): if the release node has
     `in_defer == true`, do NOT mark the variable as CLOSED and do NOT emit
     DoubleClose. Instead, add a new `ResourceLifecycle::DEFERRED` bit (or
     repurpose MOVED).
   - Alternative simpler approach: skip the release entirely in transfer, and
     instead handle it in `extract_findings()` — if a variable is OPEN at
     exit but has a deferred close, suppress the leak.

4. **Track deferred closes for leak suppression** (`src/state/facts.rs`)
   - Scan CFG for release nodes with `in_defer == true`, collect the variables
     they close into a `HashSet<SymbolId>`
   - In leak detection: if variable is in the deferred-close set, suppress
     both `state-resource-leak` and `state-resource-leak-possible`
   - Do NOT suppress `state-use-after-close` or `state-double-close` for
     deferred variables (those are still valid findings if the defer itself
     is the problem)

5. **Add test fixtures**
   - `go_defer_close.go` — `os.Open()` + `defer f.Close()` + `f.Read()` →
     no findings (clean pattern)
   - `go_defer_missing.go` — `os.Open()` without defer → `state-resource-leak`
   - `go_defer_double.go` — `defer f.Close()` twice → questionable, but no
     false positive on the use

6. **Update real-world Go fixtures**
   - Update `go/state/*.expect.json` to make defer-related expectations hard
     (`must_match: true`)

### Success Criteria
- `f, _ := os.Open(...); defer f.Close(); data := read(f)` → zero findings
- Missing defer still detected as leak
- All existing Go tests pass

### Key Files
- `src/cfg.rs` — NodeInfo struct, `build_sub()`
- `src/labels/go.rs` — `defer_statement` → `Kind::Block`
- `src/state/transfer.rs` — release detection
- `src/state/facts.rs` — leak suppression
- `tests/fixtures/state/` — new Go fixtures

---

## Phase 4 — Rust RAII and C++ Smart Pointer Suppression

**Problem:** Rust guarantees resource cleanup via `Drop`. Every `File::open()`
is automatically closed when the variable goes out of scope. The only Rust
resource pair is `alloc`/`dealloc` (unsafe raw memory), which is extremely
niche. Reporting `state-resource-leak` for normal Rust file/socket usage is
pure noise. C++ has a similar issue with smart pointers (`unique_ptr`,
`shared_ptr`, RAII wrappers).

### Deliverables

1. **Per-language resource-leak suppression policy** (`src/state/facts.rs`)
   - Add a function `lang_has_raii(lang: Lang) -> bool` returning true for
     Rust (always RAII) and optionally C++ (partial RAII)
   - For Rust: suppress ALL `state-resource-leak` and
     `state-resource-leak-possible` findings. Keep `state-use-after-close`
     and `state-double-close` (still valid for unsafe code).
   - For C++: suppress leaks only when the acquire pattern is NOT
     `malloc`/`calloc`/`realloc`/`new` (smart pointers don't use these)

2. **C++ smart pointer detection** (`src/state/transfer.rs`)
   - Recognize `std::make_unique`, `std::make_shared`,
     `std::unique_ptr`, `std::shared_ptr` as RAII-managed acquires
   - Add these to the C++ resource pairs with a new `raii_managed: bool` field
     on `ResourcePair`, or handle in transfer as "auto-cleanup"
   - Alternative simpler approach: just suppress C++ leaks for non-malloc
     acquires, since `new` without smart pointer wrapping is the real risk

3. **Variable scope tracking** (`src/state/symbol.rs`, `src/state/transfer.rs`)
   - Currently, variables are flat-interned by name — `f` in inner block and
     `f` in outer block are the same SymbolId
   - Add scope-awareness: use `(enclosing_func, name)` as the interning key
     instead of bare `name`
   - This prevents inner-scope closes from masking outer-scope leaks and
     vice versa
   - Note: full block-level scoping is not available in CFG; function-level
     scoping is the practical granularity

4. **Add test fixtures**
   - `rust_file_open.rs` — `File::open()` without close → no leak (RAII)
   - `rust_unsafe_alloc.rs` — `alloc()` without `dealloc()` → leak detected
   - `cpp_smart_ptr.cpp` — `make_unique<File>(...)` → no leak
   - `cpp_raw_new.cpp` — `new char[1024]` without delete → leak detected

5. **Update Rust/C++ real-world expectations**
   - Review and update `rust/state/*.expect.json` and `cpp/state/*.expect.json`
   - Convert appropriate `must_match: false` to `must_match: true`

### Success Criteria
- Rust `File::open()` without explicit close → zero findings
- Rust `alloc()` without `dealloc()` → still detected
- C++ `make_unique<>()` → zero leak findings
- C++ `malloc()` without `free()` → still detected
- Variable shadowing across functions does not cause cross-contamination

### Key Files
- `src/state/facts.rs` — RAII suppression policy
- `src/state/symbol.rs` — `SymbolInterner` scoping
- `src/cfg_analysis/rules.rs` — ResourcePair definitions
- `tests/fixtures/state/` — new fixtures

---

## Phase 5 — Console Rendering and Benchmark Infrastructure

**Problem:** State findings appear in JSON/SARIF with full `StateEvidence`
(machine, subject, from_state, to_state), but the console renderer in `fmt.rs`
silently drops this information. Users see only the message text with no state
machine context. Additionally, no benchmark data exists for state analysis
overhead — the micro-benchmark suite (`scan_bench.rs`) does not enable state
analysis.

### Deliverables

1. **Render `StateEvidence` in console output** (`src/fmt.rs`)
   - After the message line, render state transition info:
     ```
     12:5  [HIGH] state-use-after-close  (Score: 47.0, Confidence: High)
       variable `f` used after close
       State: resource [closed → used]  subject: f
     ```
   - Use the existing label rendering pattern (lines 295-326) as a template
   - Color the state transition with dim/cyan styling to distinguish from
     taint evidence
   - For `state-resource-leak`: show acquisition location if available
     (evidence.sink has this)

2. **Add remediation hints per rule ID** (`src/output.rs` or `src/fmt.rs`)
   - `state-use-after-close`: "Ensure the resource is not accessed after
     calling close/free. Consider restructuring to use the resource before
     releasing it."
   - `state-double-close`: "Remove the duplicate close call, or guard with a
     null/closed check."
   - `state-resource-leak`: "Add a close/free call before the function exits,
     or use a language-specific cleanup pattern (defer, with, try-with-resources,
     RAII)."
   - `state-resource-leak-possible`: "Ensure the resource is closed on all
     code paths, including error/early-return paths."
   - `state-unauthed-access`: "Add an authentication check before this
     operation, or move it behind an auth middleware/guard."

3. **Add state analysis benchmark** (`benches/scan_bench.rs`)
   - New benchmark function: `bench_full_scan_with_state`
   - Same fixture set as `bench_full_scan`, but with
     `cfg.scanner.enable_state_analysis = true`
   - Register in `criterion_group!`
   - This gives a direct A/B comparison: full scan vs full scan + state

4. **Add per-function state analysis benchmark**
   - New benchmark: `bench_state_analysis_only`
   - Parse a single large fixture, build CFG, run only
     `state::run_state_analysis()` in the benchmark loop
   - Measures state analysis overhead in isolation

5. **Add tracing spans** (`src/state/engine.rs`)
   - Add `tracing::debug_span!("state_engine_phase1")` and
     `tracing::debug_span!("state_engine_phase2")` to the two-phase engine
   - Add iteration count to Phase 1 span: `tracing::debug!(iterations = ...)`

### Success Criteria
- Console output shows state transition info for all 5 rule types
- `cargo bench` includes state analysis comparison benchmark
- Benchmark produces reproducible numbers for state analysis overhead
- Overhead is documented (target: <10% of full scan time)

### Key Files
- `src/fmt.rs` — console rendering
- `src/output.rs` — rule descriptions
- `benches/scan_bench.rs` — benchmark suite
- `src/state/engine.rs` — tracing instrumentation

---

## Phase 6 — Harden Test Expectations and Real-World Validation

**Problem:** Only 31% (29/92) of real-world state fixture expectations are
`must_match: true`. The remaining 69% are aspirational — they document what
the engine *should* find but don't fail if it misses. After Phases 1-5 fix
the major FP sources, we should convert soft expectations to hard ones wherever
detection is now reliable, and validate against the full benchmark corpus.

### Deliverables

1. **Audit all 40 real-world state fixtures**
   - Run the full scan on each fixture individually
   - For each `must_match: false` expectation, check if the finding is now
     reliably produced
   - Convert to `must_match: true` where the engine reliably detects the issue
   - Remove expectations that are no longer relevant (e.g., Python `with` noise
     entries removed in Phase 2)
   - Target: ≥60% of expectations should be `must_match: true`

2. **Add missing language coverage in basic test suite**
   - `state_tests.rs` currently has C (19 fixtures), Python (5), JS (2)
   - Add at least 2 fixtures each for: Go, Java, Ruby, PHP
   - Each language should have at least one positive and one negative test
   - Focus on language-specific patterns (Go defer, Java streams, Ruby blocks,
     PHP curl)

3. **Run full benchmark corpus evaluation**
   - Execute: `cargo test benchmark_evaluation -- --ignored --nocapture`
   - Analyze results: are state findings causing TP, FP, FN, or TN outcomes?
   - Document the precision/recall impact of state analysis on overall scanner
     accuracy
   - If state findings cause FPs in the corpus, investigate and fix or suppress

4. **Add edge-case regression tests**
   - Variable shadowing across nested scopes
   - Resource passed as function argument (ownership transfer ambiguity)
   - Resource returned from function (not a leak)
   - Multiple resources opened in sequence (only some closed)
   - Resource opened in loop iteration (each iteration leaks vs. reuse)

5. **Document known limitations**
   - Update `docs/detectors/state.md` with post-Phase-5 accuracy profile
   - List what IS detected, what is NOT detected, and what produces known
     false positives
   - Per-language accuracy notes (e.g., Rust: only unsafe alloc; C: full
     coverage)

### Success Criteria
- ≥60% of real-world expectations are `must_match: true`
- All 10 languages have at least 2 tests in `state_tests.rs`
- Benchmark corpus shows no new FPs introduced by state analysis
- Edge-case regression tests all pass
- Known limitations documented

### Key Files
- `tests/fixtures/real_world/*/state/*.expect.json` — all 40 expect files
- `tests/state_tests.rs` — basic test suite
- `tests/benchmark_test.rs` — corpus evaluation
- `docs/detectors/state.md` — documentation

---

## Phase 7 — Default-On Flip

**Problem:** After Phases 1-6, state analysis should be precise enough for
default enablement. This phase flips the default, adds per-language gating
as a safety valve, and validates the full experience.

### Pre-Conditions (must be verified, not assumed)
- [ ] Phase 1 complete: auth matching uses word-boundary logic
- [ ] Phase 2 complete: Python `with` + Java TWR suppressed
- [ ] Phase 3 complete: Go `defer` suppressed
- [ ] Phase 4 complete: Rust RAII + C++ smart pointers suppressed
- [ ] Phase 5 complete: console rendering + benchmark data available
- [ ] Phase 6 complete: ≥60% hard expectations, all 10 languages tested
- [ ] Benchmark overhead: <10% of full scan time
- [ ] Benchmark corpus: no new FPs from state analysis

### Deliverables

1. **Change default to enabled** (`src/utils/config.rs`)
   - `enable_state_analysis: bool` default from `false` to `true`
   - The "quick" profile should still have state analysis off (AST-only mode
     skips CFG entirely, so state analysis wouldn't run anyway)
   - The "ci" profile should enable state analysis (same as "full")

2. **Add per-language state analysis control** (`src/utils/config.rs`)
   - New config field: `state_analysis_languages: Option<Vec<String>>`
   - When set, only run state analysis for the listed languages
   - When `None` (default), run for all languages
   - This gives users an escape hatch if one language produces too much noise

3. **Add `--no-state` CLI flag** (`src/cli.rs`)
   - Quick opt-out for users who find state analysis noisy
   - Maps to `cfg.scanner.enable_state_analysis = false`

4. **Update profile defaults**
   - "quick": mode=Ast, state=off (no change)
   - "ci": mode=Full, state=on (new)
   - "full": mode=Full, state=on (no change)
   - "taint_only": mode=Taint, state=off (no change)
   - "conservative_large_repo": mode=Ast, state=off (no change)

5. **Integration validation**
   - Run full test suite: `cargo test --all-features`
   - Run benchmark corpus: verify no regression
   - Run on 2-3 real open-source repos (if available as test fixtures) to
     check for noise in the wild
   - Verify JSON/SARIF/console output looks correct for all 5 rule types

6. **Update documentation**
   - `docs/configuration.md`: document new default, `--no-state` flag,
     `state_analysis_languages` config
   - `docs/detectors/state.md`: mark as default-on, update accuracy profile
   - `docs/quickstart.md`: mention state analysis in default output description

### Success Criteria
- `enable_state_analysis` defaults to `true`
- All existing tests pass with the new default
- `--no-state` flag works correctly
- Per-language gating works correctly
- Documentation is updated

### Key Files
- `src/utils/config.rs` — default value, profile defaults, new config field
- `src/cli.rs` — new CLI flag
- `docs/configuration.md` — user-facing docs
- `docs/detectors/state.md` — detector docs

---

## Phase Dependency Graph

```
Phase 1 (auth fix)
    |
Phase 2 (Python with + Java TWR)
    |
Phase 3 (Go defer)
    |
Phase 4 (Rust RAII + C++ smart ptr + scoping)
    |
Phase 5 (console rendering + benchmarks)
    |
Phase 6 (harden expectations + validation)
    |
Phase 7 (flip default)
```

Phases 1-4 are strictly ordered (each adds NodeInfo fields or transfer logic
that later phases build on). Phase 5 is semi-independent but benefits from
Phases 1-4 being complete. Phase 6 requires all suppressions in place. Phase 7
is the final gate.

## Risk Mitigations

| Risk | Mitigation |
|------|------------|
| NodeInfo field additions bloat memory | `auto_cleanup` and `in_defer` are `bool` (1 byte each); negligible |
| RAII suppression hides real Rust bugs | Only suppress leaks; keep use-after-close/double-close for unsafe code |
| Auth matching too strict after fix | Test both positive (real handlers) and negative (non-handlers) cases |
| Benchmark overhead >10% | Per-function analysis with bounded lattice; budget cap at 100K iterations |
| Per-language gating adds config complexity | Make it optional (`Option<Vec>`); default `None` runs all languages |

## Metrics to Track Across Phases

| Metric | Phase 1 | Phase 6 | Phase 7 |
|--------|---------|---------|---------|
| must_match true % | 31% (baseline) | ≥60% | ≥60% |
| state_tests.rs test count | 28 | ≥42 | ≥42 |
| Languages with basic tests | 3 (C, Py, JS) | 10 | 10 |
| Auth test count | 0 | ≥6 | ≥6 |
| Known FP categories | 6 | ≤2 | ≤2 |
| Benchmark overhead | unmeasured | measured | <10% |
