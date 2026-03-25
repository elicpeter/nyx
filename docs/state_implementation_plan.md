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

## Phase 7 — State Engine Default-On Audit Gate

This phase is an AUDIT / GO-NO-GO phase first, not an implementation phase first.

The goal is to determine whether the state engine, after Phases 1-13 excluding Phase 7, is actually ready to be enabled by default.

You must evaluate the real current codebase and benchmark artifacts directly. Do not assume prior docs, comments, plans, or memory are accurate. Prefer code and test outputs over roadmap text.

### Primary Objectives

1. **Benchmark finding adjudication comes first**
    - Start by auditing the new benchmark findings in `tests/benchmark/...`, especially the findings currently labeled or suspected as "FPs" in the latest benchmark output.
    - Inspect `tests/benchmark/results/latest.json` directly.
    - Focus specifically on findings produced by the state engine / state rules.
    - For each new or disputed benchmark finding:
        - determine whether it is a **true positive (TP)** or a **false positive (FP)**
        - explain why
        - identify whether the benchmark expectation is stale / missing state expectations versus the engine actually being wrong
    - Produce a clear adjudication table/report:
        - finding id / file / rule
        - why it fired
        - TP or FP
        - whether expected results should be updated
        - whether the engine behavior should be fixed instead
    - Do **not** blindly treat benchmark "FP" labels as ground truth if the benchmark corpus simply does not yet encode valid state findings.

2. **Audit the current state engine after all completed phases**
    - Audit the actual current implementation of the state engine after Phases 1-13 excluding Phase 7.
    - Determine whether the engine is genuinely ready for default enablement.
    - Evaluate:
        - precision / noise
        - obvious unsoundness or overfiring patterns
        - per-language behavior and whether any language is notably weaker/noisier
        - config/profile integration
        - performance overhead
        - output quality in JSON / SARIF / console
        - whether current safeguards are sufficient for default-on
    - This is a real readiness audit, not a box-checking exercise.

3. **Make a go / no-go decision**
    - At the end of the audit, explicitly answer:
        - Is the state engine ready to turn on by default now?
        - If yes, why?
        - If no, what specific blockers remain?
    - If the answer is “not yet,” give the minimal concrete fix list required before default-on.

### Audit Requirements

- Read actual source code, configs, CLI wiring, tests, and benchmark outputs directly.
- Do not rely on stale roadmap text, comments, or prior assumptions.
- Distinguish:
    - benchmark expectation gaps
    - real engine false positives
    - output / classification issues
    - config / profile issues
    - performance issues
- Be skeptical and evidence-driven.

### Files / Areas To Audit

- `tests/benchmark/results/latest.json`
- `tests/benchmark/...`
- all state-analysis related code paths
- `src/utils/config.rs`
- `src/cli.rs`
- rule definitions and state detector wiring
- output serialization / reporting paths
- any test fixtures relevant to state findings

### Required Deliverables

1. **Benchmark FP/TP audit report**
    - Review all new state-related benchmark findings in `latest.json`
    - Classify each as TP or FP
    - State whether the benchmark expectation is stale or the engine is wrong

2. **State engine readiness audit**
    - Summarize the state engine’s quality after Phases 1-13 excluding 7
    - Call out strengths, weaknesses, noisy patterns, and language-specific concerns

3. **Default-on recommendation**
    - One of:
        - **GO**: safe to enable by default now
        - **GO WITH SAFETY VALVES**: safe to enable by default, but only with specific safeguards
        - **NO-GO**: do not enable by default yet
    - This recommendation must be justified with concrete evidence from the audit

4. **Only if the audit result is GO or GO WITH SAFETY VALVES: implementation plan**
    - Then and only then propose the implementation steps for flipping default-on
    - Include:
        - `enable_state_analysis` default change
        - profile defaults
        - `--no-state` CLI flag
        - optional per-language gating if justified by audit results
        - docs updates
    - If the audit is NO-GO, do not implement the default-on flip. Instead produce the blocker list and the next corrective phase.

### Important Decision Rules

- If benchmark “FPs” are actually real TPs caused by stale expected results, say so clearly.
- If even one language is materially noisier than the rest, call that out explicitly and decide whether that blocks default-on or merely justifies per-language gating.
- Do not add per-language gating unless the audit shows it is actually warranted as a safety valve.
- Do not flip the default just because the roadmap expected it by this phase. The audit result controls the decision.

### Desired Final Output

Return an audit report with these sections:

1. Benchmark finding adjudication
2. State engine quality audit
3. Performance / integration audit
4. Default-on decision: GO / GO WITH SAFETY VALVES / NO-GO
5. If GO: exact implementation changes to make
6. If NO-GO: exact blockers and next required phase

The first task in this phase is the benchmark adjudication. Do not skip it.

---

## Phase 8 — Java and PHP Constructor Callee Fix

**Problem:** Java and PHP use constructor-based resource acquisition (`new
FileInputStream(path)`, `new mysqli(host, ...)`), but the CFG's callee
extraction produces only the type name (e.g. `"FileInputStream"`), while the
resource pair patterns expect `"new FileInputStream"`. This mismatch means
**zero** Java state findings fire. C++ already has special-case normalization
for `new_expression` → `"new"`, but Java's `object_creation_expression` and
PHP's OOP constructors are unhandled.

### Root Cause

In `cfg.rs:1561-1569`, `Kind::CallFn` extraction tries field `"type"` last
and returns the bare type name. In `cfg.rs:1614-1618`, the C++ `new_expression`
override produces `"new"` but is guarded by `lang == "cpp"`.

Java patterns in `rules.rs:267-277` use `"new FileInputStream"` etc. The
`callee_matches()` function in `transfer.rs:258-267` does exact-or-suffix
matching, so `"fileinputstream"` never matches `"new fileinputstream"`.

### Approach

**Option A (preferred):** Fix the resource pair patterns to not include `"new "`.
Change `"new FileInputStream"` to `"FileInputStream"` in `JAVA_RESOURCES`.
This is simpler, requires no CFG changes, and callee_matches suffix semantics
already handle it (`"fileinputstream".ends_with("fileinputstream")` → true).

**Why not fix the callee?** Adding a `"new "` prefix to Java callees would
affect taint analysis label matching, SSA lowering, and everything else that
reads `info.callee`. Changing only the resource pair patterns is isolated to
state analysis.

For PHP, apply the same fix: add `"mysqli"` as an acquire alias alongside
`"mysqli_connect"` in `PHP_RESOURCES`, since `new mysqli(...)` extracts as
`"mysqli"`.

### Deliverables

1. **Fix Java resource pair patterns** (`src/cfg_analysis/rules.rs`)
   - Change `JAVA_RESOURCES` acquire from `["new FileInputStream", ...]` to
     `["FileInputStream", "FileOutputStream", "BufferedReader", "openConnection"]`
   - Add `getConnection` if not already present

2. **Add Java database resource pair** (`src/cfg_analysis/rules.rs`)
   - New `ResourcePair`: acquire `["DriverManager.getConnection", "getConnection"]`,
     release `[".close"]`, resource_name `"db connection"`
   - New `ResourcePair`: acquire `["Socket"]`, release `[".close"]`,
     resource_name `"socket"`

3. **Fix PHP OOP constructor matching** (`src/cfg_analysis/rules.rs`)
   - Add `"mysqli"` to the db connection acquire list alongside `"mysqli_connect"`
   - This handles both procedural `mysqli_connect(...)` and OOP `new mysqli(...)`

4. **Add per-language use patterns** (`src/cfg_analysis/rules.rs`,
   `src/state/transfer.rs`)
   - Add `use_patterns: &'static [&'static str]` field to `ResourcePair`
   - PHP curl: `["curl_exec", "curl_getinfo", "curl_setopt"]`
   - PHP mysqli: `["mysqli_query", "mysqli_fetch_array", ".query", ".fetch"]`
   - Java: `[".read", ".write", ".flush", ".available"]`
   - Keep the global `RESOURCE_USE_PATTERNS` as a fallback; check pair-specific
     patterns first

5. **Update test fixtures and expectations**
   - Promote Java `stream_lifecycle.expect.json` entries to `must_match: true`
   - Promote Java `connection_lifecycle.expect.json`, `double_close.expect.json`,
     `branch_close.expect.json` where findings now fire
   - Promote PHP `db_connection.expect.json` and `curl_state.expect.json`
   - Add unit test fixtures: `java_file_stream_leak.java` (leak without TWR),
     `java_file_stream_clean.java` (explicit close), `php_curl_use_after_close.php`,
     `php_mysqli_leak.php`
   - Add tests to `state_tests.rs` for Java and PHP lifecycle

### Success Criteria
- Java `new FileInputStream(path)` without close → `state-resource-leak`
- Java `.close()` twice → `state-double-close`
- PHP `curl_exec()` after `curl_close()` → `state-use-after-close`
- PHP `new mysqli(...)` without close → `state-resource-leak`
- All 4 Java real-world fixtures fire reliably (`must_match: true`)
- Java row in accuracy table changes from "Limited" to "Yes" across all columns

### Key Files
- `src/cfg_analysis/rules.rs` — `JAVA_RESOURCES`, `PHP_RESOURCES`, `ResourcePair`
- `src/state/transfer.rs` — `RESOURCE_USE_PATTERNS`, use detection logic
- `tests/state_tests.rs` — new Java/PHP tests
- `tests/fixtures/real_world/java/state/*.expect.json`
- `tests/fixtures/real_world/php/state/*.expect.json`

---

## Phase 9 — JavaScript/TypeScript Use Pattern Completeness

**Problem:** JavaScript and TypeScript have working acquire/release matching
(`fs.openSync`/`fs.closeSync` fire correctly), but use-after-close detection
is incomplete. The `RESOURCE_USE_PATTERNS` list uses suffix matching, and
`"readSync"` does not end with `"read"` (it ends with `"Sync"`). Similarly,
`"writeSync"` does not match `"write"`. This means `fs.readSync(fd, buf)`
after `fs.closeSync(fd)` does not produce `state-use-after-close`.

### Root Cause

`callee_matches("fs.readsync", "read")` → checks:
1. `"fs.readsync" == "read"` → false
2. `"fs.readsync".ends_with("read")` → false (ends with "readsync")

The `Sync` suffix breaks suffix matching for all Node.js `fs` module methods.

### Deliverables

1. **Extend `RESOURCE_USE_PATTERNS`** (`src/state/transfer.rs`)
   - Add JS/TS-specific patterns: `"readSync"`, `"writeSync"`, `"readFileSync"`,
     `"writeFileSync"`, `"appendFileSync"`, `"ftruncateSync"`, `"fsyncSync"`,
     `"fstatSync"`
   - Add stream operation patterns: `"pipe"`, `"unpipe"`, `"resume"`,
     `"pause"`, `"destroy"` (for streams after `.close()`)
   - Add generic method patterns that cover multiple languages: `".read"`,
     `".write"`, `".send"`, `".recv"`, `".query"`, `".execute"`, `".fetch"`
     (dot-prefix patterns catch method-call forms like `fd.read()`)

2. **Add per-pair use patterns via Phase 8's `use_patterns` field**
   - JS fd pair: `["fs.readSync", "fs.writeSync", "fs.fstatSync",
     "fs.ftruncateSync", "fs.fsyncSync"]`
   - JS stream pair: `[".pipe", ".resume", ".write", ".read", ".push"]`

3. **Update test fixtures and expectations**
   - Promote JS `handle_reuse.expect.json` use-after-close entry to
     `must_match: true`
   - Add unit test: `js_fs_use_after_close.js` — `fs.openSync` → `fs.closeSync`
     → `fs.readSync` → expect `state-use-after-close`
   - Add unit test: `ts_stream_use_after_destroy.ts` — stream `.destroy()` →
     `.write()` → expect `state-use-after-close`

### Success Criteria
- `fs.readSync(fd, buf)` after `fs.closeSync(fd)` → `state-use-after-close`
- JS/TS accuracy table changes from "Partial" to "Yes" for Use-After-Close
- All existing JS/TS state tests still pass

### Key Files
- `src/state/transfer.rs` — `RESOURCE_USE_PATTERNS`
- `src/cfg_analysis/rules.rs` — JS_RESOURCES (per-pair use patterns)
- `tests/fixtures/real_world/javascript/state/handle_reuse.expect.json`
- `tests/state_tests.rs`

---

## Phase 10 — Ruby State Detection Fix

**Problem:** Ruby has the lowest state detection accuracy. The real-world
fixture `file_lifecycle.rb` explicitly documents "state engine does not yet
fire for Ruby" — all 3 state entries (leak, double-close, use-after-close)
are soft misses. However, the unit test `ruby_file_open_no_close.rb` DOES
fire `state-resource-leak`, and `ruby_file_open_close.rb` correctly produces
no findings. This suggests acquire/release matching works for simple cases but
fails for multi-function fixtures.

### Investigation Steps (do before coding)

1. Run the real-world `file_lifecycle.rb` through the scanner with debug output
   to determine WHY the state engine misses:
   - Does the CFG correctly extract `File.open` as the callee?
   - Does `.close` match as a release?
   - Are the receiver variables (`f`) in the `uses` field of release nodes?
   - Is the `defines` field set on the acquire node?

2. Compare the CFG output for the working unit test (`ruby_file_open_no_close.rb`)
   vs the failing real-world fixture (`file_lifecycle.rb`)

3. Check if multi-function files cause SymbolInterner name collisions (same
   variable name `f` in multiple Ruby functions → same SymbolId → state
   contamination across functions)

### Likely Root Causes (based on code analysis)

**A. Per-function scope isolation:** The state engine runs on the full-file
CFG. If `file_lifecycle.rb` has multiple functions (`read_and_leak`,
`read_and_close`, `double_close`, `use_after_close`), their variable states
bleed into each other because `SymbolInterner` is name-based. Function
`read_and_close` properly closing `f` may overwrite the OPEN state from
`read_and_leak`, masking the leak.

**B. Ruby `call` vs `method_call` dispatch:** Ruby's tree-sitter grammar uses
`call` for `f.close` (receiver.method style). Check that `labels/ruby.rs`
maps `call` to `Kind::CallMethod` so receiver extraction runs correctly.

**C. Missing receiver in `uses`:** Even if callee is `"f.close"`, the
transfer function checks `info.uses` for the variable name. If `"f"` is not
in `uses`, the release won't mark `f` as CLOSED.

### Deliverables

1. **Diagnose the exact failure** — add tracing or run the scanner with
   `NYX_LOG=debug` on `file_lifecycle.rb` to identify which step breaks

2. **Fix scope contamination** (if cause A) — the cleanest fix is to run the
   state engine per-function rather than per-file. The synthesized function
   exit nodes already exist in the CFG. Alternative: reset `ResourceDomainState`
   at function boundaries.

3. **Fix receiver variable tracking** (if cause C) — in `push_node()` for
   `Kind::CallMethod`, ensure the receiver identifier is added to `info.uses`
   so the state transfer can find the variable being released.

4. **Extend Ruby resource pairs** (`src/cfg_analysis/rules.rs`)
   - Add use patterns: `[".read", ".write", ".gets", ".puts", ".each_line",
     ".readline", ".readlines", ".sysread", ".syswrite"]`
   - Add db pair: `PG.connect`/`.close` or `Sequel.connect`/`.disconnect`

5. **Update test expectations**
   - Promote Ruby `file_lifecycle.expect.json` state entries to `must_match: true`
   - Promote Ruby `conditional_close.expect.json` secondary entry
   - Add unit tests for Ruby double-close and use-after-close

### Success Criteria
- Ruby `File.open` without close → `state-resource-leak`
- Ruby `.close` twice → `state-double-close`
- Ruby read after close → `state-use-after-close`
- Ruby accuracy table changes from "Partial" to "Yes" across all columns
- Multi-function Ruby files produce correct per-function findings

### Key Files
- `src/cfg.rs` — `push_node()` receiver extraction for Ruby `call` nodes
- `src/state/engine.rs` — per-function vs per-file execution scope
- `src/state/symbol.rs` — `SymbolInterner` scope isolation
- `src/cfg_analysis/rules.rs` — `RUBY_RESOURCES`
- `tests/fixtures/real_world/ruby/state/file_lifecycle.rb`
- `tests/state_tests.rs`

---

## Phase 11 — Scope-Aware Symbol Interning

**Problem:** The `SymbolInterner` in `src/state/symbol.rs` maps variable names
to `SymbolId` values using a flat `HashMap<String, SymbolId>`. This means:

1. Same-name variables across different functions share a SymbolId, causing
   state contamination (one function's close affects another function's leak
   detection)
2. Variable shadowing within a function — inner-scope `f` and outer-scope `f`
   are the same symbol, so inner close masks outer leak

Problem 1 is the primary cause of Ruby/PHP/Java detection failures in
multi-function files (Phase 10 may partially address this). Problem 2 is a
known false negative documented in Phase 6 edge-case tests.

### Approach

Add function-scoped interning: the SymbolId key becomes
`(enclosing_function_name, variable_name)` rather than bare `variable_name`.

### Deliverables

1. **Add function context to SymbolInterner** (`src/state/symbol.rs`)
   - Change `from_cfg()` to accept a mapping from `NodeIndex` →
     `Option<String>` (enclosing function name)
   - Build this mapping during CFG construction: track which function body
     each node belongs to
   - Intern as `format!("{}::{}", func_name, var_name)` or use a tuple key

2. **Build enclosing-function map** (`src/cfg.rs` or `src/state/mod.rs`)
   - During CFG construction, `build_sub()` already knows when it enters a
     function definition (Kind::FnDef)
   - Thread the current function name through `build_sub()` and store it on
     each node's `NodeInfo` as `enclosing_func: Option<String>`
   - Alternative: post-process the CFG to compute function ownership from
     the dominator tree or node ranges

3. **Update transfer and facts** (`src/state/transfer.rs`, `src/state/facts.rs`)
   - Transfer: no changes needed — it uses SymbolId, which is now scoped
   - Facts: leak detection at exit nodes now correctly scoped per-function
   - Event messages: include function name for clarity

4. **Handle top-level code** — nodes not inside any function get a synthetic
   scope like `"<toplevel>"`. This is the fallback for languages like Python
   where code can be at module level.

5. **Test fixtures**
   - Update `variable_shadowing.c` test — now outer leak SHOULD be detected
     (change from `assert_no_state_findings` to `assert_has_prefix("state-resource-leak")`)
   - Add `multi_function_isolation.c` — two functions, same variable name `f`,
     one leaks and one doesn't → expect exactly 1 leak finding
   - Add `multi_function_isolation.rb` — same for Ruby

### Success Criteria
- `variable_shadowing.c` now reports outer-scope leak (false negative fixed)
- Multi-function files produce independent per-function findings
- No regressions in existing tests
- Variable name `f` in function A is independent of `f` in function B

### Key Files
- `src/state/symbol.rs` — `SymbolInterner` internals
- `src/cfg.rs` — `NodeInfo` struct (new `enclosing_func` field), `build_sub()`
- `src/state/transfer.rs` — transfer function
- `src/state/facts.rs` — finding extraction
- `tests/state_tests.rs` — updated shadowing test, new isolation tests

---

## Phase 12 — Factory Return Suppression and Cross-Function Hints

**Problem:** Functions that open a resource and return it to the caller (factory
pattern) produce false-positive `state-resource-leak` findings because the
state engine has no model for cross-function ownership transfer. This is one
of the two remaining "Common False Positives" documented in `state.md`.

### Approach

**Return-value suppression:** If a variable that is OPEN at function exit is
also the return value of the function, suppress the leak finding. The
resource's lifetime extends to the caller — the caller is responsible for
closing it.

This requires detecting which variable (if any) is returned. The CFG already
has `Kind::Return` nodes. If the returned expression is a simple variable
reference that matches an OPEN resource, suppress the leak.

### Deliverables

1. **Detect returned variables** (`src/state/facts.rs`)
   - In the finding extraction pass, scan the function's return nodes for
     returned variable names
   - Build a `HashSet<SymbolId>` of returned variables
   - In leak detection, if a variable is OPEN at exit AND in the returned set,
     suppress `state-resource-leak` and `state-resource-leak-possible`

2. **Identify return nodes in CFG** (`src/cfg.rs`)
   - Return nodes already exist as `Kind::Return` in the CFG
   - The returned expression is in `info.uses` or can be extracted from the
     AST child of the return node
   - Add `info.returned_var: Option<String>` to capture the simple variable
     name being returned (only for single-variable returns — complex
     expressions don't qualify)

3. **Cross-function resource hints via summaries** (optional, stretch goal)
   - Add `returns_resource: bool` to `FuncSummary`
   - Set it during pass 1 when a function returns an OPEN variable
   - In pass 2, callers that invoke a resource-returning function and don't
     close the result can be flagged with higher confidence
   - This inverts the current false positive into a true positive at the
     call site

4. **Test fixtures**
   - Update `resource_returned.c` test — now should produce NO state findings
     (change from `assert_has_prefix("state-resource-leak")` to
     `assert_no_state_findings`)
   - Add `factory_caller_leak.c` — calls `open_file()` but never closes result
     → expect `state-resource-leak` (stretch: via cross-function hint)
   - Add `factory_caller_clean.c` — calls `open_file()` and closes result →
     no findings

### Success Criteria
- Factory function `open_file()` that returns `fopen()` result → no leak finding
- Caller of factory that neglects close → still flagged (via summary, if implemented)
- No regressions — functions that open and DON'T return still report leaks

### Key Files
- `src/state/facts.rs` — return-value suppression logic
- `src/cfg.rs` — `NodeInfo` (optional `returned_var` field), return node handling
- `src/summary/mod.rs` — `FuncSummary` (optional `returns_resource` field)
- `tests/state_tests.rs` — updated factory test, new caller tests

---

## Phase 13 — Expanded Resource Pairs and Auth Improvements

**Problem:** Current resource pair definitions cover the most common patterns
per language, but miss many real-world APIs. Auth detection is limited to
function name patterns and a small set of auth-call matchers. This phase
expands coverage breadth.

### Deliverables

1. **Expand resource pairs per language** (`src/cfg_analysis/rules.rs`)

   **Java additions:**
   - `PreparedStatement`/`.close`, `ResultSet`/`.close`
   - `ServerSocket`/`.close`, `DatagramSocket`/`.close`
   - `RandomAccessFile`/`.close`
   - `Channel`/`.close` (NIO)

   **Python additions:**
   - `urllib.request.urlopen`/`.close`
   - `http.client.HTTPConnection`/`.close`
   - `sqlite3.connect`/`.close`
   - `tempfile.NamedTemporaryFile`/`.close`
   - `zipfile.ZipFile`/`.close`

   **Go additions:**
   - `http.Get`/`resp.Body.Close()` — tricky: requires recognizing that
     `resp.Body` is the resource, not `resp`
   - `sql.Open`/`.Close` (database/sql)
   - `net.Listen`/`.Close`
   - `bufio.NewReader` → no close needed (wraps, doesn't own)

   **JavaScript/TypeScript additions:**
   - `net.createConnection`/`.end`, `.destroy`
   - `http.request`/`.end`, `.destroy`
   - `new WebSocket`/`.close`
   - Database: `mysql.createConnection`/`.end`,
     `pg.Pool`/`.end`, `new Client`/`.end`

   **Ruby additions:**
   - `Net::HTTP.start`/`.finish`
   - `PG.connect`/`.close`, `PG::Connection.new`/`.close`
   - `SQLite3::Database.new`/`.close`
   - `Tempfile.new`/`.close`

   **PHP additions:**
   - `pg_connect`/`pg_close`
   - `pdo` → `new PDO`/`null` (no explicit close, but connection lifecycle)
   - `fsockopen`/`fclose`
   - `stream_socket_client`/`fclose`

2. **Expand auth detection** (`src/state/transfer.rs`)
   - Add middleware-style patterns: `authenticate`, `authorize`, `requireAuth`,
     `ensureAuthenticated`, `passport.authenticate`
   - Add decorator patterns: recognize `@login_required`, `@requires_auth`
     annotations in Python (requires AST inspection for decorators on the
     function definition, not just call-level matching)
   - Add JWT/token patterns: `verifyToken`, `validateToken`, `jwt.verify`,
     `decodeToken`
   - Add role-based patterns: `hasPermission`, `checkPermission`,
     `requireRole`, `can`

3. **Add negative tests for over-broad auth patterns**
   - `auth_false_positive_token.js` — function named `generateToken()` should
     NOT be treated as auth check
   - `auth_decorator_python.py` — `@login_required` decorated handler should
     suppress `state-unauthed-access`

4. **Update real-world expectations**
   - Re-audit Go `http_body.expect.json` — if `http.Get` pair is added, the
     leak finding should now fire
   - Re-audit JS `db_connection.expect.json` — if `mysql.createConnection` pair
     is added, the leak should fire

### Success Criteria
- ≥80% of real-world state expectations are `must_match: true`
- At least 3 new resource pairs per language
- Auth detection covers JWT/token verification patterns
- No new false positives from broader patterns (validated via negative tests)

### Key Files
- `src/cfg_analysis/rules.rs` — all `*_RESOURCES` definitions
- `src/state/transfer.rs` — auth_rules, ADMIN_PATTERNS
- `tests/state_tests.rs` — new auth and resource tests
- `tests/fixtures/real_world/*/state/*.expect.json`

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
Phase 8 (Java + PHP constructor fix) ──┐
    |                                   |
Phase 9 (JS/TS use pattern fix) ───────┤
    |                                   |
Phase 10 (Ruby state detection fix) ───┤
    |                                   |
Phase 11 (scope-aware interning) ──────┘
    |
Phase 12 (factory return suppression)
    |
Phase 13 (expanded pairs + auth)
    |
Phase 7 (flip default) ← moved to end
```

Phases 8-10 are independent of each other (each fixes a different language)
and can be done in any order. Phase 11 (scope-aware interning) builds on the
diagnostic work from Phase 10 and benefits all languages. Phase 12 (factory
suppression) requires Phase 11's function-scoped symbols. Phase 13 (expanded
pairs) is breadth expansion that benefits from all prior fixes. Phase 7
(default-on flip) moves to the end as the final gate after all precision
improvements.

## Risk Mitigations

| Risk | Mitigation |
|------|------------|
| NodeInfo field additions bloat memory | `auto_cleanup` and `in_defer` are `bool` (1 byte each); negligible |
| RAII suppression hides real Rust bugs | Only suppress leaks; keep use-after-close/double-close for unsafe code |
| Auth matching too strict after fix | Test both positive (real handlers) and negative (non-handlers) cases |
| Benchmark overhead >10% | Per-function analysis with bounded lattice; budget cap at 100K iterations |
| Per-language gating adds config complexity | Make it optional (`Option<Vec>`); default `None` runs all languages |
| Java pattern change affects taint analysis | Only change resource pair patterns, not callee extraction |
| Use pattern expansion causes false use-after-close | Each new pattern must have positive+negative test |
| Scope-aware interning changes finding counts | Run full test suite before/after; update expectations |
| Factory suppression hides real leaks | Only suppress when return value IS the open resource; not for side effects |
| Broad auth patterns cause false negatives | Add negative tests; use word-boundary matching for all new patterns |

## Metrics to Track Across Phases

| Metric | Phase 1 | Phase 6 | Phase 13 | Phase 7 |
|--------|---------|---------|----------|---------|
| must_match true % | 31% (baseline) | ≥60% | ≥80% | ≥80% |
| state_tests.rs test count | 28 | ≥62 | ≥80 | ≥80 |
| Languages with basic tests | 3 (C, Py, JS) | 10 | 10 | 10 |
| Languages with "Yes" across all detection | 4 (C, C++, Py, Go) | 4 | 9 (all but Java limited→Yes) | 9 |
| Auth test count | 0 | ≥7 | ≥12 | ≥12 |
| Known FP categories | 6 | 4 | ≤1 | ≤1 |
| Benchmark overhead | unmeasured | measured | measured | <10% |

---

## Phase 7 — Audit Results & Implementation (completed)

### Decision: GO WITH SAFETY VALVES

**Audit summary:**
- 29 state findings across benchmark corpus; all marked "unexpected" because ground truth predates state analysis
- 23 NOISE-TPs: technically correct resource leaks in short demo snippets (benchmark corpus gap)
- 5 real FPs: Go `state-unauthed-access` on safe files with allowlist/map-check patterns
- 1 borderline FP: Python `Popen` + `communicate()` not recognized as cleanup

**Implementation (GO WITH SAFETY VALVES):**
1. `enable_state_analysis` default flipped to `true` — resource lifecycle analysis (leak, use-after-close, double-close) runs by default
2. `enable_auth_analysis` added as separate config (default `false`) — auth analysis stays opt-in due to FP rate on allowlist/guard patterns
3. `--no-state` CLI flag added to disable state analysis entirely
4. `"full"` profile enables both state + auth analysis
5. All tests pass: 1098 lib + 100 state + 20 integration + 26 SSA equiv + 7 perf + 4 taint termination
