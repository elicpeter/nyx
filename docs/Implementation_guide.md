# Post-SSA Implementation Guide — Static Analysis Hardening & Capability Expansion

This is the execution-order roadmap for completing Nyx's remaining static analysis capabilities after the SSA IR milestone. Each phase is sized for one Claude Code implementation pass.

## Current State (as of Phase 17 completion — 2026-03-24)

**Engine:** SSA-only taint analysis across 10 languages. Two-pass scanning with cross-file summaries (both `FuncSummary` and `SsaFuncSummary` persisted to SQLite). Call graph with Tarjan SCC + topological ordering used for pass 2 scheduling (callee-first batch processing with SCC fixed-point iteration, max 3 iterations). SSA optimizations: constant propagation, copy propagation, alias analysis, dead code elimination, type fact inference, points-to analysis. JS/TS two-level solve for cross-scope taint. k=1 call-site-sensitive inline analysis with caching. Abstract interpretation (interval + string product domain) with widening at loop heads. Constraint solving (PathEnv with equality/relational/disequality constraints). Symbolic feasibility checking (single-path, constraint-based, produces Infeasible/Confirmed/Inconclusive verdicts). Points-based confidence scoring integrating all evidence sources.

**Test infrastructure:** 880+ tests (795 lib + 85 integration/fixture), 0 failures. 265 SSA corpus fixtures. 6 cross-file integration test projects. Real-world fixtures verify specific rule IDs, line ranges, and must_match semantics. Negative tests (e.g., `unsafe_string_bounded.js`) prove suppression does NOT over-fire.

**Implemented phases (1-17):** All implemented and wired into the default scan pipeline. See phase-by-phase sections below for details. All features default ON except state analysis (`cfg.scanner.enable_state_analysis`). Feature gates: `NYX_CONTEXT_SENSITIVE`, `NYX_ABSTRACT_INTERP`, `NYX_CONSTRAINT`, `NYX_SYMEX` (all default ON).

**Remaining architectural debt:**
- SSA summaries discarded during SCC fixed-point iteration (only `FuncSummary` caps updated between iterations — precision loss for mutually recursive functions)
- Alias analysis is copy-propagation-based, not field/reference-sensitive
- Gated sinks only for JS/TS and Python (Java/Go/Ruby/etc. have no gated sink rules)
- Guard detection is name-based pattern matching ("validate", "sanitize", "check_"), not semantic
- Callee normalization discards module path (`std::env::var` → `var`) — overload ambiguity
- Single-path symbolic execution (no forking) — Phase 18b addresses this

---

## Strategy Overview

The sequencing follows a **precision-first, then depth** philosophy:

1. **Fix what's broken before building deeper.** The 28 FPs at 67% precision mean a third of reported findings are noise. Adding deeper analysis (alias, context sensitivity, abstract interpretation) would amplify false positives, not fix them. Precision improvements come first.

2. **Ground every capability in validation.** Each phase has benchmark exit criteria. No phase that changes analysis output ships without demonstrating precision/recall stability or improvement.

3. **Build from the bottom up.** Summaries feed interprocedural analysis, which feeds context sensitivity, which feeds alias/points-to. Richer summaries must precede richer interprocedural analysis.

4. **Harden before generalizing.** SSA lowering, CFG construction, and label classification have language-specific edge cases that need hardening before building type-aware or field-sensitive analysis on top.

5. **Consolidate infrastructure before depth.** The call graph exists but isn't used for scheduling. The confidence/ranking system exists but doesn't suppress low-confidence findings. Wire these up before adding more analysis layers.

Order: correctness → precision → modeling → summaries → pruning → sensitivity → alias/points-to → abstract interpretation → symbolic execution.

---

## Phase 1: Benchmark Noise Reduction and Sink Classification Tightening

**Category:** Precision — False Positive Reduction

**Why now:** 28/44 safe cases are FP. Five of those are non-security sinks (console.log, Logger.info, error_log, log.Printf, logging.info) that should never produce taint findings. This is the lowest-hanging precision fruit — pure label tightening with no engine changes.

### Goals
- Eliminate non-security-sink FPs across all 5 languages
- Classify sinks as security-relevant vs informational
- Tighten overly broad sink matchers (Java `println`/`print`/`write` currently match all output, not just HTTP response output)
- Suppress findings where sink lacks security semantics

### Files/systems likely to be touched
- `src/labels/javascript.rs`, `python.rs`, `java.rs`, `go.rs`, `php.rs`, `ruby.rs`
- `src/labels/mod.rs` — potential `SinkKind` or `SecurityRelevance` annotation
- `src/taint/ssa_transfer.rs` — sink event filtering
- `tests/benchmark/` — ground truth updates

### Concrete implementation tasks
1. Audit all sink rules across all 10 languages; flag sinks that match non-security operations (logging, debug output, length computation)
2. Either remove non-security sinks from RULES or add a `security_relevant: bool` field to `LabelRule` / `DataLabel::Sink`
3. For Java: restrict `println`/`print`/`write` to only match when on `HttpServletResponse.getWriter()` context (or remove and replace with framework-specific matchers)
4. For Go: `fmt.Fprintf(w, ...)` with `http.ResponseWriter` is a security sink; `fmt.Printf(...)` to stdout is not — differentiate via first-argument type or context
5. Add negative benchmark fixtures for borderline cases if missing
6. Validate: re-run benchmark, confirm 5 FP→TN conversions, no TP regressions

### Validation requirements
- Benchmark precision ≥ 72% (up from 67.1%)
- Zero TP regressions
- All 439 lib tests pass

### Exit criteria
- Non-security-sink safe cases (js-safe-004, py-safe-004, java-safe-004, go-safe-004, php-safe-004) classified as TN
- No new FN introduced

### Dependencies
None. This is a standalone label refinement phase.

---

## Phase 2: Sanitizer Resolution Hardening — Inline and Interprocedural

**Category:** Precision — Sanitizer Coverage

**Why now:** 5 FPs are interprocedural sanitizer failures (sanitizer called via helper function), and 3 FPs are inline sanitizer misses. SSA taint already models sanitizers, but resolution gaps remain. Fixing sanitizer coverage is high-leverage precision work.

### Goals
- Fix inline sanitizer recognition for languages where it fails
- Enable single-hop interprocedural sanitizer resolution (call to local helper that calls known sanitizer)
- Add missing sanitizer matchers per language

### Files/systems likely to be touched
- `src/taint/ssa_transfer.rs` — callee resolution for sanitizer propagation
- `src/summary/ssa_summary.rs` — `SsaFuncSummary.param_to_return` with `StripBits`
- `src/taint/mod.rs` — `extract_intra_file_ssa_summaries` integration
- `src/labels/*.rs` — add missing sanitizer matchers
- `src/cfg.rs` — ensure sanitizer node labels propagate through assignment chains

### Concrete implementation tasks
1. Diagnose inline sanitizer failures: trace `py-safe-006` (shlex.quote), `go-safe-006` (filepath.Clean), `java-safe-006` (HtmlUtils.htmlEscape) through SSA taint to find where sanitizer bits fail to strip
2. For interprocedural cases: verify that `extract_intra_file_ssa_summaries` produces `StripBits` transforms for wrapper functions; if not, debug the per-parameter probing path
3. Wire `ssa_summaries` into callee resolution in `transfer_call_node()` — confirm that when a local function is called, its `param_to_return` with `StripBits` correctly strips taint bits from the return value
4. Add any missing sanitizer matchers discovered during diagnosis (e.g., `shlex.quote` for Python SHELL_ESCAPE, `filepath.Clean`/`filepath.Base` for Go FILE_IO — verify these are already present)
5. Add unit tests for interprocedural sanitizer chains

### Validation requirements
- Benchmark precision ≥ 75%
- Interprocedural sanitizer safe cases (js-safe-003, py-safe-003, java-safe-003, go-safe-003, php-safe-003) classified as TN
- Inline sanitizer safe cases that were FP now classified as TN
- Zero TP regressions

### Exit criteria
- All 10 sanitizer-related safe cases (inline + interprocedural) are TN
- `SsaFuncSummary` correctly produces `StripBits` for sanitizer-wrapping functions

### Dependencies
Phase 1 (sink tightening should be done first to isolate sanitizer issues from sink noise).

---

## Phase 3: Validation Guard and Allowlist Pattern Recognition

**Category:** Precision — Guard/Validation Awareness

**Why now:** 10 FPs are allowlist-dominated or validated-allowlist patterns. The engine already has `classify_condition_with_target()` and predicate classification, but allowlist patterns (map lookup, `includes`, `contains`, `in_array`, `in`) are not recognized as validation predicates. Type-check guards (typeof, isinstance, is_numeric, strconv.Atoi, regex match) account for 5 more FPs.

### Goals
- Recognize allowlist membership checks as validation predicates that kill taint
- Recognize type-check patterns as validation predicates
- Ensure validation predicates that dominate a sink suppress taint findings
- Handle early-return-after-check patterns (check fails → return/throw → sink unreachable)

### Files/systems likely to be touched
- `src/taint/path_state.rs` — `classify_condition_with_target()`, `PredicateKind` enum
- `src/taint/ssa_transfer.rs` — `compute_succ_states()` branch-aware propagation
- `src/ssa/lower.rs` — ensure if/else branch structure preserves dominance for early-return patterns
- `src/cfg.rs` — condition node extraction for allowlist patterns
- `src/labels/mod.rs` — potential new `PredicateKind` variants

### Concrete implementation tasks
1. Add `PredicateKind::AllowlistCheck` — triggered by condition text containing `includes(`, `contains(`, `in_array(`, map lookup patterns, `Set.of(`, `in `, `not in `
2. Add `PredicateKind::TypeCheck` — triggered by `typeof`, `instanceof`, `isinstance`, `is_numeric`, `is_int`, `strconv.Atoi` (with error check), regex `.matches(`, `.test(`
3. Update `classify_condition_with_target()` to detect these patterns
4. In `compute_succ_states()`: when a branch is guarded by an allowlist or type check, strip taint from the validated variable on the true branch
5. Handle early-return-after-negation pattern: `if (!allowed.includes(x)) { return; }` — taint should be killed on fall-through
6. Verify against all 10 allowlist/validated benchmark cases + 5 type-check cases

### Validation requirements
- Benchmark precision ≥ 82%
- All 15 guard/validation safe cases classified as TN
- Zero TP regressions (no real vulnerabilities suppressed)

### Exit criteria
- Allowlist and type-check patterns recognized across JS, Python, Java, Go, PHP
- Early-return-after-check patterns suppress taint on the dominating path
- Benchmark FP count ≤ 13 (down from 28)

### Dependencies
Phases 1-2. Sanitizer resolution should be solid before adding predicate-based suppression, to avoid masking sanitizer bugs with overly aggressive predicate pruning.

---

Phase 3.5: Confidence Model Rework

Category: Precision — Ranking correctness

Why now:
Engine internals changed (SSA, summaries, sanitizer resolution, path pruning).
Confidence scoring may no longer reflect actual reliability of findings.

Goals:
- Redesign confidence derivation
- Use path evidence strength
- Use sanitizer/guard distance
- Use interprocedural depth
- Use type certainty
- Use summary vs direct flow
- Prepare for later alias/points-to/constraint integration

Tasks:
- Audit rank.rs
- Audit Diag.confidence assignment
- Add evidence-based scoring
- Add path-length / hop-count scoring
- Add guard dominance scoring
- Add sanitizer proximity scoring
- Add interprocedural penalty
- Add unknown-type penalty

Validation:
- Benchmark results unchanged
- Confidence distribution reasonable
- No High confidence for weak paths

Exit:
Confidence reflects actual analysis strength

---

## Phase 4: Confidence-Based Filtering and Report Quality

**Category:** Precision — Output Quality

**Why now:** The ranking system (`rank.rs`) exists and computes attack-surface scores, but doesn't suppress low-confidence findings. The `Diag.confidence` field exists but is `None` for taint findings. Wiring confidence into output filtering would let users see only high-signal results.

### Goals
- Assign confidence levels to all finding types (taint, CFG, AST, state)
- Use confidence + taint evidence strength to filter or demote findings
- Improve default output to only show Medium+ confidence findings
- Add `--min-confidence` CLI flag (already implied by `Confidence` type's `FromStr`)
- Ensure benchmark scoring accounts for confidence-filtered output

### Files/systems likely to be touched
- `src/ast.rs` — set `confidence` on taint and CFG findings
- `src/taint/ssa_transfer.rs` — confidence from evidence (source kind, sanitizer proximity, path length)
- `src/cfg_analysis/guards.rs` — already assigns confidence; verify consistency
- `src/rank.rs` — integrate confidence into score
- `src/commands/scan.rs` — filtering by min-confidence
- `src/output.rs` / `src/fmt.rs` — display confidence in output

### Concrete implementation tasks
1. Taint findings: assign High when source is `UserInput` and no validation, Medium when source is `EnvironmentConfig` or path is validated, Low when source is `FileSystem`/`Database`
2. CFG findings: already have confidence from `guards.rs`; ensure it propagates to `Diag`
3. AST pattern findings: assign confidence based on rule specificity (exact match = Medium, broad pattern = Low)
4. Add `--min-confidence low|medium|high` flag to CLI; default to showing all but tagging low-confidence findings visually
5. Update benchmark test to optionally score at different confidence thresholds
6. Add confidence to JSON/SARIF output

### Validation requirements
- All findings have non-None confidence
- Default output unchanged (no findings dropped without user opt-in)
- Benchmark scores unchanged at default confidence level

### Exit criteria
- `Diag.confidence` populated for all finding types
- `--min-confidence medium` suppresses known low-signal findings
- Ranking score incorporates confidence

### Dependencies
Phases 1-3 (precision improvements should be done before adding confidence filtering, so the filter doesn't mask fixable FPs).

---

## Phase 5: SSA Lowering Cross-Language Hardening

**Category:** Architecture — SSA Consistency

**Why now:** SSA lowering works for all 10 languages but has language-specific edge cases that could cause incorrect analysis as deeper features are built on top. The PHP `echo` FN, exception edge handling variations, and inconsistent CFG node classification across languages need hardening before type-aware or field-sensitive analysis.

### Goals
- Fix PHP `echo` as language construct (not function call) — currently a FN
- Audit and fix CFG node classification parity across all 10 languages
- Harden exception/try-catch lowering across Java, Python, PHP, Ruby, C#
- Ensure SSA lowering handles all control flow patterns each language supports
- Document and test language-specific lowering edge cases

### Files/systems likely to be touched
- `src/cfg.rs` — `push_node()` language-specific handling
- `src/labels/*.rs` — KINDS maps and PARAM_CONFIG
- `src/ssa/lower.rs` — exception edge handling, scope boundaries
- `tests/fixtures/` — language-specific edge case fixtures
- `tests/ssa_equivalence_tests.rs` — add targeted equivalence tests

### Concrete implementation tasks
1. **PHP echo:** Add `echo_statement` to PHP KINDS as a sink-capable node type. `push_node()` must emit a Sink node for `echo` even though it's not a `call_expression`. Model similarly to how assignments with sink labels work.
2. **Audit KINDS parity:** Compare KINDS maps across all 10 languages. Ensure every language has: If, While, For, Return, Break, Continue, Block, SourceFile, Function, CallFn/CallMethod, Assignment, Try (where applicable), Throw (where applicable). Document gaps.
3. **Exception edge audit:** Verify try/catch/finally lowering produces correct CFG edges for Java, Python, PHP, Ruby, C#. Test that taint propagates through catch blocks correctly.
4. **Scope boundary audit:** Verify `lower_to_ssa`'s scope-boundary function detection works for all function/method/closure/lambda syntaxes across languages.
5. **C# yield/async:** Verify iterator blocks and async/await lower correctly (or document as known limitation).
6. **Add targeted test fixtures** for each language-specific fix.

### Validation requirements
- php-xss-001 FN resolved (echo → TP)
- All 439 lib tests pass
- No SSA lowering panics on 265 corpus fixtures
- Benchmark recall ≥ 97%

### Exit criteria
- Every language's KINDS map reviewed and gap-free
- PHP echo handled as sink
- Exception edge tests pass for Java/Python/PHP

### Dependencies
Phases 1-3 (precision work should be done first — this phase may introduce new findings that need accurate sink/sanitizer handling).

---

## Phase 6: Framework Models — Web Framework Source/Sink Specialization

**Category:** Modeling — Framework Awareness

**Why now:** Current source/sink rules are function-name matchers without framework context. Express `req.query`, Flask `request.args`, Spring `@RequestParam`, Rails `params` are modeled, but framework-specific sanitizers, middleware patterns, and response APIs are incomplete. The Java `HttpClient.send()` FN specifically requires type-aware or receiver-aware resolution.

### Goals
- Expand framework-specific source/sink/sanitizer models for major frameworks
- Add framework detection (package.json, requirements.txt, pom.xml, Gemfile, go.mod)
- Use framework context to enable/disable framework-specific rules
- Model common middleware sanitization patterns

### Files/systems likely to be touched
- `src/labels/*.rs` — expanded per-language rules
- `src/labels/mod.rs` — framework detection infrastructure
- `src/utils/project.rs` — project type detection
- `src/cfg.rs` — framework-aware label classification
- `tests/benchmark/corpus/` — framework-specific fixtures

### Concrete implementation tasks
1. **Java (critical — 12.5% TN rate):** Add `PreparedStatement` as SQL_QUERY sanitizer, OWASP ESAPI sanitizers (`Encoder.encodeForHTML`, `Validator.getValidInput`), `StringEscapeUtils.escapeHtml4` already present but needs Spring `ResponseEntity` vs `System.out.println` differentiation, `Integer.parseInt`/`Long.parseLong` as type-check sanitizers
2. **JavaScript/TypeScript:** Add Express middleware patterns (`helmet`, `cors`, `csurf`), React `dangerouslySetInnerHTML` sink, `mysql2`/`pg` parameterized query sanitizers, `validator` library sanitizers
3. **Python:** Django `mark_safe` (anti-sanitizer/sink), Flask `Markup`, SQLAlchemy `text()` sink, Jinja2 auto-escape awareness (already has `bleach.clean`)
4. **Go:** Add Gin `c.Param`/`c.Query`/`c.PostForm` sources, Echo framework sources, `html/template` as sanitizer (auto-escape), `strconv.Atoi` error-checked as type sanitizer
5. **PHP:** Add Laravel `Request::input`/`$request->input()` sources, Blade `{{ }}` as sanitizer (auto-escape), `PDO::prepare` as SQL_QUERY sanitizer, `filter_input`/`filter_var` as sanitizers
6. **Ruby:** Add Rails `render` sink classification refinement, ActionController `permit`/strong parameters as sanitizer, ERB auto-escape awareness, Sinatra sources
7. **C/C++:** Add `snprintf` (bounded) as sanitizer vs `sprintf` (unbounded) sink, `strncat`/`strncpy` as bounded sanitizers
8. **Framework detection:** Parse manifest files (package.json, requirements.txt, pom.xml, Gemfile, go.mod, composer.json) to set `framework` field on analysis context; use to enable/disable rules
9. Add benchmark fixtures for at least 2 framework-specific scenarios per language
10. Expand gated sink system beyond JS/TS — add gated sinks for Python (`subprocess.Popen` with `shell=True` activation), PHP (`mysqli_query` with prepared vs raw), Java (`Runtime.exec` with array vs string args)

### Validation requirements
- No precision regression
- New framework-specific fixtures pass
- Framework detection correctly identifies Express, Flask/Django, Spring, Gin, Laravel, Rails

### Exit criteria
- At least 5 new sanitizer rules per language from framework-specific APIs
- Framework detection implemented and wired into label classification
- Java `HttpClient.send()` FN resolved via improved receiver matching or framework model

### Dependencies
Phases 1-5. Sink classification and sanitizer resolution must be solid before expanding framework models.

---

## Phase 7: Call Graph-Driven Interprocedural Scheduling

**Category:** Architecture — Interprocedural Analysis

**Why now:** The call graph is built (`callgraph.rs`) with SCC and topological analysis, but pass 2 scans files in arbitrary order. Bottom-up (callee-first) ordering means callees are analyzed before callers, so their summaries are available during caller analysis. This is prerequisite for richer interprocedural summaries.

### Goals
- Use `CallGraphAnalysis.topo_scc_callee_first` to order pass 2 analysis
- Implement SCC fixed-point iteration for mutually recursive functions
- Reduce summary imprecision from arbitrary file ordering
- Surface unresolved/ambiguous callee diagnostics

### Files/systems likely to be touched
- `src/commands/scan.rs` — pass 2 scheduling
- `src/callgraph.rs` — topo-order file grouping
- `src/summary/mod.rs` — iterative summary refinement
- `src/ast.rs` — `run_rules_on_bytes` callee resolution
- `src/taint/mod.rs` — use updated summaries mid-pass

### Concrete implementation tasks
1. After building `CallGraph` + `CallGraphAnalysis`, group files by SCC membership
2. Schedule pass 2 in `topo_scc_callee_first` order: analyze leaf functions first, then callers
3. For SCCs (mutual recursion): run analysis iteratively until summaries stabilize (max 3 iterations)
4. After each file completes pass 2, update `GlobalSummaries` with refined summaries
5. Log unresolved/ambiguous callees as INFO-level diagnostics
6. Verify that ordering change doesn't regress benchmark precision

### Validation requirements
- Benchmark precision/recall unchanged or improved
- All 439 lib tests pass
- Topo-order produces correct results on test call graphs with known dependency order

### Exit criteria
- Pass 2 runs in callee-first topological order
- SCCs iterate to fixed point
- Unresolved callees logged

### Dependencies
Phase 6 (framework models provide better callee resolution, reducing unresolved callees).

---

## Phase 8: Richer Interprocedural Summaries

**Category:** Analysis Depth — Summary System

**Why now:** `FuncSummary` stores flat bitmasks (source_caps, sanitizer_caps, sink_caps) and `propagating_params`. `SsaFuncSummary` stores per-parameter transforms. But neither captures: (a) which specific parameter flows to which sink parameter position, (b) conditional taint (only tainted if param matches certain types), (c) field-level taint flows. These limitations cause both FPs and FNs in interprocedural scenarios.

### Goals
- Extend `SsaFuncSummary` with per-parameter-to-sink-parameter flow maps
- Persist `SsaFuncSummary` to SQLite alongside `FuncSummary` for cross-file use
- Use SSA summaries for cross-file callee resolution (not just intra-file)
- Model return-value conditionality (returns tainted only if param 0 is tainted, not always)

### Files/systems likely to be touched
- `src/summary/ssa_summary.rs` — extend `SsaFuncSummary`
- `src/summary/mod.rs` — `CalleeResolution` from SSA summaries
- `src/database.rs` — SSA summary persistence
- `src/taint/ssa_transfer.rs` — use per-parameter maps in callee resolution
- `src/taint/mod.rs` — `extract_intra_file_ssa_summaries` improvements

### Concrete implementation tasks
1. Add `param_to_sink_param: Vec<(usize, usize, Cap)>` to `SsaFuncSummary` — which caller arg flows to which internal sink arg position, with what caps
2. Add serialization for `SsaFuncSummary` and persist to SQLite `ssa_function_summaries` table
3. Update `load_all_summaries()` to load SSA summaries into a parallel `HashMap<FuncKey, SsaFuncSummary>`
4. In `transfer_call_node()`, prefer SSA summary over legacy `FuncSummary` when both available
5. Model conditional return taint: `SsaFuncSummary.param_to_return` already has `TaintTransform::Identity` — extend to `Conditional(Cap)` for "only if param carries these caps"
6. Add integration tests for cross-file interprocedural taint with SSA summaries

### Validation requirements
- Cross-file taint scenarios detected correctly
- No precision regression
- Summary serialization round-trips correctly

### Exit criteria
- SSA summaries persisted to SQLite and loaded for cross-file analysis
- Per-parameter-to-sink flows used in callee resolution
- At least 3 cross-file interprocedural test cases pass

### Dependencies
Phase 7 (scheduling ensures summaries are computed in the right order).

---

## Phase 9: Flow Sensitivity Cleanup — Reassignment and Kill Analysis

**Category:** Precision — Flow Sensitivity

**Why now:** SSA already provides flow sensitivity through rename (each assignment creates a new SsaValue), but the benchmark shows 5 reassignment cases are already TN. This phase ensures the SSA-level kill semantics are correct and complete, handles reassignment-to-constant patterns robustly, and verifies that overwritten taint is truly dead.

### Goals
- Verify SSA rename correctly kills taint on variable reassignment across all 10 languages
- Handle string reassignment (`x = "constant"`) as taint kill in all contexts
- Ensure assignment-from-sanitizer kills taint (already handled via sanitizer labels, but verify edge cases)
- Handle compound assignment patterns (`x = x + constant` — taint propagates; `x = "new"` — taint killed)

### Concrete implementation tasks
1. Audit SSA taint for all reassignment safe cases — confirm they are TN and understand why
2. Test compound assignments: `x += y` (taint propagates), `x = "safe"` (taint killed), `x = sanitize(x)` (taint stripped)
3. Verify that PHI nodes at join points after `if (cond) { x = "safe"; } sink(x)` correctly track that taint may still be live on the non-reassigned path
4. Add targeted test fixtures for reassignment edge cases
5. Document any language-specific reassignment quirks

### Validation requirements
- All 5 reassignment safe cases remain TN
- No new FP or FN from reassignment handling
- PHI-aware flow sensitivity verified

### Exit criteria
- Reassignment-to-constant kills taint in all 10 languages
- Compound assignment propagation correct
- PHI join semantics verified

### Dependencies
Phases 1-5 (SSA lowering hardening ensures correct PHI placement).

---

## Phase 10: Type-Aware Analysis — SSA Type Facts Integration

**Category:** Analysis Depth — Type Sensitivity

**Why now:** `type_facts.rs` already computes `TypeKind` (String, Int, Bool, Object, Array, Null, Unknown) per SSA value. `TypeFactResult.is_int()` exists and is wired into `ssa_transfer.rs` for suppressing SQL injection on int-typed values. But type facts are not used for: (a) differentiating sink relevance by type, (b) disambiguating overloaded function names, (c) filtering by receiver type.

### Goals
- Use type facts to suppress taint findings where type makes vulnerability impossible
- Use type facts to disambiguate method resolution (e.g., `client.send()` — is `client` an HttpClient?)
- Extend type inference to handle constructor calls, factory patterns, and import resolution
- Use type facts for receiver-aware sink matching

### Files/systems likely to be touched
- `src/ssa/type_facts.rs` — extend type inference
- `src/taint/ssa_transfer.rs` — type-conditioned sink suppression
- `src/labels/mod.rs` — type-qualified sink matchers
- `src/cfg.rs` — propagate type information through CFG nodes

### Concrete implementation tasks
1. Extend `TypeKind` with `HttpResponse`, `DatabaseConnection`, `FileHandle`, `Url` — abstract types relevant to security analysis
2. Add constructor/factory type inference: `new URL(x)` → `Url`, `DriverManager.getConnection(x)` → `DatabaseConnection`
3. Use type facts to gate sink matching: `println` on an `HttpServletResponse.getWriter()` is a sink; `println` on `System.out` is not
4. Use type facts for variable-receiver resolution: `client.send()` where `client: HttpClient` resolves to `HttpClient.send` sink
5. Suppress SQL injection when value is `Int` type (already partial — extend to all languages)
6. Add type-conditioned suppression for path traversal when value is `Int`

### Validation requirements
- java-ssrf-002 FN resolved (HttpClient.send via type inference)
- No precision regression
- Type facts correctly inferred for common patterns

### Exit criteria
- Variable-receiver method calls resolve via type inference for 2+ languages
- Type-based sink suppression works for Int → SQL, Int → path traversal
- At least 3 type-aware test fixtures pass

### Dependencies
Phase 8 (richer summaries can carry type information).

---

## Phase 11: Context Sensitivity — Call-Site-Sensitive Analysis

**Category:** Analysis Depth — Context Sensitivity

**Why now:** Current analysis is context-insensitive: a function summary is the same regardless of calling context. This causes FPs when a function is safe in one calling context but unsafe in another. JS/TS two-level solve provides a limited form of context sensitivity; this phase generalizes it.

### Goals
- Implement k-limited call-site sensitivity (k=1 initially) for intra-file calls
- Specialize function summaries per call site
- Handle callback patterns (function passed as argument, called later)
- Model higher-order function patterns common in JS/Python/Ruby

### Files/systems likely to be touched
- `src/taint/ssa_transfer.rs` — call-site specialization during callee resolution
- `src/summary/ssa_summary.rs` — context-keyed summaries
- `src/taint/mod.rs` — analysis driver for context-sensitive mode
- `src/ssa/lower.rs` — inline lowering for small callees (optional optimization)

### Concrete implementation tasks
1. For intra-file calls: at each call site, instantiate the callee's SSA body with the caller's argument taint as seed
2. Cache specialized results keyed by (callee_name, argument_taint_signature) to avoid redundant analysis
3. Limit context depth to k=1 (one level of call-site sensitivity) to bound cost
4. For callbacks: when a function is passed as an argument to another function, track the callback's identity and analyze it at the call site where it's invoked
5. Benchmark context-sensitive vs context-insensitive precision/recall
6. Add a configuration flag to enable/disable context sensitivity

### Validation requirements
- No precision regression
- Context-sensitive analysis completes within 2x of context-insensitive wall time
- At least 2 callback taint scenarios detected

### Exit criteria
- k=1 call-site sensitivity implemented for intra-file calls
- Callback taint tracking works for JS/Python
- Performance within acceptable bounds

### Dependencies
Phases 7-8 (scheduling and summaries must be solid for context-sensitive analysis to build on).

---

## Phase 12: Field-Sensitive Taint Tracking

**Category:** Analysis Depth — Field Sensitivity

**Why now:** Current taint tracks whole variables (`SsaValue`), not object fields. `obj.safe_field` and `obj.tainted_field` are conflated — if any field is tainted, the whole object is. This causes FPs for objects with mixed clean/tainted fields, and FNs when taint flows through nested field access.

### Goals
- Track taint per field path (`obj.field`, `obj.nested.field`)
- Support property read/write in field-sensitive mode
- Handle destructuring assignments (JS/Python/Ruby)
- Model dictionary/map access with known string keys

### Files/systems likely to be touched
- `src/taint/ssa_transfer.rs` — field-aware taint state
- `src/taint/domain.rs` — `VarTaint` extension for field paths
- `src/ssa/ir.rs` — field access representation in SSA ops
- `src/cfg.rs` — property access node construction
- `src/labels/mod.rs` — field-qualified source/sink matching

### Concrete implementation tasks
1. Extend `SsaOp` with field access information: `SsaOp::FieldRead { base: SsaValue, field: String }`, `SsaOp::FieldWrite { base: SsaValue, field: String }`
2. In taint state: track taint per (SsaValue, field_path) pair. Use a compact representation (e.g., `SmallVec<[(SsaValue, SmallString, VarTaint); 8]>`)
3. Source nodes: `req.query.name` taints `req.query.name` specifically, not all of `req`
4. Sink nodes: `sink(obj.safe_field)` does not fire if only `obj.tainted_field` is tainted
5. Limit field path depth to 3 to bound state size
6. Handle destructuring: `const { name, age } = req.query` → `name` is tainted, `age` is tainted (all fields of tainted source)
7. Add benchmark fixtures for field-sensitive scenarios

### Validation requirements
- No precision regression
- Field-sensitive fixtures pass
- Performance within 1.5x of whole-variable analysis

### Exit criteria
- Field-level taint tracked for property access patterns
- Destructuring handled for JS/Python
- Field depth bounded at 3

### Dependencies
Phase 10 (type facts help determine which fields exist on an object). Phase 9 (flow sensitivity must be correct before adding field dimension).

---

## Phase 13: Alias Analysis — Local Must/May Analysis

**Category:** Analysis Depth — Alias Awareness

**Why now:** Current analysis has no alias awareness. If `a = b` and then `b` is sanitized, `a` retains its taint. SSA copy propagation handles some cases, but reference aliasing (`a` and `b` point to the same object) is unmodeled.

### Goals
- Implement local (intra-procedural) must-alias analysis for SSA values
- Propagate sanitization through aliases
- Handle reference/pointer aliasing for languages with reference semantics (JS, Python, Ruby, Java, C#)
- Avoid over-approximation (may-alias is conservative but imprecise)

### Files/systems likely to be touched
- New: `src/alias.rs` — alias analysis infrastructure
- `src/taint/ssa_transfer.rs` — alias-aware taint propagation and sanitization
- `src/ssa/ir.rs` — reference creation/copy tracking
- `src/ssa/copy_prop.rs` — extend to handle aliased references

### Concrete implementation tasks
1. Define `AliasSet` type — set of SsaValues that must/may refer to the same object
2. Compute local must-alias sets from SSA: direct copies (`a = b`), reference bindings, array/object element aliases
3. When a value is sanitized, also sanitize its must-aliases
4. When a value is tainted via field write, taint through must-aliases
5. Keep may-alias conservative: only suppress findings when must-alias proves safety
6. Limit alias set size (max 16 entries) to bound analysis cost
7. Add test fixtures for alias-through-sanitization scenarios

### Validation requirements
- No precision regression (alias analysis is conservative by default)
- Alias-aware sanitization suppresses at least 1 known FP pattern
- All lib tests pass

### Exit criteria
- Must-alias computed for direct copies and reference bindings
- Sanitization propagates through must-aliases
- May-alias tracked but not used for suppression

### Dependencies
Phase 12 (field sensitivity feeds into alias analysis — field writes through aliases).

---

## Phase 14: Points-To / Pointer Analysis

**Category:** Analysis Depth — Heap Modeling

**Why now:** Points-to analysis enables tracking which variables point to which heap objects. This is needed for: container element taint (array[i] tainted), map/dict value taint, object identity tracking across function boundaries. Builds on alias analysis infrastructure.

### Goals
- Implement Andersen-style inclusion-based points-to analysis (intra-procedural)
- Track abstract heap objects for constructor calls and literals
- Model container operations (array push/pop, map set/get) with points-to
- Enable inter-procedural points-to via summary extension

### Files/systems likely to be touched
- `src/alias.rs` → extend to `src/alias.rs` / `src/pointsto.rs`
- `src/taint/ssa_transfer.rs` — points-to-aware taint propagation
- `src/ssa/ir.rs` — heap object creation tracking
- `src/summary/ssa_summary.rs` — points-to summary for cross-function use

### Concrete implementation tasks
1. Define `HeapObject` type — abstract representation of allocated objects (keyed by allocation site)
2. Compute points-to sets from SSA: `new Foo()` creates HeapObject, `a = new Foo()` → `a` points-to {H1}
3. For container operations: `arr.push(x)` → H_arr contains taint from x; `y = arr[i]` → y may be tainted if H_arr is tainted
4. For map operations: `map[key] = val` → H_map.key tainted; `x = map[key]` → x tainted if H_map.key tainted
5. Bound points-to set size (max 8 objects per variable) and abstract away unbounded containers
6. Add test fixtures for container taint flow

### Validation requirements
- No precision regression
- Container taint fixtures pass
- Analysis completes within 3x of current wall time

### Exit criteria
- Intra-procedural points-to computed for object allocations
- Container element taint tracked
- Points-to sets bounded

### Dependencies
Phase 13 (alias analysis infrastructure). Phase 12 (field sensitivity for object fields).

---

## Phase 15: Path Pruning and Constraint Solving

**Category:** Precision — Advanced Pruning

**Why now:** Current path sensitivity handles branch conditions via predicate classification, but doesn't solve constraints. Infeasible paths (where branch conditions contradict) generate false positives. Constraint solving prunes these paths.

### Goals
- Implement lightweight constraint solving for branch conditions
- Prune infeasible paths where conditions contradict (e.g., `if (x > 0) { if (x < 0) { sink(x) } }`)
- Use constant propagation results to evaluate branch feasibility
- Integrate with SSA type facts for type-based path pruning

### Files/systems likely to be touched
- New: `src/constraint.rs` — constraint representation and solver
- `src/taint/ssa_transfer.rs` — constraint-aware path propagation
- `src/ssa/const_prop.rs` — feed constants into constraint solver
- `src/taint/path_state.rs` — integrate constraints with predicates

### Concrete implementation tasks
1. Define constraint types: `Eq(SsaValue, Const)`, `Neq(SsaValue, Const)`, `Lt`/`Gt`/`Leq`/`Geq`, `TypeOf(SsaValue, TypeKind)`, `In(SsaValue, Set)`
2. At each branch point, extract constraints from the condition and add to the path's constraint set
3. Before processing a block, check if the accumulated constraints are satisfiable (simple check: no `Eq(x, a)` and `Eq(x, b)` where `a != b`)
4. If unsatisfiable, prune the path (don't process the block)
5. Use constant propagation: if `x = 5` and branch is `if x > 10`, prune the true branch
6. Limit constraint set size (max 32 constraints per path) to bound cost
7. Add test fixtures for infeasible path pruning

### Validation requirements
- No TP regressions (pruning must be sound)
- At least 1 FP eliminated by constraint pruning
- Constraint solving adds < 10% overhead

### Exit criteria
- Basic constraint solving implemented (equality, inequality, type constraints)
- Infeasible paths pruned
- Sound: no real vulnerabilities suppressed

### Dependencies
Phase 10 (type facts feed constraints). Phase 3 (predicate classification feeds constraints).

---

## Phase 16: Type-Flow Constraint Solving

**Category:** Analysis Depth — Type System Integration

**Why now:** Beyond simple type facts, some languages have type systems that can prove safety. TypeScript's type narrowing, Java's type hierarchy, Go's interface satisfaction — these can prove that certain values can't reach certain sinks.

### Goals
- Model TypeScript type narrowing through conditional branches
- Model Java type hierarchy for method resolution
- Use type constraints to prune impossible flows
- Handle type casting/assertion as type narrowing

### Files/systems likely to be touched
- `src/ssa/type_facts.rs` — extended type inference with type narrowing
- `src/taint/ssa_transfer.rs` — type-constrained taint propagation
- `src/labels/mod.rs` — type-qualified rules
- Language-specific label files for type hierarchy data

### Concrete implementation tasks
1. TypeScript: at `typeof x === "number"` branches, narrow type to `Int`; suppress sinks that require `String` input
2. Java: model basic class hierarchy (HttpServletRequest extends ServletRequest); resolve method overrides
3. Go: interface satisfaction — if a type satisfies `io.Writer` but not `http.ResponseWriter`, it's not a web response sink
4. Type casting: `(String) obj` narrows type; `as` in TypeScript narrows type
5. Feed type narrowing results into constraint solver from Phase 15
6. Add test fixtures for type-narrowing-based suppression

### Validation requirements
- No TP regressions
- TypeScript/Java type narrowing suppresses at least 1 FP pattern
- Type hierarchy data maintained per language

### Exit criteria
- Type narrowing through branches implemented for TypeScript and Java
- Type hierarchy used for method resolution in Java
- Type constraints integrated with constraint solver

### Dependencies
Phase 15 (constraint solving infrastructure). Phase 10 (type facts as foundation).

---

## Phase 17: Abstract Interpretation Framework

**Category:** Analysis Depth — Abstract Interpretation

**Why now:** With constraint solving, type-flow, and path pruning in place, the engine has the infrastructure to support abstract interpretation. Abstract interpretation provides a principled foundation for analyzing numeric ranges, string patterns, and other value domains that can prove safety or detect vulnerabilities.

### Goals
- Implement abstract interpretation framework with pluggable abstract domains
- Implement numeric interval domain (for array bounds, integer overflow)
- Implement string prefix/suffix domain (for URL validation, path canonicalization)
- Integrate abstract values with taint analysis for domain-aware suppression

### Files/systems likely to be touched
- New: `src/abstract_interp/` — abstract interpretation framework
- `src/abstract_interp/interval.rs` — numeric interval domain
- `src/abstract_interp/string.rs` — string pattern domain
- `src/taint/ssa_transfer.rs` — abstract-value-aware taint transfer
- `src/ssa/ir.rs` — abstract value annotations on SSA instructions

### Concrete implementation tasks
1. Define `AbstractDomain` trait: `bot()`, `top()`, `join()`, `meet()`, `widen()`, `leq()`
2. Implement `IntervalDomain` for integers: tracks [lo, hi] ranges. Widening at loop heads.
3. Implement `StringPrefixDomain`: tracks known prefixes ("https://internal.example.com/"). If URL prefix is known-safe, suppress SSRF.
4. Hook abstract domains into SSA taint worklist: compute abstract values alongside taint state
5. Use abstract values for domain-aware sink suppression: array index with interval [0, len-1] suppresses out-of-bounds; URL with safe prefix suppresses SSRF
6. Widening operator to ensure termination
7. Add test fixtures for abstract-value-based suppression

### Validation requirements
- Abstract interpretation terminates on all corpus fixtures
- No TP regressions
- At least 2 abstract-domain-based suppressions demonstrated

### Exit criteria
- Abstract interpretation framework with pluggable domains
- Numeric interval domain implemented
- String prefix domain implemented
- Widening ensures termination

### Dependencies
Phase 15 (constraint solving). Phase 10 (type facts). Phase 12 (field sensitivity for object field abstract values).

---

## Phase 18a: Symbolic Value Representation and Expression Trees

**Category:** Analysis Depth — Symbolic Execution Foundation

**Why now:** The current `src/symex.rs` (470 lines) performs single-path constraint-based feasibility checking using `PathEnv` — a concrete value-fact domain. This is useful but limited: it can detect contradictory equality constraints but cannot reason about symbolic relationships between values, track how tainted input transforms through arithmetic/string operations, or represent the symbolic conditions under which a vulnerability is reachable. A proper symbolic execution engine requires symbolic expression trees that preserve the structure of computations rather than collapsing them into concrete bounds.

### Current state (what exists)
- `src/symex.rs`: `annotate_findings()` walks a single path through SSA blocks, applies branch constraints via `constraint::refine_env()`, detects unsatisfiability. Produces `SymbolicVerdict` (Confirmed/Infeasible/Inconclusive). Bounded by `MAX_CANDIDATES=50`, `MAX_PATH_BLOCKS=100`. Integrated into taint pipeline at 3 call sites in `taint/mod.rs`.
- `src/constraint/`: `PathEnv` (1432 LOC domain), `refine_env()` solver, `lower_condition()` for CFG-to-constraint lowering. Tracks `ValueFact` per SSA value (exact, lo, hi, null, types, bool_state), equality/disequality/relational constraints. 100+ solver tests.
- `src/abstract_interp/`: `IntervalFact` + `StringFact` product domain with proper lattice ops. Integrated into `SsaTaintState.abstract_state`. Widened at loop heads. Used for sink suppression.
- `src/evidence.rs`: `SymbolicVerdict` struct with `verdict`, `constraints_checked`, `paths_explored`, `witness: Option<String>`. Confidence scoring: Infeasible → -5 points, Confirmed → +2 points.

### Goals
- Define `SymbolicValue` — a symbolic expression tree that preserves computation structure (not just concrete bounds)
- Define `SymbolicState` — mapping from SSA values to symbolic values + accumulated path constraints
- Implement forward symbolic transfer over SSA instructions (constants, assignments, binary ops, calls, phis, sources)
- Restructure `src/symex.rs` into `src/symex/` module directory for the growing engine
- Replace the current `PathEnv`-only approach with symbolic expressions that feed into constraint solving
- Maintain backward compatibility: the existing `annotate_findings()` API and `SymbolicVerdict` output remain unchanged

### Files/systems to be touched
- Restructure: `src/symex.rs` → `src/symex/mod.rs` (public API, `annotate_findings`)
- New: `src/symex/value.rs` — `SymbolicValue` enum and expression constructors
- New: `src/symex/state.rs` — `SymbolicState` mapping + path constraint accumulation
- New: `src/symex/transfer.rs` — forward symbolic transfer over `SsaInst` / `SsaOp`
- Modify: `src/symex/mod.rs` — `analyse_finding_path()` upgraded to use `SymbolicState` instead of raw `PathEnv`
- Modify: `src/constraint/solver.rs` — accept symbolic expressions as constraint operands (extend `refine_env` or add `refine_symbolic`)
- Modify: `src/lib.rs` or `src/main.rs` — update module declaration from `mod symex;` to `mod symex;` (directory)

### Concrete implementation tasks

1. **Restructure into module directory.** Move `src/symex.rs` to `src/symex/mod.rs`. Verify all imports and call sites (`taint/mod.rs` lines ~154, ~434, ~485) still compile. Add `pub mod value; pub mod state; pub mod transfer;` declarations.

2. **Define `SymbolicValue` enum** in `src/symex/value.rs`:
   ```
   SymbolicValue:
     Concrete(i64)                         — known integer constant
     ConcreteStr(String)                   — known string constant
     Symbol(SsaValue)                      — unconstrained symbolic input (taint source or unknown param)
     BinOp(Op, Box<SymbolicValue>, Box<SymbolicValue>)  — arithmetic: Add, Sub, Mul, Div, Mod
     Concat(Box<SymbolicValue>, Box<SymbolicValue>)     — string concatenation
     Call(String, Vec<SymbolicValue>)      — uninterpreted function application
     Phi(Vec<(BlockId, SymbolicValue)>)    — phi: predecessor-conditional value
     Unknown                               — no information (top)
   ```
   Implement: `Display` for human-readable printing, `Clone`, `PartialEq`, `Eq`, `Hash`. Add `fn is_concrete(&self) -> bool`, `fn as_concrete_int(&self) -> Option<i64>`, `fn depth(&self) -> usize` (for expression tree depth bounding). Add `const MAX_EXPR_DEPTH: usize = 32` — if building an expression would exceed this, collapse to `Unknown` to prevent blowup.

3. **Define `SymbolicState`** in `src/symex/state.rs`:
   ```
   SymbolicState:
     values: HashMap<SsaValue, SymbolicValue>     — current symbolic value per SSA value
     path_constraints: Vec<PathConstraint>         — accumulated branch conditions on this path
     tainted_symbols: HashSet<SsaValue>            — which symbols represent tainted input
   ```
   Where `PathConstraint` wraps a `ConditionExpr` + polarity (true/false branch taken).
   Implement: `fn new() -> Self`, `fn get(&self, v: SsaValue) -> &SymbolicValue` (returns `Unknown` for unmapped), `fn set(&mut self, v: SsaValue, val: SymbolicValue)`, `fn add_constraint(&mut self, cond: ConditionExpr, polarity: bool)`, `fn is_tainted(&self, v: SsaValue) -> bool` (checks if value transitively depends on any tainted symbol).

4. **Implement forward symbolic transfer** in `src/symex/transfer.rs`:
   - `fn transfer_inst(state: &mut SymbolicState, inst: &SsaInst, cfg: &Cfg)` — process one SSA instruction:
     - `SsaOp::Const` → `Concrete(n)` or `ConcreteStr(s)` from `NodeInfo.const_text`
     - `SsaOp::Assign { src, .. }` with single operand → copy symbolic value
     - `SsaOp::Assign { src, .. }` with `bin_op` → `BinOp(op, lhs_sym, rhs_sym)` (if depth < MAX_EXPR_DEPTH, else `Unknown`)
     - `SsaOp::Call { args, result, .. }` → For known pure functions (parseInt, int, ord, len, etc.): model return symbolically. For unknown: `Call(callee_name, arg_syms)`. For sanitizers: `Unknown` (strips symbolic taint info — conservative).
     - `SsaOp::Source` → `Symbol(result_value)` + mark as tainted
     - `SsaOp::Param { index }` → `Symbol(result_value)` (external input)
     - `SsaOp::Phi { operands }` → `Phi([(pred_block, operand_sym), ...])` — preserve structure for path-conditional resolution during exploration
     - `SsaOp::Nop` / `SsaOp::CatchParam` → no-op / `Symbol(result_value)`
   - `fn transfer_block(state: &mut SymbolicState, block: &SsaBlock, cfg: &Cfg)` — process all instructions in a block sequentially

5. **Seed `SymbolicState` from optimization results.** At entry block:
   - Seed from `const_values: HashMap<SsaValue, ConstLattice>` — map `ConstLattice::Int(n)` → `Concrete(n)`, `ConstLattice::Str(s)` → `ConcreteStr(s)`
   - Seed from `type_facts` — record type constraints for future path refinement
   - Mark source SSA values from the finding's flow steps as tainted symbols

6. **Upgrade `analyse_finding_path()`** in `src/symex/mod.rs`:
   - Create `SymbolicState` at entry, seed from const_values + type_facts + finding source
   - Walk path blocks: for each block, run `transfer_block()` to build symbolic values, then at branch terminators build `PathConstraint` from `ConditionExpr` + polarity
   - After each constraint: extract concrete bounds from symbolic state and check satisfiability using existing `constraint::refine_env()` (bridge: convert `SymbolicValue` constraints to `PathEnv` refinements)
   - Preserve existing `Verdict` semantics: `Infeasible` if UNSAT detected, `Confirmed` if path traversed without contradiction, `Inconclusive` if too many unknowns
   - **Critical**: the `SymbolicVerdict` output format does NOT change — same struct, same fields, same integration with `Evidence` and confidence scoring

7. **Add unit tests** in `src/symex/value.rs` and `src/symex/state.rs`:
   - Expression depth bounding: verify `MAX_EXPR_DEPTH` prevents blowup
   - Concrete folding: `BinOp(Add, Concrete(3), Concrete(5))` simplifies to `Concrete(8)` during construction
   - Taint tracking: `is_tainted(v)` returns true when v depends on a source symbol through any expression tree
   - State seeding: verify const_values correctly map to symbolic values

8. **Add integration fixture** `tests/fixtures/real_world/javascript/taint/symex_expression_tree.js`:
   ```javascript
   const express = require("express");
   const app = express();
   app.get("/api", (req, res) => {
       const x = parseInt(req.query.offset);  // tainted, but int-typed
       const y = x * 2 + 1;                   // symbolic: (Symbol(x) * 2) + 1
       const query = "SELECT * FROM t LIMIT " + y;
       connection.query(query);                // sink — should be suppressed (int arithmetic on int-typed value)
   });
   ```
   This tests that symbolic expressions preserve arithmetic structure through the taint path, enabling type+interval suppression to work on derived values (not just direct sources).

### Architecture notes

- **Expression simplification**: Implement basic constant folding during construction (`Concrete + Concrete → Concrete`). Do NOT implement a full simplifier — that's premature optimization. The constraint solver handles reasoning; the expression tree just preserves structure.
- **Phi handling**: Store phi operands symbolically but do NOT resolve them during single-path exploration. Phase 18b's multi-path forking will resolve phis by choosing the predecessor-specific operand on each explored path.
- **No forking yet**: This phase stays single-path. The symbolic state enriches what the single-path explorer can reason about, but does not add path splitting. That's Phase 18b.
- **Backward compatibility**: `annotate_findings()` signature, `SymbolicVerdict` struct, confidence scoring integration, and all 3 call sites in `taint/mod.rs` remain unchanged.

### Validation requirements
- All 880+ existing tests pass (`cargo test`)
- SSA corpus (265 fixtures) terminates without panics
- Existing symex tests continue to pass (feature gate, path extraction, skip-validated, skip-short)
- New unit tests for SymbolicValue, SymbolicState, and transfer pass
- Integration fixture demonstrates symbolic expression tracking through arithmetic
- No TP regressions on real-world fixtures

### Exit criteria
- `src/symex/` module directory with `value.rs`, `state.rs`, `transfer.rs`, `mod.rs`
- `SymbolicValue` enum with expression tree, depth bounding, concrete folding
- `SymbolicState` with value mapping, path constraint accumulation, taint tracking
- Forward symbolic transfer over all `SsaOp` variants
- `analyse_finding_path()` upgraded to build and use `SymbolicState`
- Existing `SymbolicVerdict` output unchanged — drop-in replacement for current approach

### Dependencies
Phase 17 (abstract interpretation — provides `AbstractState` on `SsaTaintState` and interval/string domains that symbolic expressions can be compared against). Phase 15 (constraint solving — `PathEnv` + `refine_env()` used for satisfiability checking of symbolic constraints). Phase 8 (SSA summaries — `SsaFuncSummary` provides interprocedural callee modeling for `Call` symbolic values).

---

## Phase 18b: Multi-Path Symbolic Exploration with Bounded Forking

**Category:** Analysis Depth — Symbolic Execution Core

**Why now:** Phase 18a gives us symbolic expression trees and a `SymbolicState` that tracks how tainted input transforms through computation — but only along a single path. The real power of symbolic execution comes from exploring multiple paths through the program to determine which are feasible and which are not. A taint finding that reports "source reaches sink" may have 3 possible paths, 2 of which are infeasible. Without multi-path exploration, we can only check the single reported path. With forking, we can explore alternatives, confirm the one true feasible path, and produce stronger verdicts.

### Current state (after Phase 18a)
- `src/symex/`: Module directory with `SymbolicValue` expression trees, `SymbolicState` (value map + path constraints + taint tracking), forward symbolic transfer over all SSA ops.
- `analyse_finding_path()`: Single-path exploration using `SymbolicState`. Walks the reported taint path, builds symbolic expressions, checks constraints. Produces `SymbolicVerdict`.
- `src/constraint/`: `PathEnv` solver with `refine_env()` — detects unsatisfiability for equality/comparison constraints.
- Budgets: `MAX_CANDIDATES=50` per file, `MAX_PATH_BLOCKS=100` per path, `MAX_EXPR_DEPTH=32` per expression.

### Goals
- Implement bounded path forking at branch points where both successors are taint-reachable
- Explore up to N paths per finding (configurable, default 8) with depth and fork budgets
- Resolve phi nodes path-sensitively: on each explored path, select the predecessor-specific phi operand
- Produce aggregate verdicts: if ANY explored path is feasible → `Confirmed`; if ALL paths are infeasible → `Infeasible`; mixed → `Confirmed` (conservative)
- Implement work queue with priority (shorter paths first) and subsumption pruning
- Maintain termination guarantees: hard caps on forks, paths, and total symbolic steps

### Files/systems to be touched
- New: `src/symex/executor.rs` — multi-path exploration engine with work queue
- Modify: `src/symex/mod.rs` — `analyse_finding_path()` delegates to executor
- Modify: `src/symex/state.rs` — add `clone()` for forking, phi resolution helper
- Modify: `src/symex/transfer.rs` — phi transfer resolves to predecessor-specific operand when exploring a known predecessor edge
- Modify: `src/evidence.rs` — `SymbolicVerdict.paths_explored` reflects actual count

### Concrete implementation tasks

1. **Define exploration budgets** in `src/symex/executor.rs`:
   ```
   const MAX_FORKS_PER_FINDING: usize = 3;   — max branch forks before stopping
   const MAX_PATHS_PER_FINDING: usize = 8;   — max total paths explored
   const MAX_TOTAL_STEPS: usize = 500;        — max symbolic transfer steps across all paths
   ```
   These prevent exponential blowup. When any budget is exhausted, stop exploring and produce verdict from what's been seen so far.

2. **Define `ExplorationState`** in `src/symex/executor.rs`:
   ```
   ExplorationState:
     sym_state: SymbolicState              — current symbolic state for this path
     remaining_blocks: Vec<BlockId>        — blocks still to visit on this path
     forks_used: usize                     — forks consumed by this path's ancestors
     steps_taken: usize                    — symbolic transfer steps on this path
   ```

3. **Define `ExplorationResult`** in `src/symex/executor.rs`:
   ```
   ExplorationResult:
     paths_completed: Vec<PathOutcome>     — outcomes of all fully explored paths
     paths_pruned: usize                   — paths abandoned due to budget or subsumption
     total_steps: usize                    — total symbolic steps across all paths
   ```
   Where `PathOutcome` is `{ verdict: Verdict, constraints_checked: u32, witness_state: Option<SymbolicState> }`.

4. **Implement `explore_finding()`** — the multi-path engine:
   ```
   fn explore_finding(
       finding: &Finding,
       ssa: &SsaBody,
       cfg: &Cfg,
       const_values: &HashMap<SsaValue, ConstLattice>,
       type_facts: &TypeFactResult,
   ) -> ExplorationResult
   ```
   Algorithm:
   - Compute taint-reachable blocks: BFS/DFS from source block to sink block using SSA block successors, collecting all blocks that are on SOME path from source to sink.
   - Seed initial `ExplorationState` with entry symbolic state and full path from source block to first branch.
   - **Work queue** (VecDeque or BinaryHeap sorted by remaining_blocks.len() — shorter paths first):
     - Pop next state from queue.
     - Process blocks sequentially: run `transfer_block()` for each.
     - At `Terminator::Branch`: check if both successors are taint-reachable.
       - If only one successor is reachable: continue on that successor (no fork).
       - If both are reachable AND `forks_used < MAX_FORKS_PER_FINDING` AND `queue.len() + 1 < MAX_PATHS_PER_FINDING`:
         - **Fork**: clone `SymbolicState`, apply true-branch constraint to one copy, false-branch constraint to the other.
         - Check each for unsatisfiability immediately — if UNSAT, record as `Infeasible` and don't enqueue.
         - Enqueue both feasible successors with updated `remaining_blocks`.
         - Increment `forks_used` on both.
       - If budget exhausted: pick the successor that's on the originally-reported path (fall back to single-path behavior).
     - At `Terminator::Goto`: continue to successor.
     - At `Terminator::Return` or end of path: record `PathOutcome`.
   - After queue is drained or total_steps exceeded: aggregate results.

5. **Aggregate verdict logic**:
   - If ALL completed paths are `Infeasible` → verdict `Infeasible` (no feasible path exists)
   - If ANY completed path is `Confirmed` (reached sink without contradiction) → verdict `Confirmed`
   - If some paths are `Confirmed` and some `Infeasible` → verdict `Confirmed` (at least one feasible path)
   - If queue was exhausted by budget → verdict `Inconclusive` (couldn't prove either way)
   - `paths_explored` = total completed paths (not pruned)
   - `constraints_checked` = sum across all paths

6. **Path-sensitive phi resolution** in `src/symex/transfer.rs`:
   - When processing a phi node and the exploration knows which predecessor block we arrived from (tracked in `ExplorationState`), resolve to that predecessor's operand's symbolic value.
   - If predecessor is unknown (shouldn't happen in well-formed SSA), fall back to `Phi(...)` expression (preserve structure).

7. **Subsumption pruning** (optional, for efficiency):
   - Before enqueueing a new path state, check if an already-completed path with the same block sequence had a superset of constraints. If so, the new path is subsumed — skip it.
   - Simple implementation: hash the `(remaining_blocks, path_constraints.len())` tuple. If seen before with fewer constraints, skip.
   - This is optional — the hard budget caps already prevent blowup. Only implement if test fixtures show redundant exploration.

8. **Wire into `analyse_finding_path()`** in `src/symex/mod.rs`:
   - Replace the current single-path loop with a call to `explore_finding()`.
   - Map `ExplorationResult` to `SymbolicVerdict` using the aggregation logic above.
   - The `annotate_findings()` entry point remains unchanged.

9. **Add unit tests** in `src/symex/executor.rs`:
   - Budget enforcement: verify MAX_FORKS, MAX_PATHS, MAX_TOTAL_STEPS all cap exploration
   - Diamond CFG: source → branch → {A, B} → merge → sink. Both paths feasible → `Confirmed` with 2 paths explored.
   - Contradictory branches: source → branch → {true_path (x==1), false_path (x==2)} → each has sink. Verify both paths explored independently with correct constraints.
   - Infeasible-only: all paths to sink are infeasible → `Infeasible` verdict.
   - Mixed: one path feasible, one infeasible → `Confirmed` verdict.
   - Budget exhaustion: create a CFG with many branches, verify exploration stops at budget and returns `Inconclusive`.

10. **Add integration fixture** `tests/fixtures/real_world/javascript/taint/symex_multipath.js`:
    ```javascript
    const express = require("express");
    const app = express();
    app.get("/api", (req, res) => {
        const mode = req.query.mode;
        let result;
        if (mode === "safe") {
            result = "constant";         // not tainted — this path is safe
        } else {
            result = req.query.payload;  // tainted — this path is dangerous
        }
        eval(result);                    // sink — one path feasible, one not
    });
    ```
    Expected: finding should be `Confirmed` (the else-branch path is feasible). With multi-path, the engine explores both branches and confirms at least one reaches the sink with tainted data.

### Architecture notes

- **Taint-reachable block computation**: This is a lightweight pre-pass (BFS from source block, intersected with reverse-BFS from sink block). It prevents exploring branches that can never reach the sink, dramatically reducing fork count.
- **State cloning cost**: `SymbolicState` contains a `HashMap<SsaValue, SymbolicValue>` + `Vec<PathConstraint>`. Cloning is O(state_size). With `MAX_EXPR_DEPTH=32` and typical SSA bodies of 50-200 values, this is small. No optimization needed.
- **No loop handling in executor**: The executor walks a DAG of blocks from source to sink. If the path passes through a loop, the loop body is traversed once (the SSA blocks along the taint path). The executor does NOT iterate loops — that's the taint engine's job (with widening). Symbolic execution only checks path feasibility, not loop invariants.
- **Interaction with existing taint analysis**: The symex executor runs AFTER taint analysis has produced findings. It does not replace taint analysis — it refines findings by checking path feasibility. The taint engine's worklist, convergence, and abstract interpretation remain unchanged.

### Validation requirements
- All existing tests pass (`cargo test`)
- Existing single-path fixtures still produce correct verdicts (no regression)
- New multi-path fixtures demonstrate forked exploration
- Budget enforcement tests prove termination on adversarial inputs
- `paths_explored` in `SymbolicVerdict` correctly reflects actual exploration count
- No TP regressions on real-world fixtures

### Exit criteria
- `src/symex/executor.rs` implements bounded multi-path exploration
- Fork/path/step budgets enforced, termination guaranteed
- Phi nodes resolved path-sensitively during exploration
- Aggregate verdicts correctly combine per-path outcomes
- `SymbolicVerdict.paths_explored` reflects real count
- At least 1 fixture demonstrates multi-path exploration improving verdict quality

### Dependencies
Phase 18a (symbolic value representation — required for `SymbolicState` cloning and path-sensitive phi resolution). Phase 15 (constraint solving — `refine_env()` used for constraint checking at each fork).

---

## Phase 18c: Witness Generation and Cross-File Symbolic Summaries

**Category:** Analysis Depth — Symbolic Execution Payoff

**Why now:** Phase 18b gives us multi-path exploration with bounded forking. The engine can now confirm or deny path feasibility. But two capabilities are missing for production-grade symbolic execution: (1) when a path IS feasible, generate a concrete proof witness — an actual input value that would trigger the vulnerability, and (2) when a taint path crosses file boundaries, model callee behavior symbolically using SSA summaries rather than treating calls as opaque. Witnesses are the user-facing payoff (actionable proof). Cross-file symbolic summaries are the precision multiplier (fewer Inconclusive verdicts on real codebases).

### Current state (after Phase 18b)
- `src/symex/`: Full module with `SymbolicValue` expression trees, `SymbolicState`, forward transfer, and multi-path `explore_finding()` with bounded forking.
- Multi-path exploration produces aggregate `SymbolicVerdict` with accurate `paths_explored` count.
- `witness: Option<String>` field on `SymbolicVerdict` exists but is always `None`.
- Cross-file calls during symbolic execution are treated as `Call(callee, args)` → `Unknown` (no interprocedural modeling).
- `SsaFuncSummary` exists with `param_to_return: Vec<(usize, TaintTransform)>` and `param_to_sink: Vec<(usize, Cap)>` — rich per-parameter transforms available but not used by symex.

### Goals
- Generate human-readable proof witnesses for `Confirmed` findings — concrete input values that satisfy all path constraints and trigger the vulnerability
- Model cross-file callee behavior during symbolic execution using `SsaFuncSummary` transforms
- Produce actionable output: "input `x = '<script>alert(1)</script>'` at line 5 reaches `eval()` at line 15 via path: source → branch(mode != 'safe') → assignment → sink"
- Calibrate confidence scoring weights based on witness quality
- Integrate witnesses into Evidence flow steps for structured output (JSON/SARIF)

### Files/systems to be touched
- New: `src/symex/witness.rs` — witness extraction and formatting
- Modify: `src/symex/executor.rs` — capture `SymbolicState` at sink for witness extraction
- Modify: `src/symex/transfer.rs` — model known callee summaries symbolically during transfer
- Modify: `src/symex/mod.rs` — wire witness generation into verdict production
- Modify: `src/evidence.rs` — extend `SymbolicVerdict.witness` format, add witness to `FlowStep` output
- Modify: `src/taint/ssa_transfer.rs` — pass `GlobalSummaries` (or a symbolic summary subset) to symex when available
- Modify: `src/taint/mod.rs` — thread summary context to `annotate_findings()`

### Concrete implementation tasks

1. **Witness extraction** in `src/symex/witness.rs`:
   - `fn extract_witness(state: &SymbolicState, finding: &Finding, ssa: &SsaBody) -> Option<String>`:
     - Identify the tainted source symbol(s) from `state.tainted_symbols`
     - Walk path constraints backward from sink to source, collecting concrete bounds on the source symbol
     - If source is string-typed: generate a concrete string that satisfies all constraints (e.g., `"<script>alert(1)</script>"` for XSS, `"'; DROP TABLE users; --"` for SQL injection, `"$(whoami)"` for command injection)
     - If source is int-typed: pick a concrete integer within the proven bounds
     - If constraints are too complex for concrete generation: produce a descriptive witness instead (`"any string where mode != 'safe'"`)
   - Witness templates per vulnerability class (keyed by `Cap`):
     - `Cap::CODE_EXEC` / XSS → `"<script>alert('xss')</script>"`
     - `Cap::SQL_QUERY` → `"' OR 1=1 --"`
     - `Cap::SHELL_ESCAPE` → `"$(id)"`
     - `Cap::FILE_IO` → `"../../etc/passwd"`
     - `Cap::SSRF` → `"http://169.254.169.254/metadata"`
     - `Cap::DESERIALIZE` → `"malicious_serialized_object"`
   - Templates are defaults — if constraints narrow the input (e.g., must start with "http://"), respect the constraints and adapt the template.

2. **Witness formatting**:
   - `fn format_witness(source_var: &str, witness_value: &str, sink_var: &str, sink_line: usize, cap: Cap) -> String`:
   - Produce: `"input x = '$(id)' at source (line 5) reaches exec() at sink (line 15)"`
   - Include path summary: list branch conditions taken (e.g., `"via: mode != 'safe' (line 8)"`)
   - Keep it concise — one line for simple paths, multi-line for complex ones

3. **Capture symbolic state at sink** in `src/symex/executor.rs`:
   - When a path reaches the sink block with verdict `Confirmed`, capture a clone of `SymbolicState` as `witness_state` on `PathOutcome`.
   - Pass the best witness state (shortest path, most constrained) to `extract_witness()`.

4. **Cross-file symbolic summary modeling** in `src/symex/transfer.rs`:
   - When processing `SsaOp::Call { callee, args, result, .. }`:
     - Check if callee has an `SsaFuncSummary` available (via `GlobalSummaries.get_ssa()`)
     - If summary has `param_to_return` with `Identity` for param i → return symbolic value = `args[i]`'s symbolic value (pass-through)
     - If summary has `param_to_return` with `StripBits(caps)` for param i → return `Unknown` (sanitized — symbolic taint stripped)
     - If summary has `param_to_return` with `AddBits(caps)` for param i → return `Symbol(fresh)` marked tainted (new taint introduced)
     - If summary has `source_caps` → return `Symbol(fresh)` marked tainted (function is a source)
     - If no summary or no matching transform → return `Call(callee, arg_syms)` (uninterpreted, as before)
   - This requires threading a summary lookup function into the transfer context. Add `summary_lookup: Option<&dyn Fn(&str) -> Option<&SsaFuncSummary>>` to `transfer_block` or to a `TransferContext` struct.

5. **Thread `GlobalSummaries` to symex** in `src/taint/mod.rs`:
   - Extend `annotate_findings()` signature to accept optional summary context:
     ```rust
     pub fn annotate_findings(
         findings: &mut [Finding],
         ssa: &SsaBody,
         cfg: &Cfg,
         const_values: &HashMap<SsaValue, ConstLattice>,
         type_facts: &TypeFactResult,
         summaries: Option<&GlobalSummaries>,  // NEW
     )
     ```
   - Update all 3 call sites in `taint/mod.rs` to pass the available `GlobalSummaries` (or `None` if not available).
   - Inside `analyse_finding_path()`, pass the summary lookup to `explore_finding()`.

6. **Confidence calibration**:
   - Review the current scoring weights: Infeasible → -5, Confirmed → +2.
   - With witnesses: Confirmed-with-witness → +3 (stronger than unwitnessed Confirmed).
   - With cross-file summaries: if symex resolved a cross-file call via summary → confidence bonus +1 (more precise than opaque call).
   - Update `compute_taint_confidence()` in `src/evidence.rs` accordingly.

7. **Integrate witness into output** in `src/evidence.rs`:
   - The `witness` field already exists on `SymbolicVerdict`. Just ensure it's serialized in JSON/SARIF output.
   - Optionally: add witness text to the `explanation` field on `Evidence` for console output.

8. **Add unit tests** in `src/symex/witness.rs`:
   - Template selection per Cap: verify correct exploit template for each vulnerability class
   - Constraint-aware witness: if path constraint says `x starts with "http://"`, verify witness respects prefix
   - Integer witness: if constraint says `5 ≤ x ≤ 100`, verify witness is within bounds
   - No-witness case: if source is fully unconstrained `Unknown`, verify descriptive fallback text

9. **Add integration fixtures**:
   - `tests/fixtures/real_world/javascript/taint/symex_witness.js` — simple path, expect witness text in verdict
   - `tests/fixtures/real_world/python/taint/symex_cross_file_witness.py` (cross-file pair) — taint flows through helper function, expect witness and cross-file summary resolution

### Architecture notes

- **Witness quality is best-effort.** Not all paths can produce clean concrete witnesses. The fallback is always a descriptive string explaining the symbolic constraint. Never block a verdict on witness generation failure.
- **Summary modeling is conservative.** If a summary transform is ambiguous or missing, treat the call as uninterpreted (`Unknown`). This is strictly more precise than the current approach (which also returns `Unknown`) — we only gain precision, never lose it.
- **SARIF witness integration.** SARIF has `threadFlows` and `codeFlows` that can carry witness information. If Nyx already emits SARIF, extend the flow steps to include witness data. If not, this is a future enhancement — JSON output with the witness string is sufficient for now.
- **Performance.** Witness generation is O(path_length × constraint_count) — negligible compared to the exploration itself. Cross-file summary lookup is a single HashMap get per call. No performance concerns.

### Validation requirements
- All existing tests pass
- Witness generated for at least 3 different vulnerability classes (XSS, SQLi, CMDI)
- Cross-file summary resolution reduces Inconclusive verdicts on cross-file fixtures
- Confidence scoring correctly applies witness bonus
- Witness text is human-readable and actionable
- No TP regressions

### Exit criteria
- `src/symex/witness.rs` generates concrete proof witnesses for Confirmed findings
- Witness templates cover all 6 major Cap classes (CODE_EXEC, SQL_QUERY, SHELL_ESCAPE, FILE_IO, SSRF, DESERIALIZE)
- Cross-file callee behavior modeled via `SsaFuncSummary` during symbolic transfer
- `annotate_findings()` accepts optional `GlobalSummaries` for cross-file resolution
- `SymbolicVerdict.witness` populated with actionable text
- Confidence scoring calibrated for witnessed vs unwitnessed verdicts
- At least 1 cross-file fixture demonstrates summary-aware symbolic execution

### Dependencies
Phase 18b (multi-path exploration — required for `witness_state` capture on completed paths). Phase 8 (SSA summaries — `SsaFuncSummary` with `TaintTransform` provides the interprocedural modeling basis). Phase 11 (context sensitivity — `GlobalSummaries` already threaded through taint; extend to symex).

---

## Phase 19: Benchmark Expansion and Precision Gate

**Category:** Validation — Benchmark Maturity

**Why now:** This phase exists as a checkpoint after the deep analysis work. The benchmark corpus (103 cases, 6 languages) needs expansion to cover the new analysis capabilities and ensure precision hasn't regressed across the extended capability set.

### Goals
- Expand benchmark to 200+ cases
- Add C, C++, C#, Rust cases to benchmark (currently only 6 of 10 languages)
- Add interprocedural, field-sensitive, alias-aware, and constraint-solving test cases
- Establish per-phase precision thresholds
- Add regression testing for each analysis capability

### Files/systems likely to be touched
- `tests/benchmark/corpus/` — new cases for C, C++, C#, Rust + expanded cases for existing languages
- `tests/benchmark/ground_truth.json` — new case entries
- `tests/benchmark_test.rs` — threshold updates
- `tests/benchmark/RESULTS.md` — updated metrics

### Concrete implementation tasks
1. Add 20+ cases per missing language (C, C++, C#, Rust): cover cmdi, sqli, xss, path_traversal, code_injection, ssrf, deserialization + safe counterparts
2. Add 5 interprocedural cases per language (cross-function taint, sanitizer wrapping, callback taint)
3. Add 5 field-sensitive cases (object field taint, destructuring, mixed clean/tainted fields)
4. Add 5 alias/points-to cases (reference aliasing, container taint, sanitization through alias)
5. Add 5 constraint/path-pruning cases (infeasible paths, type narrowing)
6. Update precision thresholds based on expanded corpus
7. Document new corpus design principles

### Validation requirements
- All new cases have ground truth labels
- Benchmark runs without errors
- Precision/recall computed on expanded corpus

### Exit criteria
- Benchmark corpus ≥ 200 cases across all 10 languages
- Per-language and per-vuln-class metrics computed
- Precision thresholds established for expanded corpus

### Dependencies
All preceding phases. This is a validation checkpoint.

---

## Audit Summary

The deep audit of the codebase (32,500 lines across all modules) reveals a solid, production-grade SSA-based taint engine with correct Cytron phi insertion, sound exception handling, and a well-designed lattice-based transfer framework. The engine is architecturally ready for extension — the `Lattice` trait, `Transfer` trait, and two-phase fixed-point design provide clean extension points for new abstract domains.

**Key architectural strengths:** Language-agnostic pipeline (Kind dispatch → CFG → SSA → taint), multi-label classification, gated sinks, structured evidence, attack-surface ranking, inline suppression, four detector families (taint, CFG structural, state model, AST patterns).

**Key architectural risks:** Suffix-matching for callee resolution produces false matches on nested objects. Callee normalization discards module paths, causing ambiguity when multiple languages define functions with the same name. `find_call_node` depth is capped at 2 — deeply wrapped calls are missed. The worklist iteration budget (100k) is generous but lacks widening — loops with growing taint sets rely on the MAX_ORIGINS=4 cap for convergence rather than principled widening.

**Critical precision observation:** All 28 FPs fall into 5 well-defined categories. Phases 1-3 target all 5 categories directly. If those phases succeed, precision should jump from 67% to ~85%+ on the current corpus.

---

## Cross-Cutting Themes

### Multi-Language Parity
Every analysis feature must work across all 10 supported languages. The current state has significant disparity:
- **Strong:** JavaScript, Python — rich rules (16-24), multiple framework models, full benchmark coverage
- **Moderate:** Java (18 rules but only 1 sanitizer rule — worst TN rate), Go (14 rules, no framework models), PHP (13 rules, no Laravel/Symfony), TypeScript (shares JS rules), Ruby (14 rules, 1 benchmark case)
- **Weak:** C (10 rules, 1 prefix-based sanitizer, no benchmark cases), C++ (10 rules, nearly identical to C), Rust (10 rules, test stub status), C# (not yet audited in benchmark)

Each phase must explicitly verify parity. If a feature is language-specific (e.g., TypeScript type narrowing), document the limitation. Java's sanitizer coverage is an urgent gap — its 12.5% TN rate is the worst of any benchmarked language.

### SSA Consistency
SSA lowering is the foundation. Any phase that changes CFG construction, node classification, or label matching must verify SSA lowering still succeeds for all 265 corpus fixtures. The `ssa_equivalence_tests.rs` corpus test is the gate.

### Soundness vs Precision Tradeoffs
The default policy is **conservative soundness**: better to report a false positive than miss a real vulnerability. But the 67% precision baseline shows the engine is too conservative. Phases 1-4 prioritize precision without sacrificing soundness. Phases 5+ add depth that may temporarily reduce precision; each phase must demonstrate precision stability.

When adding suppression rules (sanitizer recognition, validation guards, type pruning):
- Must-based suppression: suppress only when ALL paths are safe (must-alias, must-validate)
- May-based suppression: use for confidence downgrade, not finding suppression

### Benchmark Discipline
Every phase that changes analysis output must run the benchmark and report delta. Regressions in precision or recall require justification. The threshold mechanism in `benchmark_test.rs` enforces regression bounds.

Benchmark expansion (Phase 19) is scheduled after deep analysis work because the expanded corpus should cover the new capabilities. But interim benchmark additions are encouraged within individual phases.

### Detector/Model Compatibility
Label rules (`src/labels/*.rs`) and detector rules (`src/cfg_analysis/rules.rs`) must stay aligned. When a new sanitizer is added to labels, it should also be added to guard rules if it serves as a dominating guard. When a new sink is added, its cap bits must be compatible with existing sanitizer cap bits.

### Maintainability
Each phase should maintain the existing architecture's separation of concerns:
- Labels are declarative (data-driven, not logic)
- CFG construction is language-agnostic via Kind dispatch
- SSA lowering is language-agnostic via CFG abstraction
- Taint analysis is language-agnostic via SSA abstraction
- Language-specific behavior lives in `src/labels/{lang}.rs` and `KINDS` maps

New capabilities (alias analysis, constraint solving, abstract interpretation) should follow this pattern: generic engine with language-specific configuration.

### Explainability
Findings should be explainable. The `Evidence` struct already captures source/sink/guards/sanitizers. As analysis deepens:
- Path validation should note which predicate suppressed the path
- Type pruning should note which type narrowing applied
- Constraint solving should note which constraint was unsatisfiable
- Symbolic execution should produce proof witnesses
- Confidence derivation should always be traceable — the current component-based ranking in `rank.rs` is a good model

### False-Positive Control
The overriding quality metric is: **users trust the output**. Each phase must reduce or hold FP rate. If a phase adds a new analysis dimension that could increase FPs (e.g., field sensitivity could taint more fields), pair it with a suppression mechanism that prevents FP inflation.

Current FP breakdown by safe-case pattern (28 total FP across 44 safe cases):
- Allowlist dominated-check: 5 (all 5 languages)
- Validated allowlist: 5 (all 5 languages)
- Type-check guard: 5 (all 5 languages)
- Non-security sink: 5 (all 5 languages)
- Interprocedural sanitizer: 5 (all 5 languages)
- Inline sanitizer: 3 (language-specific gaps)

The remaining 16 TN include: constant args (5), reassignment to constant (5), some inline sanitizers (2), SSRF constants (4). These patterns already work — they are the baseline to protect.

### Callee Resolution Quality
The callee resolution pipeline (`normalize_callee_name` → GlobalSummaries lookup → interop fallback) has known limitations that affect precision at every layer:
- **Suffix matching** on member expressions: `obj.toString()` matches any rule ending in `toString` regardless of receiver type. This is a cross-cutting source of false positives that type-aware analysis (Phase 10) must address.
- **Module path loss**: `std::env::var` normalizes to `var`, which could match `crypto::var` or any other module's `var`. Qualified resolution would improve precision but requires import tracking infrastructure.
- **Overload ambiguity**: All functions named `render` merge into a single candidate in GlobalSummaries. Arity-aware disambiguation exists but name+arity is insufficient for method overloads.

These limitations are acceptable at current precision levels but will become bottlenecks as deeper analysis features are added. Phases 7 (scheduling), 8 (richer summaries), and 10 (type awareness) collectively address them.

---

## Ordering Rationale

### Why precision work comes first (Phases 1-4)
At 67% precision, a third of findings are noise. If users learn to ignore findings, adding deeper analysis is pointless — they'll ignore those too. Precision work is the highest-leverage investment: it makes existing findings trustworthy before adding new ones.

Phase 1 (sink tightening) is purely subtractive — removes bad rules, can't break anything. Phase 2 (sanitizer resolution) fixes a mechanical gap in the existing engine. Phase 3 (validation guards) teaches the engine about patterns it should already understand. Phase 4 (confidence) gives users a knob to control noise.

### Why SSA hardening precedes framework models (Phase 5 before 6)
Framework models depend on correct CFG/SSA construction. If PHP `echo` doesn't produce a sink node, adding a Laravel `echo` sink rule won't help. Fix the lowering first, then expand the rules.

### Why scheduling precedes richer summaries (Phase 7 before 8)
Summary quality depends on analysis order. If callee A is analyzed after its caller B, B's analysis uses A's stale summary. Fixing scheduling makes richer summaries immediately useful.

### Why flow sensitivity cleanup is between summaries and type-aware analysis (Phase 9)
Flow sensitivity through SSA rename is already correct for most cases. But before building type-aware analysis on top of SSA, verify that the foundation (kill semantics, PHI joins) is solid.

### Why type-aware analysis precedes context sensitivity (Phase 10 before 11)
Type information disambiguates method resolution — a prerequisite for precise context-sensitive analysis. Without types, context-sensitive analysis would over-approximate at every method call.

### Why field sensitivity precedes alias analysis (Phase 12 before 13)
Alias analysis is only useful if the taint state has field-level granularity. Aliasing between whole variables is already handled by SSA copy propagation. The interesting cases are field-level aliases.

### Why abstract interpretation and symbolic execution are last (Phases 17-18)
These are the most expensive analysis features and provide diminishing returns if the underlying precision is poor. They build on constraint solving (Phase 15), type-flow (Phase 16), alias analysis (Phase 13), and points-to (Phase 14). Without these foundations, abstract interpretation would over-approximate wildly and symbolic execution would explore infeasible paths.

### Why symbolic execution is split into three sub-phases (18a, 18b, 18c)
Full symbolic execution is the single most complex analysis capability in the engine. Building it monolithically would risk a half-baked solution where expression trees, multi-path exploration, and witness generation are all partially implemented but none work end-to-end. The three-phase split follows a strict dependency chain:
- **18a (expression trees)** is foundational — you cannot fork paths or generate witnesses without symbolic value representations. It also restructures the module directory, which is disruptive to do mid-feature.
- **18b (multi-path forking)** is the core capability gain. It depends on 18a's expression trees for path-sensitive phi resolution and meaningful constraint checking at fork points. Shipping 18a alone is still useful (richer single-path constraints), but 18b is where symbolic execution becomes genuinely more powerful than the existing constraint checker.
- **18c (witnesses + cross-file summaries)** is the user-facing payoff. Witnesses require completed exploration paths from 18b. Cross-file summaries require the symbolic transfer infrastructure from 18a. Neither can be built until the exploration engine is stable.

Each sub-phase is independently testable and shippable. After 18a the scanner has richer constraint reasoning. After 18b it can prove paths infeasible that the old approach couldn't. After 18c it produces proof-of-concept exploits and handles cross-file taint symbolically.

### Why benchmark expansion is a checkpoint, not a prerequisite (Phase 19)
Individual phases add benchmark fixtures as needed. The expansion phase consolidates, fills gaps for underserved languages, and establishes comprehensive regression thresholds for the complete analysis stack.

### Why the plan minimizes rework
Each phase builds on the previous phase's output. No phase introduces infrastructure that a later phase would replace:
- Labels refined in Phase 1 stay refined through all subsequent phases
- Sanitizer resolution from Phase 2 is used by every later taint phase
- SSA hardening from Phase 5 is foundational for all SSA-based features
- Summary system extended in Phase 8 is the same system used by context sensitivity, field sensitivity, and interprocedural analysis
- Constraint solver from Phase 15 is reused by type-flow and symbolic execution
