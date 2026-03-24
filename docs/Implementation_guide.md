# Post-SSA Implementation Guide — Static Analysis Hardening & Capability Expansion

This is the execution-order roadmap for completing Nyx's remaining static analysis capabilities after the SSA IR milestone. Each phase is sized for one Claude Code implementation pass.

## Current State (as of Phase 22 completion — 2026-03-24)

**Engine:** SSA-only taint analysis across 10 languages. Two-pass scanning with cross-file summaries (both `FuncSummary` and `SsaFuncSummary` persisted to SQLite). Call graph with Tarjan SCC + topological ordering used for pass 2 scheduling (callee-first batch processing with SCC fixed-point iteration, max 3 iterations). SSA optimizations: constant propagation, copy propagation, alias analysis, dead code elimination, type fact inference, points-to analysis. JS/TS two-level solve for cross-scope taint. k=1 call-site-sensitive inline analysis with caching. Abstract interpretation (interval + string product domain) with widening at loop heads. Constraint solving (PathEnv with equality/relational/disequality constraints). Symbolic feasibility checking (single-path, constraint-based, produces Infeasible/Confirmed/Inconclusive verdicts). Multi-path symbolic exploration with forking executor and verdict aggregation. SSA summaries for cross-file interprocedural analysis. Points-based confidence scoring integrating all evidence sources. Symbolic string theory: structured modeling of 6 string operations (trim, toLowerCase, toUpperCase, replace, substr, strlen) across 10 languages with concrete folding, witness generation, and sanitizer detection.

**Test infrastructure:** 968 lib tests, 0 failures. 265 SSA corpus fixtures. 6 cross-file integration test projects. Benchmark: 214 cases across 9 languages (C, C++, Rust added in Phase 19), P=82.7%, R=95.0%, F1=88.5%. Real-world fixtures verify specific rule IDs, line ranges, and must_match semantics. Negative tests (e.g., `unsafe_string_bounded.js`) prove suppression does NOT over-fire.

**Implemented phases (1-22):** All implemented and wired into the default scan pipeline. See phase-by-phase sections below for details. All features default ON except state analysis (`cfg.scanner.enable_state_analysis`). Feature gates: `NYX_CONTEXT_SENSITIVE`, `NYX_ABSTRACT_INTERP`, `NYX_CONSTRAINT`, `NYX_SYMEX` (all default ON).

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

## Phase 20: Loop-Aware Symbolic Execution

**Category:** Analysis Depth — Symbolic Execution Completeness

**Why now:** The Phase 18b executor handles loops by brute-force budget exhaustion: when a path enters a loop, it re-visits blocks until `MAX_TOTAL_STEPS=500` is consumed, then produces an `Inconclusive` verdict with `search_exhausted=false`. This wastes budget on loop bodies that don't affect the taint path, produces no useful verdict for loop-containing paths, and prevents the executor from reaching post-loop code where the actual sink may be. Any real-world codebase has loops on most taint paths — without loop awareness, symex is limited to straight-line and single-branch code.

### Current state (after Phase 18c)
- `src/symex/executor.rs`: `run_path()` follows CFG successors in a loop with no visited-block tracking, no back-edge detection, and no cycle termination strategy. Budget timeout (`MAX_TOTAL_STEPS`) is the only termination guarantee for loops.
- `src/ssa/ssa_transfer.rs`: The taint engine has `detect_back_edges()` (Phase 5.2) which identifies back edges via post-dominance analysis. Also has `detect_induction_phis()` and `is_simple_increment()` for pruning trivial loop counters. None of this is used by symex.
- `src/abstract_interp/`: The abstract domain has `widen()` on `IntervalFact` and `StringFact` (Phase 17), invoked at loop heads in the taint engine worklist. Not integrated with symex's `SymbolicState` or `PathEnv`.
- `src/constraint/domain.rs`: `PathEnv` has a per-key `meet_counts` tracker and applies widening after `WIDEN_THRESHOLD=3` meets on the same key. This is per-refinement widening, not loop-iteration widening.

### Goals
- Detect loop back edges during symex exploration so the executor knows when it's re-entering a loop
- Implement bounded loop unrolling: explore the loop body up to k iterations (default k=2), producing useful symbolic state for post-loop code
- After k iterations, widen symbolic values at loop-head phi nodes to `Unknown` and proceed past the loop — do not consume remaining budget on further iterations
- Detect and prune simple induction variables (loop counters) during symex to avoid polluting symbolic state with useless expressions like `((i+1)+1)+1`
- Maintain termination guarantees and budget semantics: loop-aware execution should never increase worst-case cost, only reduce wasted budget

### Files/systems to be touched
- Modify: `src/symex/executor.rs` — back-edge detection, per-path visit counts, bounded unrolling, early loop exit
- New: `src/symex/loops.rs` — loop detection and induction variable analysis for symex context
- Modify: `src/symex/state.rs` — `widen_at_loop_head()` method to widen phi-defined values
- Modify: `src/symex/transfer.rs` — skip induction-variable phi nodes on unrolling iterations
- Modify: `src/symex/mod.rs` — `pub mod loops;` declaration

### Concrete implementation tasks

1. **Back-edge detection for symex** in `src/symex/loops.rs`:
   - `fn detect_back_edges(ssa: &SsaBody) -> HashSet<(BlockId, BlockId)>` — compute back edges as (source, target) pairs where target dominates source. Use dominator tree from `petgraph::algo::dominators`. This mirrors `detect_back_edges()` in `ssa_transfer.rs` but operates on `BlockId` pairs rather than `NodeIndex` pairs.
   - `fn loop_heads(back_edges: &HashSet<(BlockId, BlockId)>) -> HashSet<BlockId>` — extract the set of blocks that are loop head targets.
   - Cache the result per `explore_finding()` invocation (computed once, shared across all paths).

2. **Per-path visit tracking** in `ExplorationState`:
   - Add `visit_counts: HashMap<BlockId, u8>` to `ExplorationState`. Increment when entering a block.
   - At clone (fork): the visit counts are inherited by both forks (they share history).
   - `const MAX_LOOP_UNROLL: u8 = 2` — default unrolling bound.

3. **Bounded unrolling logic** in `run_path()`:
   - Before transferring a block, check if it's a loop head AND `visit_counts[block] > MAX_LOOP_UNROLL`.
   - If so: **do not transfer the block again**. Instead:
     a. Call `state.sym_state.widen_at_loop_head(block, ssa)` to widen all phi-defined values in this block to `Unknown` and mark them untainted (conservative: widened values lose taint precision).
     b. Skip to the loop's exit successor. Determine exit successor: the branch successor that is NOT a back-edge target. If both successors are in the loop body (nested loop), fall through to the one on the taint path (`on_path` set).
     c. Continue execution past the loop.
   - If `visit_counts[block] <= MAX_LOOP_UNROLL`: transfer normally (unrolled iteration).

4. **`widen_at_loop_head()`** in `src/symex/state.rs`:
   ```rust
   pub fn widen_at_loop_head(&mut self, block: BlockId, ssa: &SsaBody) {
       let block_data = &ssa.blocks[block.0 as usize];
       for phi in &block_data.phis {
           self.values.insert(phi.value, SymbolicValue::Unknown);
           self.tainted_roots.remove(&phi.value);
       }
   }
   ```
   This is deliberately aggressive: after k unrollings, we know nothing about loop-modified values. The taint engine's abstract domain provides the precise answer; symex just needs to not blow up.

5. **Induction variable detection** in `src/symex/loops.rs`:
   - `fn detect_induction_vars(ssa: &SsaBody, back_edges: &HashSet<(BlockId, BlockId)>) -> HashSet<SsaValue>` — identify SSA values defined by phi nodes at loop heads where the back-edge operand is `v + const` or `v - const` (simple increment/decrement).
   - In `transfer_inst()`: when processing an induction-variable phi at a loop head, set the value to `Unknown` immediately rather than building a growing expression tree. This prevents `((i+1)+1)+1` chains that consume `MAX_EXPR_DEPTH` budget.

6. **Loop exit determination** in `src/symex/loops.rs`:
   - `fn loop_exit_successor(ssa: &SsaBody, block: BlockId, back_edges: &HashSet<(BlockId, BlockId)>, loop_heads: &HashSet<BlockId>) -> Option<BlockId>` — for a branch at a loop head, return the successor that exits the loop (is not dominated by the loop head, or is not a back-edge source). Falls back to `None` if both successors are inside the loop.

7. **Thread loop analysis through executor** in `src/symex/executor.rs`:
   - In `explore_finding()`: compute `back_edges`, `loop_heads`, and `induction_vars` once from the SSA body. Pass as shared references to `run_path()`.
   - Update `run_path()` signature to accept `&LoopInfo` bundle struct.

### Architecture notes

- **Widening is deliberately coarse.** The symex loop widening sets phi-defined values to `Unknown`. This is sound (never misses a real vulnerability) but imprecise (may produce false Inconclusive verdicts for values only modified inside the loop). The abstract interpretation domain in the taint engine provides the precise answer for these values — symex is a secondary check, not the primary analysis.
- **k=2 is sufficient for most security patterns.** Security-relevant loop patterns are typically: (a) iterate over input characters (sanitizer check) — unrolling 2 iterations reveals the branch structure, (b) accumulate into a string/buffer — 2 iterations show the concat pattern, (c) retry loops — 1 iteration shows the body. Deeper unrolling rarely adds precision for security analysis.
- **Budget savings are significant.** A loop with 10 instructions and 50 iterations currently consumes 500 steps (entire budget). With k=2 unrolling, it consumes 20 steps + widening, leaving 480 steps for the rest of the path. This is the primary benefit: reaching post-loop sinks that are currently unreachable.
- **Induction variable pruning is optional but valuable.** Without it, 2 loop iterations build expressions like `BinOp(Add, BinOp(Add, Symbol(i), Concrete(1)), Concrete(1))` at the phi. With it, the phi is immediately `Unknown`. Both are correct; the latter is cleaner and avoids depth-budget pressure.

### Validation requirements
- All existing tests pass (894+ lib tests)
- Loop-containing paths produce verdicts (not just budget-exhausted Inconclusive)
- Post-loop sinks are reachable after bounded unrolling
- Induction variables don't consume expression depth budget
- No increase in worst-case budget consumption (loops should use LESS budget, not more)
- New unit tests for back-edge detection, visit counting, widening, and exit determination

### Exit criteria
- `src/symex/loops.rs` with back-edge detection, loop head computation, induction variable detection, exit successor determination
- `ExplorationState.visit_counts` tracks per-block visits
- `run_path()` implements bounded unrolling (k=2 default) with widening at loop heads
- Induction variable phi nodes produce `Unknown` immediately (no expression tree growth)
- At least 2 integration fixtures with loops: one where the sink is inside the loop body, one where it's after the loop
- Budget utilization improves: loop-containing paths use fewer total steps

### Dependencies
Phase 18b (multi-path exploration — provides `ExplorationState`, `run_path()`, budget framework). Phase 5.2 (induction variable detection in taint engine — design reference, not code dependency).

---

## Phase 21: Symbolic Memory Model — Field-Sensitive Heap

**Category:** Analysis Depth — Symbolic Execution Precision

**Why now:** The symbolic executor treats all property accesses and container operations as opaque function calls: `obj.field` becomes `Call(".field", [obj])` and `arr[i]` becomes `Call("[]", [arr, i])`. This means taint that flows through object fields or array elements is invisible to symex — it can only confirm paths where taint flows through scalar variables. Real vulnerability patterns frequently involve object fields: `req.body.username` → `query.where.name` → `db.query()`. Without a memory model, these paths produce `Inconclusive` verdicts because the symbolic executor cannot connect the store to the load.

### Current state (after Phase 20)
- `src/symex/transfer.rs`: Property access and array indexing produce `Call(method, args)` — uninterpreted.
- `src/symex/state.rs`: `SymbolicState` maps `SsaValue → SymbolicValue`. No heap or field tracking.
- `src/ssa/heap.rs`: The taint engine has `HeapState` with `HeapObjectId(SsaValue)` allocation-site identities and per-object `HeapTaint` (caps + origins). Container operations (`push`, `pop`, `set`, `get`) are classified by `classify_container_op()` in `pointsto.rs`.
- `src/ssa/pointsto.rs`: `PointsToResult` tracks which SSA values point to which heap objects. `PointsToSet` is bounded to 4 objects per value.
- `src/cfg.rs`: `NodeInfo` has `receiver: Option<String>` for method calls, `defines: Option<String>` for LHS of assignments. Property access patterns are available from the AST.

### Goals
- Add a symbolic heap to `SymbolicState` that maps (object identity, field name) → `SymbolicValue`
- Model property stores: `obj.field = expr` updates the symbolic heap
- Model property loads: `x = obj.field` reads from the symbolic heap (or produces `Unknown` if field not tracked)
- Use allocation-site identity from `PointsToResult` to distinguish different objects
- Track taint through object field assignments and reads
- Bounded: cap tracked fields per object and total heap entries to prevent blowup

### Files/systems to be touched
- New: `src/symex/heap.rs` — `SymbolicHeap`, `HeapKey`, store/load operations
- Modify: `src/symex/state.rs` — add `heap: SymbolicHeap` to `SymbolicState`, update `clone()`
- Modify: `src/symex/transfer.rs` — model property store/load instructions through symbolic heap
- Modify: `src/symex/executor.rs` — thread `PointsToResult` into exploration context
- Modify: `src/symex/mod.rs` — `pub mod heap;`, add `points_to: Option<&PointsToResult>` to `SymexContext`
- Modify: `src/taint/mod.rs` — pass `PointsToResult` from `OptimizeResult` into `SymexContext`

### Concrete implementation tasks

1. **Define `SymbolicHeap`** in `src/symex/heap.rs`:
   ```rust
   /// Symbolic heap mapping (object, field) → SymbolicValue.
   /// Allocation-site sensitive: each allocation site is a distinct object.
   pub struct SymbolicHeap {
       fields: HashMap<HeapKey, SymbolicValue>,
       tainted_keys: HashSet<HeapKey>,
   }

   #[derive(Hash, Eq, PartialEq, Clone)]
   pub struct HeapKey {
       object: SsaValue,      // allocation site (SSA value that created the object)
       field: CompactString,   // field name ("username", "0", etc.)
   }
   ```
   Implement: `store(key, value)`, `load(key) -> SymbolicValue` (returns `Unknown` if absent), `is_tainted(key) -> bool`, `clone()`.
   - `const MAX_HEAP_ENTRIES: usize = 64` — if exceeded, evict oldest entries (LRU or FIFO). Sound: eviction produces `Unknown` on subsequent load, which is conservative.
   - `const MAX_FIELDS_PER_OBJECT: usize = 8` — per-object cap. Beyond this, the object is "smeared" — all fields collapse to a single `Unknown` entry.

2. **Identify store/load patterns** in `src/symex/transfer.rs`:
   - **Store pattern**: `SsaOp::Assign([rhs])` where `cfg_node.defines` contains a `.` (property assignment like `obj.field = rhs`). Extract receiver and field from `defines` string (split on last `.`).
   - **Load pattern**: `SsaOp::Call { callee, args, receiver }` where `callee` matches a property access pattern (contains `.` prefix or is a known getter). Or: `SsaOp::Assign([src])` where `cfg_node` has a property-access use pattern.
   - **Container store**: `SsaOp::Call` where callee matches `push`, `set`, `append`, `add` — classify via a simplified version of `classify_container_op()` from `pointsto.rs`.
   - **Container load**: `SsaOp::Call` where callee matches `pop`, `get`, `shift`, `remove`.
   - **Resolve object identity**: look up the receiver SSA value in `PointsToResult` to get `HeapObjectId`. If `PointsToSet` has exactly one object, use that as the allocation site. If multiple objects (may-alias), fall through to `Unknown` (sound: don't guess among aliases).

3. **Wire symbolic heap into transfer**:
   - In `transfer_inst()`, before the existing `SsaOp::Assign` and `SsaOp::Call` handling:
     a. Check if instruction matches a store pattern → `state.heap.store(key, rhs_sym)` + propagate taint
     b. Check if instruction matches a load pattern → `state.set(result, state.heap.load(key))` + propagate taint from heap entry
   - Fall through to existing handling if no store/load pattern matches. This ensures backward compatibility — no existing behavior changes.

4. **Thread `PointsToResult` to symex**:
   - Add `points_to: Option<&'a PointsToResult>` to `SymexContext`.
   - In `taint/mod.rs` call sites, pass `Some(&opt.points_to)` (already available from `OptimizeResult`).
   - In `transfer_inst()`, resolve receiver identities via points-to lookup.

5. **Heap-aware witness generation** in `src/symex/witness.rs`:
   - When building witness for a confirmed path, check if any tainted heap entries contributed to the sink expression.
   - If so, include the field path in the witness: `"input 'req.body.username' stores to user.name, flows to query()"`.
   - Use `SymbolicHeap.tainted_keys` to find the relevant field paths.

6. **Add unit tests**:
   - `test_heap_store_load_roundtrip` — store a value, load it back, verify equality
   - `test_heap_taint_propagation` — store tainted value, load produces tainted result
   - `test_heap_unknown_on_missing_field` — load from unstored field returns Unknown
   - `test_heap_bounds` — exceed `MAX_HEAP_ENTRIES`, verify eviction doesn't crash and loads return Unknown
   - `test_heap_alias_fallback` — multiple objects in PointsToSet → no store/load (fall through to Unknown)

7. **Add integration fixtures**:
   - `tests/fixtures/real_world/javascript/taint/symex_field_taint.js` — `req.body.name` stored into `user.name`, passed to `db.query()`. Expect Confirmed with field-aware witness.
   - `tests/fixtures/real_world/javascript/taint/symex_field_sanitized.js` — field stored after sanitization. Expect no false positive.

### Architecture notes

- **Allocation-site sensitivity is the right granularity.** Each `new Object()` / `{}` literal gets a distinct identity. This distinguishes `userInput` from `config` without tracking every assignment. It matches the existing `HeapObjectId` model in the taint engine.
- **Single-object precision, fall back on may-alias.** If `PointsToSet` has >1 object, the store/load is ambiguous — fall through to existing opaque-call behavior. This is sound (same as today) and avoids false precision. Only exact (single-object) aliases benefit from the heap model.
- **No nested structures.** `obj.field.subfield` requires two loads. The first load produces a `SymbolicValue` that may be another object identity, enabling chained access. But this is best-effort — if the intermediate load returns `Unknown`, the chain breaks. Full nested tracking would require recursive heap modeling, which is Phase 23 (SMT) territory.
- **Heap state is per-path.** `SymbolicHeap` is cloned at fork points, same as `SymbolicState`. This is O(heap_size) per fork — bounded by `MAX_HEAP_ENTRIES=64`.

### Validation requirements
- All existing tests pass
- Field-tainted paths produce Confirmed verdicts (previously Inconclusive)
- Heap bounds prevent blowup on object-heavy code
- May-alias scenarios fall back to existing behavior (no precision loss)
- Witnesses include field paths where applicable

### Exit criteria
- `src/symex/heap.rs` with `SymbolicHeap`, bounded store/load, taint tracking
- Property access patterns detected and routed through symbolic heap in `transfer_inst()`
- `PointsToResult` threaded through `SymexContext` for object identity resolution
- Field-tainted findings produce improved verdicts with field-aware witnesses
- 2+ integration fixtures demonstrate field-sensitive symbolic execution

### Dependencies
Phase 18c (witness generation — field paths extend witness format). Phase 14 (points-to analysis — `PointsToResult` provides object identities). Phase 20 (loop awareness — loops over object fields need bounded unrolling before heap loads).

---

## Phase 22: Symbolic String Theory

**Category:** Analysis Depth — Symbolic Execution Precision

**Why now:** String operations dominate web vulnerability patterns: SQL injection involves string concatenation with user input, XSS involves HTML template rendering, command injection involves shell command construction, path traversal involves filesystem path assembly. The symbolic executor currently models `Concat` but treats all other string operations as opaque `Call` nodes: `.replace()`, `.substring()`, `.split()`, `.trim()`, `.toLowerCase()`, `.indexOf()` all produce `Unknown`. This means (a) witness generation cannot show how string transformations affect the exploit payload, (b) the constraint solver cannot reason about string conditions like `.startsWith("http://")` or `.length > 0`, and (c) sanitizer-like string operations (`.replace(/<script>/g, "")`) are invisible to symex even when the taint engine already models them.

### Current state (after Phase 21)
- `src/symex/value.rs`: `SymbolicValue::Concat(Box, Box)` and `SymbolicValue::ConcreteStr(String)` exist. `mk_concat()` folds two `ConcreteStr` values into one. No other string operations.
- `src/symex/witness.rs`: `evaluate_concrete()` folds `Concat` chains to strings. `substitute_tainted()` replaces `Symbol` nodes with payload strings. Works well for simple concat but cannot model string method results.
- `src/abstract_interp/string_domain.rs`: `StringFact { prefix: Option<String>, suffix: Option<String> }` — the abstract domain tracks string prefixes and suffixes. `concat_transfer()` propagates prefixes/suffixes through concatenation. Join uses longest common prefix/suffix.
- `src/constraint/domain.rs`: `ConstValue::Str(String)` exists as an exact string constant in `ValueFact`. String comparisons (`==`, `!=`) work. No prefix/suffix/length reasoning in the constraint domain.

### Goals
- Extend `SymbolicValue` with common string operations that preserve structure through the symbolic path
- Model string methods during symbolic transfer: `substring`, `replace`, `trim`, `toLowerCase`/`toUpperCase`, `split`, `indexOf`, `startsWith`/`endsWith`, `length`
- Add string-aware constraint reasoning: prefix checks, length bounds, pattern membership
- Improve witness generation to show string operation effects on exploit payloads
- Detect when string operations act as sanitizers (e.g., `.replace(/<script>/g, "")` strips XSS payload) and produce appropriate verdicts

### Files/systems to be touched
- Modify: `src/symex/value.rs` — add `StrOp` enum and `SymbolicValue::StrOp(StrOp, Box<SymbolicValue>, Vec<SymbolicValue>)` variant (or: add specific variants for key operations)
- New: `src/symex/strings.rs` — string operation modeling, concrete evaluation, sanitizer detection
- Modify: `src/symex/transfer.rs` — recognize string method calls and produce structured `SymbolicValue` instead of opaque `Call`
- Modify: `src/symex/witness.rs` — evaluate string operations during witness generation
- Modify: `src/constraint/solver.rs` — add string-aware refinement rules (optional, for prefix/length reasoning)
- Modify: `src/symex/mod.rs` — `pub mod strings;` declaration

### Concrete implementation tasks

1. **Extend `SymbolicValue`** in `src/symex/value.rs`:
   - Option A (enum extension): Add variants for high-value operations:
     ```rust
     Substr(Box<SymbolicValue>, Box<SymbolicValue>, Option<Box<SymbolicValue>>)  // str, start, end?
     Replace(Box<SymbolicValue>, String, String)  // str, pattern, replacement (concrete pattern/repl only)
     ToLower(Box<SymbolicValue>)
     ToUpper(Box<SymbolicValue>)
     Trim(Box<SymbolicValue>)
     StrLen(Box<SymbolicValue>)  // returns Concrete(n) for ConcreteStr, or StrLen(sym) for symbolic
     ```
   - Option B (generic StrOp): `StrOp(StringMethod, Box<SymbolicValue>, Vec<SymbolicValue>)` with `StringMethod` enum. More extensible but less type-safe.
   - **Recommendation**: Option A for the 6 operations above. These are the high-value operations for security analysis. Additional operations can be added incrementally.
   - Implement smart constructors: `mk_substr()`, `mk_replace()`, `mk_tolower()`, etc. Each folds concrete arguments immediately (e.g., `mk_tolower(ConcreteStr("ABC"))` → `ConcreteStr("abc")`).

2. **String method recognition** in `src/symex/strings.rs`:
   - `fn recognize_string_method(callee: &str, lang: Lang) -> Option<StringMethod>` — map callee names to semantic operations across languages:
     - `substring`, `slice`, `substr` (JS/TS), `[:]` slicing (Python) → `Substr`
     - `replace`, `replaceAll` (JS), `str.replace` (Python), `gsub` (Ruby) → `Replace`
     - `toLowerCase` (JS), `lower` (Python), `downcase` (Ruby) → `ToLower`
     - `toUpperCase` (JS), `upper` (Python), `upcase` (Ruby) → `ToUpper`
     - `trim`, `strip` (Python/Ruby) → `Trim`
     - `length`, `len` (Python), `size` (Ruby) → `StrLen`
   - This is a classifier, not exhaustive — unrecognized methods fall through to `Call`.

3. **String transfer** in `src/symex/transfer.rs`:
   - In the `SsaOp::Call` arm, before the existing fallback:
     a. Check if callee is a recognized string method via `recognize_string_method()`.
     b. If recognized and receiver is present: build the appropriate `SymbolicValue` variant using the receiver's symbolic value and concrete arguments (if available).
     c. Taint propagation: string operations preserve taint from the input string. `Replace` additionally checks if replacement operands are tainted.
     d. If arguments are not concrete (e.g., dynamic replace pattern): fall through to `Call` (can't model dynamic string operations precisely).

4. **Concrete evaluation for witnesses** in `src/symex/witness.rs`:
   - Extend `evaluate_concrete()` to handle new string variants:
     - `Substr(ConcreteStr(s), Concrete(start), Some(Concrete(end)))` → `s[start..end]`
     - `Replace(ConcreteStr(s), pattern, repl)` → `s.replace(pattern, repl)`
     - `ToLower(ConcreteStr(s))` → `s.to_lowercase()`
     - etc.
   - Extend `substitute_tainted()` to recurse into string operation operands.
   - This makes witnesses more accurate: `"input 'name' = \"<script>alert('xss')</script>\" flows to res.send(\"<h1>Hello \" + name.trim() + \"</h1>\")"` shows the trim didn't affect the payload.

5. **Sanitizer detection via string operations** in `src/symex/strings.rs`:
   - `fn is_string_sanitizer(method: StringMethod, pattern: &str, cap: Cap) -> bool`:
     - `Replace` with pattern containing `<script>`, `<img`, `<svg`, `on\w+=` → sanitizer for `Cap::HTML_ESCAPE` / `Cap::CODE_EXEC`
     - `Replace` with pattern containing `'`, `"`, `--`, `;` → potential sanitizer for `Cap::SQL_QUERY`
     - `Replace` with pattern containing `$`, `` ` ``, `|`, `;` → potential sanitizer for `Cap::SHELL_ESCAPE`
   - When a recognized sanitizer pattern is detected during transfer, the result value's taint can be conditionally cleared (or at minimum, the constraint solver can note that the dangerous pattern was removed).
   - **Conservative policy**: Only clear taint when the replace pattern is provably comprehensive (e.g., global replace). Partial sanitization (non-global, single character) should NOT clear taint — log as a note instead.

6. **String-aware constraint reasoning** (optional, in `src/constraint/solver.rs`):
   - When `ConditionExpr::Comparison` has `lhs = StrLen(var)` and `rhs = Concrete(n)`: refine `var`'s `ValueFact` with string length bounds.
   - When `BoolTest` on a value known to be a `startsWith` result: infer prefix constraint on the tested string.
   - This is lower priority than the transfer/witness improvements — implement if budget allows, skip otherwise.

7. **Add unit tests** in `src/symex/strings.rs`:
   - `test_recognize_string_methods` — verify method recognition across JS, Python, Ruby
   - `test_concrete_folding` — `mk_tolower(ConcreteStr("ABC"))` → `ConcreteStr("abc")`
   - `test_substr_concrete` — `mk_substr(ConcreteStr("hello world"), 0, 5)` → `ConcreteStr("hello")`
   - `test_replace_concrete` — `mk_replace(ConcreteStr("a<script>b"), "<script>", "")` → `ConcreteStr("ab")`
   - `test_taint_preserved_through_string_ops` — tainted input through `ToLower` stays tainted
   - `test_sanitizer_detection` — `Replace` with XSS pattern detected as sanitizer
   - `test_dynamic_pattern_fallback` — non-concrete replace pattern falls through to `Call`

8. **Add integration fixtures**:
   - `tests/fixtures/real_world/javascript/taint/symex_string_ops.js` — input goes through `.trim().toLowerCase()` before reaching sink. Witness should show the transformations.
   - `tests/fixtures/real_world/javascript/taint/symex_string_sanitizer.js` — input goes through `.replace(/<script>/g, "")` — symex should detect this as a sanitizer pattern and report accordingly.

### Architecture notes

- **Concrete arguments only for structured modeling.** `"hello".replace(userInput, "")` has a dynamic pattern — this cannot be modeled as a `Replace` node because the pattern is symbolic. Fall through to `Call` in these cases. Only concrete patterns and replacements produce structured `SymbolicValue` variants.
- **Security-focused operation set.** The 6 operations above (substr, replace, tolower, toupper, trim, strlen) cover 90%+ of string operations relevant to security analysis. Encoding operations (`encodeURIComponent`, `htmlspecialchars`) should be modeled as sanitizers in the taint engine (which they already are), not as string operations in symex.
- **No regex engine.** `Replace` with pattern is modeled as literal string replacement for concrete folding and sanitizer detection. Regex semantics (`/pattern/g`) are not interpreted — the pattern string is checked for known dangerous substrings. Full regex reasoning would require a regex theory solver, which is out of scope.
- **String operations compose.** `input.trim().toLowerCase().replace(...)` builds a nested tree: `Replace(ToLower(Trim(Symbol(input))), ...)`. `evaluate_concrete()` unwinds this recursively. Depth bounding (`MAX_EXPR_DEPTH=32`) prevents blowup.

### Validation requirements
- All existing tests pass
- String operations produce structured symbolic values (not opaque `Call`)
- Witnesses show string transformation effects on exploit payloads
- Sanitizer detection via `Replace` works for at least XSS and SQLi patterns
- Concrete folding correct for all 6 operation types
- No false negatives from overly aggressive sanitizer detection

### Exit criteria
- 6 string operation variants in `SymbolicValue` with smart constructors and concrete folding
- String method recognition across JS, Python, Ruby (at minimum)
- `transfer_inst()` routes recognized string methods through structured modeling
- `evaluate_concrete()` and `substitute_tainted()` handle all new variants
- Sanitizer detection for `Replace` patterns covering XSS, SQLi, CMDi
- Witnesses include string operation effects
- 2+ integration fixtures

### Dependencies
Phase 18c (witness generation — string operations extend witness evaluation). Phase 20 (loop awareness — string operations inside loops need bounded handling).

---

## Phase 23: SMT Solver Integration

**Category:** Analysis Depth — Symbolic Execution Decision Procedure

**Why now:** The constraint system (`PathEnv` + `refine_env`) is a lightweight abstract domain that tracks per-value facts (intervals, types, nullability, exact values) and detects contradictions incrementally. This handles simple cases well but cannot reason about: (a) arithmetic relationships between multiple variables (`x + y > 10 && x < 3 && y < 5`), (b) disjunctive conditions (`(a && !b) || (!a && b)`), (c) complex string constraints beyond prefix/suffix, (d) array index reasoning, or (e) combined constraints that require backtracking search. An SMT solver provides a complete decision procedure for these constraint classes. This is the single largest capability upgrade for the symbolic executor — it replaces "detect obvious contradictions" with "prove satisfiability or unsatisfiability."

### Current state (after Phase 22)
- `src/constraint/domain.rs`: `PathEnv` with per-value `ValueFact` (intervals, types, nullability, exact, excluded), equality classes (`UnionFind`), disequalities, relational constraints (`a < b`, `a <= b`). Bounded: `MAX_PATH_ENV_ENTRIES=64`, `MAX_RELATIONAL=16`.
- `src/constraint/solver.rs`: `refine_env()` applies single `ConditionExpr` to `PathEnv` — monotone lattice refinement, no backtracking. `is_satisfiable()` checks `env.unsat` flag.
- `src/constraint/lower.rs`: `lower_condition()` produces `ConditionExpr` from CFG condition nodes. Text-based operator extraction as fallback.
- `src/symex/executor.rs`: Calls `constraint::refine_env()` at each branch, checks `env.is_unsat()`. Branches with UNSAT environments produce `Infeasible` verdicts.
- No Z3, SMT-LIB, or SAT solver dependency in `Cargo.toml`.

### Goals
- Integrate Z3 (via the `z3` crate) as an optional backend for constraint solving
- Implement a hybrid architecture: `PathEnv` handles fast-path refinement (95% of cases), Z3 handles hard cases where `PathEnv` returns `Unknown`/inconclusive
- Translate accumulated path constraints to Z3 assertions incrementally (push/pop scoping aligned with path exploration)
- Support integer arithmetic theory (QF_LIA), string theory (QF_S), and bitvector theory (QF_BV) for comprehensive reasoning
- Provide concrete counterexamples from Z3 models to improve witness generation
- Feature-gated: `NYX_SMT=1` enables Z3 backend (default OFF until proven stable and performant)

### Files/systems to be touched
- New: `src/symex/smt.rs` — Z3 context management, expression translation, query interface
- Modify: `src/symex/executor.rs` — use SMT backend for branch feasibility when PathEnv is inconclusive
- Modify: `src/symex/witness.rs` — extract concrete values from Z3 model for witnesses
- Modify: `src/symex/mod.rs` — `pub mod smt;`, feature gate, `SmtContext` lifetime management
- Modify: `Cargo.toml` — add `z3` crate as optional dependency behind a feature flag

### Concrete implementation tasks

1. **Add Z3 dependency** in `Cargo.toml`:
   ```toml
   [features]
   smt = ["z3"]

   [dependencies]
   z3 = { version = "0.12", optional = true }
   ```
   Conditional compilation: all SMT code behind `#[cfg(feature = "smt")]`. When the feature is disabled, the solver falls back to `PathEnv`-only (current behavior).

2. **Define `SmtContext`** in `src/symex/smt.rs`:
   ```rust
   pub struct SmtContext<'ctx> {
       ctx: &'ctx z3::Context,
       solver: z3::Solver<'ctx>,
       /// SSA value → Z3 AST node mapping
       var_map: HashMap<SsaValue, z3::ast::Dynamic<'ctx>>,
       /// Sort assignment: which SSA values are ints, which are strings
       sorts: HashMap<SsaValue, SmtSort>,
       /// Assertion stack depth (for push/pop at forks)
       scope_depth: u32,
   }

   enum SmtSort { Int, String, Bool }
   ```

3. **Expression translation** in `src/symex/smt.rs`:
   - `fn translate_value(ctx: &SmtContext, val: &SymbolicValue) -> z3::ast::Dynamic`:
     - `Concrete(n)` → `z3::ast::Int::from_i64(ctx, n)`
     - `ConcreteStr(s)` → `z3::ast::String::from_str(ctx, s)`
     - `Symbol(v)` → lookup or create fresh Z3 variable with appropriate sort
     - `BinOp(op, l, r)` → translate recursively, apply Z3 arithmetic operations
     - `Concat(l, r)` → `z3::ast::String::concat(ctx, &[&l_z3, &r_z3])`
     - `StrLen(s)` → `z3::ast::String::length(&s_z3)`
     - `Substr(s, start, end)` → `z3::ast::String::extract(&s_z3, &start_z3, &len_z3)`
     - `Replace(s, pat, repl)` → `z3::ast::String::replace(&s_z3, &pat_z3, &repl_z3)`
     - `Call(_, _)` / `Phi(_, _)` / `Unknown` → fresh unconstrained Z3 variable (sound: no knowledge)
   - Sort inference: if a value appears in arithmetic context → Int; if in string context → String; default → Int.

4. **Constraint assertion** in `src/symex/smt.rs`:
   - `fn assert_condition(ctx: &mut SmtContext, cond: &ConditionExpr, polarity: bool)`:
     - `Comparison { lhs, op, rhs }` → translate operands, assert comparison with Z3 operator
     - `NullCheck { var, is_null }` → model as equality with a distinguished null constant
     - `TypeCheck { var, type_name, positive }` → model as sort constraint (limited: Z3 doesn't have JS type system, but int/string distinction is useful)
     - `BoolTest { var }` → assert `var != 0` (truthiness)
     - Apply `polarity` via Z3 negation
   - `fn check_sat(ctx: &SmtContext) -> SatResult { Sat, Unsat, Unknown }`:
     - Call `ctx.solver.check()` with timeout (default 100ms per query)
     - Map Z3 result to `SatResult`

5. **Hybrid architecture** in `src/symex/executor.rs`:
   - At branch points in `run_path()`:
     a. First: apply `constraint::refine_env()` to `PathEnv` (fast path, microseconds)
     b. If `PathEnv.is_unsat()` → `Infeasible` (no SMT needed)
     c. If `PathEnv` is satisfiable but has accumulated >3 constraints on the same path AND `NYX_SMT=1`: invoke Z3 as confirmation
     d. `SmtContext::assert_condition()` for each `PathConstraint` accumulated on this path
     e. `SmtContext::check_sat()` → if `Unsat`, override verdict to `Infeasible`
   - Z3 is the **secondary** solver, not the primary. Most branches are decided by `PathEnv` alone. Z3 is only invoked when `PathEnv` says "satisfiable" but the accumulated constraints are complex enough that `PathEnv` might be wrong (imprecise).
   - Push/pop Z3 solver scopes at fork points for incremental solving.

6. **Model extraction for witnesses** in `src/symex/witness.rs`:
   - When Z3 returns `Sat`, extract the model: `ctx.solver.get_model()`.
   - Map Z3 variable assignments back to SSA values via `var_map`.
   - Use concrete values from the model as witness values instead of exploit templates.
   - Example: if Z3 determines `x = "admin' OR 1=1 --"` satisfies all constraints, use that exact string as the witness instead of the generic `"' OR 1=1 --"` template.

7. **Timeout and resource bounding**:
   - Per-query timeout: `const SMT_QUERY_TIMEOUT_MS: u64 = 100` — individual Z3 check-sat calls
   - Per-finding budget: `const MAX_SMT_QUERIES_PER_FINDING: usize = 10` — cap total Z3 invocations
   - Global Z3 context: create once per `explore_finding()`, destroy at end (avoids per-query context overhead)
   - If Z3 returns `Unknown` (timeout): treat as satisfiable (conservative, same as no SMT)

8. **Add unit tests** (behind `#[cfg(feature = "smt")]`):
   - `test_smt_simple_contradiction` — `x > 5 && x < 3` → Unsat
   - `test_smt_multi_variable` — `x + y > 10 && x < 3 && y < 5` → Unsat (PathEnv cannot detect this)
   - `test_smt_string_prefix` — `startsWith(x, "http://") && contains(x, "169.254")` → Sat (SSRF witness)
   - `test_smt_satisfiable_path` — simple satisfiable constraints → Sat with model extraction
   - `test_smt_timeout_fallback` — artificially complex query → Unknown → treated as Sat

9. **Add integration fixtures**:
   - `tests/fixtures/real_world/javascript/taint/symex_smt_infeasible.js` — path with multi-variable constraint that PathEnv cannot prove infeasible but Z3 can. With SMT enabled, expect `Infeasible`; without, expect `Confirmed` (false positive that SMT eliminates).

### Architecture notes

- **Z3 is optional, not required.** The `smt` feature flag keeps Z3 as an opt-in capability. The scanner works identically without it — `PathEnv` is the default. This is important for deployment: Z3 is a ~50MB native library with platform-specific builds.
- **Hybrid is critical for performance.** Z3 queries take 1-100ms each. With 50 findings per file × 8 paths × multiple branches, naive SMT usage would add seconds per file. The hybrid approach ensures Z3 is only invoked on hard cases (estimated <5% of branches) — PathEnv handles the rest in microseconds.
- **Incremental solving via push/pop.** Z3's incremental mode reuses prior assertions. At each fork, push a scope; at backtrack, pop. This avoids re-asserting the entire path history and leverages Z3's internal caching.
- **String theory is Z3's biggest win for security.** Z3's string theory (QF_S / Seq) can reason about `concat`, `contains`, `indexOf`, `replace`, `length`, `substr` natively. This directly complements Phase 22's symbolic string operations — the expression tree provides the structure, Z3 provides the reasoning.
- **Do not replace PathEnv.** `PathEnv` is fast, predictable, and sufficient for 95% of cases. Z3 is for the remaining 5% where PathEnv's per-value abstraction loses precision. Replacing PathEnv with Z3-only would be a massive performance regression.

### Validation requirements
- All existing tests pass with SMT feature disabled (default)
- With `NYX_SMT=1`: additional infeasible paths detected that PathEnv misses
- Z3 query timeout prevents unbounded latency
- Model extraction produces valid concrete witnesses
- No false negatives introduced by SMT (conservative fallback on Unknown)
- Performance: <200ms added per file with SMT enabled (measured on benchmark corpus)

### Exit criteria
- `z3` crate integrated as optional dependency behind `smt` feature flag
- `SmtContext` translates `SymbolicValue` + `ConditionExpr` to Z3 formulas
- Hybrid solver: PathEnv fast-path, Z3 for complex cases
- Push/pop scoping at path forks for incremental solving
- Model extraction feeds concrete values into witness generation
- Per-query timeout (100ms) and per-finding budget (10 queries) enforced
- Feature gate `NYX_SMT` (default OFF)
- At least 1 integration fixture demonstrating SMT-only infeasibility detection

### Dependencies
Phase 18b (multi-path exploration — Z3 scoping mirrors fork points). Phase 22 (string theory — Z3 string operations complement symbolic string values). Phase 20 (loop awareness — loop-widened values produce fresh Z3 variables at loop exits).

---

## Phase 24A: Interprocedural Symbolic Execution — Core

**Category:** Analysis Depth — Symbolic Execution Precision

**Why now:** The symbolic executor currently resolves cross-file calls via pre-computed `SsaFuncSummary` transforms (Phase 18c): Identity pass-through, StripBits sanitizer, AddBits source. This works for simple functions but loses precision for callees with internal branching, data-dependent returns, or multiple effects. Example: `function getUser(id) { if (id < 0) return "guest"; return db.query("SELECT * FROM users WHERE id=" + id); }` — the summary says Identity (param flows to return), but it does not capture that the return value is a SQL query string only when `id >= 0`. Interprocedural symbolic inlining would walk the callee's SSA body during symex, maintaining full symbolic precision through the callee's control flow.

### Current state (after Phase 23)
- `src/symex/transfer.rs`: Cross-file calls resolved via `resolve_callee_symbolically()` — looks up `SsaFuncSummary` and models return value based on `TaintTransform` variants. Falls back to opaque `Call(callee, args)` when no summary or ambiguous resolution.
- `src/taint/ssa_transfer.rs`: The taint engine has k=1 call-site-sensitive inline analysis via `inline_analyse_callee()` — re-analyzes callee SSA body with actual argument taint. Uses `CalleeSsaBody` (pre-lowered SSA + OptimizeResult + param_count) and `InlineCache` (keyed by `(callee_name, ArgTaintSig)`).
- `src/taint/mod.rs`: `lower_all_functions()` produces both `SsaFuncSummary` and `CalleeSsaBody` for each intra-file function. `CalleeSsaBody` is available at taint analysis time.
- `src/symex/executor.rs`: `explore_finding()` accepts `&SymexContext` with optional `GlobalSummaries` for summary-based resolution. No callee body access.

### Goals
- Inline callee SSA bodies into the symbolic executor's path exploration, enabling full symbolic precision through callee control flow
- Maintain call depth bound (k=1 default, configurable) to prevent unbounded inlining
- Seed callee parameters with actual call-site argument symbolic values (not just taint bits)
- Propagate callee return's symbolic value back to the caller's result SSA value
- Detect callee-internal sinks during inline symex exploration (beyond taint engine's `param_to_sink`)
- Cache inline analysis results keyed by (callee, argument symbolic signatures) to avoid redundant exploration

### Files/systems to be touched
- Modify: `src/symex/transfer.rs` — add inline callee exploration as resolution step before summary fallback
- New: `src/symex/inline.rs` — inline symbolic exploration of callee bodies
- Modify: `src/symex/executor.rs` — support recursive `run_path()` calls for callee exploration, or separate callee exploration engine
- Modify: `src/symex/mod.rs` — `pub mod inline;`, add `callee_bodies: Option<&HashMap<String, CalleeSsaBody>>` to `SymexContext`
- Modify: `src/taint/mod.rs` — thread `CalleeSsaBody` map into `SymexContext` at all 3 call sites

### Concrete implementation tasks

1. **Define `InlineSymexResult`** in `src/symex/inline.rs`:
   ```rust
   pub struct InlineSymexResult {
       /// Symbolic value at the callee's return point.
       pub return_value: SymbolicValue,
       /// Whether the return value carries taint.
       pub return_tainted: bool,
       /// Callee-internal sink events detected during exploration.
       pub internal_sinks: Vec<InlineSinkEvent>,
       /// Constraints accumulated inside the callee.
       pub callee_constraints: Vec<PathConstraint>,
   }

   pub struct InlineSinkEvent {
       pub sink_cfg_node: NodeIndex,
       pub tainted_arg: SsaValue,
       pub cap: Cap,
   }
   ```

2. **Implement `inline_explore_callee()`** in `src/symex/inline.rs`:
   ```rust
   pub fn inline_explore_callee(
       callee_body: &CalleeSsaBody,
       arg_values: &[SymbolicValue],
       arg_tainted: &[bool],
       caller_ctx: &SymexContext,
       depth: usize,
   ) -> Option<InlineSymexResult>
   ```
   Logic:
   a. Check depth bound: if `depth >= MAX_INLINE_DEPTH` (default 1), return `None` (fall through to summary).
   b. Check callee size: if `callee_body.ssa.blocks.len() > MAX_INLINE_BLOCKS` (default 50), return `None`.
   c. Create fresh `SymbolicState` for the callee. Seed parameter SSA values from `arg_values`.
   d. Mark parameters as tainted based on `arg_tainted`.
   e. Run a simplified version of `explore_finding()` on the callee's SSA body — but instead of looking for a specific sink, run to completion (all `Return` terminators).
   f. At each `Return` terminator, collect the symbolic value of the return SSA value.
   g. If multiple return points with different symbolic values: build a `Phi` of the return values (or `Unknown` if too many).
   h. Collect any sink events encountered during the callee's exploration (callee-internal sinks).

3. **Integrate into transfer** in `src/symex/transfer.rs`:
   - In the `SsaOp::Call` arm, add inline resolution BEFORE the existing summary resolution:
     a. If `callee_bodies` is available in context and contains the callee name:
     b. Build `arg_values` and `arg_tainted` from the current symbolic state.
     c. Call `inline_explore_callee()`.
     d. If returns `Some(result)`: use `result.return_value` as the call's symbolic value, propagate `result.return_tainted`, record `result.internal_sinks` for later evidence.
     e. If returns `None` (depth exceeded, too large, etc.): fall through to summary resolution.
   - **Resolution order**: inline body → summary → opaque `Call`.

4. **Callee-internal sink detection**:
   - During inline exploration, check if any SSA instruction in the callee body is a sink (via `cfg[inst.cfg_node].labels` containing `DataLabel::Sink`).
   - If a tainted value reaches a callee-internal sink: record as `InlineSinkEvent`.
   - These events complement the taint engine's `param_to_sink` — they provide symbolic precision about WHICH argument value reaches the sink and under WHAT path constraints.
   - Report inline sink events as additional evidence on the caller's finding.

5. **Inline cache** in `src/symex/inline.rs`:
   - `InlineSymexCache`: `HashMap<(String, SymbolicArgSig), InlineSymexResult>`
   - `SymbolicArgSig`: compact signature of argument symbolic values — hash of each arg's `SymbolicValue` discriminant + taint status. Full structural hashing is too expensive; discriminant + taint captures the behavioral signature.
   - Cache is per-`explore_finding()` invocation (not global) to bound memory.
   - On cache hit: return cached result immediately. On miss: run inline exploration and cache.

6. **Thread `CalleeSsaBody` map to symex**:
   - Add `callee_bodies: Option<&'a HashMap<String, CalleeSsaBody>>` to `SymexContext`.
   - In `taint/mod.rs`: the `CalleeSsaBody` map is already produced by `lower_all_functions()` for the taint engine's inline analysis. Pass it into `SymexContext` at all 3 call sites.
   - For the JS two-level solve, each function scope's `callee_bodies` map is passed through.

7. **Depth and budget limits**:
   - `const MAX_INLINE_DEPTH: usize = 1` — single-level inlining (caller → callee, no callee → callee's callee).
   - `const MAX_INLINE_BLOCKS: usize = 50` — skip inlining for large callees.
   - `const MAX_INLINE_STEPS: usize = 100` — symbolic transfer step budget for the callee exploration (separate from the caller's budget).
   - `const MAX_INLINE_FORKS: usize = 1` — at most 1 fork inside the callee (keep it simple — callee branching adds complexity).

8. **Add unit tests** in `src/symex/inline.rs`:
   - `test_inline_identity_function` — `function id(x) { return x; }` → return value equals arg value
   - `test_inline_conditional_return` — `function safe(x) { if (x > 0) return x; return "default"; }` → return value is Phi or specific based on constraints
   - `test_inline_depth_bound` — exceed `MAX_INLINE_DEPTH` → falls through to summary
   - `test_inline_callee_size_bound` — large callee → falls through to summary
   - `test_inline_cache_hit` — same callee with same arg signature → cached result reused
   - `test_inline_callee_internal_sink` — callee has an internal sink → `InlineSinkEvent` collected

9. **Add integration fixtures**:
   - `tests/fixtures/real_world/javascript/taint/symex_inline_passthrough.js` — helper function that conditionally passes input through. Inline analysis should confirm the feasible path.
   - `tests/fixtures/real_world/javascript/taint/symex_inline_sanitizer.js` — helper function that sanitizes input on one branch. Inline analysis should detect the sanitization and improve verdict precision.

### Architecture notes

- **Inline symex complements, not replaces, the taint engine's inline analysis.** The taint engine's `inline_analyse_callee()` propagates taint bits (cap bitsets) — it answers "does taint flow through this callee?" The symex inline analysis propagates symbolic values and path constraints — it answers "what concrete value would taint have after passing through this callee?" Both are needed: taint for recall, symex for precision/witnesses.
- **Resolution order is critical.** Inline body is most precise (full control flow), summary is medium precision (transform-level), opaque call is least precise (Unknown with taint propagation). The chain should always try higher precision first and fall back gracefully. Never let a failed inline attempt produce LESS precision than the summary would have provided.
- **No callee event propagation to caller findings.** If the callee has internal sinks (e.g., an inner `eval()` call), those are separate findings that the taint engine already detects via `param_to_sink`. The inline symex records them for evidence enrichment, not for creating new findings at the caller level. This prevents double-counting.
- **Single-level inlining (k=1) is the sweet spot.** k=2 (callee of callee) would require `CalleeSsaBody` availability for transitive callees, which is only available for same-file functions. Cross-file callee bodies are not available. k=1 covers the most common pattern (helper function wrapping a sink or sanitizer).
- **Cache key design matters.** Using full `SymbolicValue` hashing as cache key is too expensive (deep trees). The discriminant + taint signature captures "is arg 0 a concrete string? is arg 1 tainted?" — this is sufficient to distinguish behavioral outcomes for most helper functions.

### Validation requirements
- All existing tests pass
- Inline exploration improves verdicts for helper-function patterns (Identity through branching callee)
- Callee size and depth bounds prevent performance regression
- Inline cache prevents redundant exploration
- Resolution fallback chain (inline → summary → opaque) never loses precision
- No false negatives from inline analysis (conservative on all fallback paths)

### Exit criteria
- `src/symex/inline.rs` with `inline_explore_callee()`, cache, and result types
- Inline resolution integrated into `transfer_inst()` Call arm, before summary resolution
- `CalleeSsaBody` map threaded through `SymexContext`
- Depth (k=1), size (50 blocks), step (100), and fork (1) bounds enforced
- Callee-internal sinks detected and reported as evidence
- Inline cache keyed by (callee_name, arg_discriminant_sig)
- 2+ integration fixtures demonstrating inline precision improvement

### Dependencies
Phase 18c (cross-file summaries — inline resolution precedes summary in the resolution chain). Phase 11 (context sensitivity — `CalleeSsaBody` and `InlineCache` design patterns reused from taint engine). Phase 20 (loop awareness — callee bodies may contain loops; inline exploration needs bounded unrolling).

---

## Phase 24B: Interprocedural Symbolic Execution — Controls, Scaling & Hardening

**Category:** Analysis Depth — Symbolic Execution Robustness

**Why now:** Phase 24A introduces the interprocedural symbolic execution core: callee body execution as nested frames, full state propagation (return values, heap mutations, taint), canonical return semantics via `Terminator::Return(Option<SsaValue>)`, and transitive call descent. Phase 24B completes this capability by adding the controls, bounds, and diagnostics needed for production use.

### Goals
- Add full budget and cutoff controls: max call depth, max recursive re-entry per function / SCC, max frames per finding, max executed blocks / instructions, max symbolic forks, max solver checks, max retained path states
- Add explicit recursion and SCC policy: bounded recursive unrolling, SCC-aware limits (detect mutual recursion via call graph), widen / summarize / cut off when limits are reached, record cutoff reasons in evidence
- Formalize interprocedural branch handling: mid-block forking when callee has multiple feasible exit states, prune infeasible branches inside callees (PathEnv + SMT), fork both feasible branches when budget allows, rank/collapse only under budget pressure, define merge behavior explicitly (phi, union, widening)
- Add richer memoization / caching for interprocedural outcomes: key by function identity + argument abstraction + heap state abstraction, include concrete value hashes not just discriminant/taint, context-sensitive cache invalidation
- Harden diagnostics and traces: preserve full caller → callee → ... → sink call chains in evidence, mark fallback / cutoff / summary-replacement points clearly, witness strings include callee-internal operations
- Add comprehensive fixtures and benchmarks: nested helper chains (depth 3+), callee heap mutation affecting later caller sinks, callee sanitization of shared state, multiple feasible callee return paths with forking, recursive / mutually recursive helpers, callee-internal sink findings, budget exhaustion behavior, cross-file transitive execution
- Validate benchmark impact and ensure stable behavior under pressure

### Architecture notes
Phase B completes the interprocedural symbolic execution capability by adding recursion/SCC controls, execution budgets, interprocedural branch management, richer memoization, and diagnostic hardening. After this phase, interprocedural symex is not just functional, but bounded, explainable, and robust enough for production benchmarking and release use.

Phase A is about correctness and semantics. Phase B is about boundedness, scaling, and release hardening.

### Dependencies
Phase 24A (interprocedural execution core — provides `InterprocCtx`, `CallOutcome`, `execute_callee()`, canonical return semantics). Phase 20 (loop awareness — callee bodies may contain loops). Phase 23 (SMT solving — interprocedural branch feasibility).

---

## Phase 25: Exception-Aware Symbolic Execution

**Category:** Analysis Depth — Symbolic Execution Completeness

**Why now:** The symbolic executor only explores normal control flow (Goto, Branch, Return). Exception edges — try/catch/finally — are recorded in `SsaBody.exception_edges` and used by the taint engine, but the symex explorer skips them entirely. Real-world code uses try/catch extensively. Security-relevant patterns include: taint flowing through caught exceptions (`catch(e) { sink(e.message) }`), sanitization in finally blocks that may not execute, and error-path-specific sinks (error logging with user data). Without exception-path exploration, symex produces `Inconclusive` on any taint path that passes through a catch block.

### Current state
- `SsaBody.exception_edges: Vec<(BlockId, BlockId)>` records source→catch edges (stripped from CFG before SSA lowering but preserved for taint)
- `CatchParam` SSA op creates symbolic values for caught exception parameters
- Taint engine (`ssa_transfer.rs`) handles exception edges: orphan catch blocks are initialized with `SsaTaintState::initial()`, and taint flows through `CatchParam` to catch-body sinks
- Symex executor (`executor.rs`) processes only `Terminator::Goto`, `Branch`, `Return`, `Unreachable` — exception successors never entered

### Goals
- Extend the symex explorer to fork into exception paths at call sites within try blocks
- Model caught exception parameters as symbolic inputs carrying caller-context taint
- Explore both normal and exception successors when budget allows
- Handle finally blocks as code reachable from both normal and exception paths
- Detect taint flows through exception-handling patterns that the current executor misses

### Files/systems to be touched
- `src/symex/executor.rs` — extend `run_path()` to track exception successors and fork into catch blocks
- `src/symex/state.rs` — optional: `ExceptionState` to model caught exception symbolic value
- `src/symex/transfer.rs` — handle `SsaOp::CatchParam` with proper symbolic seeding (currently creates Symbol but no exception context)
- `src/ssa/ir.rs` — no structural changes needed; `exception_edges` already available

### Concrete implementation tasks

1. **Build exception successor map**: At the start of `explore_finding()`, construct `HashMap<BlockId, Vec<BlockId>>` from `ssa.exception_edges` mapping source blocks to their catch entry blocks. This is O(n) and cached per finding.

2. **Extend `ExplorationState`**: Add `exception_context: Option<SymbolicValue>` to track the symbolic value of the exception object when exploring a catch path. Used to seed `CatchParam` instructions.

3. **Fork into exception paths at call sites**: After processing a block containing a Call instruction that is an exception source (key in exception map):
   - If fork budget allows and the catch block is on a source→sink path (reachability check):
     - Clone current `ExplorationState`
     - Set `exception_context` to a tainted `Symbol` (exception carries caller taint)
     - Set `current_block` to the catch entry block
     - Push to work queue
   - If budget exhausted: skip exception path (conservative — taint engine already handles it)

4. **Transfer `CatchParam` with exception context**: In `transfer_inst()`, when processing `SsaOp::CatchParam`:
   - If `exception_context` is `Some(val)`: set the catch param to that symbolic value, propagate taint
   - If `None` (not on an exception path): set to `Symbol(v)` with taint if the param appears in flow steps

5. **Finally block handling**: Finally blocks appear as normal successors of both the try-body exit and the catch-body exit. No special handling needed — the explorer naturally reaches finally blocks via Goto from either path. The key correctness property is that the symex state at finally entry correctly reflects which path was taken (normal vs exception). This is automatic because each forked path carries its own state.

6. **Reachability pruning**: Extend `compute_reachable_blocks()` to include exception edges. Currently it only uses Goto/Branch successors. Add exception edges so catch blocks appear in the reachable set.

7. **Add integration fixtures**:
   - `symex_exception_catch_taint.js` — taint flows through caught exception to sink in catch block
   - `symex_exception_finally_cleanup.js` — sanitization in finally block (safe pattern)
   - `symex_exception_rethrow.js` — exception caught, modified, and re-thrown to outer catch

### Architecture notes
- Exception paths are explored as forks, not as primary paths. The normal path is always explored first; exception paths are queued like branch forks.
- The fork budget (`MAX_FORKS_PER_FINDING`) is shared between branch forks and exception forks. Under budget pressure, exception forks are lower priority than branch forks (branch forks explore the taint path directly; exception forks explore alternative paths).
- Exception paths do NOT produce new findings — they enrich existing findings with additional evidence (exception-path feasibility). The taint engine is authoritative for finding discovery.
- Sound: skipping exception paths under budget → Inconclusive (not Infeasible). The taint engine already detects exception-path taint flows independently.

### Validation requirements
- All existing tests pass (999+ lib tests, SSA corpus, integration fixtures)
- New fixtures exercise exception-path exploration
- No regressions in benchmark precision/recall
- Exception-path forks bounded by existing fork budget

### Exit criteria
- Exception successor map built in `explore_finding()`
- Exception forks queued when call sites have exception edges and budget allows
- `CatchParam` transfer uses exception context for symbolic seeding
- Reachability analysis includes exception edges
- 3 integration fixtures demonstrating exception-path taint detection

### Dependencies
Phase 18b (multi-path exploration — fork machinery). Phase 5 (SSA hardening — try/catch in CFG). Phase 24B (budget controls — exception forks draw from shared budget).

---

## Phase 26: Bitwise Operations and Extended Arithmetic

**Category:** Analysis Depth — Expression Completeness

**Why now:** The `BinOp` enum in `cfg.rs` only has `Add, Sub, Mul, Div, Mod`. Bitwise operations (`&`, `|`, `^`, `<<`, `>>`) are explicitly excluded by `extract_bin_op()` (returns `None`). This means any computation involving bit manipulation collapses to `Unknown` in the symbolic executor. Bitwise ops appear in security-relevant patterns: permission masks (`if (flags & ADMIN_FLAG)`), hash computations, and protocol field extraction. The CFG already parses the operator text; it just doesn't classify bitwise variants.

### Current state
- `cfg::BinOp`: 5 variants (Add, Sub, Mul, Div, Mod)
- `extract_bin_op()` in `cfg.rs` (line 1483): returns `None` for all non-arithmetic operators including `&`, `|`, `^`, `<<`, `>>`
- `symex::Op`: mirrors `cfg::BinOp` with `From<cfg::BinOp>` impl
- `mk_binop()` in `value.rs`: concrete folding for arithmetic only
- Z3 in `smt.rs`: translates `Op` to Z3 integer arithmetic; no bitvector operations

### Goals
- Extend `BinOp` and `Op` with bitwise variants
- Extract bitwise operators from tree-sitter AST
- Implement concrete folding for bitwise operations
- Extend Z3 translation to handle bitvector constraints
- Add comparison operators (`==`, `!=`, `<`, `>`, `<=`, `>=`) as expression-level operations (currently only in path constraints)

### Files/systems to be touched
- `src/cfg.rs` — extend `BinOp` enum, update `extract_bin_op()`
- `src/symex/value.rs` — extend `Op` enum, `From<BinOp>`, concrete folding in `mk_binop()`
- `src/symex/smt.rs` — optional: Z3 bitvector translation for bitwise constraints
- `src/abstract_interp/interval.rs` — optional: interval transfer for bitwise ops

### Concrete implementation tasks

1. **Extend `cfg::BinOp`**:
   ```rust
   pub enum BinOp {
       Add, Sub, Mul, Div, Mod,
       BitAnd, BitOr, BitXor, LeftShift, RightShift,
       Eq, NotEq, Lt, LtEq, Gt, GtEq,
   }
   ```

2. **Update `extract_bin_op()` in `cfg.rs`**: Add operator text matching for `"&"` → `BitAnd`, `"|"` → `BitOr`, `"^"` → `BitXor`, `"<<"` → `LeftShift`, `">>"` → `RightShift`, `"=="/"===" ` → `Eq`, `"!="/"!==" ` → `NotEq`, `"<"` → `Lt`, `">"` → `Gt`, `"<="` → `LtEq`, `">="` → `GtEq`. Must distinguish `&`(bitwise) from `&&`(logical) and `|` from `||` — check operator text length.

3. **Extend `symex::Op` and `From<BinOp>`**: Mirror all new variants.

4. **Implement concrete folding in `mk_binop()`**:
   ```rust
   Op::BitAnd => lhs.checked_and(rhs)?,   // i64 & i64
   Op::BitOr  => lhs.checked_or(rhs)?,    // i64 | i64 (no overflow possible)
   Op::BitXor => Some(lhs ^ rhs),
   Op::LeftShift => if rhs >= 0 && rhs < 64 { Some(lhs << rhs) } else { None },
   Op::RightShift => if rhs >= 0 && rhs < 64 { Some(lhs >> rhs) } else { None },
   Op::Eq => /* returns 1 or 0, or use ConcreteStr for bool? */,
   ```
   Note: shift amounts must be bounds-checked (0..63) to prevent panic. Out-of-range → `Unknown`.

5. **Z3 bitvector translation** (optional, lower priority): Z3's integer sort supports `mod`/`div` but not bitwise natively. Two options: (a) use Z3 bitvector sort (`BV(64)`) for variables involved in bitwise ops, or (b) skip bitwise constraints in SMT (conservative, sound). Option (b) is simpler for Phase 26; bitvector SMT can be a follow-up.

6. **Abstract interpretation transfer** (optional): `IntervalFact` transfer for `BitAnd(x, mask)` when mask is a known constant → result bounded by `[0, mask]`. Useful for permission flag patterns.

7. **Add unit tests**: Concrete folding for all new ops, overflow/shift bounds, display formatting.

### Validation requirements
- All existing tests pass
- `extract_bin_op()` correctly parses bitwise and comparison operators across all 10 languages
- Concrete folding is correct and panic-free for all edge cases
- No regressions: existing `BinOp` variants unchanged

### Exit criteria
- `BinOp` and `Op` extended with 11 new variants
- `extract_bin_op()` classifies bitwise and comparison operators
- Concrete folding implemented with bounds checking
- Unit tests for all new operations

### Dependencies
None. Standalone extension of existing enum + extraction + folding.

---

## Phase 27: SMT String Theory

**Category:** Analysis Depth — Constraint Solving Precision

**Why now:** The Z3 integration (Phase 23) only supports integer sort. String-valued constraints — `if (input.startsWith("safe"))`, `if (cmd === "allowed")`, `if (url.includes("://"))` — are silently skipped, meaning the SMT solver cannot prove infeasibility of string-guarded paths. String comparisons are among the most common guard patterns in web applications. Z3's string theory (`QF_S`) supports concatenation, containment, prefix/suffix, length, and regex matching.

### Current state
- `VarSort` enum in `smt.rs`: only `Int` variant
- `translate_operand()`: returns `None` for `ConstValue::Str(_)` (line 353)
- `seed_from_path_env()`: skips non-integer facts
- String-valued path constraints: accumulated in `PathConstraint` but never asserted to Z3
- Z3 crate (0.19): provides `z3::ast::String` with `concat()`, `contains()`, `prefix_of()`, `suffix_of()`, `length()`, `at()`, `substr()` methods

### Goals
- Add Z3 string sort alongside integer sort
- Translate string-valued operands and constraints to Z3 string theory
- Prove infeasibility of string-guarded paths (e.g., `startsWith` check that excludes tainted prefix)
- Integrate symbolic string operations (`SymbolicValue::Concat`, `Replace`, `ToLower`, etc.) into Z3 assertions

### Files/systems to be touched
- `src/symex/smt.rs` — extend `VarSort`, variable map, constraint translation, operand handling
- `src/symex/value.rs` — no changes (expression trees already encode string ops)
- `src/constraint/mod.rs` — optional: extend `ConditionExpr` with string comparison operators

### Concrete implementation tasks

1. **Extend `VarSort`**:
   ```rust
   enum VarSort {
       Int,
       Str,
   }
   ```

2. **Extend variable map to hold both sorts**: Change `var_map: HashMap<SsaValue, (Z3Int, VarSort)>` to use an enum:
   ```rust
   enum Z3Var {
       Int(Z3Int),
       Str(z3::ast::String),
   }
   type VarMap = HashMap<SsaValue, (Z3Var, VarSort)>;
   ```

3. **Add `ensure_str_var()`**: Analog to `ensure_int_var()`. Create Z3 string variables for SSA values known to be string-typed (from `ConstLattice::Str`, `TypeFactResult`, or `SymbolicValue::ConcreteStr`).

4. **Extend `translate_operand()`**: Handle `Operand::Const(ConstValue::Str(s))` → `z3::ast::String::from_str(s)`. Handle `Operand::Value(v)` where `v` has `VarSort::Str` → return the string variable.

5. **Extend `assert_path_constraint()`** for string comparisons:
   - `Eq` with two string operands → `str_a._eq(&str_b)`
   - `NotEq` → `str_a._eq(&str_b).not()`
   - String method predicates (startsWith, includes, endsWith) require translating `ConditionExpr` patterns into Z3 string operations:
     - `x.startsWith("safe")` → `z3::ast::String::prefix_of(&z3_const_safe, &z3_x)`
     - `x.includes("://")` → `z3::ast::String::contains(&z3_x, &z3_const_scheme)`

6. **Translate symbolic string ops to Z3**:
   - `SymbolicValue::Concat(a, b)` → `z3::ast::String::concat(&[&z3_a, &z3_b])`
   - `SymbolicValue::Substr(s, start, len)` → `z3::ast::String::substr(&z3_s, &z3_start, &z3_len)`
   - `SymbolicValue::StrLen(s)` → `z3::ast::String::length(&z3_s)` (returns Int)
   - `SymbolicValue::ToLower(s)` / `ToUpper(s)` → uninterpreted function (Z3 has no case conversion)
   - `SymbolicValue::Replace(s, pat, rep)` → `z3::ast::String::replace(&z3_s, &z3_pat, &z3_rep)`

7. **Sort inference logic**: Determine whether an SSA value is string-typed:
   - `ConstLattice::Str(_)` → Str
   - `type_facts.get_type(v) == Some(TypeKind::String)` → Str
   - Operand in a string comparison → Str
   - Unknown → skip (conservative)

8. **Budget considerations**: String theory queries are more expensive than integer queries. Keep the per-finding budget at 10 queries but add a string-specific timeout multiplier (e.g., 200ms vs 100ms for integer queries).

9. **Add unit tests**: String equality, inequality, prefix, containment, concat, mixed int+string constraints.

### Validation requirements
- All existing tests pass
- New string constraints correctly prune infeasible paths (e.g., `startsWith("safe")` guard on tainted input)
- No regressions from integer-only SMT behavior
- Budget and timeout bounds prevent solver blowup

### Exit criteria
- `VarSort::Str` and `Z3Var::Str` in SMT context
- String operands translated to Z3 string theory
- Concat, prefix, contains, replace operations translated
- String-guarded paths provably pruned when infeasible
- Unit tests for all string constraint patterns

### Dependencies
Phase 23 (SMT solving — provides `SmtContext`, `check_path_feasibility()`, solver infrastructure). Phase 22 (symbolic string theory — provides `SymbolicValue` string op variants).

---

## Phase 28: Symbolic Encoding and Decoding Models

**Category:** Analysis Depth — Sanitizer Precision

**Why now:** Encoding functions (`encodeURIComponent`, `html.escape`, `base64.b64encode`, `htmlspecialchars`) are recognized as sanitizers in label rules and strip capability bits during taint analysis. But the symbolic executor treats them as opaque `Call` nodes returning `Unknown`. This means symex cannot reason about whether an encoding actually neutralizes the attack payload. For example, `encodeURIComponent` prevents SSRF by encoding `://` but does NOT prevent SQL injection — this distinction is lost when the call is opaque. Modeling encoding semantics enables symex to produce more precise witnesses and verify that the correct encoding was applied for the vulnerability class.

### Current state
- Label rules across JS/TS, Python, PHP, Ruby, Java have encoding sanitizer matchers (encodeURIComponent, html.escape, htmlspecialchars, CGI.escapeHTML, etc.)
- Taint engine strips capability bits based on sanitizer caps (e.g., HTML_ESCAPE strips HTML cap but not SQL cap)
- Symex `strings.rs`: NO encoding methods recognized — only trim/case/replace/substr/strlen
- Symex witness generation: Cannot show what the encoded output looks like

### Goals
- Recognize encoding/decoding functions as named symbolic operations
- Model encoding semantics per vulnerability class (which caps each encoding neutralizes)
- Produce encoded witness strings showing the actual output (e.g., `%3Cscript%3E` for URL-encoded XSS attempt)
- Verify encoding completeness: flag cases where encoding is applied but doesn't match the sink's vulnerability class

### Files/systems to be touched
- `src/symex/strings.rs` — extend `classify_string_method()` and add `EncodingKind` enum
- `src/symex/value.rs` — add `SymbolicValue::Encode { kind: EncodingKind, inner: Box<SymbolicValue> }` and `Decode` variant
- `src/symex/transfer.rs` — recognize encoding calls and construct Encode nodes
- `src/symex/witness.rs` — implement concrete encoding evaluation for witness generation

### Concrete implementation tasks

1. **Define `EncodingKind` enum** in `src/symex/strings.rs`:
   ```rust
   pub enum EncodingKind {
       HtmlEscape,      // &lt; &gt; &amp; &quot;
       UrlEncode,       // %XX encoding
       Base64Encode,
       Base64Decode,
       UrlDecode,
       ShellEscape,     // single-quote wrapping or backslash escaping
       SqlEscape,       // doubling single quotes
       JsonStringify,   // JSON string escaping
   }
   ```

2. **Extend `classify_string_method()`** per language to recognize encoding methods:
   - JS/TS: `encodeURIComponent` → UrlEncode, `encodeURI` → UrlEncode, `btoa` → Base64Encode, `atob` → Base64Decode, `JSON.stringify` → JsonStringify
   - Python: `html.escape` → HtmlEscape, `urllib.parse.quote` → UrlEncode, `base64.b64encode` → Base64Encode, `shlex.quote` → ShellEscape, `json.dumps` → JsonStringify
   - PHP: `htmlspecialchars`/`htmlentities` → HtmlEscape, `urlencode`/`rawurlencode` → UrlEncode, `base64_encode` → Base64Encode, `escapeshellarg` → ShellEscape, `addslashes` → SqlEscape
   - Ruby: `CGI.escapeHTML`/`ERB::Util.html_escape` → HtmlEscape, `CGI.escape` → UrlEncode, `Shellwords.escape` → ShellEscape
   - Java: `URLEncoder.encode` → UrlEncode, `StringEscapeUtils.escapeHtml` → HtmlEscape
   - Go: `url.QueryEscape` → UrlEncode, `html.EscapeString` → HtmlEscape

3. **Add `SymbolicValue::Encode` and `Decode` variants**:
   ```rust
   Encode { kind: EncodingKind, inner: Box<SymbolicValue> },
   Decode { kind: EncodingKind, inner: Box<SymbolicValue> },
   ```
   Smart constructors `mk_encode()` / `mk_decode()` with concrete folding: when inner is `ConcreteStr`, apply the encoding and produce a new `ConcreteStr`.

4. **Concrete encoding implementations** in `strings.rs`:
   - `HtmlEscape`: `<` → `&lt;`, `>` → `&gt;`, `&` → `&amp;`, `"` → `&quot;`, `'` → `&#x27;`
   - `UrlEncode`: non-alphanumeric → `%XX`
   - `Base64Encode`: standard base64 encoding
   - `ShellEscape`: wrap in single quotes, escape internal single quotes
   - `SqlEscape`: double single quotes
   - `JsonStringify`: escape `\`, `"`, control characters

5. **Witness generation**: In `witness.rs`, when the sink expression contains `Encode { kind, inner }`:
   - Substitute tainted symbols in `inner` with the attack payload
   - Apply the encoding to the substituted string
   - Show both the raw and encoded forms: `input 'x' = "<script>alert(1)</script>" → encoded as "%3Cscript%3Ealert(1)%3C%2Fscript%3E" reaches sink()`

6. **Cap-encoding mismatch detection**: When an `Encode` node reaches a sink, check if the encoding's cap coverage matches the sink's cap:
   - `HtmlEscape` at a `SQL_QUERY` sink → encoding doesn't help, taint should NOT be stripped
   - `UrlEncode` at an `SSRF` sink → encoding neutralizes `://` → taint could be stripped
   - Record mismatch as evidence note: "HTML encoding applied but sink requires SQL escaping"

7. **Add integration fixtures**:
   - `symex_encoding_html_xss.js` — html escape before XSS sink (safe)
   - `symex_encoding_wrong_type.js` — URL encoding before SQL sink (unsafe — wrong encoding type)

### Validation requirements
- All existing tests pass
- Encoding functions produce concrete encoded strings in witnesses
- Cap-encoding mismatch detected and reported
- No regressions in sanitizer detection from taint engine

### Exit criteria
- `EncodingKind` enum with 8 encoding types
- Per-language encoding method recognition
- `SymbolicValue::Encode`/`Decode` with concrete folding
- Witness strings show encoded output
- Cap-encoding mismatch detection in evidence

### Dependencies
Phase 22 (symbolic string theory — `classify_string_method()` infrastructure). Phase 18a (expression trees — `SymbolicValue` variants).

---

## Phase 29: Array Index Sensitivity

**Category:** Analysis Precision — Heap Model Refinement

**Why now:** The symbolic heap uses `FieldSlot::Elements` as a flow-insensitive union of all array/list elements. `arr.push(tainted); arr.push(safe); sink(arr[1])` reports taint even though index 1 holds the safe value. For arrays with known constant indices, per-index tracking would eliminate these false positives. The constant propagation pass already computes known integer values for many SSA values, making index extraction feasible.

### Current state
- `FieldSlot::Elements` — single slot for all array elements, regardless of index
- Container ops (`push`, `pop`, `append`, `get`, `set`) all map to `Elements` slot
- `ConstLattice::Int(n)` available via `const_values` on `OptimizeResult`
- Points-to analysis provides `HeapObjectId` for allocation sites

### Goals
- Track per-index symbolic values for arrays when the index is a known constant
- Fall back to `Elements` (flow-insensitive union) for dynamic indices
- Widen per-index tracking to `Elements` at loop heads to prevent unbounded growth
- Improve precision for common patterns: `args[0]` (command), `args[1]` (first argument), `params[key]`

### Files/systems to be touched
- `src/symex/heap.rs` — extend `FieldSlot` with indexed variant, update store/load/fingerprint
- `src/symex/transfer.rs` — extract constant index from call arguments for array access
- `src/symex/executor.rs` — no changes needed (heap is opaque to executor)

### Concrete implementation tasks

1. **Extend `FieldSlot`**:
   ```rust
   pub enum FieldSlot {
       Named(String),
       Elements,
       Index(u64),  // NEW: concrete array index
   }
   ```

2. **Add `MAX_TRACKED_INDICES`** constant (e.g., 16): when an array has more than this many distinct concrete indices, collapse all `Index(n)` entries to a single `Elements` entry (union taint).

3. **Update `store()`**: When storing to an array with a known constant index, use `FieldSlot::Index(n)`. When index is unknown, store to `FieldSlot::Elements` AND mark all existing `Index(n)` entries for that object as potentially overwritten (conservative).

4. **Update `load()`**: When loading with a known constant index, check `Index(n)` first, then fall back to `Elements`. When index is unknown, load from `Elements`.

5. **Extract constant index in transfer**: In the container-op handler (`transfer.rs`), when the op is `get`/`set`/array index:
   - Check if the index argument SSA value has a known `ConstLattice::Int(n)` via `const_values`
   - If yes, use `FieldSlot::Index(n as u64)`
   - If no, use `FieldSlot::Elements`

6. **Widening**: In `heap.widen()`, collapse all `Index(n)` entries to `Elements` (union values and taint). This matches the existing widening behavior.

7. **Fingerprint update**: Include `Index(n)` entries in `fingerprint()` computation, sorted by index for determinism.

8. **Add unit tests**: Per-index store/load, index overflow to Elements, mixed indexed/unindexed access, widening collapse.

### Validation requirements
- All existing tests pass
- Per-index tracking eliminates false positives for constant-indexed array access
- Dynamic indices fall back to Elements (no precision loss vs current behavior)
- Heap size bounded by MAX_TRACKED_INDICES per array

### Exit criteria
- `FieldSlot::Index(u64)` variant
- Store/load with constant index extraction
- Widening collapses indices to Elements
- Bounded at 16 tracked indices per array

### Dependencies
Phase 21 (field-sensitive heap — provides `FieldSlot`, `SymbolicHeap`). Phase 14 (points-to — provides `HeapObjectId` for object identity).

---

## Phase 30: Cross-File Interprocedural Symbolic Execution

**Category:** Analysis Depth — Interprocedural Precision

**Why now:** Phase 24A/B provides intra-file interprocedural symbolic execution: callee bodies are walked as nested frames. But cross-file calls fall back to `SsaFuncSummary` transform modeling (Phase 18c), which loses all internal control flow, branching, and data-dependent behavior. For multi-file projects, the most interesting security patterns span files: a utility module sanitizes input, a route handler calls it, a database module receives the result. Cross-file body execution would enable symex to trace taint precisely through these chains.

### Current state
- `InterprocCtx.callee_bodies: &HashMap<String, CalleeSsaBody>` — intra-file only
- `CalleeSsaBody` bundles pre-lowered `SsaBody` + `OptimizeResult` + `param_count`
- `SsaFuncSummary` stored in SQLite (`ssa_function_summaries` table) with `FuncKey` metadata
- `GlobalSummaries.ssa_by_key: HashMap<FuncKey, SsaFuncSummary>` — cross-file summaries available
- Resolution chain in `transfer.rs`: interproc body → summary → opaque call
- `scan.rs` pass 1: `lower_all_functions()` produces both summaries and bodies per file, but bodies are discarded after pass 1 taint analysis

### Goals
- Persist `CalleeSsaBody` alongside `SsaFuncSummary` for cross-file callees
- Make cross-file callee bodies available to the symbolic executor
- Extend `InterprocCtx` to resolve callees from both intra-file and cross-file body stores
- Gate cross-file execution on body size and budget to prevent blowup
- Maintain the resolution chain: intra-file body → cross-file body → summary → opaque call

### Files/systems to be touched
- `src/database.rs` — add SQLite table for serialized `CalleeSsaBody` blobs
- `src/summary/mod.rs` — extend `GlobalSummaries` with `bodies_by_key: HashMap<FuncKey, CalleeSsaBody>`
- `src/commands/scan.rs` — persist bodies in pass 1, load between passes
- `src/symex/interproc.rs` — extend callee resolution to check cross-file bodies
- `src/symex/mod.rs` — add `cross_file_bodies` to `SymexContext`
- `src/taint/mod.rs` — thread cross-file bodies into `SymexContext`

### Concrete implementation tasks

1. **Serialize `CalleeSsaBody`**: `SsaBody` and `OptimizeResult` must implement `Serialize`/`Deserialize`. `SsaBody` contains `Vec<SsaBlock>` with `SsaInst`, `SsaOp`, `Terminator` — all need serde derives. `OptimizeResult` contains `const_values: HashMap<SsaValue, ConstLattice>`, `type_facts: TypeFactResult`, `points_to: PointsToResult`, `alias_result` — all need serde.

2. **SQLite storage**: New table `ssa_function_bodies` with columns: `file_path TEXT`, `func_name TEXT`, `arity INTEGER`, `lang TEXT`, `namespace TEXT`, `body_blob BLOB` (bincode-serialized `CalleeSsaBody`). Stored alongside `ssa_function_summaries` in pass 1.

3. **Size gate**: Only persist bodies smaller than `MAX_CROSS_FILE_BODY_BLOCKS = 100`. Larger functions use summary-only resolution. This bounds storage and execution cost.

4. **Load between passes**: In `scan.rs` between pass 1 and pass 2, load cross-file bodies from SQLite into `GlobalSummaries.bodies_by_key`.

5. **Extend `InterprocCtx`**: Add `cross_file_bodies: Option<&HashMap<FuncKey, CalleeSsaBody>>`. Resolution in `execute_callee()`: after checking intra-file `callee_bodies`, check `cross_file_bodies` using `resolve_callee_key()` for name+lang+arity matching.

6. **Budget isolation**: Cross-file execution shares the same `InterprocBudget` but has a separate depth limit: `MAX_CROSS_FILE_DEPTH = 1` (one level of cross-file descent). Prevents deep cross-file chains from consuming all budget.

7. **CFG for cross-file callees**: Cross-file bodies reference `NodeIndex` values from their original file's CFG. Store a minimal `Cfg` subset (just the `NodeInfo` entries referenced by the SSA body) alongside the body. Or, restructure `CalleeSsaBody` to be self-contained with embedded node info.

8. **Add integration fixtures**: Multi-file test with cross-file helper function.

### Architecture notes
- Cross-file body execution is optional and additive. Files without available cross-file bodies fall back to summary resolution (existing behavior, no regression).
- Serialization adds ~3-10KB per function body to SQLite. For a 1000-function project, this is ~3-10MB — acceptable.
- The resolution chain becomes: intra-file body → cross-file body → SSA summary → legacy summary → opaque call.

### Validation requirements
- All existing tests pass
- Cross-file body execution improves symex verdicts for multi-file patterns
- Storage bounded by body size gate
- Budget prevents cross-file execution from dominating analysis time

### Exit criteria
- `CalleeSsaBody` serializable and persisted to SQLite
- Cross-file bodies loaded into `GlobalSummaries`
- `InterprocCtx` resolves cross-file callees
- Depth-limited cross-file execution
- Integration fixture with cross-file taint path

### Dependencies
Phase 24A/B (interprocedural execution core + controls). Phase 8 (SSA summary persistence — SQLite infrastructure).

---

## Phase 31: Dynamic Dispatch and Type-Qualified Symbolic Resolution

**Category:** Analysis Precision — Call Resolution

**Why now:** The symbolic executor resolves calls by name only. When a receiver has a known type (e.g., `HttpClient.send(url)` where `client` was constructed as `new HttpClient()`), the taint engine's `resolve_type_qualified_labels()` constructs `"HttpClient.send"` for label matching — but the symex transfer doesn't use type facts for call resolution. This means virtual method calls to framework APIs (database clients, HTTP clients, template engines) are treated as opaque even when the receiver type is known.

### Current state
- `SymexContext.type_facts: &TypeFactResult` available but unused in symex call resolution
- `TypeFactResult.get_type(v) → Option<TypeKind>` returns known types from constructor inference
- `TypeKind::label_prefix()` maps security types to label-matching prefixes ("HttpClient" → "HttpClient")
- Taint engine uses type-qualified resolution in `resolve_callee()` step 0 (Phase 10)
- Symex transfer Call arm: container ops → string methods → interproc → summary → opaque

### Goals
- Use type facts to construct type-qualified callee names for symbolic resolution
- Integrate type-qualified resolution into the symex call resolution chain
- Enable summary-based modeling for framework API methods via type-qualified names

### Files/systems to be touched
- `src/symex/transfer.rs` — add type-qualified resolution step in Call arm

### Concrete implementation tasks

1. **Add type-qualified resolution step** in `transfer_inst()` Call arm, after interproc and before summary:
   ```rust
   // Phase 31: Type-qualified symbolic resolution
   if let Some(receiver) = receiver {
       if let Some(type_facts) = /* thread type_facts through */ {
           if let Some(kind) = type_facts.get_type(*receiver) {
               if let Some(prefix) = kind.label_prefix() {
                   let qualified = format!("{}.{}", prefix, callee_method_name);
                   if let Some(result) = resolve_callee_symbolically(ctx, &qualified, ...) {
                       state.set(inst.value, result.value);
                       if result.tainted { state.mark_tainted(inst.value); }
                       return;
                   }
               }
           }
       }
   }
   ```

2. **Thread `type_facts` to transfer**: Add `type_facts: Option<&TypeFactResult>` to the transfer function parameters, or include it in `SymexSummaryCtx`.

3. **Extract method name from callee string**: For `obj.method()`, the callee string is `"method"` (after normalization). Combine with receiver type prefix.

4. **Add unit test**: Mock type fact for a receiver, verify qualified name is resolved.

### Validation requirements
- All existing tests pass
- Type-qualified resolution fires for known-type receivers
- Fallback to unqualified resolution when receiver type is unknown

### Exit criteria
- Type-qualified callee names constructed in symex Call arm
- Summary resolution uses qualified names
- No regressions

### Dependencies
Phase 10 (type-aware analysis — provides `TypeKind`, `label_prefix()`, constructor inference).

---

## Phase 32: Floating Point and Extended Numeric Types

**Category:** Analysis Completeness — Numeric Domain

**Why now:** `ConstLattice` only supports `Int(i64)`. Floating-point literals (`0.5`, `1.0e-3`, `NaN`, `Infinity`) collapse to `Varying`, losing precision in constant propagation and symbolic execution. While float values rarely carry taint directly, they appear in security-relevant comparisons: threshold checks (`if (score > 0.95)`), rate limits, and financial calculations. Adding float support completes the numeric domain.

### Current state
- `ConstLattice`: `Top | Str(String) | Int(i64) | Bool(bool) | Null | Varying`
- `parse()` in `const_prop.rs`: attempts `i64` parse, falls back to `Str` or `Varying`
- `SymbolicValue::Concrete(i64)`: integer only
- Abstract interpretation `IntervalFact`: `lo: i64, hi: i64`

### Goals
- Add `Float(f64)` variant to `ConstLattice`
- Add `ConcreteFloat(f64)` variant to `SymbolicValue` (or reuse `Concrete` with a wider type)
- Parse float literals in constant propagation
- Extend `mk_binop()` with float arithmetic and concrete folding
- Optional: extend `IntervalFact` with float bounds

### Files/systems to be touched
- `src/ssa/const_prop.rs` — add `Float(f64)` to `ConstLattice`, update `parse()`
- `src/symex/value.rs` — add `ConcreteFloat(f64)` or extend `Concrete` to `ConcreteNum(NumericValue)`
- `src/symex/transfer.rs` — seed float constants from `ConstLattice::Float`
- `src/abstract_interp/interval.rs` — optional: float interval bounds

### Concrete implementation tasks

1. **Extend `ConstLattice`**: Add `Float(f64)`. Update `parse()` to try `f64` parse after `i64` fails (but before `Str` fallback). Handle `NaN`, `Infinity`, `-Infinity` as special cases.

2. **Extend `SymbolicValue`**: Add `ConcreteFloat(f64)`. Smart constructor `mk_float_binop()` with concrete folding. Handle `NaN` propagation: any op involving `NaN` → `Unknown` (conservative).

3. **Concrete folding for floats**: `Add(1.5, 2.5) → 4.0`, `Div(1.0, 0.0) → Unknown` (infinity), `Mul(NaN, x) → Unknown`.

4. **Z3 translation** (optional): Z3 Real sort for float variables. `check_float_constraint()` for float comparisons in path constraints.

5. **Display**: `ConcreteFloat(f)` → formatted as `f64` string in witness generation.

### Validation requirements
- All existing tests pass
- Float literals parsed correctly
- Float arithmetic folding correct for normal, infinity, NaN cases
- No regressions in integer handling

### Exit criteria
- `ConstLattice::Float(f64)` with parsing
- `SymbolicValue::ConcreteFloat(f64)` with folding
- Float constants seeded in symex transfer

### Dependencies
None. Standalone numeric domain extension.

---

## Phase 33: Regex-Aware String Analysis

**Category:** Analysis Depth — String Domain Precision

**Why now:** Regex-based validation is ubiquitous in web applications: input validation (`/^[a-zA-Z0-9]+$/`), sanitization (`str.replace(/[<>"']/g, '')`), and routing (`/^\/api\/v[12]\//`). The symex engine treats regex operations as opaque — `Replace` only works with concrete string patterns, not regex patterns. This means regex-based sanitizers cannot be verified symbolically, and regex-based validators cannot prune infeasible paths.

### Current state
- `SymbolicValue::Replace(inner, pattern, replacement)` — pattern and replacement are concrete `String` only
- `detect_replace_sanitizer()` in `strings.rs` — matches XSS/SQLi/CMDi patterns in Replace, but only for literal string patterns
- No regex crate dependency in nyx
- Path constraints have no regex-match predicate

### Goals
- Recognize regex patterns in Replace and Match operations
- Classify common security-relevant regex patterns (alphanumeric-only, no-special-chars, URL format)
- Use regex classification to determine if a sanitizer/validator is effective for a given vulnerability class
- Optional: concrete regex evaluation for witness generation

### Files/systems to be touched
- `src/symex/strings.rs` — add `RegexPattern` classification, extend `detect_replace_sanitizer()`
- `src/symex/value.rs` — extend `Replace` to accept regex patterns, add `RegexMatch` variant
- `src/symex/witness.rs` — concrete regex evaluation for encoded witnesses
- `Cargo.toml` — add `regex` crate dependency (feature-gated)

### Concrete implementation tasks

1. **Add `regex` crate** as optional dependency: `regex = { version = "1", optional = true }`. Feature gate: `regex_symex`.

2. **Define `RegexClassification` enum**:
   ```rust
   pub enum RegexClassification {
       AlphanumericOnly,      // ^[a-zA-Z0-9]+$
       NoSpecialChars,        // removes <>"'&; etc.
       NumericOnly,           // ^[0-9]+$
       UrlFormat,             // ^https?://...
       EmailFormat,           // basic email pattern
       WhitelistChars(String),// [allowed_chars]+
       Unknown,               // unrecognized pattern
   }
   ```

3. **Implement `classify_regex(pattern: &str) → RegexClassification`**: Pattern-match against known security-relevant regex shapes. Use heuristics (check for `^`, `$` anchors, character classes) rather than full regex parsing.

4. **Extend `detect_replace_sanitizer()`**: When the pattern is a regex string (starts with `/` in JS or contains regex metacharacters), classify it and determine if it strips dangerous characters for the relevant vulnerability class.

5. **Add `SymbolicValue::RegexMatch`** variant:
   ```rust
   RegexMatch { input: Box<SymbolicValue>, pattern: String, classification: RegexClassification }
   ```

6. **Concrete regex evaluation** (with `regex` feature):
   - For witness generation, apply regex patterns to concrete strings
   - `Replace(/[<>"']/g, '')` on `<script>alert(1)</script>` → `scriptalert(1)/script`
   - Show the post-regex output in witness

7. **Path constraint integration**: When a regex test appears in a branch condition (`if (/^[0-9]+$/.test(input))`), create a `PathConstraint` with the regex classification. If the classification is `NumericOnly` and the sink requires `SQL_QUERY`, the path is safe (numeric input can't cause SQL injection).

### Validation requirements
- All existing tests pass
- Common security regex patterns correctly classified
- Replace with regex patterns produces correct witnesses (with regex feature)
- Graceful degradation without regex feature (Unknown classification)

### Exit criteria
- `RegexClassification` enum with 7 categories
- `classify_regex()` for common security patterns
- Regex-aware `detect_replace_sanitizer()`
- Concrete regex evaluation in witness generation
- Feature-gated regex dependency

### Dependencies
Phase 22 (symbolic string theory — `Replace` infrastructure, `detect_replace_sanitizer()`). Phase 28 (encoding models — complements regex sanitizers).

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
