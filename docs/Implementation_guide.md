# Post-SSA Implementation Guide — Static Analysis Hardening & Capability Expansion

This is the execution-order roadmap for completing Nyx's remaining static analysis capabilities after the SSA IR milestone. Each phase is sized for one Claude Code implementation pass.

## Current State

**Engine:** SSA-only taint analysis across 10 languages. Two-pass scanning with cross-file summaries (SQLite persistence). Call graph with SCC/topological analysis (constructed but not yet used for scheduling). SSA optimizations: constant propagation, copy propagation, dead code elimination, branch pruning. JS/TS two-level solve for cross-scope taint.

**Precision:** 67.1% precision / 96.6% recall / 79.2% F1 on 103-case benchmark (Phase 30). 28 false positives out of 44 safe cases. Recall is strong; precision is the bottleneck.

**Test infrastructure:** 439 lib tests, 268 real-world fixtures (10 languages), 103 benchmark cases (6 languages), 265 SSA corpus fixtures, 8 integration test projects. Benchmark has regression thresholds enforced in CI (P≥60.4%, R≥91.4%, F1≥72.9%).

**False positive root causes (observed from benchmark):**
- Allowlist/dominated-check patterns not recognized as validation (10 FP across 5 languages)
- Interprocedural sanitizer calls not resolved (5 FP — sanitizer applied via helper function)
- Non-security sinks flagged (5 FP — console.log, Logger.info, etc.)
- Type-check guards not recognized (5 FP — typeof, isinstance, strconv.Atoi, is_numeric, regex)
- Inline sanitizers partially missed (3 FP — some languages work, others don't)

**One false negatives:** Java `HttpClient.send()` (variable receiver doesn't match type-qualified sink).

**Language coverage disparity:**

| Language | Rules | Sanitizers | Framework Support | Benchmark Cases |
|----------|-------|------------|-------------------|-----------------|
| Python | 24 | 6 | Flask, Django, Jinja2, pickle | 21 |
| Java | 18 | 1 | Spring, Hibernate, JPA, JNDI | 19 |
| JavaScript | 16+2 gated | 5 | Express, DOM APIs | 21 |
| TypeScript | 15+2 gated | 4 | (shares JS rules) | 0 |
| Ruby | 14 | 3 | Rails (basic) | 1 |
| Go | 14 | 3 | (stdlib only) | 21 |
| PHP | 13 | 3 | (no framework) | 20 |
| C | 10 | 1 | N/A | 0 |
| C++ | 10 | 1 | N/A | 0 |
| Rust | 10 | 3 | (stub) | 0 |

Java has only 1 sanitizer rule (HtmlUtils.htmlEscape + StringEscapeUtils.escapeHtml4) despite 18 total rules — explaining its 12.5% TN rate (worst of any language). Go, C, C++, Rust have no framework-specific models. TypeScript, C, C++, Rust have zero benchmark cases.

**Architectural debt (from audit):**
- Call graph built but topo order not used for pass 2 scheduling
- `SsaFuncSummary` computed intra-file but not persisted to SQLite for cross-file use
- `Diag.confidence` field exists but is `None` for taint findings
- Type facts computed but only used for SQL injection suppression on int-typed values
- No field sensitivity — `obj.safe_field` and `obj.tainted_field` conflated
- No alias tracking — sanitization of aliased references not propagated
- No widening — loops with growing taint sets rely on MAX_ORIGINS=4 cap
- `find_call_node` search depth fixed at 2 levels — misses deeply wrapped calls
- Member expression classification uses suffix-matching — false positive risk on nested objects
- Callee normalization discards module path (`std::env::var` → `var`) — overload ambiguity

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

## Phase 18: Symbolic Execution (Targeted)

**Category:** Analysis Depth — Symbolic Execution

**Why now:** With abstract interpretation, constraint solving, and rich summaries in place, targeted symbolic execution can explore specific paths to confirm or deny vulnerability reachability. This is the deepest analysis layer — use sparingly for high-value confirmation.

### Goals
- Implement targeted symbolic execution for confirming taint findings
- Use symbolic execution to verify that a taint path is feasible (not pruned by constraints)
- Generate concrete inputs that trigger the vulnerability (proof of exploitability)
- Limit scope: only symbolically execute high-confidence findings, not the entire program

### Files/systems likely to be touched
- New: `src/symex/` — symbolic execution engine
- `src/symex/state.rs` — symbolic state
- `src/symex/executor.rs` — path explorer
- `src/constraint.rs` — integration with constraint solver
- `src/taint/ssa_transfer.rs` — trigger symbolic execution for high-value findings

### Concrete implementation tasks
1. Define `SymbolicValue` — symbolic representation of values (concrete, symbolic variable, expression tree)
2. Define `SymbolicState` — mapping from SSA values to symbolic values + path constraints
3. Implement forward symbolic execution over SSA blocks, collecting path constraints at branches
4. At sink nodes: check if path constraints are satisfiable with tainted symbolic source
5. If satisfiable: upgrade finding confidence to High with proof witness
6. If unsatisfiable: downgrade finding confidence to Low (infeasible path)
7. Limit: max 100 blocks per symbolic execution; max 3 path forks per finding
8. Add test fixtures demonstrating symbolic execution confirmation

### Validation requirements
- Symbolic execution terminates on all triggered findings
- No TP regressions
- At least 1 finding upgraded with proof witness
- At least 1 finding downgraded as infeasible

### Exit criteria
- Targeted symbolic execution implemented for SSA taint findings
- Path feasibility checked via constraint solving
- Proof witnesses generated for confirmed findings
- Bounded: execution limited by block count and fork count

### Dependencies
Phase 17 (abstract interpretation). Phase 15 (constraint solving). Phase 8 (summaries for interprocedural symbolic execution).

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

### Why benchmark expansion is a checkpoint, not a prerequisite (Phase 19)
Individual phases add benchmark fixtures as needed. The expansion phase consolidates, fills gaps for underserved languages, and establishes comprehensive regression thresholds for the complete analysis stack.

### Why the plan minimizes rework
Each phase builds on the previous phase's output. No phase introduces infrastructure that a later phase would replace:
- Labels refined in Phase 1 stay refined through all subsequent phases
- Sanitizer resolution from Phase 2 is used by every later taint phase
- SSA hardening from Phase 5 is foundational for all SSA-based features
- Summary system extended in Phase 8 is the same system used by context sensitivity, field sensitivity, and interprocedural analysis
- Constraint solver from Phase 15 is reused by type-flow and symbolic execution
