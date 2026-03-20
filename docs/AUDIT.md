Nyx Audit Report

Executive Summary

Nyx is a genuinely impressive piece of engineering — 24K lines of Rust implementing a monotone-dataflow taint engine, language-agnostic CFG construction, cross-file function summaries, and a call graph, all backed by tree-sitter and SQLite       
incremental indexing. The theoretical foundations (bounded lattice with guaranteed convergence, two-pass architecture, conservative summary merging) are sound and well-implemented. The test suite is mature (394 tests, 160 real-world fixtures,    
100% pass rate). This is not a toy.

However, Phase 1 is not ready to build on without targeted reinforcement. The headline features — interprocedural analysis, path sensitivity, cross-language interop — are architecturally present but practically shallow. The taint engine is purely
name-based with no aliasing, no per-argument propagation precision, and no exception path modeling. The rule base across 10 languages is broad but thin (88 total rules, ~6-13 per language). The call graph is computed but unused. The JS two-level
solve has a stale-seed bug. Several correctness gaps would cause a skeptical security engineer to lose confidence quickly: try scanning a real Express app or Spring service and counting the false negatives. The 160 real-world fixtures are a     
strong foundation, but 99 soft misses and 267 unexpected findings signal that precision and recall calibration is still early.

Phase 2 (dynamic analysis) should wait. The static engine's correctness gaps would propagate into dynamic analysis design decisions. The highest-leverage work right now is: tightening taint precision (per-argument propagation, exception paths,   
collection taint), deepening the rule base for the 3-4 most commercially important languages, and building a proper evaluation benchmark. A scanner that finds 20 real bugs with zero false positives is worth more than one that finds 100 bugs mixed
with 80 false positives.

What Nyx Already Does Well

- Mathematically grounded taint engine: Bounded lattice (height ~8,704), guaranteed convergence, two-phase worklist with iteration budget — this is real dataflow analysis, not regex
- Language-agnostic CFG: Single build_cfg() works for 10 languages via Kind enum dispatch + tree-sitter; genuinely elegant
- Two-pass architecture: Parallel pass 1 (summary extraction) + correct pass 2 (cross-file context) is the right design for scalability
- Conservative summary merging: OR-union on name collisions is the correct default for soundness
- Deterministic ranking: Five-component scoring with stable tie-breaking; findings are reproducible regardless of parallelism
- Test infrastructure: 394 tests, 160 real-world fixtures with .expect.json schema, env-var filtering for fast iteration — this is a mature test harness
- Suppression system: Rock-solid — 10 languages, wildcard matching, next-line directives, taint ID canonicalization, 22 unit tests
- SQLite incremental indexing: WAL mode, blake3 hashing, mmap — production-grade caching
- SmallVec/SmallBitSet optimization: Hot-path allocations bounded; memory-efficient lattice representation
- SARIF 2.1.0 compliance: Spec-correct output that would work with GitHub Code Scanning
- Honest documentation: Limitations are generally acknowledged (RAII false positives, intra-procedural state analysis)

Biggest Risks / Weakest Areas

- Taint is purely name-based: No aliasing, no field sensitivity, no per-element collection tracking — obj.field, arr[i], and *ptr are all opaque. This causes both false positives (whole-collection taint) and false negatives (taint through        
  dereference)
- No exception path modeling: Try/catch/finally creates implicit control flow the CFG doesn't capture — significant for Java, Python, JS, PHP
- Per-argument taint propagation is boolean: propagates_taint is all-or-nothing; a function that passes only arg 0 to return taints the result when arg 1 is tainted
- Rule base is broad but shallow: 88 total rules across 10 languages. No SSRF sinks, no crypto vulnerability class, no XML/XXE, no deserialization for most languages, weak SQL injection coverage
- Call graph computed but dead code: SCC topological ordering exists but is #[allow(dead_code)]; pass 2 doesn't use it
- JS two-level solve has stale-seed bug: global_seed is read-only; inter-function mutation of globals is invisible to other functions
- 267 unexpected findings in the real-world test suite suggests precision is uncalibrated
- No evaluation against known benchmarks: No comparison to OWASP Benchmark, Juliet, or any public vulnerability corpus
- Cross-language interop requires manual edge definition: Marketed as a feature but is really an extensibility hook
- State analysis disabled by default and underdeveloped: Resource lifecycle is C-only in tests; auth-level tracking is monotone-only (no de-escalation on else branches)

Detailed Findings

1. Static-analysis correctness

CFG Construction (src/cfg.rs, 1,919 lines):

The recursive build_sub() function (600+ lines) correctly models if/else, loops (for/while/infinite), break/continue, and returns with proper edge kinds (Seq/True/False/Back). Language dispatch via Kind enum + lookup() is elegant and works for   
structured control flow.

Critical gaps:

- Short-circuit evaluation not modeled: if (x && dangerous(x)) creates a single condition node. The CFG doesn't split &&/|| into separate branches, so guards appear to cover both operands when the second may not execute. This causes false        
  negatives on guard-dependent vulnerabilities.
- Try/catch/finally not modeled: Exception flow is absent. A call inside try that throws is treated as always completing normally. This is a significant gap for Java, Python, JS, and PHP where exception-based control flow is pervasive. finally   
  cleanup doesn't kill taint on exception paths.
- Async/await treated as synchronous: No special handling for Promise-returning functions or await suspension points. Race conditions and ordering violations are invisible.
- Ternary operators treated as sequential: x = cond ? tainted() : safe() loses branching semantics; both paths appear to flow unconditionally.
- Variable scoping not enforced: Shadowed variables (same name in nested blocks) share taint state. This causes false positives where inner-scope sanitization appears to affect outer-scope variables.
- Method receiver not tracked: tainted_obj.method() doesn't propagate taint through the receiver; only arguments are in uses.

Taint Propagation (src/taint/transfer.rs, 458 lines):

The transfer function correctly implements Source → Sanitizer → Call → Assignment → Predicate → Sink ordering with edge-aware application. The cap-based sanitizer stripping (new_caps &= !sanitizer_caps) is correct.

Critical gaps:

- No aliasing: Taint tracking is purely name-based. *p, p.field, arr[i] are all independent from p and arr. This is the single largest precision gap.
- propagates_taint is boolean, not per-argument: func(tainted, safe) marks the return as tainted regardless of which argument actually flows to the return value. tainted_sink_params exists in summaries but isn't used at call sites in
  apply_call().
- String operations are semantically lossy: Concatenation propagates taint (correct), but template injection (format(tainted_template, safe_arg)) and substring extraction are not distinguished.
- Collection taint is whole-object: arr[0] = tainted marks all of arr as tainted. This is conservative (no false negatives) but causes false positives on collection-heavy code.
- Global seed in JS two-level solve is stale: global_seed is computed once from top-level convergence and never updated. If function A modifies a global and function B reads it, B sees the pre-A value. This is a real false negative source in     
  JS/TS codebases.
- No implicit flow tracking: if (secret) { x = 1; } else { x = 2; } doesn't mark x as dependent on secret. This is standard for taint analysis but worth noting as a fundamental limitation.

Path Sensitivity (src/taint/path_state.rs, domain.rs):

Predicate tracking with contradiction pruning is implemented but narrowly scoped.

- Only 3 predicate kinds tracked: NullCheck, EmptyCheck, ErrorCheck. All other conditions (type checks, range checks, custom validation) are Unknown and ignored.
- Condition classification is text-based heuristic: checking for substrings like "is_empty", ".len() == 0". Language-specific idioms (unless in Ruby, not in Python, truthy checks in JS) are partially missed.
- Contradiction pruning is aggressive: if known_true & known_false != 0 for any variable, the entire state becomes bottom. A single predicate inference error eliminates an entire path.

Interprocedural Analysis (src/summary.rs, src/callgraph.rs):

Two-pass architecture is correct. Conservative merging (OR caps, OR booleans) is the right default.

- Virtual dispatch/polymorphism not handled: obj.method() resolves by string name only. In OOP languages, the actual callee depends on the receiver's runtime type.
- Function pointers and callbacks not resolved: Indirect calls are stored as string names; the actual target cannot be determined statically.
- Call graph SCC/topo ordering is computed but not used: Pass 2 analyzes files in arbitrary order, not bottom-up topological order. This means callee summaries may be incomplete when callers are analyzed.
- Recursive functions partially handled: Mutual recursion creates a chicken-egg problem; first-pass summaries may be incomplete. The conservative merge partially mitigates this.

Deduplication and Ranking (src/rank.rs, src/commands/scan.rs):

Solid. Five-component scoring (severity base + analysis kind + evidence strength + state rule bonus + path validation penalty) with deterministic tie-breaking. Findings are ranked after all analysis completes, then truncated by max_results.      
Rollup support collapses repeated instances. Suppressed findings excluded from --fail-on.

Suppression Handling (src/suppress/mod.rs):

Excellent. All 10 languages, wildcard suffix matching, comma-separated rules, taint ID canonicalization, string guards to avoid matching in code. 22 unit tests. This is production-ready.

2. Validation and battle-testing

Test suite overview: 394 tests, 100% pass rate.

┌────────────────────────┬───────┬─────────────────────────────────────────────────────────────────────┐                                                                                                                                              
│        Category        │ Count │                               Quality                               │                                                                                                                                            
├────────────────────────┼───────┼─────────────────────────────────────────────────────────────────────┤                                                                                                                                              
│ Taint unit tests       │ 61    │ Strong — covers single-file, cross-file, cross-language, predicates │                                                                                                                                            
├────────────────────────┼───────┼─────────────────────────────────────────────────────────────────────┤
│ CFG analysis tests     │ 57    │ Strong — auth gaps, resource lifecycle, reachability                │                                                                                                                                              
├────────────────────────┼───────┼─────────────────────────────────────────────────────────────────────┤                                                                                                                                              
│ State analysis tests   │ 21    │ Good but C-only                                                     │                                                                                                                                              
├────────────────────────┼───────┼─────────────────────────────────────────────────────────────────────┤                                                                                                                                              
│ Pattern validation     │ 26    │ Thorough — positive + negative for all 10 languages                 │                                                                                                                                            
├────────────────────────┼───────┼─────────────────────────────────────────────────────────────────────┤                                                                                                                                              
│ Integration tests      │ 12    │ Good — multi-component fixture validation                           │                                                                                                                                            
├────────────────────────┼───────┼─────────────────────────────────────────────────────────────────────┤                                                                                                                                              
│ Real-world fixtures    │ 160   │ Excellent infrastructure, early calibration                         │                                                                                                                                            
├────────────────────────┼───────┼─────────────────────────────────────────────────────────────────────┤                                                                                                                                              
│ Performance regression │ 7     │ Present but small-scale fixtures                                    │                                                                                                                                            
├────────────────────────┼───────┼─────────────────────────────────────────────────────────────────────┤                                                                                                                                              
│ Taint termination      │ 4     │ Good regression test for known hang bug                             │                                                                                                                                            
└────────────────────────┴───────┴─────────────────────────────────────────────────────────────────────┘

What's strong:
- Cross-file taint tests (12 tests) actually validate the two-pass pipeline end-to-end
- Cross-language interop tests (10 tests) cover Python→JS, Go→Python, Rust→JS, C→Java, 3-language chains
- Path-sensitive tests cover null check contradiction, validation-in-branch, budget graceful degradation
- Negative pattern fixtures for all 10 languages prove false-positive resistance on AST patterns
- Real-world fixture framework with .expect.json is excellent engineering for regression prevention

What's concerning:
- 99 soft misses in real-world fixtures: These are documented aspirational gaps, but they represent known false negatives the scanner cannot currently find. Many are core vulnerability patterns (base64+pickle, YAML deserialization, Ruby block    
  resources, TS promise chains).
- 267 unexpected findings in real-world fixtures: These are findings the scanner produces that weren't expected. Many may be true positives, but uncategorized unexpected findings suggest the scanner's precision hasn't been systematically       
  calibrated.
- No negative taint test suite: There are no dedicated "should NOT produce a taint finding" scenarios. Pattern tests have negatives, but taint tests only validate presence of findings, not absence.
- State analysis tested only on C: 19 C fixtures, zero for Rust/Python/Ruby/JS resource lifecycle. README claims state analysis for all languages.
- No public benchmark evaluation: No comparison against OWASP Benchmark, Juliet Test Suite, or any standard vulnerability corpus. No published false-positive rate.
- Benchmarks are small-scale: benches/scan_bench.rs runs on fixture files (a few hundred lines each). The "rust-lang/rust in ~1s" claim has no corresponding benchmark.
- Missing adversarial tests: No tests for evasion techniques (obfuscated taint flow, indirect calls, dynamic dispatch, aliased variables, exception-based control flow).

3. Rule quality and language coverage

88 total rules across 10 languages (6-13 per language).

Coverage matrix (key vulnerability classes):

┌───────────────────────┬───────────────────────────────┬────────────────────────────────────────────────────────────────────────────────────┐                                                                                                        
│         Class         │            Covered            │                                  Missing or Weak                                   │                                                                                                      
├───────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤                                                                                                        
│ Command injection     │ All 10 languages              │ Reasonable                                                                         │                                                                                                      
├───────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤                                                                                                        
│ SQL injection         │ Java, Go, PHP, Python         │ No Rust/C/C++/Ruby/JS/TS SQL sinks                                                 │                                                                                                        
├───────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤                                                                                                        
│ XSS                   │ JS, TS, PHP, Ruby (partial)   │ No template engine sinks, weak DOM API coverage                                    │                                                                                                        
├───────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤                                                                                                        
│ Code injection (eval) │ JS, TS, PHP, Python, Ruby     │ No Java Expression Language, no Rust proc macros                                   │                                                                                                      
├───────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤                                                                                                        
│ Path traversal        │ Rust, C, C++, Go, PHP, Python │ No Java, Ruby, JS, TS path sinks                                                   │                                                                                                      
├───────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤                                                                                                        
│ SSRF                  │ None                          │ No HTTP client sinks in any language                                               │                                                                                                      
├───────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤                                                                                                        
│ Deserialization       │ PHP (unserialize)             │ Missing pickle (Python), Marshal (Ruby), ObjectInputStream (Java), JSON.parse (JS) │                                                                                                      
├───────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤                                                                                                        
│ Crypto                │ None                          │ No weak algorithm detection, no random source tracking                             │                                                                                                      
├───────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤                                                                                                        
│ XML/XXE               │ None                          │ No XML parser sinks in any language                                                │                                                                                                      
├───────────────────────┼───────────────────────────────┼────────────────────────────────────────────────────────────────────────────────────┤                                                                                                        
│ Format string         │ C, C++, Go                    │ No Java logging format, no Python f-string                                         │                                                                                                      
└───────────────────────┴───────────────────────────────┴────────────────────────────────────────────────────────────────────────────────────┘

Language strength ranking:

1. Go (11 rules): Best framework coverage (http.Request chains), good sanitizer set (html, url, filepath)
2. PHP (11 rules): Complete superglobal set, extensive exec/eval/unserialize/include sinks
3. Python (13 rules): Flask/Django implicit patterns, subprocess variants, but missing pickle
4. Java (8 rules): Servlet API sources, but no Spring, no PreparedStatement, Class.forName mislabeled as SHELL_ESCAPE
5. JavaScript (9 rules): Express patterns, but minimal DOM API, no fetch/postMessage sinks
6. TypeScript (10 rules): Mirrors JS, adds type-specific patterns (any annotation)
7. C (7 rules): Basic exec/format/file sinks, weak input sources
8. C++ (7 rules): Adds std::cin/getline over C, try/catch KINDS, but similar gaps
9. Rust (6 rules): Fully qualified paths (good), but minimal sink coverage beyond Command/File
10. Ruby (6 rules): Minimal — bare function names, no Rails framework coverage, no ERB template sinks

Key inconsistencies:
- SQL sinks use SHELL_ESCAPE cap across languages — should be a separate cap or Cap::all()
- Java's Class.forName labeled as shell sink (should be code injection)
- C/C++ sprintf/strcpy labeled as HTML sinks (should be buffer/format string)
- Eval sinks use SHELL_ESCAPE in some languages, Cap::all() in others

Assessment: The rule base is broad but shallow. Every language has at least basic command injection and code injection coverage, but framework-specific modeling is minimal. High-value vulnerability classes (SSRF, deserialization, crypto) are     
entirely absent. This is the most impactful area for improvement before Phase 2.

4. Architecture and maintainability

Strong points:
- Module boundaries are clean: taint/, state/, labels/, patterns/, commands/ are well-separated. Adding a new analysis domain would follow the Transfer<S: Lattice> pattern naturally.
- Generic dataflow engine (state/engine.rs): The Transfer<S> trait + run_forward() two-phase loop is reusable across taint and state analysis. Adding new analysis domains is architecturally straightforward.
- Language addition is mechanical: Add labels/{lang}.rs with KINDS/RULES/PARAM_CONFIG, add tree-sitter parser dependency, register in labels/mod.rs. The process is documented.
- Config system is well-designed: Default → user → local TOML merge, per-language custom rules, runtime rule addition via CLI.

Fragile points:
- Code duplication in ast.rs: ~200 lines of taint finding/evidence construction duplicated between run_rules_on_bytes() and analyse_file_fused(). This will diverge over time and is the highest-risk duplication.
- build_sub() in cfg.rs is 600+ lines: A single recursive function with many match arms. Adding new control flow constructs (try/catch, async) will increase complexity significantly. Should be broken into per-construct handlers.
- scan.rs is 1,514 lines: The two scan paths (indexed and non-indexed) have duplicated orchestration logic. The fused/non-fused paths add another dimension. Refactoring into a shared pipeline builder would reduce maintenance burden.
- Cap bitflags are only 7 bits: Adding new vulnerability classes requires either expanding the bitfield or a redesign. The current system can't represent SSRF vs SQL injection as separate capabilities — both would use generic caps.
- Technical debt in summary system: propagates_taint should be per-argument. tainted_sink_params exists but isn't used at call sites. These are partially implemented features that create confusion.
- Dual crate setup (lib.rs + main.rs): Module declarations must be mirrored. This is a minor annoyance but a regression trap.

Where adding new rules will be painful:
- Adding a new vulnerability class (e.g., SSRF) requires: new Cap bit (if bit budget allows), new rules in all 10 language files, new test fixtures, new pattern definitions. This is ~10-file change with no abstraction to help.
- Framework-specific rules (e.g., Spring's @RequestParam) require understanding tree-sitter query syntax for that language's annotation grammar. No tooling to generate or validate these.

Technical debt accumulation:
- Fastest: ast.rs duplication, scan.rs path multiplication
- Moderate: Cap bit budget exhaustion, incomplete per-argument propagation
- Slowest: Language files are independent and won't interfere with each other

5. Product credibility

README positioning is mostly honest. The scanner delivers on its core promises (multi-language AST + CFG + taint, SARIF output, incremental indexing). Two concerns:

1. "~1s for rust-lang/rust" claim is unsubstantiated: No benchmark in the repo validates this. This is the only claim that could embarrass the project if challenged.
2. Cross-language interop marketed as a feature but requires manual edge setup: Should be qualified as "extensible cross-language bridging" rather than "automatic cross-language analysis."
3. State analysis is opt-in but README doesn't note this: The capability table implies it's always active.

SARIF output: Spec-compliant and would work with GitHub Code Scanning. Includes rule metadata, related locations for rollups, confidence scores, and evidence. This is strong.

CLI usability: Well-designed clap interface with --fail-on, --severity, --mode, --format, --index, --min-score, --min-confidence. CI-friendly exit codes. Progress bars. This is above average for security CLI tools.

Severity/confidence model: Severity is driven by source kind (UserInput/EnvironmentConfig = High, FileSystem/Database = Medium). Confidence is per-pattern for AST rules and derived from analysis kind for taint/state/cfg. The model is reasonable  
but not documented for end users.

What would most improve trust:
- Published evaluation against a known benchmark (even small-scale)
- Documented false-positive rates per language and vulnerability class
- Comparison table showing Nyx findings vs a well-known scanner on the same codebase
- Sample CI integration guide with realistic output

Top 10 Highest-Leverage Improvements

1. Add per-argument taint propagation

Why: The boolean propagates_taint is the single largest source of false positives in cross-file analysis. func(tainted, safe) incorrectly marks the return as tainted when only arg 1 flows to the return.

Expected impact: Eliminates a class of false positives that makes taint findings untrustworthy in real codebases.

Difficulty: Medium. Change propagates_taint: bool to propagating_params: Vec<usize> in FuncSummary. Update apply_call() in transfer.rs to check which specific arguments are tainted. Wire tainted_sink_params into call-site checking.

Improves: Precision, trust. Before Phase 2: Yes.

2. Model try/catch/finally in CFG

Why: Exception-based control flow is pervasive in Java, Python, JS, and PHP. Without it, the scanner misses all exception-path vulnerabilities and produces false negatives on finally-based cleanup.

Expected impact: Enables meaningful analysis of Java/Python/JS/PHP error handling patterns — a major vulnerability class (error fallthrough, uncaught exception info leak).

Difficulty: High. Requires new CFG edges (exception edges from call nodes to catch blocks), new StmtKind variants, and updates to all 4 languages' KINDS maps.

Improves: Recall, correctness. Before Phase 2: Yes.

3. Triple the rule depth for JS/TS and Python

Why: These 3 languages represent the vast majority of web application code. Currently JS has 9 rules and Python has 13 — missing SSRF, fetch sinks, template engines, ORM query builders, session handling, authentication middleware.

Expected impact: Dramatically improves real-world recall for the most commercially important languages.

Difficulty: Medium. Adding rules is mechanical (matchers + label + cap). The bottleneck is knowing what to add. Start with OWASP Top 10 vulnerability patterns for Express/Flask/Django.

Improves: Recall, adoption, credibility. Before Phase 2: Yes.

4. Build an evaluation benchmark

Why: Without a published evaluation, every claim about precision and recall is unverifiable. A skeptical security engineer will benchmark the tool themselves; you want to control the narrative.

Expected impact: Establishes credibility. Identifies the gap between claimed and actual detection. Provides a regression target for every future change.

Difficulty: Medium. Create a curated corpus of 50-100 known vulnerabilities (from CVE databases, OWASP Benchmark, or hand-crafted) with ground truth. Run Nyx, measure precision and recall, publish results.

Improves: Trust, credibility, adoption. Before Phase 2: Absolutely.

5. Use call graph topological ordering in pass 2

Why: The call graph SCC analysis is already computed (callgraph.rs) but unused. Pass 2 analyzes files in arbitrary order, meaning callee summaries may be incomplete when callers are analyzed.

Expected impact: Improves recall for multi-file taint chains. Unlocks bottom-up propagation where callee behavior is fully known before caller analysis.

Difficulty: Low. The infrastructure exists. Wire topo_scc_callee_first ordering into the pass 2 file iteration in scan.rs.

Improves: Recall, correctness. Before Phase 2: Yes.

6. Add SSRF and deserialization vulnerability classes

Why: SSRF is the #1 missing vulnerability class — zero coverage across all 10 languages. Deserialization is covered only for PHP. These are high-impact, frequently exploited vulnerability classes.

Expected impact: Catches real vulnerabilities that the scanner currently cannot detect at all.

Difficulty: Low-Medium. SSRF requires adding HTTP client sinks (fetch, urllib, HttpClient, etc.) to each language. Deserialization requires pickle (Python), Marshal (Ruby), ObjectInputStream (Java), yaml.unsafe_load.

Improves: Recall, credibility. Before Phase 2: Yes.

7. Fix the JS two-level solve stale-seed bug

Why: global_seed is computed once and never updated. Functions that modify globals are invisible to other functions. This causes false negatives in real JS/TS codebases where global state mutation is common.

Expected impact: Fixes a class of false negatives specific to JS/TS — the languages most likely to be scanned.

Difficulty: Medium. Options: (a) iterate the two-level solve to a fixed point, or (b) propagate function side effects back to the global state before seeding the next function.

Improves: Recall, correctness. Before Phase 2: Yes.

8. Expand Cap bitflags or redesign capability system

Why: 7 bits are exhausted. Adding SSRF, SQL injection (distinct from shell), crypto, deserialization requires either more bits or a redesign. Currently SQL sinks use SHELL_ESCAPE which is semantically wrong.

Expected impact: Enables correct capability modeling for all vulnerability classes, preventing cap-mismatch false positives.

Difficulty: Medium. Expanding to u16 (16 bits) is minimal code change but requires updating all serialization. A richer capability model (enum per vulnerability class) would be more future-proof.

Improves: Precision, maintainability. Before Phase 2: Yes.

9. Add negative taint test suite

Why: The test suite validates finding presence but not absence. There are no dedicated "this code is safe, do NOT flag it" taint scenarios. The 267 unexpected findings in real-world fixtures suggest precision calibration is needed.

Expected impact: Catches precision regressions. Forces the engine to prove it doesn't over-report. Builds confidence that findings are actionable.

Difficulty: Low. Create 20-30 safe-code fixtures per language where no taint findings should appear. Assert zero findings.

Improves: Precision, trust. Before Phase 2: Yes.

10. Extract shared evidence/finding construction from ast.rs

Why: ~200 lines of taint finding/evidence construction are duplicated between run_rules_on_bytes() and analyse_file_fused(). This will diverge, causing inconsistent output between index-mode and no-index mode.

Expected impact: Prevents the most likely regression path in the codebase.

Difficulty: Low. Extract into a fn build_taint_diag(finding: &Finding, ...) -> Diag helper.

Improves: Maintainability. Before Phase 2: Preferable.

Must Do Before Phase 2

1. Build an evaluation benchmark — Without measured precision/recall, dynamic analysis will be built on unvalidated assumptions about what the static engine catches
2. Fix per-argument taint propagation — Dynamic analysis will need to know which arguments are actually tainted; the boolean propagates_taint will cause incorrect dynamic harness generation
3. Fix JS two-level solve stale-seed — JS/TS are the most likely targets for dynamic analysis; the stale-seed bug would carry over
4. Add negative taint tests — Dynamic analysis integration tests need a known-good baseline
5. Model try/catch in CFG — Dynamic fuzzing that triggers exceptions will interact with the CFG; the scanner must model this
6. Expand Cap bitflags — Dynamic analysis will need to distinguish SSRF from command injection; 7 bits aren't enough
7. Categorize the 267 unexpected findings — Are they true positives or false positives? This directly affects whether dynamic validation targets are correct

Quick Wins (1–2 Weeks)

1. Wire call graph topo ordering into pass 2 — Infrastructure exists, just needs plumbing (~1 day)
2. Extract shared finding construction from ast.rs — Eliminate 200-line duplication (~1 day)
3. Add 30 negative taint fixtures (3 per language) — Assert zero findings on safe code (~2 days)
4. Add SSRF sinks to JS, Python, Go, Java — fetch, urllib.urlopen, http.NewRequest, HttpClient.execute (~1 day)
5. Add pickle/yaml deserialization sinks to Python, Ruby — pickle.loads, yaml.unsafe_load, Marshal.load (~1 day)
6. Fix Cap mismatch: SQL sinks should use a distinct cap or Cap::all(), not SHELL_ESCAPE (~2 hours)
7. Soften the "rust-lang/rust in ~1s" README claim — Change to "typically scans large codebases in seconds" or publish actual benchmark (~1 hour)
8. Add state analysis fixtures for Python and JS — Extend beyond C-only (~2 days)
9. Document confidence levels in pattern docs — Define what High/Medium/Low means (~1 hour)
10. Note state analysis opt-in in README capability table (~5 minutes)

Big Strategic Bets

A. Field-sensitive taint tracking

Model obj.field as a separate taint entity from obj. This would dramatically reduce false positives on OOP code (Java, Python, JS/TS) and enable framework-aware modeling (e.g., req.body is tainted but req.method is not). High difficulty (~4      
weeks) but transformative for precision.

B. Framework-specific modeling packs

Create curated rule packs for: Express.js (middleware, routes, body-parser), Flask/Django (views, forms, ORM), Spring Boot (annotations, dependency injection, JPA), Rails (ActiveRecord, ERB, strong_params). Each pack would include                
sources/sinks/sanitizers that understand the framework's idiom. Medium difficulty per pack (~1-2 weeks each) with massive adoption impact.

C. Standard library taint summaries

Pre-populate function summaries for standard library functions across all 10 languages. String.format(), os.path.join(), url.parse(), Buffer.from() — these are the connective tissue of real code. Without them, taint flow breaks at every stdlib   
call boundary. Medium difficulty (~2-3 weeks for top 3 languages) with enormous recall improvement.

D. Incremental cross-file invalidation

Use call graph reverse edges to determine which files need re-analysis when a dependency changes. Currently, taint mode always re-analyzes all files in pass 2. With dependency tracking, only files whose callee summaries changed need              
recomputation. Medium-high difficulty (~3 weeks) but critical for scaling to large monorepos.

Recommended Next Roadmap

Stage A: Validation hardening (Weeks 1-2)

- Build evaluation benchmark (50 known vulnerabilities, ground truth)
- Add 30 negative taint fixtures
- Categorize 267 unexpected findings in real-world suite
- Publish precision/recall numbers (even if imperfect)
- Fix README claims (perf benchmark, state analysis opt-in)

Stage B: Core engine refinements (Weeks 3-5)

- Implement per-argument taint propagation
- Fix JS two-level solve stale-seed
- Wire call graph topo ordering into pass 2
- Expand Cap bitflags to u16
- Extract shared ast.rs finding construction
- Model try/catch/finally in CFG (at least for Java and JS)

Stage C: Rule and framework depth (Weeks 5-7)

- Add SSRF vulnerability class (all languages)
- Add deserialization sinks (Python, Ruby, Java)
- Create Express.js framework rule pack
- Create Flask/Django framework rule pack
- Add state analysis fixtures for Python, JS, Rust
- Triple JS/TS rule count (DOM APIs, fetch, postMessage, WebSocket)

Stage D: Selective Phase 2 entry (Week 8+)

- Re-run evaluation benchmark, compare to Stage A numbers
- Design dynamic analysis integration for the language with best static precision (likely Go or Rust)
- Prototype controlled execution for a single vulnerability class (command injection — most amenable to dynamic validation)
- Do NOT generalize dynamic analysis until single-class prototype proves value

If I Were the Maintainer

Weeks 1-2: I would stop all feature work and build the evaluation benchmark. I'd take 50 real CVEs from public advisory databases across the 3 most important languages (Python, JS, Java), create minimal reproducer fixtures, establish ground      
truth, run Nyx, and publish the numbers. If precision is <50%, I'd focus the next 4 weeks entirely on false positive elimination. If recall is <30%, I'd focus on rule depth. The benchmark tells you what to do next — everything else is guessing.

Week 2: In parallel, I'd fix the three cheapest correctness bugs: wire topo ordering (1 day), extract ast.rs duplication (1 day), fix Cap mismatch for SQL (2 hours). Ship a release.

Weeks 3-4: Implement per-argument taint propagation and fix the JS stale-seed bug. These are the two correctness issues most likely to affect real-world scan quality. Re-run the benchmark and measure improvement.

Weeks 5-6: Deep-dive on rules. I'd focus exclusively on Express.js and Flask/Django — create framework rule packs with 20+ sources/sinks/sanitizers each, informed by the OWASP Top 10. Add SSRF sinks across all languages. Expand Cap to u16. Re-run
benchmark.

Week 7: Model try/catch in CFG for Java and JS. Add negative taint test suite. Categorize all unexpected findings in the real-world suite. Re-run benchmark.

Week 8: Assess readiness for Phase 2. By now the benchmark should show measurable improvement in both precision and recall. If it does, prototype dynamic analysis for command injection in Python (most tractable: subprocess.call with controlled   
input). If it doesn't, loop back to Stage B.

The key discipline is: measure before and after every change. The benchmark is the single most important thing to build, because without it, you can't tell whether any change actually matters.   