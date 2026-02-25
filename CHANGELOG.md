# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **Attack surface ranking** — deterministic post-analysis scoring layer that prioritizes findings by exploitability. Each `Diag` receives an `f64` score computed from five components: severity base (High=60, Medium=30, Low=10), analysis kind bonus (taint +10 > state +8 > cfg +3/5 > ast 0), evidence strength (+1 per item, +2–6 for source-kind priority), state rule type bonus (+1–6), and a path-validation penalty (−5 for guarded paths). Findings are sorted by descending score before truncation so `max_results` keeps the most important results. Tie-breaking is deterministic by severity, rule ID, file path, line, column, and message hash.
  - **`rank_score` and `rank_reason` fields on `Diag`** — optional fields with `#[serde(skip_serializing_if = "Option::is_none")]`; JSON output is unchanged when ranking is disabled.
  - **`--no-rank` CLI flag** — disables attack-surface ranking (enabled by default).
  - **`output.attack_surface_ranking` config key** — boolean (default `true`) to control ranking via config file.
  - **Console score display** — dim `Score: N` appended to each finding's header line when ranking is enabled.
  - **New module `src/rank.rs`** — `compute_attack_rank()`, `rank_diags()`, and `sort_key()` functions. Scoring uses only in-memory data; no extra file I/O or graph recomputation.
  - 10 new unit tests: ordering correctness (high taint > medium file-io, must-leak > may-leak, taint > cfg-only, state rules, AST lowest at same severity), determinism (input-order-independent), path-validation penalty, and JSON serialization (rank fields omitted when None, present when set).
- **State-model dataflow analysis** — new `src/state/` module implementing a forward worklist dataflow engine over the existing CFG. Tracks per-variable resource lifecycle (`UNINIT`, `OPEN`, `CLOSED`, `MOVED`) via bitset lattice and per-path authentication level (`Unauthed`, `Authed`, `Admin`) as a composable product domain. Detects:
  - **Use-after-close** (`state-use-after-close`, High) — variable read/written after its resource handle was closed.
  - **Double-close** (`state-double-close`, Medium) — resource handle closed more than once.
  - **Must-leak** (`state-resource-leak`, High) — resource acquired but never closed on any exit path.
  - **May-leak** (`state-resource-leak-possible`, Medium) — resource open on some but not all exit paths (branch-aware via lattice join).
  - **Unauthenticated access** (`state-unauthed-access`, High) — sensitive sink reached without a preceding auth/admin check.
- **State analysis architecture** — six-module design:
  - `lattice.rs` — `Lattice` trait (`bot`, `join`, `leq`) for generic fixed-point computation.
  - `domain.rs` — `ResourceLifecycle` (bitflag), `ResourceDomainState`, `AuthLevel`, `AuthDomainState`, `ProductState` with lattice impls.
  - `symbol.rs` — `SymbolInterner` that builds a string-interning table from CFG node defines/uses; `SymbolId` newtype.
  - `transfer.rs` — `DefaultTransfer` function: maps CFG node kinds (Call, Assignment, If, Return) to state transitions using the existing `ResourcePair` definitions from `cfg_analysis::rules`. Emits `TransferEvent` for illegal transitions.
  - `engine.rs` — two-phase forward worklist solver: Phase 1 iterates to a fixed point (no events collected to avoid spurious reports from intermediate states); Phase 2 re-applies transfer once over converged states to collect events. Bounded by `MAX_TRACKED_VARS` (64) with guarded degradation.
  - `facts.rs` — post-analysis pass: extracts `StateFinding`s from transfer events (use-after-close, double-close) and exit-node state inspection (must-leak, may-leak, unauthed access).
- **`scanner.enable_state_analysis` config option** — opt-in boolean (default `false`) in `ScannerConfig` and `default-nyx.conf`. Requires CFG mode (`full` or `taint`).
- **`Diag.message` field** — optional human-readable message on diagnostic output. State findings carry variable-specific context (e.g. "variable `f` used after close"). Surfaced in console output (dimmed line below the finding), JSON, and SARIF (`message.text` prefers per-finding message over generic rule description).
- **State finding dedup** — when state analysis produces findings on a line, overlapping `cfg-resource-leak` and `cfg-auth-gap` findings on the same line are suppressed (state analysis is more precise).
- **SARIF rule descriptions** for all five state rule IDs.
- 21 integration tests (`tests/state_tests.rs`) with 19 C fixture files covering: use-after-close, double-close, resource leak, clean usage, opt-in gating, may-leak vs must-leak branch semantics, early return, nested branches, both-branches-close, loop convergence, loop use-after-close, handle overwrite, reopen-after-close, multiple handles, conservative join masking, chain operations, malloc/free pairs, straight-line double-close, and message field population.
- 30+ unit tests across state modules: lattice properties, lifecycle join/leq, domain merging, auth-level join, product state composition, may/must leak semantics, symbol interning, and transfer event generation.
- **`--severity <EXPR>` filter** — replaces `--high-only` with a flexible severity expression supporting single levels (`HIGH`), comma lists (`HIGH,MEDIUM`), and thresholds (`>=MEDIUM`). Parsing is case-insensitive with whitespace tolerance. `SeverityFilter` type with `parse()` and `matches()` in `patterns/mod.rs`.
- **`--mode <full|ast|cfg|taint>`** — replaces `--ast-only` and `--cfg-only` with a single canonical analysis mode flag. Enforces mutual exclusivity via clap `ValueEnum`.
- **`--index <auto|off|rebuild>`** — replaces `--no-index` and `--rebuild-index` with a single flag (default `auto`).
- **`--fail-on <SEVERITY>`** — CI ergonomics: exit code 1 if any emitted finding meets or exceeds the threshold severity. Example: `--fail-on HIGH`.
- **`--quiet`** — CLI flag to suppress all human-readable status output (equivalent to `output.quiet = true` in config).
- **`--keep-nonprod-severity`** — renamed from `--include-nonprod` for clarity; old name kept as hidden alias.
- **`OutputFormat` enum** — `--format` now uses clap `ValueEnum` with typed `Console`, `Json`, `Sarif` variants (default `Console`). No more empty-string default.
- 10 new unit tests: `SeverityFilter` parsing (single, comma list, threshold, case-insensitive, whitespace, empty rejection, invalid level rejection), `Severity::from_str` rejection of unknown values, and `severity_filter_applied_at_output_stage` integration test verifying that downgraded findings are correctly filtered.
- **AST pattern overhaul** -- all 10 language pattern files (`src/patterns/*.rs`) rewritten with consistent conventions, structured metadata, and validated tree-sitter queries.
  - **Pattern schema extensions** -- `PatternTier` (A = structural, B = heuristic-guarded), `PatternCategory` (13 vulnerability classes), and `Hash` on `Severity`. Module-level docs explain conventions and how to add new patterns.
  - **Namespaced IDs** -- all pattern IDs follow `<lang>.<category>.<specific>` format (e.g. `java.deser.readobject`, `py.cmdi.os_system`, `js.xss.document_write`).
  - **New vulnerability coverage** -- 30+ new patterns across languages: Python deserialization (`pickle.loads`, `yaml.load`, `shelve.open`), Python command injection (`os.system`, `os.popen`), Python weak crypto (`hashlib.md5/sha1`), Java reflection (`Method.invoke`), Java weak digest (`MessageDigest.getInstance("MD5")`), Java XSS (`getWriter().println`), Go TLS misconfiguration (`InsecureSkipVerify: true`), Go SQL concat, Go hardcoded secrets, Go gob deserialization, PHP `assert()` code exec, PHP `include $var` path traversal, PHP weak crypto (`md5`/`sha1`/`rand`), C/C++ `popen()`, C/C++ format-string with variable first arg, C++ `const_cast`, Ruby `Digest::MD5`.
  - **Query fixes** -- fixed 11 broken tree-sitter queries: Java `object_creation_expression` used wrong type node (`identifier` → `type_identifier`), C++ `reinterpret_cast`/`const_cast` used non-existent node types (→ `template_function` match), Ruby backtick used `shell_command` (→ `subshell`), Python SQL used `binary_expression` (→ `binary_operator`), TypeScript `as any` used inaccessible field (→ positional child), PHP patterns missing `argument` wrapper nodes, Rust `unsafe fn` regex used unsupported `\b`.
  - **No-duplicate rule** -- patterns that overlap with taint sinks use distinct ID namespaces and are documented; dedup in `ast.rs` prevents duplicate findings at the same location.
  - **Severity recalibration** -- `unwrap`/`expect`/`panic!`/`todo!` moved to Low (filtered by default `min_severity`). Security patterns remain High/Medium.
- **Pattern test suite** (`tests/pattern_tests.rs`, 26 tests) -- sanity checks (unique IDs, query compilation, non-empty descriptions, naming convention, severity distribution), positive fixture tests (10 languages), and negative fixture tests (10 languages verifying no false positives on safe code).
- **Pattern test fixtures** -- positive and negative fixture files for all 10 languages under `tests/fixtures/patterns/<lang>/`.

### Changed
- **Breaking**: Config and data directory changed from `dev.ecpeter23.nyx` to `nyx` (e.g. `~/Library/Application Support/nyx/` on macOS). Existing config files (`nyx.conf`, `nyx.local`) and SQLite indexes at the old path will not be picked up automatically — copy them to the new location or re-run `nyx scan` to regenerate.
- **Improved diagnostic output formatting** — overhauled console renderer for a professional, security-tool-grade look:
  - Severity is now the strongest visual anchor: HIGH (bold red with ✖), MEDIUM (bold orange ⚠), LOW (muted blue-gray ●). Fewer colors, clearer hierarchy.
  - File paths rendered dim blue (never brighter than severity).
  - Taint flow messages now use `→` arrow between shortened source/sink instead of backtick-wrapped text.
  - Evidence values (Source, Sink) no longer wrapped in backticks — cleaner rendering with no risk of broken backtick spans across wrapped lines.
- **Fixed taint expression rendering** — multi-line sink/source call chains are now normalised before display:
  - Whitespace collapsed (`foo()        .bar()` → `foo().bar()`).
  - Newlines joined into single-line canonical form.
  - Spacing artefacts between `)` and `.` in method chains cleaned up.
  - Long chains truncated with `…` ellipsis.
- Added `terminal_size` dependency for terminal-width-aware line wrapping.
- **Monotone forward dataflow taint analysis** — replaced the BFS taint engine in `taint/mod.rs` with a proper worklist-based forward dataflow analysis where termination is guaranteed by lattice finiteness. The generic `Transfer<S: Lattice>` trait in `state/engine.rs` now powers both the resource lifecycle/auth analysis and taint analysis.
  - **`TaintState` lattice** (`taint/domain.rs`) — bounded abstract state with per-variable `VarTaint` (Cap bitflags + multi-origin tracking via `SmallVec<[TaintOrigin; 2]>`), dual validation bitsets (`validated_must` for intersection/all-paths, `validated_may` for union/any-path), and monotone `PredicateSummary` for contradiction pruning. Variables stored in sorted `SmallVec` keyed by `SymbolId` for O(n) merge-join. Lattice height bounded at ~8700 (7-bit Cap × 64 vars + validation bits + predicate bits).
  - **`TaintTransfer`** (`taint/transfer.rs`) — implements `Transfer<TaintState>` with identical taint logic to the old BFS (source → propagation → sanitization → sink check). Callee resolution unchanged (local → global same-lang → interop edges). Emits `TaintEvent::SinkReached` events during Phase 2 of the engine.
  - **JS/TS two-level solve** — prevents cross-function taint leakage (the main source of state explosion in the old BFS) while preserving global-to-function flows. Level 1 solves top-level code; Level 2 solves each function seeded with read-only top-level taint via `global_seed`.
  - **Monotone predicate tracking** — path-sensitivity predicates moved from per-BFS-item `PathState` (which duplicated state exponentially) to monotone `PredicateSummary` in the lattice. Contradiction pruning uses `known_true & known_false` bit intersection (NullCheck/EmptyCheck/ErrorCheck only), which is both more precise and guaranteed monotone.
  - **Multi-origin tracking** — each tainted variable tracks up to 4 `TaintOrigin` (node + `SourceKind`), enabling multiple findings when distinct sources flow to the same sink.
  - **Guaranteed termination** — no more `MAX_BFS_ITERATIONS`/`MAX_SEEN_STATES` safety nets needed (though a 100K worklist iteration budget remains as defense-in-depth). Convergence follows from finite lattice height × finite CFG edges.
  - **`analyse_file()` signature unchanged** — `Finding` struct, `Diag` conversion, and all callers are unaffected.
- **Generic dataflow engine** (`state/engine.rs`) — `run_forward()` and `DataflowResult` are now generic over any `S: Lattice` + `T: Transfer<S>`. `DefaultTransfer` (resource lifecycle) implements `Transfer<ProductState>`; `TaintTransfer` implements `Transfer<TaintState>`. Per-domain iteration budget and `on_budget_exceeded` hooks added.
- **`path_state.rs` simplified** — removed `PathState`, `Predicate`, `MAX_PATH_PREDICATES`, `state_hash()`, `priority()` structs/methods. Kept `PredicateKind` enum and `classify_condition()` function (used by the new transfer for predicate classification).
- **Removed BFS infrastructure** — `taint_hash()`, BFS `Item` struct, `pred` predecessor map, two-tier seen-state map, and all bail-out constants (`MAX_BFS_ITERATIONS=200K`, `MAX_SEEN_STATES=100K`, `PATH_SENSITIVITY_NODE_LIMIT=500`, `PATH_SENSITIVITY_QUEUE_LIMIT=10K`, `MAX_PATH_VARIANTS_PER_KEY=4`) are no longer needed and have been removed.
- **Severity filtering applied at output stage** — `--severity` (and legacy `--high-only`) filtering is now applied ONCE in `scan::handle()` after all severity normalization (nonprod downgrades, dedup, truncation). Previously `--high-only` only filtered AST patterns during analysis; taint and CFG findings bypassed the filter entirely.
- **`--format` default is `console`** — previously defaulted to empty string, requiring fallback logic.
- **All status/progress output goes to stderr** — "Checking...", "Finished in...", config notes, and progress bars now use `eprintln!`/stderr exclusively. JSON and SARIF output is stdout-only.
- **`Severity::from_str` returns `Err` for unknown values** — previously returned `Ok(Severity::Low)` for any unrecognized input.
- **Deprecated CLI flags preserved as hidden aliases** — `--high-only`, `--no-index`, `--rebuild-index`, `--ast-only`, `--cfg-only`, and `--include-nonprod` are hidden from help but still functional, mapping to their canonical replacements.
- **Path-sensitive taint analysis** -- the BFS taint engine now carries a `PathState` (bounded set of branch predicates) alongside the taint map. When the BFS traverses a True or False edge from an `If` node, it records a `Predicate` with the condition's variables, kind, and polarity. This enables two new capabilities:
  - **Infeasible path pruning** -- paths with contradictory predicates (e.g. `if x.is_none() { return; } if x.is_none() { sink }`) are detected and pruned, eliminating false positives on code guarded by redundant null/empty/error checks. Contradiction detection is conservative: only whitelisted kinds (`NullCheck`, `EmptyCheck`, `ErrorCheck`) with single-variable predicates are pruned.
  - **Validation guard annotation** -- when all tainted variables reaching a sink are guarded by a `ValidationCall` predicate (e.g. `if validate(&x) { sink }` or `if !validate(&x) { return; } sink`), the finding is annotated with `path_validated: true` and `guard_kind: ValidationCall`. This metadata is surfaced in JSON and console output without changing severity.
- **Condition metadata on CFG nodes** -- `NodeInfo` now carries `condition_text`, `condition_vars`, and `condition_negated` for `If` nodes, extracted during CFG construction. Negation detection handles `!expr`, `not expr`, and Ruby `unless`. Classification of condition text into `PredicateKind` (NullCheck, EmptyCheck, ErrorCheck, ValidationCall, SanitizerCall, Comparison, Unknown) is conservative: call-based kinds require `(` in the text and a matching callee token.
- **`path_validated` and `guard_kind` fields on `Diag`** -- taint findings carry path-sensitivity metadata in JSON output (fields omitted when not set) and console output (suffix line `Path guard: ValidationCall` when present). Finding IDs are unchanged for dedup stability.
- **`smallvec` dependency** -- used for inline-allocated predicate storage in `PathState` (avoids heap allocation for the common case of ≤4 predicates per path).
- **Interprocedural call graph** -- a whole-program `CallGraph` (`petgraph::DiGraph<FuncKey, CallEdge>`) is now built between Pass 1 and Pass 2 of every taint-enabled scan. Each function definition is a node; resolved callee relationships are edges. The graph is constructed from the merged `GlobalSummaries` and is available in both the filesystem and indexed scan paths.
- **Three-valued callee resolution** -- `CalleeResolution` enum distinguishes `Resolved(FuncKey)`, `NotFound`, and `Ambiguous(Vec<FuncKey>)`. Ambiguous callees (same name in multiple namespaces, caller in a third namespace) are tracked separately from missing callees for diagnostics.
- **Shared resolution helper** -- `GlobalSummaries::resolve_callee_key()` centralizes same-language callee resolution with arity-aware filtering and namespace disambiguation. Both the call graph builder and the taint engine now use the same resolution logic.
- **Callee-name normalization** -- `normalize_callee_name()` extracts the last segment from qualified callee text (`"env::var"` → `"var"`, `"obj.method"` → `"method"`) before resolution. The raw call-site text is preserved on graph edges for diagnostics.
- **SCC / topological analysis** -- `CallGraphAnalysis` computes strongly connected components via Tarjan's algorithm and exposes a callee-first (leaves-first) topological ordering of SCC indices, ready for future bottom-up taint propagation.
- **Call graph tracing** -- `tracing::info!` log with node count, edge count, unresolved-not-found count, unresolved-ambiguous count, and SCC count is emitted after every call graph build.
- 8 new path-sensitivity integration tests: early-return validation guard, failed-validation branch, contradictory null-check pruning, if/else validation annotation, sanitize-one-branch regression, path-state budget graceful degradation, unknown-predicate non-pruning, multi-var non-pruning.
- 35 new unit tests in `taint::path_state`: classify_condition variants, PathState push/truncation, contradiction detection (whitelisted kinds, single-var only), has_validation_for semantics, state_hash determinism, priority ordering.
- 11 new unit tests: callee normalization, same-name-different-namespaces resolution, cross-language isolation, arity separation, recursive SCC detection, not-found vs ambiguous diagnostics, diamond topo ordering, interop edge resolution, namespace normalization consistency, and raw call-site preservation.
- **Edge-aware taint traversal** -- `analyse_file()` now uses `cfg.edges(node)` instead of `cfg.neighbors(node)`, inspecting `EdgeKind` on each edge. This is required for predicate recording but also makes the taint engine aware of the CFG's branch structure for the first time.
- **Two-tier seen-state deduplication** -- the BFS seen-state map changed from `HashSet<(NodeIndex, u64)>` to a `HashMap` keyed by `(NodeIndex, taint_hash)` mapping to a bounded list of `(path_hash, priority)` pairs. At most `MAX_PATH_VARIANTS_PER_KEY` (4) path variants are tracked per taint state, with deterministic eviction preferring non-truncated states with fewer predicates.
- **Finding deduplication** -- taint findings are now deduplicated by `(sink, source)` pair after analysis, preferring findings with `path_validated = true` (most informative metadata).
- **`taint::Finding` struct** -- added `path_validated: bool` and `guard_kind: Option<PredicateKind>` fields. Code that constructs `Finding` directly must include these fields.
- **`Diag` struct** -- added `path_validated: bool` and `guard_kind: Option<String>` fields. Both use `#[serde(skip_serializing_if)]` to omit from JSON when not set.
- **`taint::resolve_callee()` refactored** -- the global resolution step now delegates to `GlobalSummaries::resolve_callee_key()` and applies `normalize_callee_name()` before lookup, unifying resolution logic with the call graph builder.

### Fixed
- **Taint source kind misclassified as "unknown" for non-call sources** — source-bearing nodes with `CallWrapper` or `Assignment` kind (e.g. `userInput = req.query.data`) had their `callee` field set to `None` because the CFG builder only populated `callee` for `StmtKind::Call` nodes. This caused `infer_source_kind()` to receive an empty string, failing to match any keyword pattern and defaulting to `SourceKind::Unknown`. Fixed by also setting `callee` when a label (Source/Sink/Sanitizer) is detected, so the extracted member text (e.g. "req.query") flows through to source kind inference. Affects severity classification and diagnostic output for property-access sources across all languages.
- **Full KINDS map audit across all 10 languages** — 89 missing tree-sitter node types added to KINDS maps so the CFG builder no longer silently drops code inside switch/case, try/catch/finally, class bodies, closures/lambdas, and other container nodes. Previously, any node not in a language's KINDS map hit the `build_sub` fallback which created a terminal Seq node without recursing into children, effectively making all wrapped code invisible to analysis.
  - **C** (+3): `switch_statement`, `case_statement`, `labeled_statement`
  - **C++** (+7, 1 fix): `switch_statement`, `case_statement`, `labeled_statement`, `throw_statement` (Return), `try_statement`, `catch_clause`, `lambda_expression`; **critical fix**: `namespace_definition` changed from `Trivia` to `Block` (all function definitions inside namespaces were silently dropped)
  - **Java** (+11): `do_statement` (While), `throw_statement` (Return), `switch_expression`, `switch_block`, `switch_block_statement_group`, `try_statement`, `catch_clause`, `finally_clause`, `lambda_expression`, `constructor_body`, `static_initializer`
  - **JavaScript** (+11): `switch_statement`, `switch_body`, `switch_case`, `switch_default`, `try_statement`, `catch_clause`, `finally_clause`, `class_declaration`, `class` (expression), `class_body`, `export_statement`
  - **TypeScript** (+13): all JS switch/try/class entries plus `abstract_class_declaration`, `export_statement`, `enum_declaration` (Trivia)
  - **PHP** (+11): `do_statement` (While), `throw_expression` (Return), `switch_statement`, `switch_block`, `case_statement`, `default_statement`, `try_statement`, `catch_clause`, `finally_clause`, `colon_block`, `class_declaration`
  - **Python** (+7): `try_statement`, `except_clause`, `finally_clause`, `class_definition`, `decorated_definition`, `match_statement`, `case_clause`
  - **Ruby** (+11): `until` (While), `begin`, `rescue`, `ensure`, `case`, `when`, `class`, `module`, `singleton_method` (Function), `do`, `block`
  - **Go** (+10): `expression_switch_statement`, `type_switch_statement`, `expression_case`, `type_case`, `default_case`, `select_statement`, `communication_case`, `go_statement`, `defer_statement`, `func_literal` (Function)
  - **Rust** (+5, 1 removal): `closure_expression`, `async_block`, `impl_item`, `trait_item`, `declaration_list`; removed dead `loop_statement` entry (node doesn't exist in tree-sitter-rust 0.24.0)
- Removed unused `Kind::LoopBody` enum variant from `labels/mod.rs` (no arm in `build_sub`, last reference was the dead Rust `loop_statement` entry)
- **CFG: `else_clause` not recursed into for C/C++** — tree-sitter's C and C++ grammars wrap else bodies in an `else_clause` node. This node was missing from both languages' `KINDS` maps, so the CFG builder's fallback arm treated it as a terminal `Seq` node without descending into children. All statements inside else blocks (e.g. `fclose(f)`) were silently dropped from the CFG, causing false-positive resource leak and incorrect branch analysis. Fixed by mapping `"else_clause" => Kind::Block` in `src/labels/c.rs` and `src/labels/cpp.rs`.
- **CFG: `else_clause` missing from Rust, JavaScript, TypeScript, Python, PHP KINDS maps** — same bug class as C/C++: tree-sitter wraps else bodies in an `else_clause` node that was not in KINDS, silently dropping all code inside else blocks from the CFG. Fixed by mapping `"else_clause" => Kind::Block` in all five languages. Also added `"elif_clause" => Kind::Block` (Python), `"else_if_clause" => Kind::Block` (PHP), and `"elsif" => Kind::If` (Ruby) to handle chained elif/elsif nodes.
- **Rust KINDS using wrong tree-sitter node names** — tree-sitter-rust uses `_expression` suffixes (not `_statement`) for `while`, `for`, and `return` nodes. The existing `while_statement`, `for_statement`, and `return_statement` entries were dead code (0 grammar matches). Added `while_expression`, `for_expression`, and `return_expression` mappings.
- **Rust `match_expression`, `match_block`, `match_arm`, `unsafe_block` missing from KINDS** — these wrapper nodes were not mapped, causing all code inside match arms and unsafe blocks to be silently dropped from the CFG. Mapped to `Kind::Block` for sequential traversal.
- **TypeScript missing `throw_statement` and `do_statement`** — `throw` was mapped in JavaScript but not TypeScript; `do_statement` (do-while loops) was missing from both JS and TS. Added `"throw_statement" => Kind::Return` and `"do_statement" => Kind::While` to both languages.
- **Python `raise_statement` and `with_statement` missing from KINDS** — `raise` terminates the current path (mapped to `Kind::Return`); `with` wraps code in a context manager (mapped to `Kind::Block`). Both were silently dropping enclosed code.
- **Dead KINDS entries removed** — `"for_of_statement"` in TypeScript (0 grammar matches; TS inherits `for_in_statement` from JS) and `"method_call"` in Ruby (0 grammar matches; Ruby only has `call`).
- **`--high-only` emitting Low/Medium taint and CFG findings** — severity filter was only applied to AST pattern queries during analysis. Taint findings (whose severity derives from `SourceKind`) and CFG structural findings passed through unfiltered. The filter is now applied at the final output stage after all severity normalization, ensuring `--severity HIGH` never emits downgraded Medium/Low findings.
- **JSON/SARIF output contaminated with status messages on stdout** — status messages ("Checking...", "Finished in...") used `println!` and appeared in stdout alongside machine output. Now all status goes to stderr.
- **CFG: False edge to then-block exits in no-else if statements** -- previously, `if (cond) { body }` without an else block created a `False` edge from the condition node directly to the then-block's exit nodes. This made the false path appear to traverse the then-block, causing incorrect predicate polarity in path-sensitive analysis and duplicate taint findings with contradictory metadata. The CFG now creates a synthetic pass-through `Seq` node for the false path with an explicit `False` edge from the condition, correctly modeling "skip the then-block." This also fixes the frontier: previously, the no-else non-terminating case duplicated `then_exits` in the frontier (`then_exits ++ then_exits.clone()`); it now correctly produces `then_exits ∪ [pass_through]`.
- **Taint BFS non-termination on large JS files** — the BFS taint engine in `taint/mod.rs` had no global iteration bound. The seen-state deduplication keyed on `(node, taint_hash)`, so every distinct taint map at a CFG node was treated as a novel state. In files with loops and many tainted variables (e.g. a 2,200-line JS file with 18+ top-level variables tainted via `window.location.search`), each loop iteration produced a slightly different taint map, causing the BFS to revisit loop bodies indefinitely. Both `--no-index` and `--rebuild-index` scans hung near completion (progress showed e.g. 87/88 files). Fixed by adding two hard bounds: `MAX_BFS_ITERATIONS` (200,000 queue pops) and `MAX_SEEN_STATES` (100,000 unique `(node, taint_hash)` entries in the seen-state map). When either limit is reached the analysis bails out gracefully and returns all findings collected so far. A `tracing::warn!` is emitted on iteration-limit bail-out. Normal files are unaffected (typical BFS uses <1,000 iterations).

## [0.3.0] - 2026-02-25

### Added
- **Configurable analysis rules** -- users can define custom sources, sanitizers, and sinks per language via TOML config (`nyx.local`) or the new `nyx config` CLI. Config rules take priority over built-in rules, so project-specific sanitizers like `escapeHtml()` are recognized without code changes.
- **`nyx config` CLI subcommand** with four actions:
  - `show` -- print effective merged configuration as TOML
  - `path` -- print config directory path
  - `add-rule --lang <LANG> --matcher <NAME> --kind <KIND> --cap <CAP>` -- append a label rule to `nyx.local`
  - `add-terminator --lang <LANG> --name <NAME>` -- append a terminator function to `nyx.local`
- **`--include-nonprod` CLI flag** -- by default, findings in non-production paths (tests, vendor, benchmarks, examples, fixtures, build scripts, `*.min.js`) are now downgraded by one severity tier (High→Medium, Medium→Low). Pass `--include-nonprod` to restore original severity. Controlled by `scanner.include_nonprod` config key.
- **`SourceKind` enum** in the taint engine -- taint findings now carry a `source_kind` field (`UserInput`, `EnvironmentConfig`, `FileSystem`, `Database`, `Unknown`) inferred from the source callee name and capabilities. Severity is based on source kind rather than hardcoded to High: filesystem and database sources produce Medium, user input and environment sources produce High.
- **Configurable terminators** -- functions like `process.exit()` can be declared as terminators per language; the CFG treats them as dead ends, preventing false positives on code after termination calls.
- **Event handler callback suppression** -- functions passed as arguments to configured event handler calls (e.g. `addEventListener`) are no longer flagged as unreachable code.
- **Exec-path guard rules** -- calls to `which`, `resolve_binary`, `find_program`, `lookup_path`, and `shutil.which` are recognized as guards for `SHELL_ESCAPE` sinks. If such a guard dominates a shell-exec sink, the `cfg-unguarded-sink` finding is suppressed.
- **One-hop constant binding trace** -- the constant-arg sink suppression now traces one hop through the CFG. If a sink's variable was defined by a node with no uses and no Source label, it is treated as constant. Fixes false positives on patterns like `cmd = "git"; subprocess.run([cmd, "status"])`.
- **Evidence-based severity in cfg-only mode** -- when taint analysis is not active (no global summaries and no taint findings), structural `cfg-unguarded-sink` findings without source-derived evidence are downgraded from Medium to Low.
- **FileResponse ownership transfer** -- file handles passed to consuming sinks (`FileResponse`, `StreamingHttpResponse`, `send_file`, `make_response`) are no longer flagged as resource leaks.
- **Lock-not-released refinement** -- mutex findings now require an explicit `.acquire()` or `.lock()` call on the acquired variable. Constructor-only patterns like `lock = threading.Lock()` without acquire no longer produce `cfg-lock-not-released`.
- **Python `connect`/`cursor` exclusions** -- `signal.connect`, `event.connect`, and `.register` are excluded from the Python db-connection acquire pattern, preventing false `cfg-resource-leak` findings on Django signal handlers and event registrations.
- **`location.href` sink rules** for JavaScript -- `location.href`, `window.location.href`, and `document.location.href` assignments are classified as `Sink(URL_ENCODE)`.
- **`throw_statement` as terminator** in JavaScript -- `throw` now terminates the current block in the CFG (mapped to `Kind::Return`), preventing false `cfg-error-fallthrough` findings after throw statements.
- **`Cap::FMT_STRING` capability bit** -- new bitflag (`0b0100_0000`) for format-string vulnerabilities, distinct from HTML injection. Sources using `Cap::all()` automatically match.
- **Python taint sources** -- `open`, `argparse.parse_args`, `urllib.request.urlopen`, `requests.get`, `requests.post` added as `Cap::all()` sources for broader attack-surface coverage.
- **SARIF 2.1.0 output format** (`-f sarif`) -- produces spec-compliant Static Analysis Results Interchange Format JSON on stdout. Includes tool metadata, deduplicated rule definitions with descriptions, severity-to-level mapping (`High→error`, `Medium→warning`, `Low→note`), and physical locations with relative paths. Suitable for GitHub Code Scanning, Azure DevOps, and other SARIF-consuming CI tools.
- **Progress bars** via `indicatif` -- file discovery, Pass 1, and Pass 2 each display a progress bar on stderr with file counts and ETA. Bars are automatically hidden when output format is `json`/`sarif` or quiet mode is enabled. Index building also shows progress.
- **Quiet mode** (`output.quiet = true`) -- suppresses all status messages (config notes, "Checking...", "Finished in...") on stderr. Useful for CI pipelines and scripted invocations.
- **Resource leak detection for Python, Ruby, PHP, JavaScript, and TypeScript** -- new acquire/release pairs: Python (`open`/`.close`, `socket`/`.close`, `connect`/`.close`, `threading.Lock`/`.release`), Ruby (`File.open`/`.close`, `TCPSocket.new`/`.close`, `.lock`/`.unlock`), PHP (`fopen`/`fclose`, `mysqli_connect`/`mysqli_close`, `curl_init`/`curl_close`), JS/TS (`fs.open`/`fs.close`, `createReadStream`/`.close`).
- **Walker config wired up** -- `performance.max_depth`, `scanner.one_file_system`, `scanner.require_git_to_read_vcsignore`, and `scanner.excluded_files` are now enforced during directory walking (previously parsed but ignored).
- **`database.vacuum_on_startup`** -- when enabled, runs SQLite VACUUM before indexed scans to reclaim space.
- 31 new unit tests covering config round-trip, rule merging, classify extension, href classification, throw termination, terminator detection, config sanitizer suppression, Python/C++ precision, unreachable+unguarded dedup, resource leak detection, one-hop constant binding, exec-path guards, cfg-only severity downgrade, FileResponse ownership, lock constructor suppression, signal.connect exclusion, nonprod path detection, and severity downgrade.

### Changed
- **`taint::Finding` struct** -- added `source_kind: SourceKind` field. Code that constructs `Finding` directly must include this field.
- **`AnalysisContext` struct** -- added `taint_active: bool` and `analysis_rules` fields. Code that constructs `AnalysisContext` directly must include these fields.
- **`ScannerConfig` struct** -- added `include_nonprod: bool` field (default `false`). Deserialization is unaffected due to `#[serde(default)]`.
- **`proto_pollution` AST pattern severity** -- downgraded from High to Low. The AST-only pattern is a structural indicator; the taint engine separately produces High findings when attacker-controlled data flows to `__proto__`.
- **`location_href_assignment` AST pattern** -- constrained to require a known browser global object (`window`, `location`, `document`, `self`, `top`, `parent`, `frames`). Prevents `el.href = val` from matching; only `window.location.href = val` and similar patterns trigger the finding.
- **Taint finding severity** -- no longer hardcoded to High. Severity is now derived from `SourceKind`: UserInput/EnvironmentConfig/Unknown → High, FileSystem/Database → Medium.
- **C/C++ sink reclassification** -- `printf`/`fprintf` moved from `Sink(HTML_ESCAPE)` to `Sink(FMT_STRING)`. `std::cout`, `std::cerr`, `std::clog` removed from sinks entirely (output/logging, not injection vectors). `sprintf`/`strcpy`/`strcat` remain `Sink(HTML_ESCAPE)`.
- `classify()` now accepts an optional `extra: Option<&[RuntimeLabelRule]>` parameter; config-defined rules are checked first (higher priority) before built-in static rules.
- `build_cfg()`, `build_sub()`, and `push_node()` accept optional `LangAnalysisRules` for config-driven label classification, terminator detection, and event handler awareness.
- `find_guard_nodes()` and `is_guard_call()` now recognize config-defined sanitizers as guards with matching capability bits.
- `merge_configs()` union-merges analysis rules, terminators, and event handlers per language key with dedup.
- Assignment LHS classification now tries the full member expression text (e.g. `location.href`) before falling back to property-only (e.g. `innerHTML`), fixing false positives on `a.href` assignments.
- `handle_command()` now receives `config_dir` to support the `config` subcommand.
- **Fused single-pass analysis** -- AST-only mode now runs a single fused pass (`analyse_file_fused`) that parses each file and builds the CFG once, producing both function summaries and diagnostics. Previously every file was parsed twice (once for summary extraction, once for analysis). Taint mode uses the fused pass for Pass 1, eliminating redundant CFG construction during summary extraction.
- **O(N²) → O(N) function-level dataflow sweep in CFG builder** -- the light-weight dataflow sweep and return-node wiring in `build_sub` for `Kind::Function` now iterate only over nodes created within the current function scope (tracked via a snapshot of the node count) instead of scanning the entire graph. Eliminates quadratic scaling in files with many functions.
- **Parallel summary merging** -- `scan_filesystem` now uses rayon `fold`/`reduce` to build per-thread `GlobalSummaries` maps in parallel, then merges them in a binary reduce tree. Eliminates the serial `merge_summaries` bottleneck. Added `GlobalSummaries::merge()`.
- **Redundant file I/O eliminated in indexed path** -- files are now read once and hashed once per scan. Added `Indexer::should_scan_with_hash()` and `Indexer::upsert_file_with_hash()` to accept pre-computed hashes. Pass 2 uses `run_rules_on_bytes` with already-read bytes instead of re-reading from disk. Previously files could be read up to 4 times and hashed up to 3 times per indexed scan.
- **SQLite mutex mode relaxed** -- switched from `SQLITE_OPEN_FULL_MUTEX` (global serialization) to `SQLITE_OPEN_NO_MUTEX`. The r2d2 connection pool guarantees one-connection-per-thread safety; combined with WAL mode this allows concurrent readers without a global lock.
- **Parallel JSON deserialization in `load_all_summaries`** -- for large result sets (>256 summaries), JSON deserialization is now parallelized with rayon.
- **Zero-allocation taint hashing** -- `taint_hash()` replaced sorted-`Vec` + blake3 with an order-independent XOR-of-FNV scheme. Eliminates a heap allocation and sort per BFS edge in the taint engine.
- **In-place taint transfer** -- `apply_taint()` now mutates the taint map in place instead of cloning and returning a new `HashMap` per node visit. The BFS loop caches hash values and uses `std::mem::take` for the last successor to avoid unnecessary clones.

### Fixed
- **False positives on one-hop constant bindings** -- `cmd = "git"; Command::new(cmd)` no longer triggers `cfg-unguarded-sink` because the variable is traced back to a constant definition.
- **False positives from exec-path guards** -- `resolve_binary(&bin); Command::new(bin)` is now recognized as guarded.
- **False `cfg-resource-leak` on Django signal handlers** -- `signal.connect(handler)` no longer matches the Python db-connection acquire pattern.
- **False `cfg-lock-not-released` on Lock constructors** -- `threading.Lock()` without `.acquire()` no longer produces a finding.
- **False `cfg-resource-leak` on FileResponse** -- `f = open(...); return FileResponse(f)` is recognized as ownership transfer.
- **Inflated severity in cfg-only mode** -- structural findings without taint evidence now correctly produce Low severity instead of Medium.
- **`el.href = val` false positive in AST patterns** -- the `location_href_assignment` pattern now requires a known browser global, eliminating matches on DOM element `.href` assignments.
- **Structured output modes (`-f json`, `-f sarif`) now produce zero stderr noise** -- config notes, "Checking …", and "Finished in …" messages are fully suppressed (not just redirected to stderr) so that `nyx scan -f json | jq` and CI SARIF upload work without extraneous output. Human-readable console format continues to show status messages.
- **Console output column alignment** -- severity tags are now bracketed and padded to a fixed display width (`[HIGH]`, `[MEDIUM]`, `[LOW]`) so that rule IDs align consistently regardless of severity. ANSI color codes are applied after width calculation, not before.
- **`.href` false positives** -- `el.href = "/about"` no longer triggers `location_href_assignment` or sink classification; only `location.href` (and `window.location.href`, `document.location.href`) match.
- **Constant-arg sink false positives** -- sinks whose arguments are all constants (no variable uses beyond the callee name) with no taint confirmation are now suppressed. Fixes false positives on patterns like `subprocess.run(["make","clean"])` and `printf("hello\n")`.
- **Unreachable + unguarded dedup** -- when both `cfg-unreachable-sink` and `cfg-unguarded-sink` fire on the same span, the unguarded finding is suppressed (unreachable is more specific).
- **`std::cout` false positives** -- `std::cout` no longer classified as a sink, eliminating spurious findings on every C++ iostream print.
- **Break/continue scope correctness** -- `break` and `continue` inside loops now correctly wire to their enclosing loop header/exit. Previously, `break` in a `while`/`for` body created a dead-end node that left post-loop code unreachable, producing false `cfg-unreachable-*` findings. The If handler's no-else case also now correctly flows the false branch to subsequent code when the then-branch terminates (return/break/continue). True/False edge labels are applied to branch entry nodes rather than exit nodes, fixing `cfg-error-fallthrough` false positives on `if (err) { return; }` patterns.
- **Preprocessor dangling-else CFG recovery** -- `#ifdef`/`#endif` blocks that split an `if/else` across preprocessor boundaries no longer orphan subsequent code. The CFG block handler now recovers the frontier after preprocessor nodes, preventing false unreachable-code findings on code following `#ifdef ... #endif` blocks.
- **Wrapper resource function recognition** -- `curlx_fopen`, `curlx_fdopen`, `fdopen`, and `curlx_fclose` are now recognized as acquire/release functions for C file handles, eliminating false `cfg-resource-leak` findings on codebases (e.g. curl) that use wrapper functions around standard I/O.
- **`freopen` false positive** -- `freopen()` (and `curlx_freopen`) no longer triggers `cfg-resource-leak` findings. Previously `freopen` matched the `fopen` acquire pattern via `ends_with`; a new `exclude_acquire` field on `ResourcePair` filters out these false matches for both the file handle and file descriptor resource pairs.
- **Struct field ownership transfer** -- resource leak detection now recognizes ownership transfer via struct field assignment (`s->stream = fp`, `obj.field = ptr`). When an acquired resource is stored into a struct field downstream, the finding is suppressed since the receiving struct assumes lifetime responsibility.
- **Linked-list/global insertion** -- resource leak detection now recognizes linked-list insertion patterns (`p->next = list; list = p`) and global variable assignment as ownership transfers, eliminating false `cfg-resource-leak` findings on common C allocation-and-insert idioms.
- Removed incorrect `value_enum` attribute from CLI `--format` argument.
- Benchmark compilation error: `classify()` calls in `benches/scan_bench.rs` were missing the third `extra` parameter.

## [0.2.0] - 2026-02-24

### Added
- **Cross-file taint analysis** -- two-pass architecture: Pass 1 extracts `FuncSummary` per function (source/sanitizer/sink capabilities, taint propagation, callees), Pass 2 runs BFS taint propagation with cross-file callee resolution.
- **CFG analysis engine** with five detectors: unguarded sinks (`cfg-unguarded-sink`), auth gaps in web handlers (`cfg-auth-gap`), unreachable security code (`cfg-unreachable-*`), error fallthrough (`cfg-error-fallthrough`), and resource leaks (`cfg-resource-leak`).
- **Cross-language interop** -- taint flows across language boundaries via explicit `InteropEdge` structs without false-positive name collisions.
- **Function summaries** persisted to SQLite (`function_summaries` table) with arity, parameter names, capability bitflags, and callee lists.
- **Multi-language CFG + taint support** -- all 10 languages (Rust, C, C++, Java, Go, PHP, Python, Ruby, TypeScript, JavaScript) now have `KINDS` maps, `RULES`, and `PARAM_CONFIG` for full CFG construction and taint analysis.
- **Resource leak detection** for C/C++ (malloc/free, fopen/fclose), Go (os.Open/Close, Lock/Unlock), Rust (alloc/dealloc), and Java (streams, connections).
- **Finding scoring system** -- numeric scores based on severity, proximity to entry point, path complexity, taint confirmation, and confidence multiplier.
- **Analysis modes** -- `Full` (default), `Ast` (`--ast-only`), and `Taint` (`--cfg-only`) selectable via CLI flags or `scanner.mode` config.
- **`GlobalSummaries`** with conservative merge: union caps, OR booleans, union param/callee lists on name collisions across files.
- **Performance optimizations** -- `_from_bytes` variants to read-once/hash-once, lock-free rayon parallelism, SQLite WAL + 8 MB cache + 256 MB mmap.
- **Tracing instrumentation** -- `tracing` spans on all pipeline phases (walk, pass1, merge, pass2, per-file ops, db_init).
- **Benchmark suite** -- criterion benchmarks in `benches/scan_bench.rs` with fixtures.
- 107 unit tests covering taint propagation, cross-file resolution, cross-language interop, CFG analysis, and summaries.

### Changed
- Bumped all dependencies to latest compatible versions.
- `Cap` bitflags expanded: `ENV_VAR`, `HTML_ESCAPE`, `SHELL_ESCAPE`, `URL_ENCODE`, `JSON_PARSE`, `FILE_IO`.
- `classify()` in labels uses zero-allocation byte-level case-insensitive comparisons.
- Indexed scans now always re-analyze all files in Pass 2 when taint is enabled (conservative: global summaries may have changed even if a file didn't).

### Fixed
- Clippy `ptr_arg` lint in perf tests (`&PathBuf` -> `&Path`).

## [0.2.0-alpha] - 2025-06-28

### Added
- Experimental intra‑procedural CFG + taint analysis for Rust. Nyx now builds a control‑flow graph, applies data‑flow rules, and flags unsanitised Source → Sink paths (e.g. env::var → Command::new).
- O(1) node‑kind lookup via per‑language PHF tables for zero‑cost dispatch.
- Six unit tests covering conditionals, loops, sanitizers, and multiple sources.
- Debug channel target=cfg (use RUST_LOG=nyx::cfg=debug) to inspect generated graphs.

### Fixed
- Fixed a bug in the release pipeline where Windows was trying to call the zip, PowerShell doesn't have a zip command

## [0.1.1-alpha] - 2025-06-25

### Fixed
- Fixed a bug where the `scan --no-index` command would not respect the `max_results` config setting (#1)

### Added
- Integration tests covering indexing and scanning pipelines (#3, #4, #5, #8)

## [0.1.0-alpha] - 2025-06-25

### Added
- Initial alpha release of **Nyx** CLI tool
- Multi-language AST pattern scanning via `tree-sitter` for Rust, C/C++, Java, Go, PHP, Python, Ruby, TypeScript, JavaScript
- `scan` command: filesystem walker, pattern execution, console output
- `index` command: build, rebuild, and status reporting of SQLite-backed index
- `list` command: list indexed projects with optional verbosity
- `clean` command: remove one or all project indexes
- Configuration system with `nyx.conf` (generated) and `nyx.local` (user overrides)
- Default severity levels: High, Medium, Low
- Unit tests for core modules (config, ext, project utils)
