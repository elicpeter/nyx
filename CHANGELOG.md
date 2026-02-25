# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- **`--severity <EXPR>` filter** — replaces `--high-only` with a flexible severity expression supporting single levels (`HIGH`), comma lists (`HIGH,MEDIUM`), and thresholds (`>=MEDIUM`). Parsing is case-insensitive with whitespace tolerance. `SeverityFilter` type with `parse()` and `matches()` in `patterns/mod.rs`.
- **`--mode <full|ast|cfg|taint>`** — replaces `--ast-only` and `--cfg-only` with a single canonical analysis mode flag. Enforces mutual exclusivity via clap `ValueEnum`.
- **`--index <auto|off|rebuild>`** — replaces `--no-index` and `--rebuild-index` with a single flag (default `auto`).
- **`--fail-on <SEVERITY>`** — CI ergonomics: exit code 1 if any emitted finding meets or exceeds the threshold severity. Example: `--fail-on HIGH`.
- **`--quiet`** — CLI flag to suppress all human-readable status output (equivalent to `output.quiet = true` in config).
- **`--keep-nonprod-severity`** — renamed from `--include-nonprod` for clarity; old name kept as hidden alias.
- **`OutputFormat` enum** — `--format` now uses clap `ValueEnum` with typed `Console`, `Json`, `Sarif` variants (default `Console`). No more empty-string default.
- 10 new unit tests: `SeverityFilter` parsing (single, comma list, threshold, case-insensitive, whitespace, empty rejection, invalid level rejection), `Severity::from_str` rejection of unknown values, and `severity_filter_applied_at_output_stage` integration test verifying that downgraded findings are correctly filtered.

### Changed
- **Severity filtering applied at output stage** — `--severity` (and legacy `--high-only`) filtering is now applied ONCE in `scan::handle()` after all severity normalization (nonprod downgrades, dedup, truncation). Previously `--high-only` only filtered AST patterns during analysis; taint and CFG findings bypassed the filter entirely.
- **`--format` default is `console`** — previously defaulted to empty string, requiring fallback logic.
- **All status/progress output goes to stderr** — "Checking...", "Finished in...", config notes, and progress bars now use `eprintln!`/stderr exclusively. JSON and SARIF output is stdout-only.
- **`Severity::from_str` returns `Err` for unknown values** — previously returned `Ok(Severity::Low)` for any unrecognized input.
- **Deprecated CLI flags preserved as hidden aliases** — `--high-only`, `--no-index`, `--rebuild-index`, `--ast-only`, `--cfg-only`, and `--include-nonprod` are hidden from help but still functional, mapping to their canonical replacements.

### Fixed
- **`--high-only` emitting Low/Medium taint and CFG findings** — severity filter was only applied to AST pattern queries during analysis. Taint findings (whose severity derives from `SourceKind`) and CFG structural findings passed through unfiltered. The filter is now applied at the final output stage after all severity normalization, ensuring `--severity HIGH` never emits downgraded Medium/Low findings.
- **JSON/SARIF output contaminated with status messages on stdout** — status messages ("Checking...", "Finished in...") used `println!` and appeared in stdout alongside machine output. Now all status goes to stderr.

### Added
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

### Changed
- **Edge-aware taint traversal** -- `analyse_file()` now uses `cfg.edges(node)` instead of `cfg.neighbors(node)`, inspecting `EdgeKind` on each edge. This is required for predicate recording but also makes the taint engine aware of the CFG's branch structure for the first time.
- **Two-tier seen-state deduplication** -- the BFS seen-state map changed from `HashSet<(NodeIndex, u64)>` to a `HashMap` keyed by `(NodeIndex, taint_hash)` mapping to a bounded list of `(path_hash, priority)` pairs. At most `MAX_PATH_VARIANTS_PER_KEY` (4) path variants are tracked per taint state, with deterministic eviction preferring non-truncated states with fewer predicates.
- **Finding deduplication** -- taint findings are now deduplicated by `(sink, source)` pair after analysis, preferring findings with `path_validated = true` (most informative metadata).
- **`taint::Finding` struct** -- added `path_validated: bool` and `guard_kind: Option<PredicateKind>` fields. Code that constructs `Finding` directly must include these fields.
- **`Diag` struct** -- added `path_validated: bool` and `guard_kind: Option<String>` fields. Both use `#[serde(skip_serializing_if)]` to omit from JSON when not set.
- **`taint::resolve_callee()` refactored** -- the global resolution step now delegates to `GlobalSummaries::resolve_callee_key()` and applies `normalize_callee_name()` before lookup, unifying resolution logic with the call graph builder.

### Fixed
- **CFG: False edge to then-block exits in no-else if statements** -- previously, `if (cond) { body }` without an else block created a `False` edge from the condition node directly to the then-block's exit nodes. This made the false path appear to traverse the then-block, causing incorrect predicate polarity in path-sensitive analysis and duplicate taint findings with contradictory metadata. The CFG now creates a synthetic pass-through `Seq` node for the false path with an explicit `False` edge from the condition, correctly modeling "skip the then-block." This also fixes the frontier: previously, the no-else non-terminating case duplicated `then_exits` in the frontier (`then_exits ++ then_exits.clone()`); it now correctly produces `then_exits ∪ [pass_through]`.

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
