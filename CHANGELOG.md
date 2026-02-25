# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.1] - 2026-02-25

### Added
- **Configurable analysis rules** -- users can define custom sources, sanitizers, and sinks per language via TOML config (`nyx.local`) or the new `nyx config` CLI. Config rules take priority over built-in rules, so project-specific sanitizers like `escapeHtml()` are recognized without code changes.
- **`nyx config` CLI subcommand** with four actions:
  - `show` -- print effective merged configuration as TOML
  - `path` -- print config directory path
  - `add-rule --lang <LANG> --matcher <NAME> --kind <KIND> --cap <CAP>` -- append a label rule to `nyx.local`
  - `add-terminator --lang <LANG> --name <NAME>` -- append a terminator function to `nyx.local`
- **Configurable terminators** -- functions like `process.exit()` can be declared as terminators per language; the CFG treats them as dead ends, preventing false positives on code after termination calls.
- **Event handler callback suppression** -- functions passed as arguments to configured event handler calls (e.g. `addEventListener`) are no longer flagged as unreachable code.
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
- 22 new unit tests covering config round-trip, rule merging, classify extension, href classification, throw termination, terminator detection, config sanitizer suppression, Python/C++ precision (constant-arg suppression, source-derived sinks), unreachable+unguarded dedup, and resource leak detection for Python/PHP/JS.

### Changed
- **C/C++ sink reclassification** -- `printf`/`fprintf` moved from `Sink(HTML_ESCAPE)` to `Sink(FMT_STRING)`. `std::cout`, `std::cerr`, `std::clog` removed from sinks entirely (output/logging, not injection vectors). `sprintf`/`strcpy`/`strcat` remain `Sink(HTML_ESCAPE)`.
- `classify()` now accepts an optional `extra: Option<&[RuntimeLabelRule]>` parameter; config-defined rules are checked first (higher priority) before built-in static rules.
- `build_cfg()`, `build_sub()`, and `push_node()` accept optional `LangAnalysisRules` for config-driven label classification, terminator detection, and event handler awareness.
- `AnalysisContext` carries `analysis_rules` so CFG analyses (guards, unreachable) can consult config rules.
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
