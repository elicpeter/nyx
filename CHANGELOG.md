# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

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
