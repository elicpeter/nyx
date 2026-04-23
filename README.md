<div align="center">
  <img src="assets/nyx-logo-text.png" alt="nyx logo" width="500"/>

**A cross-language static analysis tool for security vulnerabilities.**

[![crates.io](https://img.shields.io/crates/v/nyx-scanner.svg)](https://crates.io/crates/nyx-scanner)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange)](https://www.rust-lang.org)
[![CI](https://img.shields.io/github/actions/workflow/status/elicpeter/nyx/ci.yml?branch=master)](https://github.com/elicpeter/nyx/actions)
</div>

---

## What is Nyx?

**Nyx** is a Rust-native command-line tool that detects security vulnerabilities across 10 programming languages. It combines [`tree-sitter`](https://tree-sitter.github.io/) parsing, intra-procedural control-flow graphs, and cross-file taint analysis with an optional SQLite-backed index for incremental scans.

Rule depth and detection confidence differ meaningfully between languages — Python, JavaScript, and TypeScript are the deepest, while C, C++, and Rust are narrower. See the [Language Maturity Matrix](docs/language-maturity.md) before committing Nyx to a CI gate on a given stack.

---

## Key Capabilities

| Capability | Description |
|---|---|
| Multi-language support | 10 languages across four maturity tiers — see [Language Maturity](docs/language-maturity.md). Stable: Python, JavaScript, TypeScript. Beta: Go, Java, Ruby, PHP. Preview: C, C++. Experimental: Rust. |
| AST-level pattern matching | Language-specific queries written against precise parse trees |
| Control-flow graph analysis | Auth gaps, unguarded sinks, unreachable security code, resource leaks, error fallthrough |
| Cross-file taint via function summaries | Intra-procedural monotone forward dataflow from sources through sanitizers to sinks, with cross-file call resolution through summarized capabilities. Not full inter-procedural analysis — see the detail below. |
| Cross-language interop | Taint flows across language boundaries via explicit interop edges (requires configuration) |
| Two-pass architecture | Pass 1 extracts function summaries; Pass 2 runs taint with full cross-file context |
| Incremental indexing | SQLite database stores file hashes, summaries, and findings to skip unchanged files |
| Parallel execution | File walking and analysis run concurrently via Rayon; scales with available CPU cores |
| Configurable analysis rules | Define custom sources, sanitizers, sinks, terminators, and event handlers per language via TOML config or CLI |
| Configurable scan parameters | Exclude directories, set maximum file size, tune worker threads, limit output, and more |
| Multiple output formats | Console (default), JSON, and SARIF 2.1.0 for CI integration |
| Progress reporting | Real-time progress bars for file discovery and analysis passes |

---

## Design Goals

| Property | Details |
|---|---|
| **Pure-Rust, single binary** | No JVM, Python, or server required. |
| **Parallel** | Uses Rayon for concurrent file walking and analysis; scales with available CPU cores. Per-fixture wall-clock budgets are enforced in CI by `tests/perf_tests.rs`; run `cargo bench` locally for numbers on your hardware. |
| **CFG + taint analysis** | Intra-procedural CFG construction and monotone forward dataflow taint analysis with guaranteed termination. Cross-file function summaries and capability-based sanitizer tracking. |
| **Index-aware** | An optional SQLite index stores file hashes and findings; subsequent scans skip unchanged files. |
| **Offline** | No login, cloud account, or telemetry required. Suitable for air-gapped environments. |
| **Tree-sitter parsing** | Parses real language grammars rather than using regex matching. |
| **Extensible** | Custom sources, sanitizers, sinks, and terminators can be added via TOML config or CLI. |

---

## Installation

### Install crate
```bash
$ cargo install nyx-scanner
```

### Install Github release
1. Navigate to the [Releases](https://github.com/elicpeter/nyx/releases) page of the repository.
2. Download the appropriate binary for your system:

    ```nyx-x86_64-unknown-linux-gnu.zip``` for Linux

    ```nyx-x86_64-pc-windows-msvc.zip``` for Windows

    ```nyx-x86_64-apple-darwin.zip``` or ```nyx-aarch64-apple-darwin.zip``` for macOS (Intel or Apple Silicon)

3. (Recommended) Verify the archive against the published `SHA256SUMS`:
    ```bash
    # Download SHA256SUMS from the same release, then:
    sha256sum -c SHA256SUMS --ignore-missing
    ```
    ```pwsh
    # Windows PowerShell equivalent
    (Get-FileHash .\nyx-x86_64-pc-windows-msvc.zip -Algorithm SHA256).Hash
    # Compare against the matching line in SHA256SUMS
    ```

4. Unzip the file and move the executable to a directory in your system PATH:
    ```bash
    # Example for Unix systems
    unzip nyx-x86_64-unknown-linux-gnu.zip
    chmod +x nyx
    sudo mv nyx /usr/local/bin/
    ```
    ```bash
    # Example for Windows in PowerShell
    Expand-Archive -Path nyx-x86_64-pc-windows-msvc.zip -DestinationPath .
    Move-Item -Path .\nyx.exe -Destination "C:\Program Files\Nyx\"  # Add to PATH manually if needed
    ```

5. Verify the installation:
     ```bash
    nyx --version
    ```
### Build from source

```bash
$ git clone https://github.com/elicpeter/nyx.git
$ cd nyx
$ cargo build --release
# optional – copy the binary into PATH
$ cargo install --path .
```

Nyx targets **stable Rust 1.85 or later**.

---

## Quick Start

```bash
# Scan the current directory (creates/uses an index automatically)
$ nyx scan

# Scan a specific path and emit JSON
$ nyx scan ./server --format json

# Emit SARIF 2.1.0 for CI integration (GitHub Code Scanning, etc.)
$ nyx scan --format sarif > results.sarif

# Perform an ad-hoc scan without touching the index
$ nyx scan --index off

# Restrict results to high-severity findings
$ nyx scan --severity HIGH

# Filter by severity expression (high and medium)
$ nyx scan --severity ">=MEDIUM"

# AST pattern matching only (fastest, no CFG/taint)
$ nyx scan --mode ast

# CFG + taint analysis only (skip AST pattern rules)
$ nyx scan --mode cfg

# CI gate: fail on medium+, SARIF output
$ nyx scan --format sarif --fail-on MEDIUM > results.sarif

# Suppress status messages (for CI/scripting)
$ nyx scan --quiet --format json

# Include test/vendor/benchmark paths at original severity
# (by default these are downgraded one tier)
$ nyx scan --keep-nonprod-severity
```

### Use in CI

Nyx ships a reusable GitHub Action. Pin to a tagged release; the action downloads the matching binary, runs `nyx scan`, and optionally fails the job on a severity threshold.

```yaml
- name: Scan with Nyx
  uses: elicpeter/nyx@v0.5.0
  with:
    format: sarif
    fail-on: MEDIUM
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: nyx-results.sarif
```

**Inputs** (all optional):

| Input | Default | Description |
|---|---|---|
| `path` | `.` | Directory to scan |
| `version` | `latest` | Release tag (e.g. `v0.5.0`) or `latest` |
| `format` | `sarif` | `sarif`, `json`, or `console` |
| `fail-on` | _(empty)_ | Exit non-zero if findings meet this severity (`HIGH`, `MEDIUM`, or `LOW`) |
| `args` | _(empty)_ | Additional CLI arguments (e.g. `--severity >=MEDIUM --profile ci`) |
| `token` | `${{ github.token }}` | GitHub token used for release download (avoids rate limits) |

**Outputs**:

| Output | Description |
|---|---|
| `finding-count` | Number of findings detected |
| `sarif-file` | Path to SARIF results file (empty when `format` is not `sarif`) |
| `exit-code` | Raw nyx exit code (`0` clean, `1` threshold breached) |
| `nyx-version` | Installed nyx version |

Linux and macOS runners are supported (x86_64 and ARM64).

### Index Management

```bash
# Create or rebuild an index
$ nyx index build [PATH] [--force]

# Display index metadata (size, modified date, etc.)
$ nyx index status [PATH]

# List all indexed projects (add -v for detailed view)
$ nyx list [-v]

# Remove a single project or purge all indexes
$ nyx clean <PROJECT_NAME>
$ nyx clean --all
```

### Configuration Management

```bash
# Print the effective merged configuration
$ nyx config show

# Print the config directory path
$ nyx config path

# Add a custom sanitizer rule (written to nyx.local)
$ nyx config add-rule --lang javascript --matcher escapeHtml --kind sanitizer --cap html_escape

# Add a terminator function
$ nyx config add-terminator --lang javascript --name process.exit
```

---

## Analysis Modes

Nyx supports four analysis modes, selectable via `--mode` or the `scanner.mode` config option:

| Mode | CLI flag | What runs |
|---|---|---|
| **Full** (default) | `--mode full` | AST pattern matching + CFG construction + taint analysis |
| **AST-only** | `--mode ast` | AST pattern matching only; skips CFG and taint entirely |
| **CFG** | `--mode cfg` | CFG + taint analysis only; filters out AST pattern findings |
| **Taint** | `--mode taint` | Alias for `cfg` (CFG + taint analysis) |

### What the CFG + taint engine detects

| Finding | Rule ID | Description |
|---|---|---|
| Tainted data flow | `taint-*` | Untrusted data (env vars, user input, file reads) flowing to dangerous sinks (shell exec, SQL, file write) without matching sanitization |
| Unguarded sink | `cfg-unguarded-sink` | Sink calls not dominated by a guard or sanitizer on the control-flow path |
| Auth gap | `cfg-auth-gap` | Web handler functions that reach privileged sinks without an auth check |
| Unreachable security code | `cfg-unreachable-*` | Sanitizers, guards, or sinks in dead code branches |
| Error fallthrough | `cfg-error-fallthrough` | Error-handling branches that don't terminate, allowing execution to fall through to dangerous operations |
| Resource leak | `cfg-resource-leak` | Resources acquired but not released on all exit paths (malloc/free, fopen/fclose, Lock/Unlock) |
| Use-after-close | `state-use-after-close` | Variable read/written after its resource handle was closed |
| Double-close | `state-double-close` | Resource handle closed more than once |
| Must-leak | `state-resource-leak` | Resource acquired but never closed on any exit path |
| May-leak | `state-resource-leak-possible` | Resource open on some but not all exit paths |
| Unauthenticated access | `state-unauthed-access` | Sensitive sink reached without a preceding auth/admin check |

### Attack Surface Ranking

Every finding is assigned a deterministic **attack-surface score** that estimates exploitability using only information already in memory. No extra source passes are needed. Findings are sorted by descending score before truncation, so `max_results` always keeps the most important results.

The score is the sum of five components:

| Component | Weight | Description |
|---|---|---|
| **Severity base** | High = 60, Medium = 30, Low = 10 | Primary ordering signal. Severity reflects source-kind exploitability and rule confidence. |
| **Analysis kind** | taint = +10, state = +8, cfg = +3/+5, ast = 0 | Taint-confirmed flows are the strongest signal; AST-only pattern matches rank lowest at equal severity. CFG findings with evidence get +5, without get +3. |
| **Evidence strength** | +1 per evidence item (max 4), +2–6 for source kind | More evidence increases confidence. Source-kind priority: user input (+6) > env/config (+5) > unknown (+4) > file system (+3) > database (+2). |
| **State rule type** | +1 to +6 | Use-after-close and unauthenticated access (+6) rank above double-close (+3), must-leak (+2), and may-leak (+1). |
| **Path validation** | −5 | Findings on paths guarded by a validation predicate receive a small exploitability penalty because the guard may prevent triggering. |

**Score ranges** (approximate):

| Finding type | Score |
|---|---|
| High taint + user input | ~78 |
| High state (use-after-close) | ~74 |
| High CFG structural | ~63 |
| Medium taint + env source | ~47 |
| Medium state (resource leak) | ~40 |
| Low AST-only pattern | ~10 |

Tie-breaking is deterministic: severity → rule ID → file path → line → column → message hash. The same set of findings always produces the same ordering regardless of parallelism or input order.

Ranking is enabled by default. Disable it with `--no-rank` or `output.attack_surface_ranking = false` in config. When disabled, `rank_score` is omitted from JSON/SARIF output.

---

## Supported Languages

All 10 languages parse via tree-sitter and run through the full CFG + taint + AST pipeline, but **rule depth, cross-file confidence, and idiom coverage are not uniform**. The tiers below are grounded in benchmark F1 (see [Detection Accuracy](#detection-accuracy)) and the per-language weak-spot lists the maintainers keep open in [`tests/benchmark/RESULTS.md`](tests/benchmark/RESULTS.md). See [Language Maturity](docs/language-maturity.md) for per-dimension detail, known blind spots, and how to contribute.

| Tier | Languages | Rule-level F1 (latest) | Notes |
|---|---|---|---|
| **Stable** | Python, JavaScript, TypeScript | 96.8%–100.0% | Deep rule sets (20+ sinks, 7+ sanitizers), argument-role-aware gated sinks, framework detection (Flask/Django, Express/Koa/Fastify), majority of advanced-analysis (SSA / context-sensitive / symbolic-execution) fixtures. Safe to use as a CI gate. |
| **Beta** | Go, Java, Ruby, PHP | 92.9%–97.0% | Solid mid-depth rule sets covering 7–8 vulnerability classes each. No gated sinks yet; some idioms (string interpolation, variable-typed method receivers, framework context) are incomplete. Usable in CI with light FP triage. |
| **Preview** | C, C++ | 88.9%–92.3% | Pattern-only coverage. Pointer aliasing, function pointers, array-element taint, and STL container flows are not modeled. Suitable for finding obvious unsafe API uses; do not use as a sole SAST gate. Pair with clang-tidy / Clang Static Analyzer / Infer. |
| **Experimental** | Rust | 86.4% | Full source coverage but several FPs persist on adversarial safe cases pending engine work (match-arm guards, structural sinks with type facts). Treat findings as a starting point for review rather than authoritative. |

Resource-leak detection is available for every tier where language-specific acquire/release pairs are defined.

### Scope caveats for narrower-tier languages

- **C and C++** currently cover command injection, buffer overflow, format
  string, file I/O, SSRF, and basic path traversal only. SQL injection, code
  execution, and deserialization rules are not yet implemented. For
  comprehensive C/C++ coverage, pair Nyx with clang-tidy, the Clang Static
  Analyzer, or Infer.
- **PHP** support is production-ready for plain PHP. Laravel-specific ORM,
  validation, and middleware patterns are not comprehensively modeled.
  Laravel codebases should pair Nyx with Psalm or PHPStan.

---

## Configuration Overview

Nyx merges a default configuration file (`nyx.conf`) with user overrides (`nyx.local`). Both live in the platform-specific configuration directory shown below.

| Platform | Directory |
|---|---|
| Linux | `~/.config/nyx/` |
| macOS | `~/Library/Application Support/nyx/` |
| Windows | `%APPDATA%\elicpeter\nyx\config\` |

Minimal example (`nyx.local`):

```toml
[scanner]
mode                = "full"       # full | ast | taint
min_severity        = "Medium"
follow_symlinks     = true
excluded_extensions = ["mp3", "mp4"]

[output]
default_format = "json"
max_results    = 200
quiet          = true       # suppress status messages

[performance]
worker_threads     = 8  # 0 = auto-detect
batch_size         = 200
channel_multiplier = 2
```

### Custom Analysis Rules

You can define custom sources, sanitizers, sinks, terminators, and event handlers per language. These take priority over built-in rules, letting you teach Nyx about project-specific functions.

```toml
[analysis.languages.javascript]
terminators = ["process.exit"]
event_handlers = ["addEventListener"]

[[analysis.languages.javascript.rules]]
matchers = ["escapeHtml"]
kind = "sanitizer"          # "source" | "sanitizer" | "sink"
cap = "html_escape"         # "env_var" | "html_escape" | "shell_escape" |
                            # "url_encode" | "json_parse" | "file_io" | "all"

[[analysis.languages.javascript.rules]]
matchers = ["dangerouslySetHTML"]
kind = "sink"
cap = "html_escape"
```

Rules can also be added interactively via `nyx config add-rule` and `nyx config add-terminator`.

A fully documented `nyx.conf` is generated automatically on first run.

---

## Architecture in Brief

Nyx uses a **two-pass architecture** to enable cross-file analysis without sacrificing parallelism:

1. **File enumeration.** A parallel walker (Rayon + `ignore` crate) applies gitignore rules, size limits, and user exclusions.
2. **Pass 1: Summary extraction.** Each file is parsed via tree-sitter, an intra-procedural CFG is built (petgraph), and a `FuncSummary` is exported per function capturing source/sanitizer/sink capabilities (bitflags), taint propagation behavior, and callee lists. Summaries are persisted to SQLite.
3. **Summary merge.** All per-file summaries are merged into a `GlobalSummaries` map with conservative conflict resolution (union caps, OR booleans).
4. **Pass 2: Analysis.** Files are re-parsed and analyzed with the full cross-file context: a monotone forward dataflow engine resolves callees against local and global summaries and propagates taint through a bounded lattice with guaranteed convergence. CFG analysis checks for auth gaps, unguarded sinks, resource leaks, and more.
5. **Reporting.** Findings are scored, ranked, deduplicated, and emitted to the console or serialized as JSON.

With indexing enabled, Pass 1 skips files whose blake3 content hash is unchanged, and cached findings are served directly for AST-only results.

---

## What's New in 0.5.0

- **SSA-based taint engine.** Taint analysis now runs over a pruned SSA IR (Cytron phi insertion over petgraph dominance frontiers) for all 10 languages. Value-keyed lattice with per-predecessor phi merging, induction-variable pruning, and targeted validation predicates. Replaces the legacy AST-level taint engine entirely.
- **Cross-file SCC fixed-point with parameter-granularity points-to summaries.** Pass 2 processes call-graph SCCs in topological order and iterates within each SCC until taint summaries converge, so mutually recursive functions get accurate summaries. `SsaFuncSummary` carries a parameter-granularity `PointsToSummary` (container stores + return aliases) that is applied at call sites so heap-backed taint propagates across file boundaries.
- **Demand-driven backwards taint (opt-in).** Enable with `--backwards-analysis` or `NYX_BACKWARDS=1`. Walks the SSA backwards from candidate sinks to uncover flows the forward solver gave up on; adds cutoff notes to findings instead of silently losing precision.
- **Symbolic execution with SMT (opt-in).** Interprocedural symbolic executor walks callee bodies as nested frames, models six string operations (substr/replace/trim/case/len), and can escalate to Z3 for cross-variable constraints when built with `--features smt`.
- **Local web UI (`nyx serve`).** React + Vite frontend over an Axum server with loopback-only bind, host-header and CSRF enforcement, triage state persisted to `.nyx/triage.json`, and flow-path visualisation for findings.

---

## Status

Nyx is under active development. APIs, detector behavior, and configuration options may change between releases.

---

## Scope

Nyx is a static analysis engine focused on:

- Multi-language taint analysis (source → sanitizer → sink)
- Control-flow-aware structural detectors
- Security-oriented AST pattern matching
- Optional cross-language interop edges (requires explicit configuration)
- Resource lifecycle and auth state analysis (enabled by default; disable with `scanner.enable_state_analysis = false`)

Nyx is not intended to replace full commercial SAST tools. Some analyses are heuristic-based and results may require manual review.

---

## Limitations

- State analysis (`use-after-close`, `double-close`, `resource-leak`, `unauthenticated-access`) is enabled by default; disable with `scanner.enable_state_analysis = false`
- Cross-language interop edges must be configured explicitly
- Taint analysis is intra-procedural with cross-file function summaries; it does not perform full inter-procedural analysis
- Some detectors rely on heuristic matching (see [AST Patterns](docs/detectors/patterns.md) for false positive/negative details)
- Not all language features are modeled (e.g., macros, dynamic dispatch, aliased imports)
- Results may contain false positives or false negatives

---

## Performance

Benchmarks can be run locally with `cargo bench`. Results depend on hardware, repository size, and analysis mode.

AST-only mode (`--mode ast`) is the fastest and skips CFG construction and taint analysis. Full mode (`--mode full`) includes CFG and taint analysis and is slower. State analysis adds additional overhead when enabled.

Incremental indexing significantly reduces scan time for subsequent runs on unchanged files.

### Detection Accuracy

Measured on our 273-case benchmark corpus at
[`tests/benchmark/ground_truth.json`](tests/benchmark/ground_truth.json) across
10 languages (C, C++, Go, Java, JavaScript, PHP, Python, Ruby, Rust,
TypeScript) covering 15 vulnerability classes. These numbers are specific to
that corpus and are not a general-purpose accuracy claim — real-world results
depend on the language mix, rule coverage for your stack, and the
vulnerability classes that matter to you. Full historical results live in
[`tests/benchmark/RESULTS.md`](tests/benchmark/RESULTS.md). The corpus also
includes 3 real historical CVEs across 3 languages (Python, JavaScript,
TypeScript); per-CVE results are tracked in
[`tests/benchmark/RESULTS.md`](tests/benchmark/RESULTS.md) under "Real-CVE
Corpus."

Current rule-level baseline on the 273-case corpus:

| Metric | Score |
|---|---|
| Precision | 94.2% |
| Recall | 99.4% |
| F1 | 96.7% |

**What these numbers mean.** The bulk of the benchmark is 267 synthetic mini-fixtures (20–120 LOC each) curated for known-good and known-bad cases, supplemented by 6 real-CVE cases (vulnerable + patched pairs for each CVE). F1 numbers are reported per language in the Language Maturity matrix; the aggregate hides per-tier variance. The benchmark uses `allowed_alternative_rule_ids` to credit findings under any of several semantically equivalent rule IDs, which softens precision compared to a strict-rule-only scoring. Real-world repositories with framework-specific idioms (Django middleware, Spring DI, async runtimes, ORMs) will produce different numbers; treat 96.7% as a regression-protection floor on this corpus, not a general accuracy claim.

The benchmark is wired as a CI regression gate. Every pull request runs `tests/benchmark_test.rs::benchmark_evaluation` in release mode under the `benchmark-gate` job and fails if rule-level Precision, Recall, or F1 drops below the thresholds encoded in the test:

| Metric | Floor | Current baseline |
|---|---|---|
| Precision | ≥ 86.1% | 94.2% |
| Recall | ≥ 94.4% | 99.4% |
| F1 | ≥ 90.1% | 96.7% |

Floors sit ~8 pp below the measured 273-case baseline. Tighten them when an improvement lands; never relax them to accommodate a regression.

The same job also runs `tests/perf_tests.rs` with `NYX_CI_BENCH=1` and enforces per-fixture wall-clock budgets (see each fixture's `expectations.json`).

Recall is strong across all classes. Precision is limited by false positives on safe code where sanitization, reassignment, or type-checking patterns are not yet recognized by the taint engine. Improving precision is an active focus area.

---

## Roadmap

### Deep Static Engine (Complete)

| Feature | Status | Description |
|---|--------|---|
| Interprocedural call graph | Done | Precise symbol resolution via `FuncKey`, language-scoped namespaces, cross-module linking. Full call graph with SCC and topological analysis. |
| Predicate-aware analysis | Done | Per-predecessor phi merging with classified condition predicates. Validation-only-in-one-branch detection via PredStates. Symbolic / SMT path-sensitive variants are opt-in. |
| Dataflow & state modeling | Done | Resource state machines (init -> use -> close), auth state transitions, privilege level tracking. Generic `Transfer` trait over bounded lattices with guaranteed convergence. |
| Monotone taint analysis | Done | Forward worklist dataflow analysis over a finite `TaintState` lattice. Multi-origin tracking, dual validated-must/may sets, JS/TS two-level solve. Termination guaranteed by lattice finiteness. |
| Attack surface ranking | Done | Deterministic post-analysis scoring of findings by severity, analysis kind, evidence strength, source-kind exploitability, and validation state. Findings sorted by score before truncation so `max_results` keeps the most important results. |
| Inline suppressions | Done | `nyx:ignore` and `nyx:ignore-next-line` comments with wildcard matching, all 10 languages supported. `--show-suppressed` flag for visibility. |
| Low-noise prioritization | Done | Category filtering, rollup grouping for high-frequency rules, configurable LOW budgets. Quality-category findings hidden by default. |
| Pattern-level confidence | Done | Explicit High/Medium/Low confidence on every AST pattern. Confidence flows into output alongside severity and rank score. |
| AST pattern overhaul | Done | 30+ new patterns across all languages, 11 broken query fixes, namespaced IDs, severity recalibration. |

### Dynamic Capability (Planned)

| Feature | Description |
|---|---|
| Controlled dynamic execution | Local sandbox: identify entry points, spin up test harnesses, inject payloads, detect runtime crashes and command execution. Deterministic automated exploit validation: static finds `exec(user_input)`, dynamic confirms it with `; id`. |
| Fuzzing integration | libFuzzer (C/C++), cargo-fuzz (Rust), go-fuzz, HTTP fuzzing harness. Static engine identifies interesting functions, fuzzer targets only those. |

### Reasoning Layer (Planned)

| Feature | Description |
|---|---|
| Semantic similarity | Embeddings for finding similar vulnerability patterns across codebases. |
| LLM reasoning | AI-assisted detection of non-obvious logic bugs. |
| Exploit refinement | Automated loops to refine and validate exploit chains. |

### Other planned improvements

| Area | Details |
|---|---|
| Output formats | JUnit XML, HTML report generator |
| UX | Smart file-watch re-scan, richer artifact browsing, interactive trace inspection |
| Language coverage | Expanded taint rules per language |
| Rule updates | Remote rule feed with signature verification |
| UX | Smart file-watch re-scan |

Community feedback shapes priorities. [Open an issue](https://github.com/elicpeter/nyx/issues) to discuss proposed changes.

---

## Documentation

Full documentation is available in the [`docs/`](docs/index.md) directory:

- [Installation](docs/installation.md): cargo, binaries, CI tips
- [Quick Start](docs/quickstart.md): first scan in 60 seconds
- [CLI Reference](docs/cli.md): every flag and subcommand
- [Configuration](docs/configuration.md): config file schema, custom rules
- [Output Formats](docs/output.md): console, JSON, SARIF; exit codes
- [Detector Overview](docs/detectors.md): how the four detector families work
  - [Taint Analysis](docs/detectors/taint.md): cross-file source-to-sink dataflow
  - [CFG Structural](docs/detectors/cfg.md): auth gaps, unguarded sinks, resource leaks
  - [State Model](docs/detectors/state.md): resource lifecycle, authentication state
  - [AST Patterns](docs/detectors/patterns.md): tree-sitter structural matching
- [Rule Reference](docs/rules/index.md): per-language rule listings with examples
- [Language Maturity](docs/language-maturity.md): honest per-language tier classification, known blind spots, and weak-spot list

---

## Contributing

Pull requests are welcome. To contribute:

1. Fork the repository and create a feature branch.
2. Adhere to `rustfmt` and ensure `cargo clippy --all -- -D warnings` passes.
3. Add unit and/or integration tests where applicable (`cargo test` should remain green).
4. Submit a concise, well-documented pull request.

Please open an issue for any crash, panic, or suspicious result. Attach the minimal code snippet and mention the Nyx version.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for full guidelines, including how to add new rules and support new languages.

---

## License

Nyx is licensed under the **GNU General Public License v3.0 or later (GPL-3.0-or-later)**.

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

The optional `smt` feature bundles the Z3 SMT solver (MIT-licensed). Distributors of binaries built with `--features smt` should include Z3's license in their attribution.

See [LICENSE](./LICENSE) for full details. Third-party dependencies and their licenses are listed in [THIRDPARTY-LICENSES.html](./THIRDPARTY-LICENSES.html).
