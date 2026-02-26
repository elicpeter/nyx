<div align="center">
  <img src="assets/logo.png" alt="nyx logo" width="300"/>

**Fast, cross-language cli vulnerability scanner.**

[![crates.io](https://img.shields.io/crates/v/nyx-scanner.svg)](https://crates.io/crates/nyx-scanner)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange)](https://www.rust-lang.org)
[![CI](https://img.shields.io/github/actions/workflow/status/elicpeter/nyx/ci.yml?branch=master)](https://github.com/elicpeter/nyx/actions)
</div>

---

## What is Nyx?

**Nyx** is a lightweight, lightning-fast Rust-native command-line tool that detects security vulnerabilities across 10 programming languages. It combines [`tree-sitter`](https://tree-sitter.github.io/) parsing, intra-procedural control-flow graphs, and cross-file taint analysis with an optional SQLite-backed index to deliver deep, repeatable scans on projects of any size.

---

## Key Capabilities

| Capability | Description |
|---|---|
| Multi-language support | Rust, C, C++, Java, Go, PHP, Python, Ruby, TypeScript, JavaScript |
| AST-level pattern matching | Language-specific queries written against precise parse trees |
| Control-flow graph analysis | Auth gaps, unguarded sinks, unreachable security code, resource leaks, error fallthrough |
| Cross-file taint tracking | Monotone forward dataflow taint analysis from sources through sanitizers to sinks with function summaries |
| Cross-language interop | Taint flows across language boundaries via explicit interop edges |
| Two-pass architecture | Pass 1 extracts function summaries; Pass 2 runs taint with full cross-file context |
| Incremental indexing | SQLite database stores file hashes, summaries, and findings to skip unchanged files |
| Parallel execution | File walking and analysis run concurrently via Rayon; scales with available CPU cores |
| Configurable analysis rules | Define custom sources, sanitizers, sinks, terminators, and event handlers per language via TOML config or CLI |
| Configurable scan parameters | Exclude directories, set maximum file size, tune worker threads, limit output, and more |
| Multiple output formats | Console (default), JSON, and SARIF 2.1.0 for CI integration |
| Progress reporting | Real-time progress bars for file discovery and analysis passes |

---

## Why choose Nyx?

| Advantage | What it means for you |
|---|---|
| **Pure-Rust, single binary** | No JVM, Python, or server to install; drop the `nyx` executable into your `$PATH` and go. |
| **Massively parallel** | Uses Rayon and a thread-pool walker; scales to all CPU cores. Scanning the entire **rust-lang/rust** codebase (~53,000 files) on an M2 MacBook Pro takes **~1 s**. |
| **Deep analysis** | Real CFG construction and monotone dataflow taint analysis with guaranteed termination, not just regex matching. Cross-file function summaries, capability-based sanitizer tracking, and scored findings. |
| **Index-aware** | An optional SQLite index stores file hashes and findings; subsequent scans touch *only* changed files, slashing CI times. |
| **Offline & privacy-friendly** | Requires no login, cloud account, or telemetry. Perfect for air-gapped environments and strict compliance policies. |
| **Tree-sitter precision** | Parses real language grammars, not regexes, giving far fewer false positives than line-based scanners. |
| **Extensible** | Add new patterns with concise `tree-sitter` queries; no SaaS lock-in. |

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

3. Unzip the file and move the executable to a directory in your system PATH:
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

4. Verify the installation:
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

Every finding is assigned a deterministic **attack-surface score** that estimates exploitability using only information already in memory — no extra source passes are needed. Findings are sorted by descending score before truncation, so `max_results` always keeps the most important results.

The score is the sum of five components:

| Component | Weight | Description |
|---|---|---|
| **Severity base** | High = 60, Medium = 30, Low = 10 | Primary ordering signal. Severity reflects source-kind exploitability and rule confidence. |
| **Analysis kind** | taint = +10, state = +8, cfg = +3/+5, ast = 0 | Taint-confirmed flows are the strongest signal; AST-only pattern matches rank lowest at equal severity. CFG findings with evidence get +5, without get +3. |
| **Evidence strength** | +1 per evidence item (max 4), +2–6 for source kind | More evidence increases confidence. Source-kind priority: user input (+6) > env/config (+5) > unknown (+4) > file system (+3) > database (+2). |
| **State rule type** | +1 to +6 | Use-after-close and unauthenticated access (+6) rank above double-close (+3), must-leak (+2), and may-leak (+1). |
| **Path validation** | −5 | Findings on paths guarded by a validation predicate receive a small exploitability penalty — the guard may prevent triggering. |

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

All 10 languages have full AST pattern matching and CFG/taint analysis. Resource leak detection is available where language-specific acquire/release pairs are defined.

| Language | AST Patterns | CFG + Taint | Resource Leaks |
|---|---|---|---|
| Rust | Yes | Yes | Yes |
| C | Yes | Yes | Yes |
| C++ | Yes | Yes | Yes |
| Java | Yes | Yes | Yes |
| Go | Yes | Yes | Yes |
| PHP | Yes | Yes | Yes |
| Python | Yes | Yes | Yes |
| Ruby | Yes | Yes | Yes |
| TypeScript | Yes | Yes | Yes |
| JavaScript | Yes | Yes | Yes |

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

1. **File enumeration** -- A parallel walker (Rayon + `ignore` crate) applies gitignore rules, size limits, and user exclusions.
2. **Pass 1 -- Summary extraction** -- Each file is parsed via tree-sitter, an intra-procedural CFG is built (petgraph), and a `FuncSummary` is exported per function capturing source/sanitizer/sink capabilities (bitflags), taint propagation behavior, and callee lists. Summaries are persisted to SQLite.
3. **Summary merge** -- All per-file summaries are merged into a `GlobalSummaries` map with conservative conflict resolution (union caps, OR booleans).
4. **Pass 2 -- Analysis** -- Files are re-parsed and analyzed with the full cross-file context: a monotone forward dataflow engine resolves callees against local and global summaries and propagates taint through a bounded lattice with guaranteed convergence. CFG analysis checks for auth gaps, unguarded sinks, resource leaks, and more.
5. **Reporting** -- Findings are scored, ranked, deduplicated, and emitted to the console or serialized as JSON.

With indexing enabled, Pass 1 skips files whose blake3 content hash is unchanged, and cached findings are served directly for AST-only results.

---

## Roadmap

### Phase 1 -- Deep Static Engine (Complete)

| Feature | Status | Description |
|---|--------|---|
| Interprocedural call graph | Done | Precise symbol resolution via `FuncKey`, language-scoped namespaces, cross-module linking. Full call graph with SCC and topological analysis. |
| Path-sensitive analysis | Done | Track path predicates and conditional constraints. Detect infeasible paths and validation-only-in-one-branch patterns. Monotone predicate summaries with contradiction pruning. |
| Dataflow & state modeling | Done | Resource state machines (init -> use -> close), auth state transitions, privilege level tracking. Generic `Transfer` trait over bounded lattices with guaranteed convergence. |
| Monotone taint analysis | Done | Replaced BFS taint engine with a forward worklist dataflow analysis over a finite `TaintState` lattice. Multi-origin tracking, dual validated-must/may sets, JS/TS two-level solve. Guaranteed termination via lattice finiteness. |
| Attack surface ranking | Done | Deterministic post-analysis scoring of findings by severity, analysis kind, evidence strength, source-kind exploitability, and validation state. Findings sorted by score before truncation so `max_results` keeps the most important results. |
| Inline suppressions | Done | `nyx:ignore` and `nyx:ignore-next-line` comments with wildcard matching, all 10 languages supported. `--show-suppressed` flag for visibility. |
| Low-noise prioritization | Done | Category filtering, rollup grouping for high-frequency rules, configurable LOW budgets. Quality-category findings hidden by default. |
| Pattern-level confidence | Done | Explicit High/Medium/Low confidence on every AST pattern. Confidence flows into output alongside severity and rank score. |
| AST pattern overhaul | Done | 30+ new patterns across all languages, 11 broken query fixes, namespaced IDs, severity recalibration. |

### Phase 2 -- Dynamic Capability

| Feature | Description |
|---|---|
| Controlled dynamic execution | Local sandbox: identify entry points, spin up test harnesses, inject payloads, detect runtime crashes and command execution. Deterministic automated exploit validation -- static finds `exec(user_input)`, dynamic confirms it with `; id`. |
| Fuzzing integration | libFuzzer (C/C++), cargo-fuzz (Rust), go-fuzz, HTTP fuzzing harness. Static engine identifies interesting functions, fuzzer targets only those. |

### Phase 3 -- Intelligent Reasoning Layer

| Feature | Description |
|---|---|
| Semantic similarity | Embeddings for finding similar vulnerability patterns across codebases. |
| LLM reasoning | AI-assisted detection of non-obvious logic bugs. |
| Exploit refinement | Automated loops to refine and validate exploit chains. |

### Other planned improvements

| Area | Details |
|---|---|
| Output formats | JUnit XML, HTML report generator |
| Language coverage | Expanded taint rules per language |
| Rule updates | Remote rule feed with signature verification |
| UX | Smart file-watch re-scan |

Community feedback shapes priorities -- please [open an issue](https://github.com/elicpeter/nyx/issues) to discuss proposed changes.

---

## Documentation

Full documentation is available in the [`docs/`](docs/index.md) directory:

- [Installation](docs/installation.md) — cargo, binaries, CI tips
- [Quick Start](docs/quickstart.md) — Your first scan in 60 seconds
- [CLI Reference](docs/cli.md) — Every flag and subcommand
- [Configuration](docs/configuration.md) — Config file schema, custom rules
- [Output Formats](docs/output.md) — Console, JSON, SARIF; exit codes
- [Detector Overview](docs/detectors.md) — How the four detector families work
  - [Taint Analysis](docs/detectors/taint.md) — Cross-file source-to-sink dataflow
  - [CFG Structural](docs/detectors/cfg.md) — Auth gaps, unguarded sinks, resource leaks
  - [State Model](docs/detectors/state.md) — Resource lifecycle, authentication state
  - [AST Patterns](docs/detectors/patterns.md) — Tree-sitter structural matching
- [Rule Reference](docs/rules/index.md) — Per-language rule listings with examples

---

## Contributing

Pull requests are welcome. To contribute:

1. Fork the repository and create a feature branch.
2. Adhere to `rustfmt` and ensure `cargo clippy --all -- -D warnings` passes.
3. Add unit and/or integration tests where applicable (`cargo test` should remain green).
4. Submit a concise, well-documented pull request.

Please open an issue for any crash, panic, or suspicious result -- attach the minimal code snippet and mention the Nyx version.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for full guidelines, including how to add new rules and support new languages.

---

## License

Nyx is licensed under the **GNU General Public License v3.0 (GPL-3.0)**.

This ensures that all modified versions of the scanner remain free and open-source, protecting the integrity and transparency of security tools.

See [LICENSE](./LICENSE) for full details.
