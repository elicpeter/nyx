<div align="center">
  <img src="assets/logo.png" alt="nyx logo" width="300"/>

**Fast, cross-language cli vulnerability scanner.**

[![crates.io](https://img.shields.io/crates/v/nyx-scanner.svg)](https://crates.io/crates/nyx-scanner)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)
[![Rust 1.85+](https://img.shields.io/badge/rust-1.85%2B-orange)](https://www.rust-lang.org)
[![CI](https://img.shields.io/github/actions/workflow/status/ecpeter23/nyx/ci.yml?branch=master)](https://github.com/ecpeter23/nyx/actions)
</div>

---

## What is Nyx?

**Nyx** is a lightweight lightning-fast Rust‑native command‑line tool that detects potentially dangerous code patterns across several programming languages. It combines the accuracy of [`tree‑sitter`](https://tree-sitter.github.io/) parsing with a curated rule set and an optional SQLite‑backed index to deliver fast, repeatable scans on projects of any size.

>[!IMPORTANT]
> **Project status – Alpha**   
> Nyx is under active development. The public interface, rule set, and output formats may change without notice while we stabilise the core. The new CFG + taint engine is experimental and Rust-only for now – please report any crashes or false-positives. Pin exact versions in production environments

---

## Key Capabilities

| Capability                   | Description                                                                               |
|------------------------------|-------------------------------------------------------------------------------------------|
| Multi‑language support       | Rust, C, C++, Java, Go, PHP, Python, Ruby, TypeScript, JavaScript                         |
| AST‑level pattern matching   | Language‑specific queries written against precise parse trees                             |
| Incremental indexing         | SQLite database stores file hashes and previous findings to skip unchanged files          |
| Parallel execution           | File walking and rule execution run concurrently; defaults scale with available CPU cores |
| Configurable scan parameters | Exclude directories, set maximum file size, tune worker threads, limit output, and more   |
| Multiple output formats      | Human‑readable console view (default) and machine‑readable JSON / CSV / SARIF (roadmap)   |

---

## Why choose Nyx?

| Advantage                      | What it means for you                                                                                                                                                        |
|--------------------------------|------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| **Pure-Rust, single binary**   | No JVM, Python, or server to install; drop the `nyx` executable into your `$PATH` and go.                                                                                    |
| **Massively parallel**         | Uses Rayon and a thread-pool walker; scales to all CPU cores. Example: scanning the entire **rust-lang/rust** codebase (~53,000 files) on an M2 MacBook Pro takes **≈ 1 s**. |
| **Index-aware**                | An optional SQLite index stores file hashes and findings, subsequent scans touch *only* changed files, slashing CI times.                                                    |
| **Offline & privacy-friendly** | Requires no login, cloud account, or telemetry. Perfect for air-gapped environments and strict compliance policies.                                                          |
| **Tree-sitter precision**      | Parses real language grammars, not regexes, giving far fewer false positives than line-based scanners.                                                                       |
| **Extensible**                 | Add new patterns with concise `tree-sitter` queries; no SaaS lock-in.                                                                                                        |

---

## Installation

### Install crate
```bash
$ cargo install nyx-scanner
```

### Install Github release
1. Navigate to the [Releases](https://github.com/ecpeter23/nyx/releases) page of the repository.
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
$ git clone https://github.com/ecpeter23/nyx.git
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

# Perform an ad‑hoc scan without touching the index
$ nyx scan --no-index

# Restrict results to high‑severity findings
$ nyx scan --high-only
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

---

## Configuration Overview

Nyx merges a default configuration file (`nyx.conf`) with user overrides (`nyx.local`). Both live in the platform‑specific configuration directory shown below.

| Platform      | Directory                                          |
|---------------|----------------------------------------------------|
| Linux         | `~/.config/nyx/`                                   |
| macOS         | `~/Library/Application Support/dev.ecpeter23.nyx/` |
| Windows       | `%APPDATA%\ecpeter23\nyx\config\`                  |

Minimal example (`nyx.local`):

```toml
[scanner]
min_severity        = "Medium"
follow_symlinks     = true
excluded_extensions = ["mp3", "mp4"]

[output]
default_format = "json"
max_results    = 200

[performance]
worker_threads     = 8  # 0 = auto‑detect
batch_size         = 200
channel_multiplier = 2
```

A fully documented `nyx.conf` is generated automatically on first run.

---

## Architecture in Brief

1. **File enumeration** – A highly parallel walker applies ignore rules, size limits, and user exclusions.
2. **Parsing** – Supported files are parsed into ASTs via the appropriate `tree‑sitter` grammar.
3. **Rule execution** – Each language ships with a dedicated rule set expressed as `tree‑sitter` queries. Matches are classified into three severity levels (`High`, `Medium`, `Low`).
4. **Indexing (optional)** – File digests and findings are stored in SQLite. Later scans skip files whose content and modification time are unchanged.
5. **Reporting** – Results are grouped by file and emitted to the console or serialized in the requested format.

---

## Roadmap

| Area                  | Planned Improvements                                                                                  |
|-----------------------|-------------------------------------------------------------------------------------------------------|
| More language support | Plans to create rule sets for over 100 languages for maximum coverage                                 |
| Control‑flow analysis | Inter‑procedural function summaries. Cap label propagation & bit‑flag checks. Loop/branch sensitivity |
| Taint tracking        | Intra‑ / inter‑procedural tracing of untrusted data from sources to sinks                             |
| Output formats        | Full SARIF 2.1.0, JUnit XML, HTML report generator                                                    |
| Rule updates          | Remote rule feed with signature verification                                                          |
| Performance & UX      | Incremental CFG cache, progress‑bar UX, smart file‑watch re‑scan                                      |

Community feedback will help shape priorities; please open an issue to discuss proposed changes.

---

## Experimental Features & Feedback

The new Rust intra‑procedural CFG + taint engine is not enabled.

Expect rough edges: slightly slower scans, occasional false positives, limited language coverage.

Please open an issue for every crash, panic, or suspicious result – attach the minimal code snippet and mention the Nyx version.

---

## Contributing

Pull requests are welcome. To contribute:

1. Fork the repository and create a feature branch.
2. Adhere to `rustfmt` and ensure `cargo clippy --all -- -D warnings` passes.
3. Add unit and/or integration tests where applicable (`cargo test` should remain green).
4. Submit a concise, well‑documented pull request.

See `CONTRIBUTING.md` for full guidelines.

---

## License

Nyx is licensed under the **GNU General Public License v3.0 (GPL‑3.0)**.

This ensures that all modified versions of the scanner remain free and open-source, protecting the integrity and transparency of security tools.

See [LICENSE](./LICENSE) for full details.
