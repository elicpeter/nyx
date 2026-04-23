# CLI Reference

## Global

```
nyx [COMMAND]
nyx --version
nyx --help
```

---

## `nyx scan`

Run a security scan on a directory.

```
nyx scan [PATH] [OPTIONS]
```

**PATH** defaults to `.` (current directory).

### Analysis Mode

| Flag | Default | Description |
|------|---------|-------------|
| `--mode <MODE>` | `full` | Analysis mode: `full`, `ast`, `cfg`, or `taint` |

| Mode | What runs |
|------|-----------|
| `full` | AST patterns + CFG structural analysis + taint analysis |
| `ast` | AST patterns only (fastest, no CFG or taint) |
| `cfg` / `taint` | CFG + taint analysis only (no AST patterns) |

**Deprecated aliases**: `--ast-only` (use `--mode ast`), `--cfg-only` (use `--mode cfg`), `--all-targets` (use `--mode full`).

### Index Control

| Flag | Default | Description |
|------|---------|-------------|
| `--index <MODE>` | `auto` | Index behavior: `auto`, `off`, or `rebuild` |

| Index Mode | Behavior |
|------------|----------|
| `auto` | Use existing index if available; build if missing |
| `off` | Skip indexing, scan filesystem directly |
| `rebuild` | Force rebuild index before scanning |

**Deprecated aliases**: `--no-index` (use `--index off`), `--rebuild-index` (use `--index rebuild`).

### Output

| Flag | Default | Description |
|------|---------|-------------|
| `-f, --format <FMT>` | `console` | Output format: `console`, `json`, or `sarif` |
| `--quiet` | off | Suppress status messages (stderr), including the Preview-tier banner for C/C++ scans |
| `--no-rank` | off | Disable attack-surface ranking |

### Filtering

| Flag | Default | Description |
|------|---------|-------------|
| `--severity <EXPR>` | *(none)* | Filter findings by severity |
| `--min-score <N>` | *(none)* | Drop findings with rank score below N |
| `--min-confidence <LEVEL>` | *(none)* | Drop findings below this confidence level (`low`, `medium`, `high`) |
| `--require-converged` | off | Drop findings whose engine provenance notes indicate widening (over-report) or analysis bail. Keeps `under-report` findings (emitted flow is still real). Intended for strict CI gates. |
| `--fail-on <SEV>` | *(none)* | Exit code 1 if any finding >= this severity |
| `--show-suppressed` | off | Show inline-suppressed findings (dimmed, tagged `[SUPPRESSED]`) |
| `--keep-nonprod-severity` | off | Don't downgrade severity for test/vendor paths |
| `--all` | off | Disable category filtering, rollups, and LOW budgets -- show everything |
| `--include-quality` | off | Include Quality-category findings (hidden by default) |
| `--max-low <N>` | `20` | Maximum total LOW findings to show |
| `--max-low-per-file <N>` | `1` | Maximum LOW findings per file |
| `--max-low-per-rule <N>` | `10` | Maximum LOW findings per rule |
| `--rollup-examples <N>` | `5` | Number of example locations in rollup findings |
| `--show-instances <RULE>` | *(none)* | Expand all instances of a specific rule (bypass rollup) |

**Severity expression formats**:

```bash
--severity HIGH              # Only high
--severity "HIGH,MEDIUM"     # High or medium
--severity ">=MEDIUM"        # Medium and above (high + medium)
--severity ">= low"         # All severities (case-insensitive)
```

**Deprecated aliases**: `--high-only` (use `--severity HIGH`), `--include-nonprod` (use `--keep-nonprod-severity`).

### Analysis Engine Toggles

Override the corresponding `[analysis.engine]` values in `nyx.conf` for a single run.  All default **on**; pass the `--no-*` variant to disable.

| Pair | Config field | Effect when disabled |
|------|---|---|
| `--constraint-solving` / `--no-constraint-solving` | `constraint_solving` | Skip path-constraint solving; infeasible paths no longer pruned |
| `--abstract-interp` / `--no-abstract-interp` | `abstract_interpretation` | Skip interval / string / bit abstract domains |
| `--context-sensitive` / `--no-context-sensitive` | `context_sensitive` | Treat intra-file callees insensitively (summary-only) |
| `--symex` / `--no-symex` | `symex.enabled` | Skip the symex pipeline; no symbolic verdicts or witnesses |
| `--cross-file-symex` / `--no-cross-file-symex` | `symex.cross_file` | Skip extracting / consulting cross-file SSA bodies |
| `--symex-interproc` / `--no-symex-interproc` | `symex.interprocedural` | Cap symex frame stack at the entry function |
| `--smt` / `--no-smt` | `symex.smt` | Skip the SMT backend (still a no-op without the `smt` feature) |
| `--backwards-analysis` / `--no-backwards-analysis` | `backwards_analysis` | Demand-driven backwards taint walk from sinks (default **off**) |
| `--parse-timeout-ms <N>` | `parse_timeout_ms` | Per-file tree-sitter parse timeout (ms); `0` disables the cap |

See [configuration.md](configuration.md#analysisengine) for the full schema.

### Engine-Depth Profile

Individual engine toggles are fine-grained but hard to remember in combination.  The `--engine-profile` shortcut sets the whole stack in one shot, and individual flags are layered on top after the profile is applied.

| Flag | What it sets |
|------|--------------|
| `--engine-profile fast` | AST + CFG + basic taint only.  Disables abstract interpretation, context-sensitive inlining, symex (all variants), backwards analysis, and SMT. |
| `--engine-profile balanced` | AST + CFG + SSA taint + abstract interpretation + context-sensitive inlining.  Disables symex, backwards analysis, and SMT. (This is equivalent to the default posture without symex.) |
| `--engine-profile deep` | Everything in `balanced` plus symex (with cross-file and interprocedural) and backwards analysis.  Still disables SMT (requires the `smt` cargo feature). |

Individual flags override the profile.  For example, `--engine-profile fast --backwards-analysis` runs the fast stack but with backwards analysis on.

### Explain Effective Engine

`--explain-engine` prints the resolved engine configuration (profile + config + CLI overrides + env-var fallbacks) to stdout and exits without scanning.  Useful for sanity-checking a CI invocation.

```bash
nyx scan --engine-profile deep --no-smt --explain-engine
```

### Examples

```bash
# Basic scan
nyx scan

# Scan specific path, JSON output
nyx scan ./server --format json

# CI gate: fail on medium+, SARIF output
nyx scan . --format sarif --fail-on medium > results.sarif

# Fast AST-only scan, no index
nyx scan . --mode ast --index off

# High-severity only, quiet mode
nyx scan . --severity HIGH --quiet

# Only findings scoring 50 or above
nyx scan . --min-score 50

# Only medium+ confidence findings
nyx scan . --min-confidence medium

# Show everything (no filtering, no rollups)
nyx scan . --all

# Include quality findings but keep rollups and budgets
nyx scan . --include-quality

# See all unwrap findings expanded
nyx scan . --include-quality --show-instances rs.quality.unwrap

# Allow more LOW findings
nyx scan . --max-low 50 --max-low-per-file 5
```

---

## `nyx index`

Manage the SQLite file index.

### `nyx index build`

```
nyx index build [PATH] [--force]
```

Build or update the index for the given path (default: `.`).

| Flag | Description |
|------|-------------|
| `-f, --force` | Force full rebuild, ignoring cached file hashes |

### `nyx index status`

```
nyx index status [PATH]
```

Display index statistics (file count, size, last modified) for the given path.

---

## `nyx list`

```
nyx list [-v]
```

List all indexed projects.

| Flag | Description |
|------|-------------|
| `-v, --verbose` | Show detailed information per project |

---

## `nyx clean`

```
nyx clean [PROJECT] [--all]
```

Remove index data.

| Argument/Flag | Description |
|---------------|-------------|
| `PROJECT` | Project name or path to clean |
| `--all` | Clean all indexed projects |

---

## `nyx config`

Manage configuration.

### `nyx config show`

Print the effective merged configuration as TOML.

### `nyx config path`

Print the configuration directory path.

### `nyx config add-rule`

```
nyx config add-rule --lang <LANG> --matcher <MATCHER> --kind <KIND> --cap <CAP>
```

Add a custom taint rule. Written to `nyx.local`.

| Flag | Values |
|------|--------|
| `--lang` | `rust`, `javascript`, `typescript`, `python`, `go`, `java`, `c`, `cpp`, `php`, `ruby` |
| `--matcher` | Function or property name to match |
| `--kind` | `source`, `sanitizer`, `sink` |
| `--cap` | `env_var`, `html_escape`, `shell_escape`, `url_encode`, `json_parse`, `file_io`, `all` |

### `nyx config add-terminator`

```
nyx config add-terminator --lang <LANG> --name <NAME>
```

Add a terminator function (e.g. `process.exit`). Written to `nyx.local`.

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed; no findings matched `--fail-on` threshold (or no `--fail-on` specified) |
| `1` | Scan completed but at least one finding met or exceeded the `--fail-on` severity |
| Non-zero | Error during scan (I/O error, config parse error, database error, etc.) |

---

## Environment Variables

| Variable | Description |
|----------|-------------|
| `RUST_LOG` | Set tracing verbosity (e.g. `RUST_LOG=debug nyx scan .`) |
| `NO_COLOR` | Disable ANSI color output |
