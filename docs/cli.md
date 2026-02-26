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
| `--quiet` | off | Suppress status messages (stderr); stdout stays clean |
| `--no-rank` | off | Disable attack-surface ranking |

### Filtering

| Flag | Default | Description |
|------|---------|-------------|
| `--severity <EXPR>` | *(none)* | Filter findings by severity |
| `--min-score <N>` | *(none)* | Drop findings with rank score below N |
| `--fail-on <SEV>` | *(none)* | Exit code 1 if any finding >= this severity |
| `--show-suppressed` | off | Show inline-suppressed findings (dimmed, tagged `[SUPPRESSED]`) |
| `--keep-nonprod-severity` | off | Don't downgrade severity for test/vendor paths |

**Severity expression formats**:

```bash
--severity HIGH              # Only high
--severity "HIGH,MEDIUM"     # High or medium
--severity ">=MEDIUM"        # Medium and above (high + medium)
--severity ">= low"         # All severities (case-insensitive)
```

**Deprecated aliases**: `--high-only` (use `--severity HIGH`), `--include-nonprod` (use `--keep-nonprod-severity`).

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
