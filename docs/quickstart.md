# Quick Start

## Your first scan

```bash
# Scan the current directory
nyx scan

# Scan a specific path
nyx scan ./my-project
```

Nyx automatically creates an SQLite index on first run. Subsequent scans skip unchanged files.

## Understanding the output

A typical console output looks like:

```
[HIGH]   taint-unsanitised-flow (source 5:11)  src/handler.rs:12:5
         Source: env::var("CMD") at 5:11
         Sink: Command::new("sh").arg("-c")
         Score: 76

[MEDIUM] cfg-unguarded-sink                    src/handler.rs:12:5
         Score: 35

[MEDIUM] rs.quality.unsafe_block               src/lib.rs:44:5
         Score: 30
```

Each finding shows:

| Field | Meaning |
|-------|---------|
| **Severity tag** | `[HIGH]`, `[MEDIUM]`, or `[LOW]` |
| **Rule ID** | Identifies the detector and specific rule |
| **Location** | `file:line:col` |
| **Evidence** | Source, Sink, and guard details (taint findings only) |
| **Score** | Attack-surface ranking score (higher = more exploitable) |

## Common workflows

### CI gate -- fail on high-severity findings

```bash
nyx scan . --fail-on high --quiet
# Exit code 1 if any HIGH finding exists, 0 otherwise
```

### Export for tooling

```bash
# JSON for scripting
nyx scan . --format json > findings.json

# SARIF for GitHub Code Scanning
nyx scan . --format sarif > results.sarif
```

### Fast structural scan (no dataflow)

```bash
nyx scan . --mode ast
```

AST-only mode runs tree-sitter pattern queries without building CFGs or running taint analysis. Much faster, but misses dataflow vulnerabilities.

### Filter by severity

```bash
# Only high-severity
nyx scan . --severity HIGH

# High and medium
nyx scan . --severity ">=MEDIUM"

# Specific set
nyx scan . --severity "HIGH,MEDIUM"
```

### Skip the index

```bash
nyx scan . --index off
```

Useful for one-off scans or when you don't want to write to disk.

### Scan without non-production noise

By default, findings in test/vendor/build paths are downgraded one severity tier. To keep original severity:

```bash
nyx scan . --keep-nonprod-severity
```

## Next steps

- [CLI Reference](cli.md) -- All flags and options
- [Configuration](configuration.md) -- Customize rules, exclusions, and behavior
- [Detector Overview](detectors.md) -- How the analysis engines work
- [Rule Reference](rules/index.md) -- Browse all rules by language
