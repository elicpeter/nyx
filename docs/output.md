# Output Formats

Nyx supports three output formats, selected with `--format` or `output.default_format` in config.

## Console (default)

Human-readable, color-coded output to stdout. Status messages go to stderr.

```
[HIGH]   taint-unsanitised-flow (source 5:11)  src/handler.rs:12:5
         Source: env::var("CMD") at 5:11
         Sink: Command::new("sh").arg("-c")
         Score: 76

[MEDIUM] cfg-unguarded-sink                    src/handler.rs:12:5
         Score: 35

[LOW]    rs.quality.unwrap                     src/lib.rs:88:5
         Score: 10
```

### Severity indicators

| Tag | Color | Meaning |
|-----|-------|---------|
| `[HIGH]` | Red, bold | Critical — likely exploitable |
| `[MEDIUM]` | Orange, bold | Important — may be exploitable |
| `[LOW]` | Dim green | Informational — code quality or weak signal |

### Evidence fields

Taint and state findings include structured evidence:

| Label | Meaning |
|-------|---------|
| **Source** | Where tainted data originated (function name + location) |
| **Sink** | Where the dangerous operation happens |
| **Path guard** | Type of validation predicate protecting the path |

### Score

When attack-surface ranking is enabled (default), each finding shows a `Score` value. Higher scores indicate greater exploitability. See [Detector Overview](detectors.md) for the scoring formula.

---

## JSON

Machine-readable JSON array. Each finding is an object:

```json
[
  {
    "path": "src/handler.rs",
    "line": 12,
    "col": 5,
    "severity": "High",
    "id": "taint-unsanitised-flow (source 5:11)",
    "path_validated": false,
    "evidence": [
      ["Source", "env::var(\"CMD\") at 5:11"],
      ["Sink", "Command::new(\"sh\").arg(\"-c\")"]
    ],
    "rank_score": 76.0,
    "rank_reason": [
      ["severity_base", "60"],
      ["analysis_kind", "10"],
      ["source_kind", "5"],
      ["evidence_count", "1"]
    ]
  }
]
```

### Field descriptions

| Field | Type | Always present | Description |
|-------|------|----------------|-------------|
| `path` | string | yes | File path relative to scan root |
| `line` | int | yes | 1-indexed line number |
| `col` | int | yes | 1-indexed column number |
| `severity` | string | yes | `"High"`, `"Medium"`, or `"Low"` |
| `id` | string | yes | Rule ID |
| `path_validated` | bool | no | True if guarded by validation predicate |
| `guard_kind` | string | no | Predicate type (e.g. `"NullCheck"`, `"ValidationCall"`) |
| `message` | string | no | Human-readable context (state analysis findings) |
| `evidence` | array | no | Array of `[label, value]` pairs |
| `rank_score` | float | no | Attack-surface score (omitted when ranking disabled) |
| `rank_reason` | array | no | Score breakdown (omitted when ranking disabled) |

Fields marked "no" are omitted when empty/null/false to keep output compact.

---

## SARIF (Static Analysis Results Interchange Format)

SARIF 2.1.0 JSON, suitable for GitHub Code Scanning and other SARIF-compatible tools.

```bash
nyx scan . --format sarif > results.sarif
```

The SARIF output includes:

- **Tool metadata** — Nyx name and version
- **Rules** — Rule ID, description, severity mapping
- **Results** — One result per finding with location, message, and properties
- **Artifacts** — File paths referenced by findings

### GitHub Code Scanning integration

```yaml
- name: Run Nyx
  run: nyx scan . --format sarif > results.sarif

- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| `0` | Scan completed successfully; no findings matched `--fail-on` threshold |
| `1` | `--fail-on` threshold breached (at least one finding meets or exceeds the specified severity) |
| Non-zero | Error (I/O, config, database, parse error) |

Without `--fail-on`, Nyx always exits `0` on a successful scan regardless of findings count.

---

## Severity Levels

| Level | Description | Typical rules |
|-------|-------------|---------------|
| **High** | Critical vulnerabilities — likely exploitable | Command injection, unsafe deserialization, banned C functions, taint-confirmed flows with user input sources |
| **Medium** | Important issues — may be exploitable with additional context | SQL concatenation, XSS sinks, reflection, unguarded sinks, resource leaks |
| **Low** | Informational — code quality or weak signals | Weak crypto algorithms, insecure randomness, `unwrap()`/`panic!()`, type-safety escapes |

### Non-production severity downgrade

By default, findings in paths matching common non-production patterns (`tests/`, `test/`, `vendor/`, `build/`, `examples/`, `benchmarks/`) are downgraded by one tier:

- High → Medium
- Medium → Low
- Low → Low (unchanged)

Use `--keep-nonprod-severity` to disable this behavior.

---

## Rule ID Format

| Prefix | Detector | Example |
|--------|----------|---------|
| `taint-*` | Taint analysis | `taint-unsanitised-flow (source 5:11)` |
| `cfg-*` | CFG structural | `cfg-unguarded-sink`, `cfg-auth-gap` |
| `state-*` | State model | `state-use-after-close`, `state-resource-leak` |
| `<lang>.*.*` | AST patterns | `rs.memory.transmute`, `js.code_exec.eval` |

See the [Rule Reference](rules/index.md) for a complete listing.
