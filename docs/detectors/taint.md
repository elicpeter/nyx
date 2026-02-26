# Taint Analysis

## Summary

Nyx's taint analysis tracks the flow of untrusted data from **sources** (where data enters the program) through **assignments and function calls** to **sinks** (where dangerous operations happen). If the data reaches a sink without passing through a **sanitizer** with matching capabilities, a finding is emitted.

The engine uses a monotone forward dataflow analysis over a finite lattice with guaranteed termination. Analysis is **intra-procedural with cross-file function summaries** — it does not follow calls into other functions but uses pre-computed summaries of their behavior.

## Rule ID

```
taint-unsanitised-flow (source <line>:<col>)
```

One rule ID covers all taint findings. The parenthetical identifies the specific source location.

## What It Detects

- Environment variables flowing to shell execution (`env::var` → `Command::new`)
- User input flowing to code evaluation (`req.body` → `eval()`)
- File contents flowing to SQL queries (`fs::read_to_string` → `db.execute()`)
- Request parameters flowing to HTML output (`req.query` → `innerHTML`)
- Any source-to-sink flow where the sink's required capability is not stripped by a sanitizer

## What It Cannot Detect

- **Inter-procedural flows without summaries**: If a function isn't summarized (e.g. from a third-party library without source), the taint engine cannot track data through it. It conservatively treats unknown callees as neither propagating nor sanitizing.
- **Flows through data structures**: Taint is tracked per-variable, not per-field. `obj.field = tainted; sink(obj.other_field)` may produce a false positive because taint attaches to `obj` as a whole.
- **Aliasing**: `let y = &x; sink(*y)` — the engine tracks `y` as a fresh variable, not an alias of `x`. This can cause false negatives.
- **Complex control flow**: The analysis is flow-sensitive (respects control flow within a function) but does not track taint through arbitrary loops with complex exit conditions.
- **Implicit flows**: Taint only follows explicit data flow, not information flow through branching (e.g. `if (secret) { x = 1 } else { x = 0 }` does not taint `x`).

## Common False Positives

| Scenario | Why it happens | Mitigation |
|----------|---------------|------------|
| Custom sanitizer not recognized | Nyx only knows built-in and configured sanitizers | Add a custom sanitizer rule in config |
| Taint through struct fields | Variable-level (not field-level) tracking | No current mitigation; field sensitivity is planned |
| Dead code paths | The engine is path-insensitive within a function (it considers all paths) | Contradiction pruning catches some cases; path-validated findings score lower |
| Library wrappers | A wrapper around a dangerous function may re-introduce taint that was sanitized by the wrapper | Summarize the wrapper function or add it as a sanitizer |

## Common False Negatives

| Scenario | Why it's missed |
|----------|----------------|
| Third-party library calls | No summary available; callee treated as opaque |
| Taint through global/static variables | Not tracked across function boundaries |
| Taint through closures/callbacks in some languages | Closure capture analysis is limited (JS/TS/Ruby/Go anonymous functions ARE analyzed) |
| Flows spanning more than two files | Summary approximation loses precision at depth |

## Confidence Signals

These signals in the output indicate higher-confidence findings:

| Signal | What it means |
|--------|--------------|
| **Evidence: Source + Sink** | Both endpoints identified with specific function names and locations |
| **Source kind = user input** | Source is directly controllable by an attacker (req.body, argv, etc.) |
| **path_validated = false** | No validation guard on the path — higher exploitability |
| **No guard_kind** | No dominating predicate check (null check, error check, etc.) |
| **High rank_score** | Multiple confidence signals combined |

Lower-confidence:

| Signal | What it means |
|--------|--------------|
| **path_validated = true** | A validation predicate guards the path — may not be exploitable |
| **guard_kind = "ValidationCall"** | An explicit validation function was called before the sink |
| **Source kind = database** | Data from DB — may already be validated at insertion time |

## Tuning and Noise Controls

### Add custom sanitizers

If your codebase has a custom sanitizer that Nyx doesn't recognize:

```toml
# nyx.local
[[analysis.languages.javascript.rules]]
matchers = ["escapeHtml", "sanitizeInput"]
kind = "sanitizer"
cap = "html_escape"
```

Or via CLI:
```bash
nyx config add-rule --lang javascript --matcher escapeHtml --kind sanitizer --cap html_escape
```

### Filter by severity

```bash
nyx scan . --severity HIGH          # Only high-severity taint findings
nyx scan . --severity ">=MEDIUM"    # Skip low-severity
```

### Skip non-production code

By default, findings in `tests/`, `vendor/`, `build/` paths are downgraded one severity tier. To exclude them entirely, add to config:

```toml
[scanner]
excluded_directories = ["tests", "vendor", "build", "examples"]
```

### Disable taint (AST-only mode)

```bash
nyx scan . --mode ast
```

## Example

**Vulnerable code** (Rust):
```rust
use std::env;
use std::process::Command;

fn main() {
    let cmd = env::var("USER_CMD").unwrap();          // line 5: source
    Command::new("sh").arg("-c").arg(&cmd).output();   // line 6: sink
}
```

**Finding**:
```
[HIGH]   taint-unsanitised-flow (source 5:15)  src/main.rs:6:5
         Source: env::var("USER_CMD") at 5:15
         Sink: Command::new("sh").arg("-c")
         Score: 76
```

**Safe alternative**:
```rust
use std::env;
use std::process::Command;

fn main() {
    let cmd = env::var("USER_CMD").unwrap();
    // Use the value as a direct argument, not a shell command
    Command::new(&cmd).output();
    // Or validate against an allowlist
}
```

## Technical Details

### Capability System

Taint uses a bitflag capability system to match sources with appropriate sanitizers and sinks:

| Capability | Bit | Sources | Sanitizers | Sinks |
|-----------|-----|---------|------------|-------|
| `ENV_VAR` | 0x01 | `env::var`, `getenv` | — | — |
| `HTML_ESCAPE` | 0x02 | — | `html_escape`, `DOMPurify.sanitize` | `innerHTML`, `document.write` |
| `SHELL_ESCAPE` | 0x04 | — | `shell_escape` | `Command::new`, `system()`, `eval()` |
| `URL_ENCODE` | 0x08 | — | `encodeURIComponent` | `location.href` |
| `JSON_PARSE` | 0x10 | — | `JSON.parse` | — |
| `FILE_IO` | 0x20 | — | `filepath.Clean`, `basename`, `os.path.realpath` | `fopen`, `open`, `send_file`, `fs::read_to_string` |
| `FMT_STRING` | 0x40 | — | — | `printf(var)` |

Sources typically use `Cap::all()` to match any sink. A sanitizer strips specific capability bits. A finding fires when a tainted variable reaches a sink and the taint still has the matching capability bit set.

### Nested Function Analysis

The CFG builder recursively discovers function expressions nested inside call arguments:

- **JavaScript/TypeScript**: `function_expression`, `arrow_function` inside call arguments (e.g., Express route handlers)
- **Ruby**: `do_block` and `block` nodes (e.g., Sinatra `get '/path' do...end`)
- **Go**: `func_literal` (anonymous function literals)

Each nested function is walked as a separate scope and receives a unique identifier (`<anon@{byte_offset}>`) to prevent collisions when multiple anonymous functions exist in the same file.

### Chained Call Classification

Method chains like `r.URL.Query().Get("host")` are normalized by stripping internal `()` segments between `.` separators. The classifier matches against both the original text and the normalized form, enabling rules like `r.URL` to match within `r.URL.Query.Get`.

### Nested Call Fallback

When the outermost call in an expression doesn't classify as a source/sink, the engine tries all nested inner calls. This handles patterns like `str(eval(expr))` where `str` is not a sink but the inner `eval` is.

### Rust `if let` / `while let` Pattern Bindings

The CFG builder recognizes Rust `let_condition` nodes inside `if` and `while` expressions. The value expression is classified for source/sink labels, and the pattern binding is extracted as a variable definition:

```rust
if let Ok(cmd) = env::var("CMD") {
    // cmd is tainted — env::var is a source, cmd is the binding
    Command::new("sh").arg("-c").arg(&cmd).output();  // taint-unsanitised-flow
}
```

This also works for `while let` patterns.

### JS/TS Two-Level Solve

For JavaScript and TypeScript, taint analysis uses a two-level approach:

1. **Level 1**: Solve top-level code (module scope)
2. **Level 2**: Solve each function seeded with the converged top-level state

This prevents false positives from cross-function taint leakage while preserving global-to-function flows.
