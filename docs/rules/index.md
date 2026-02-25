# Rule Reference

This section lists every detection rule in Nyx, organized by language.

## Rule ID Format

| Prefix | Detector Family | Example |
|--------|----------------|---------|
| `taint-*` | [Taint analysis](../detectors/taint.md) | `taint-unsanitised-flow (source 5:11)` |
| `cfg-*` | [CFG structural](../detectors/cfg.md) | `cfg-unguarded-sink`, `cfg-auth-gap` |
| `state-*` | [State model](../detectors/state.md) | `state-use-after-close`, `state-resource-leak` |
| `<lang>.*.*` | [AST patterns](../detectors/patterns.md) | `rs.memory.transmute`, `js.code_exec.eval` |

## Cross-Language Rules

These rules apply to all supported languages:

### Taint Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `taint-unsanitised-flow (source L:C)` | Varies by source kind | Unsanitized data flows from source to sink |

### CFG Structural Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `cfg-unguarded-sink` | High/Medium | Sink without dominating guard |
| `cfg-auth-gap` | High | Web handler reaches privileged sink without auth |
| `cfg-unreachable-sink` | Medium | Dangerous function in unreachable code |
| `cfg-unreachable-sanitizer` | Low | Sanitizer in unreachable code |
| `cfg-unreachable-source` | Low | Source in unreachable code |
| `cfg-error-fallthrough` | High/Medium | Error path doesn't terminate before dangerous code |
| `cfg-resource-leak` | Medium | Resource not released on all exit paths |
| `cfg-lock-not-released` | Medium | Lock not released on all exit paths |

### State Model Rules

| Rule ID | Severity | Description |
|---------|----------|-------------|
| `state-use-after-close` | High | Variable used after being closed |
| `state-double-close` | Medium | Resource closed twice |
| `state-resource-leak` | Medium | Resource never closed (definite) |
| `state-resource-leak-possible` | Low | Resource may not close on all paths |
| `state-unauthed-access` | High | Privileged operation without authentication |

## Per-Language AST Pattern Rules

Each language page lists all AST pattern rules with examples:

- [Rust](rust.md) — 12 rules (memory safety, code quality)
- [C](c.md) — 8 rules (banned functions, command execution, format strings)
- [C++](cpp.md) — 8 rules (banned functions, dangerous casts, command execution)
- [Java](java.md) — 8 rules (deserialization, command execution, reflection, SQL, crypto, XSS)
- [Go](go.md) — 8 rules (command execution, unsafe pointer, TLS, crypto, SQL, secrets, deserialization)
- [JavaScript](javascript.md) — 12 rules (code execution, XSS, prototype pollution, crypto, transport)
- [TypeScript](typescript.md) — 10 rules (mirrors JS + type-safety escapes)
- [Python](python.md) — 12 rules (code execution, command execution, deserialization, SQL, crypto, XSS)
- [PHP](php.md) — 11 rules (code execution, command execution, deserialization, SQL, path traversal, crypto)
- [Ruby](ruby.md) — 10 rules (code execution, command execution, deserialization, reflection, SSRF, crypto)

## Taint Label Coverage

Taint analysis uses language-specific source/sink/sanitizer labels. Coverage varies by language:

| Language | Sources | Sinks | Sanitizers | Coverage |
|----------|---------|-------|------------|----------|
| Rust | Complete | Complete | Complete | Full |
| JavaScript | Complete | Complete | Partial | Full |
| TypeScript | Partial | Partial | Partial | Moderate |
| Python | Partial | Partial | Minimal | Moderate |
| C | Partial | Partial | Minimal | Moderate |
| C++ | Partial | Partial | Minimal | Moderate |
| Java | Partial | Partial | Minimal | Moderate |
| Go | Partial | Partial | Minimal | Moderate |
| PHP | Minimal | Minimal | Minimal | Starter |
| Ruby | Minimal | Minimal | Minimal | Starter |

"Starter" coverage means basic rules exist but many common library functions are not yet labeled. Contributions welcome.
