# Nyx Documentation

Welcome to the Nyx documentation. Nyx is a multi-language static vulnerability scanner built in Rust.

## User Guide

- [Installation](installation.md) — Install via cargo, prebuilt binaries, or from source
- [Quick Start](quickstart.md) — Your first scan in 60 seconds
- [CLI Reference](cli.md) — Every flag, subcommand, and option
- [Configuration](configuration.md) — Config file schema, precedence, custom rules
- [Output Formats](output.md) — Console, JSON, SARIF; exit codes; evidence fields

## Detector Reference

- [Detector Overview](detectors.md) — How the four detector families work together
- [Taint Analysis](detectors/taint.md) — Cross-file source-to-sink dataflow tracking
- [CFG Structural Analysis](detectors/cfg.md) — Auth gaps, unguarded sinks, resource leaks
- [State Model Analysis](detectors/state.md) — Resource lifecycle and authentication state
- [AST Patterns](detectors/patterns.md) — Tree-sitter structural pattern matching

## Rule Reference

- [Rule Index](rules/index.md) — How rules are organized
- [Rust](rules/rust.md) | [C](rules/c.md) | [C++](rules/cpp.md) | [Java](rules/java.md) | [Go](rules/go.md)
- [JavaScript](rules/javascript.md) | [TypeScript](rules/typescript.md) | [Python](rules/python.md)
- [PHP](rules/php.md) | [Ruby](rules/ruby.md)

## Contributing

- [Contributing Guide](../CONTRIBUTING.md) — Development setup, adding rules, PR guidelines
- [Security Policy](../SECURITY.md) — Responsible disclosure
- [Code of Conduct](../CODE_OF_CONDUCT.md)
