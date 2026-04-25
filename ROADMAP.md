# Roadmap

Nyx today is a static-only multi-language vulnerability scanner. The roadmap below extends it into a hybrid scanner that combines static analysis with controlled execution and AI-assisted reasoning.

## Phase 1 — Static Analysis (current)

The shipped scanner. Multi-language taint tracking on a pruned SSA IR, cross-file function summaries, points-to and abstract interpretation, symbolic execution with an optional SMT backend, and a local web UI for triage. See the [Changelog](CHANGELOG.md) for the full breakdown of what's landed through 0.5.0.

## Phase 2 — Dynamic Capability

| Feature | Description |
| --- | --- |
| Controlled dynamic execution | Local sandbox: identify entry points, spin up test harnesses, inject payloads, detect runtime crashes and command execution. Deterministic automated exploit validation — static finds `exec(user_input)`, dynamic confirms it with `; id`. |
| Fuzzing integration | libFuzzer (C/C++), cargo-fuzz (Rust), go-fuzz, HTTP fuzzing harness. Static engine identifies interesting functions, fuzzer targets only those. |

## Phase 3 — Intelligent Reasoning Layer

| Feature | Description |
| --- | --- |
| Semantic similarity | Embeddings for finding similar vulnerability patterns across codebases. |
| LLM reasoning | AI-assisted detection of non-obvious logic bugs. |
| Exploit refinement | Automated loops to refine and validate exploit chains. |
