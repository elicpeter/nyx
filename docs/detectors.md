# Detector Overview

Nyx uses four independent detector families. Each targets different vulnerability classes and operates at a different level of analysis depth. Findings from all active detectors are merged, deduplicated, ranked, and presented in a single result set.

## The Four Detector Families

| Family | Rule prefix | Analysis depth | What it finds |
|--------|------------|----------------|---------------|
| [**Taint Analysis**](detectors/taint.md) | `taint-*` | Cross-file dataflow | Unsanitized data flowing from sources to sinks |
| [**CFG Structural**](detectors/cfg.md) | `cfg-*` | Intra-procedural CFG | Auth gaps, unguarded sinks, resource leaks, error fallthrough |
| [**State Model**](detectors/state.md) | `state-*` | Intra-procedural lattice | Use-after-close, double-close, resource leaks, unauthenticated access |
| [**AST Patterns**](detectors/patterns.md) | `<lang>.*.*` | Structural (no flow) | Dangerous function calls, banned APIs, weak crypto |

## How They Combine

In `--mode full` (default), all four families run. Findings are deduplicated:

1. **Taint supersedes AST**: If a taint finding and an AST pattern both fire at the same location (e.g. both flag `eval(userInput)`), both are kept with distinct rule IDs. The taint finding ranks higher due to the analysis-kind bonus.

2. **State supersedes CFG**: If a state-model finding (e.g. `state-resource-leak`) fires at the same location as a CFG finding (e.g. `cfg-resource-leak`), the CFG finding is suppressed.

3. **Location-level dedup**: Exact duplicates (same line, column, rule ID, severity) are removed.

## Analysis Modes

| Mode | CLI flag | Active detectors |
|------|----------|-----------------|
| Full | `--mode full` | All four |
| AST-only | `--mode ast` | AST patterns only |
| CFG/Taint | `--mode cfg` | Taint + CFG + State |

## Attack-Surface Ranking

Every finding receives a deterministic **attack-surface score** estimating exploitability. Findings are sorted by descending score.

### Scoring Formula

```
score = severity_base + analysis_kind + evidence_strength + state_bonus - validation_penalty
```

| Component | Values | Purpose |
|-----------|--------|---------|
| **Severity base** | High=60, Medium=30, Low=10 | Primary signal |
| **Analysis kind** | taint=+10, state=+8, cfg(with evidence)=+5, cfg(no evidence)=+3, ast=+0 | Confidence of analysis |
| **Evidence strength** | +1 per evidence item (max 4), +2-6 for source kind | Specificity of finding |
| **State bonus** | use-after-close/unauthed=+6, double-close=+3, must-leak=+2, may-leak=+1 | State rule severity |
| **Validation penalty** | -5 if path-validated | Guard reduces exploitability |

### Source-kind priority

| Source type | Bonus | Examples |
|-------------|-------|---------|
| User input | +6 | `req.body`, `argv`, `stdin`, `form`, `query`, `params` |
| Environment | +5 | `env::var`, `getenv`, `process.env` |
| Unknown | +4 | Conservative default |
| File system | +3 | `fs::read_to_string`, `fgets` |
| Database | +2 | Query results |

### Score ranges (approximate)

| Finding type | Score range |
|-------------|------------|
| High taint + user input | ~76-80 |
| High state (use-after-close) | ~74 |
| High CFG structural | ~63-68 |
| Medium taint + env source | ~45-50 |
| Medium state (resource leak) | ~40 |
| Low AST-only pattern | ~10 |

Ranking is enabled by default. Disable with `--no-rank` or `output.attack_surface_ranking = false`.

## Two-Pass Architecture

Nyx's taint analysis requires cross-file context, achieved via two passes:

1. **Pass 1 -- Summary extraction**: Each file is parsed, a CFG is built, and a `FuncSummary` is extracted per function. Summaries capture source/sanitizer/sink capabilities (bitflags), taint propagation behavior, and callee lists. Summaries are persisted to SQLite.

2. **Pass 2 -- Analysis**: All summaries are merged into a global map. Files are re-parsed and analyzed with full cross-file context. The taint engine resolves callees against local summaries (more precise) first, then falls back to global summaries.

With indexing enabled, Pass 1 skips files whose content hash hasn't changed since the last scan.
