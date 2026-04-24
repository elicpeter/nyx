# Advanced Analysis

Nyx ships four optional analysis passes that layer on top of the core SSA
taint engine. Each pass is independently switchable via config
(`[analysis.engine]` in `nyx.conf` / `nyx.local`), a matching CLI flag pair,
or; as a legacy last-resort override for library users with no CLI entry
point; a `NYX_*` environment variable. All four are **on by default**: turning
them off trades precision for speed.

See [`Configuration`](configuration.md#analysisengine) for the full config
surface and CLI flag table. This page explains what each pass does, why it
helps, how to disable it, and what it does not cover.

---

## Abstract interpretation

**What it does.** Propagates interval and string abstract domains through the
SSA worklist alongside taint. Integer values carry `[lo, hi]` bounds;
string values carry a prefix and suffix (plus a bit domain for known-zero /
known-one bits). Values are joined at merge points and widened at loop
heads so the worklist always terminates.

**Why it helps.** Lets Nyx suppress some findings that are obviously safe
given the abstract value; a proven-bounded integer does not flow into a
SQL sink as an injection risk; an SSRF sink whose URL prefix is locked to a
trusted host stays quiet. This turns a large class of FPs on numeric and
locked-prefix paths into true negatives.

**How to turn it off.**

| Surface | Value |
|---|---|
| Config | `abstract_interpretation = false` under `[analysis.engine]` |
| CLI flag | `--no-abstract-interp` |
| Env var (legacy) | `NYX_ABSTRACT_INTERP=0` |

**Limitations.** The interval domain is 64-bit signed; very wide or
overflow-producing arithmetic degrades to `⊤` (unbounded). String prefix /
suffix tracking is concat-only; it does not model reordering, reversal, or
character-level regex constraints. Loop widening deliberately drops
changing bounds rather than chasing fixpoints.

**Source**: [`src/abstract_interp/`](https://github.com/elicpeter/nyx/tree/master/src/abstract_interp/).

---

## Context-sensitive analysis

**What it does.** Adds k=1 call-site-sensitive taint propagation for
intra-file callees. When a function is invoked, Nyx reanalyzes the callee
body with the actual per-argument taint signature of the call site,
producing call-site-specific return taint. Results are cached by
`(function_name, ArgTaintSig)` so repeated calls with the same signature
are free.

**Why it helps.** A helper called once with a tainted argument and once
with a sanitized argument produces two different findings; without k=1
sensitivity, the conservative union of both call sites would be applied
to the sanitized call, producing a spurious finding there.

**How to turn it off.**

| Surface | Value |
|---|---|
| Config | `context_sensitive = false` under `[analysis.engine]` |
| CLI flag | `--no-context-sensitive` |
| Env var (legacy) | `NYX_CONTEXT_SENSITIVE=0` |

**Limitations.** Intra-file only. Cross-file callees are resolved via
summaries (see `src/summary/`) rather than re-inlined. Depth is capped at
k=1 to prevent cache blow-up and re-entrancy; higher k would require a
different cache key design. Callee bodies larger than the internal
`MAX_INLINE_BLOCKS` threshold fall back to the summary path. Cache keys
hash per-argument `Cap` bits but not source-origin identity, so two
callers with identical caps but different origins share cached
origin-attribution.

**Source**: [`src/taint/ssa_transfer.rs`](https://github.com/elicpeter/nyx/blob/master/src/taint/ssa_transfer.rs)
(`ArgTaintSig`, `InlineCache`, `inline_analyse_callee`).

---

## Symbolic execution

**What it does.** Builds a symbolic expression tree per tainted SSA value,
generates a witness string for each taint finding (the concrete-looking
shape of the dangerous value at the sink), and detects sanitization
patterns that the taint engine alone would miss. Supports string
operations (`trim`, `replace`, `toLower`, `substring`, `strlen`, …),
arithmetic, concatenation, phi nodes, and opaque calls.

**Why it helps.** Raises finding quality. A taint finding with a rendered
witness like `"SELECT * FROM t WHERE id=" + userInput` is substantially
easier to triage than one without. Also powers some confidence-gating for
downstream display.

**How to turn it off.**

| Surface | Value |
|---|---|
| Config | `symex.enabled = false` under `[analysis.engine]` |
| CLI flag | `--no-symex` |
| Env var (legacy) | `NYX_SYMEX=0` |

Two nested switches refine the scope without disabling symex entirely:

| Setting | CLI | Env | Default | Effect |
|---|---|---|---|---|
| `symex.cross_file` | `--no-cross-file-symex` | `NYX_CROSS_FILE_SYMEX=0` | on | Consult cross-file SSA bodies so symex can reason about callees defined in other files |
| `symex.interprocedural` | `--no-symex-interproc` | `NYX_SYMEX_INTERPROC=0` | on | Intra-file interprocedural symex (k ≥ 2 via frame stack) |

**Limitations.** Expression trees are bounded at `MAX_EXPR_DEPTH=32`;
deeper expressions degrade to `Unknown` rather than growing unboundedly.
Sanitizer detection is informational: string-replace sanitizer patterns
are reported as witness metadata, not used to clear taint.

**Source**: [`src/symex/`](https://github.com/elicpeter/nyx/tree/master/src/symex/).

---

## Demand-driven analysis

**What it does.** After the forward pass-2 taint analysis finishes, runs a
*backwards* walk from each sink's tainted SSA operands.  The walk follows
reverse SSA-edge transfer (phi fan-out, `Assign` operand-fanout, `Call`
body-expansion or arg-fanout) until it reaches a taint source, proves
the flow infeasible via an accumulated path predicate, or exhausts its
budget.  Each forward finding is then annotated with the aggregate verdict:

- `backwards-confirmed`; a matching source was reached.  Finding picks
  up a small confidence boost and the note appears in
  `evidence.symbolic.cutoff_notes`.
- `backwards-infeasible`; every walk proved the flow unreachable.
  Finding is capped to Low confidence and a user-readable limiter is
  attached.
- `backwards-budget-exhausted`; the walk hit `BACKWARDS_VALUE_BUDGET`
  without a verdict.  Recorded as a limiter so operators can see when
  the pass could not keep up.
- Inconclusive outcomes are a no-op: the forward finding is untouched.

Because the backwards walk can consult `GlobalSummaries.bodies_by_key`
(populated by the cross-file callee body persistence layer) it closes
across file boundaries; when a callee body is not loadable the walk
falls back to fanning out over the call's arguments so local reach-back
is still possible.

**Why it helps.** Inverts the analysis direction so budget follows
questions the scanner actually cares about; "does any source reach
*this* sink?"; instead of proving every potential source-to-sink
path.  Corroborated findings are a stronger signal than forward-only
ones, and proven-infeasible flows provide a principled way to lower
confidence on forward false positives without silently dropping them.

**How to turn it on.** Defaults off so the benchmark floor is preserved
while the pass stabilises.

| Surface | Value |
|---|---|
| Config | `backwards_analysis = true` under `[analysis.engine]` |
| CLI flag | `--backwards-analysis` / `--no-backwards-analysis` |
| Env var (legacy) | `NYX_BACKWARDS=1` |

**Limitations (first cut).** Reverse call-graph expansion past a
`ReachedParam` is deferred; the walk terminates at function parameters
rather than crossing back into callers.  Path-constraint pruning is
conservative: only the accumulated `PredicateSummary` bits are consulted,
not the full symbolic predicate stack.  Depth-bounded at k=2 for
cross-function body expansion.  See `DEFAULT_BACKWARDS_DEPTH`,
`BACKWARDS_VALUE_BUDGET`, and `MAX_BACKWARDS_CALLEE_BLOCKS` in
`src/taint/backwards.rs` for the exact bounds.

**Source**: [`src/taint/backwards.rs`](https://github.com/elicpeter/nyx/blob/master/src/taint/backwards.rs).

---

## Constraint solving

**What it does.** Collects path constraints at each branch in SSA and
propagates them alongside taint. Prunes paths whose accumulated constraint
set is unsatisfiable; a taint flow guarded by `if x < 0 && x > 10` is
dropped rather than surfaced. Optionally delegates the satisfiability
check to Z3 when Nyx is built with the `smt` Cargo feature.

**Why it helps.** Removes a class of FPs rooted in clearly-infeasible
control-flow combinations. Without path constraints, a taint flow that
only occurs when mutually-exclusive branches are simultaneously taken can
still produce a finding.

**How to turn it off.**

| Surface | Value |
|---|---|
| Config | `constraint_solving = false` under `[analysis.engine]` |
| CLI flag | `--no-constraint-solving` |
| Env var (legacy) | `NYX_CONSTRAINT=0` |

The SMT backend is a separate switch:

| Setting | CLI | Env | Default | Effect |
|---|---|---|---|---|
| `symex.smt` | `--no-smt` | `NYX_SMT=0` | on when built with `smt` feature | Delegate satisfiability checks to Z3; ignored if Nyx was built without `smt` |

**Limitations.** The default path-constraint domain is syntactic;
trivially-inconsistent pairs are caught without an SMT solver, but richer
algebraic unsatisfiability requires the `smt` feature (Z3). Without `smt`,
Nyx ships a lightweight satisfiability check that catches literal
contradictions but not deeper reasoning.

**Source**: [`src/constraint/`](https://github.com/elicpeter/nyx/tree/master/src/constraint/).

---

## Combining the switches

The defaults (all on) are the configuration Nyx is benchmarked against.
Turning any switch off trades precision for speed and may move findings
relative to the published baseline; CI regression gates assume defaults.
If you need a minimal-overhead scan (for very large repositories or a
pre-commit fast path), the AST-only scan mode (`--mode ast`) skips CFG,
taint, and all four advanced passes entirely and is the right tool.
