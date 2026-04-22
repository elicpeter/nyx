# Nyx Cross-File Strengthening Plan

This plan takes nyx's cross-file taint analysis from "conservative function
summaries" to "strong inter-procedural analysis" in seven phases. Each
phase is sized to fit comfortably in a single Claude Code session. Every
phase re-inlines the shared project context so it can be handed to a fresh
session with the prompt:

> "Implement Phase CF-N from CROSS_FILE_PLAN.md"

and have everything needed to execute without reading the rest of the
document.

## Phase summary

| Phase | Title                                               | Depends on  | Est. session size | Status                       |
|-------|-----------------------------------------------------|-------------|-------------------|------------------------------|
| CF-1  | Cross-file SSA body availability (infrastructure)   | —           | 1 session         | Landed 2026-04-21            |
| CF-2  | Cross-file k=1 context-sensitive inline taint       | CF-1        | 1 session         | Landed 2026-04-22            |
| CF-3  | Abstract-domain transfer channels in summaries      | —           | 1 session         | Landed 2026-04-22            |
| CF-4  | Per-return-path summary decomposition               | —           | 1 session         | Landed 2026-04-22            |
| CF-5  | Cross-file SCC joint fixed-point                    | CF-1, CF-2  | 1 session         | Landed 2026-04-22            |
| CF-6  | Parameter-granularity points-to summaries           | CF-4        | 1 session         | Not started                  |
| CF-7  | Demand-driven backwards analysis from sinks         | CF-1..CF-4  | 1 full session    | Not started                  |

Recommended order: CF-1 → CF-2 first (the biggest immediate precision
win). CF-3 and CF-4 are independent and can run in parallel. CF-5 follows
CF-1/CF-2. CF-6 layers on CF-4. CF-7 is the paradigm shift and should come
last so it has everything to lean on.

Each phase is independently landable. After every phase, the benchmark F1
should stay within the existing regression gate, and new fixtures should
close previously-honest FNs or FPs that the phase targets.

---

## Shared project context

**Every phase below re-inlines this block. Skip down to the phase you
want.**

Nyx is a multi-language static security scanner written in Rust (Rust
2024, builds on 1.85+). Repo root: `/Users/elipeter/nyx`. Current release
branch: `release/0.5.0`. Default branch: `master`.

Core architecture:
- Tree-sitter frontend across 10 languages (JS, TS, Python, Go, Java, Ruby,
  PHP, Rust, C, C++).
- Per-file AST → CFG (petgraph) → SSA IR → SSA-only taint analysis with
  `Cap` bitflags.
- Two-pass scan: pass 1 extracts `FuncSummary` + `SsaFuncSummary` per file
  and persists to SQLite; pass 2 runs taint with a `GlobalSummaries`
  merged view.
- Call graph (`src/callgraph.rs`) drives SCC-based topo batching in pass 2
  with an iterative SCC fixed-point capped at `MAX_SCC_FIXPOINT_ITERS = 3`
  and a safety cap at `SCC_FIXPOINT_SAFETY_CAP = 64`.
- k=1 context-sensitive inline re-analysis exists today **only for
  intra-file callees** via `CalleeSsaBody` + `InlineCache` + `ArgTaintSig`
  in `src/taint/ssa_transfer.rs`. Cross-file callees go through
  `SsaFuncSummary` / `FuncSummary` instead, losing path predicates,
  abstract-domain facts, and per-call-site specialisation.

Key source files:
- `src/cfg.rs` — AST→CFG (~9k lines)
- `src/ssa/lower.rs` — Cytron phi insertion + SSA lowering
- `src/ssa/ir.rs` — `SsaValue`, `BlockId`, `SsaOp`, `SsaBody`
- `src/taint/ssa_transfer.rs` — SSA taint transfer (~7.5k lines);
  `SsaTaintState`, `SsaTaintTransfer`, `inline_analyse_callee`,
  `CalleeSsaBody`, `InlineCache`, `ArgTaintSig`, `resolve_callee`
- `src/taint/mod.rs` — `lower_all_functions`, `analyse_ssa_js_two_level`,
  top-level entry `run_ssa_taint` / `run_ssa_taint_full`
- `src/taint/domain.rs` — `VarTaint`, `SmallBitSet`, `PredicateSummary`,
  `TaintTransform`
- `src/taint/path_state.rs` — predicate classification
- `src/summary/` — `FuncSummary`, `SsaFuncSummary`, merge logic
- `src/commands/scan.rs` — both scan paths (`scan_filesystem`,
  `scan_with_index_parallel`); `run_topo_batches`,
  `scc_file_batches_with_metadata`
- `src/database.rs` — SQLite layer; tables include `function_summaries`,
  `ssa_function_summaries`, `ssa_function_bodies` (the last persists SSA
  bodies for symex cross-file; taint does not currently read it)
- `src/callgraph.rs` — call graph + SCC analysis
- `src/abstract_interp/` — interval, string prefix/suffix, bit domains
- `src/symex/` — symbolic execution; note that symex already has
  cross-file body access (`symex.cross_file`), so there is working
  precedent for loading SSA bodies from the DB into pass 2
- `src/constraint/` — path-constraint domain, optional SMT via `smt`
  feature

Configuration surface for analysis switches lives at `[analysis.engine]`
in `nyx.conf` / `nyx.local`. Each switch has a matching CLI flag
(`--no-context-sensitive`, `--no-abstract-interp`, `--no-symex`,
`--cross-file-symex` / `--no-cross-file-symex`, etc.) and a legacy
`NYX_*` environment variable.

Tests live in `tests/` (integration) and inline `#[test]` blocks in
`src/`. Fixtures live in `tests/fixtures/`. Expectations are
`.expect.json` per fixture, with `expected`, `must_match`,
`must_not_match`, `max_count` schema fields. Benchmark corpus is
`tests/benchmark/ground_truth.json`.

**When in doubt about an engine invariant, prefer SSA-based semantics
over any legacy fallback.** The legacy `TaintTransfer` / `TaintState`
paths were removed and must not be resurrected.

---

## Phase CF-1 — Cross-file SSA body availability (infrastructure)

**Status:** Not started
**Estimated effort:** 1 session
**Depends on:** Nothing

### Project context

(See "Shared project context" at the top of this document.)

### Why this phase exists

Today the taint engine's k=1 context-sensitive inline re-analysis works
**only within a single file**. The call graph spans files but the inline
pipeline does not: `CalleeSsaBody` is constructed per-file in
`lower_all_functions()` and plumbed only into the current file's analyser.
Cross-file callees fall through to `GlobalSummaries.ssa_by_key` / the
summary path.

The DB already persists SSA bodies — the `ssa_function_bodies` table was
added so `symex.cross_file` could reason about callees defined in other
files. This phase makes the same cross-file body access available to the
taint engine as a pure plumbing change, without any behaviour change. CF-2
is the phase that actually uses it.

Splitting plumbing from use keeps the change reviewable and keeps the
potential precision shift isolated to CF-2.

### Files you will touch

- `src/database.rs` — add a read path for `ssa_function_bodies` keyed by
  `FuncKey` (or whatever key the symex side already uses — reuse it).
- `src/summary/` — extend `GlobalSummaries` to carry an optional
  `bodies_by_key: HashMap<FuncKey, CalleeSsaBody>`.
- `src/taint/ssa_transfer.rs` — expose a constructor or setter for
  `SsaTaintTransfer` that accepts a borrowed
  `&HashMap<FuncKey, CalleeSsaBody>` from `GlobalSummaries` alongside
  existing state. **Do not** yet consult it in `resolve_callee`.
- `src/commands/scan.rs` — in both scan paths (`scan_filesystem`,
  `scan_with_index_parallel`), load cross-file bodies between pass 1 and
  pass 2 and pass them into the analyser.
- `tests/cross_file_body_loading_tests.rs` (new) — smoke test asserting
  a multi-file fixture populates `bodies_by_key`.

### Files you MUST NOT touch

- `src/ssa/lower.rs` — lowering is already correct; this phase does not
  change how bodies are built.
- The body construction side in `lower_all_functions()` — reuse existing
  `CalleeSsaBody` output, don't re-lower.
- `src/symex/` — symex has its own cross-file path; don't disturb it.
- Any benchmark expectation files.

### Tasks

1. **Verify the DB schema and symex read path.** Read the column
   definitions for `ssa_function_bodies` in `src/database.rs` and the
   loader the symex side uses. Document (in a short comment at the load
   site) what format the bodies are stored in and which `FuncKey`
   components are indexed.
2. **Add `load_all_ssa_bodies() -> HashMap<FuncKey, CalleeSsaBody>`** (or
   equivalent if bodies need on-demand rather than bulk load). Mirror the
   shape of `load_all_ssa_summaries()`. Pool access via `r2d2`.
3. **Extend `GlobalSummaries`** with a new field
   `bodies_by_key: HashMap<FuncKey, CalleeSsaBody>` (or `Arc<...>` if
   cloning into each rayon worker would be expensive — measure). Populate
   it in both scan paths immediately after
   `load_all_ssa_summaries()`.
4. **Thread the map into `SsaTaintTransfer`**. Add a field like
   `cross_file_bodies: Option<&'a HashMap<FuncKey, CalleeSsaBody>>` and a
   constructor that accepts it. Default to `None` so non-cross-file
   callers (unit tests, JS two-level inner runs) still compile. Do **not**
   read from this field anywhere except a no-op getter.
5. **Add a smoke test** (`tests/cross_file_body_loading_tests.rs`): a
   two-file Python fixture (`a.py` defines a function, `b.py` calls it),
   run a scan, assert `GlobalSummaries.bodies_by_key` contains an entry
   for the callee and that its `param_count` matches the real parameter
   count.
6. **Observability**: log at `debug` level the count of cross-file bodies
   loaded per scan, so CF-2 can distinguish "no bodies available" from
   "bodies available but inline didn't fire."

### Verification

```bash
cargo build --all-features
cargo test --workspace --all-features
cargo test --test cross_file_body_loading_tests
# Benchmark must be unchanged because no analysis behaviour changed:
cargo bench --bench scan_bench -- --save-baseline post-phase-cf-1
```

### Definition of done

- [ ] `GlobalSummaries.bodies_by_key` is populated in both scan paths.
- [ ] `SsaTaintTransfer` has an (unused) cross-file bodies field.
- [ ] New smoke test passes.
- [ ] Benchmark F1 is byte-for-byte unchanged vs the prior baseline
      (this phase is pure plumbing).
- [ ] No changes outside the file list above.

---

## Phase CF-2 — Cross-file k=1 context-sensitive inline taint

**Status:** Landed 2026-04-22 — see `tests/benchmark/RESULTS.md` for the
benchmark delta (F1 0.951 → 0.966, precision +2.9pp, recall unchanged).
**Estimated effort:** 1 session
**Depends on:** CF-1

### Project context

(See "Shared project context" at the top of this document.)

Additional context: Phase 11 shipped k=1 context-sensitive inline
analysis for intra-file callees. The machinery lives in
`src/taint/ssa_transfer.rs` and is gated by the config switch
`context_sensitive` (default on). The cache key `ArgTaintSig` encodes
per-arg cap bits only (origins excluded). `inline_analyse_callee` depth
is capped at 1 (the `Cell<u32>` depth counter prevents recursion). After
CF-1, `GlobalSummaries.bodies_by_key` carries cross-file
`CalleeSsaBody` entries.

### Why this phase exists

With CF-1 in place, the infrastructure is available but unused. This
phase wires cross-file bodies into the actual inline pipeline so a callee
defined in a different file gets the same per-call-site specialisation as
an intra-file callee. This is the largest single precision win in the
plan because it lifts the "call-site conservatism" that summaries impose
on every cross-file edge.

### Files you will touch

- `src/taint/ssa_transfer.rs` — extend `resolve_callee` (and any sibling
  resolution site called from `transfer_inst`) to try cross-file inline
  before falling through to summary-based resolution.
- `src/taint/mod.rs` — audit `analyse_ssa_js_two_level` for the path
  where its inner per-function analyses resolve callees; ensure the same
  cross-file opportunity is present there.
- `src/commands/scan.rs` — if the rayon parallelism of pass 2 needs the
  bodies map to be `Arc<...>`-wrapped for worker sharing, adjust the
  plumbing added in CF-1.
- `tests/fixtures/cross_file_context/` — **new** directory with ~4
  fixtures:
    - `two_call_sites/` — Python. One file defines a helper; a second
      file calls it twice, once with tainted and once with sanitised
      input. Expect finding on the tainted call only.
    - `callback_across_files/` — JS. File A defines a function, file B
      passes it as a callback to a helper whose sink reaches the
      callback. Mirrors the intra-file `callback_sink_tracking.js`
      fixture at cross-file scope.
    - `sanitizer_across_files/` — JS. A sanitiser lives in file A, is
      called from file B on user input before a sink. Expect no
      finding.
    - `deep_chain/` — Python. File A → file B → file C, with the sink
      in C. k=1 means this should still produce a finding (because the
      last hop remains context-sensitive), but the B-level specialisation
      will not propagate. Assert the documented limit.
- `tests/cross_file_context_tests.rs` (new) — ties the fixtures to the
  harness and adds one direct `GlobalSummaries`-level assertion that
  `bodies_by_key` was consulted (via the observability counter added in
  CF-1; promote it to a metric if needed).

### Files you MUST NOT touch

- `src/summary/` — summaries themselves do not change in this phase;
  CF-3 / CF-4 handle summary enrichment.
- `src/ssa/lower.rs`, `src/cfg.rs` — body construction is CF-1 territory.
- `src/symex/` — symex already has its own cross-file path. Do not merge
  or share inline machinery yet.
- Benchmark expectation files in `tests/benchmark/corpus/`.

### Tasks

1. **Audit current `resolve_callee` ordering** in
   `src/taint/ssa_transfer.rs`. Document the current steps (callback
   binding, summary lookup, label-classification fallback, etc.) in a
   comment at the top of the function if one does not already exist.
2. **Add a new resolution step** that, when a callee is not resolved
   intra-file but has an entry in `bodies_by_key`, calls
   `inline_analyse_callee` with the cross-file body. Reuse the existing
   cache (`InlineCache`) keyed by `(function_name, ArgTaintSig)` — do
   not introduce a separate cache.
3. **Respect existing budgets**: `MAX_INLINE_BLOCKS`, the k=1 depth cap,
   the `context_sensitive` config switch. Add a new per-scan metric
   counter for "cross-file inline hits" and "cross-file inline misses
   (budget-exceeded)" so operators can reason about precision cost.
4. **Return-path extraction**: reuse the existing return-block exit-state
   extraction. Cross-file bodies are shape-compatible with intra-file
   bodies — if the existing code has intra-file-only assumptions
   (language tag, path, etc.), lift them to the `CalleeSsaBody`
   struct rather than forking the code path.
5. **Fixtures and tests.** Add the four fixtures above. Each `.expect.json`
   must include a `must_not_match` clause that would fire if the phase
   regresses (e.g., the sanitised call produces a finding).
6. **Benchmark F1 guardrail.** Run the benchmark. The phase **may**
   change the benchmark numbers; that is expected. Precision should not
   drop below the floor. Recall should be equal or better. Document the
   delta in `tests/benchmark/RESULTS.md` under a new section dated with
   the commit day.

### Verification

```bash
cargo test --workspace --all-features
cargo test --test cross_file_context_tests
cargo bench --bench scan_bench -- --save-baseline post-phase-cf-2
# Compare to post-phase-cf-1: F1 must not regress below the
# existing CI floor (86.1 / 94.4 / 90.1).
NYX_CONTEXT_SENSITIVE=0 cargo test --test cross_file_context_tests
# With the switch off, cross-file context sensitivity must *not* fire,
# so those fixtures expecting specialisation should flip to summary-level
# behaviour (assert this explicitly in the tests).
```

### Definition of done

- [ ] `resolve_callee` consults `GlobalSummaries.bodies_by_key` on
      cross-file callees before the summary path.
- [ ] All four new fixtures pass.
- [ ] `NYX_CONTEXT_SENSITIVE=0` (or the CLI equivalent) reverts to
      pre-phase behaviour on those fixtures.
- [ ] Benchmark numbers stay within the CI regression gate; any delta is
      documented in `RESULTS.md`.
- [ ] Cross-file inline hit / miss counters are logged at `debug`.

---

## Phase CF-3 — Abstract-domain transfer channels in summaries

**Status:** Landed 2026-04-22 on `release/0.5.0`. Benchmark neutral
(rule-level F1 0.966 — unchanged from CF-2); the precision win is
latent pending resolution of a pre-existing JS suppression-pipeline
quirk documented in `memory/project_cf3_suppression_quirks.md`.
Structural Identity detection and transfer-apply semantics are
covered by `tests/abstract_transfer_tests.rs` (29 unit tests plus
an end-to-end passthrough-identity test through the real extraction
pipeline).
**Estimated effort:** 1 session
**Depends on:** Nothing (independent of CF-1 / CF-2)

### Project context

(See "Shared project context" at the top of this document.)

Additional context: Nyx's abstract interpretation (`src/abstract_interp/`)
tracks interval bounds, string prefix/suffix, and a known-bit domain per
SSA value during pass 2. These facts are used to suppress findings (see
`is_abstract_safe_for_sink` in `src/taint/ssa_transfer.rs`). **None of
these facts currently cross function boundaries through summaries.** A
caller that proves `port: u16 ∈ [1024, 65535]` loses that bound the
moment the value is passed to a callee in another file; the callee's
summary was computed under `⊤` assumptions.

### Why this phase exists

The cheapest way to recover a large slice of the precision lost to
summaries — without paying the inline re-analysis cost on every call site
— is to record, per function, how each parameter's abstract value
propagates to each return path. This is a static fact about the callee
body that can be computed once (in pass 1) and applied at every call site
(in pass 2) without re-running the callee analysis.

### Files you will touch

- `src/summary/` — extend `SsaFuncSummary` with a new
  `abstract_transfer: AbstractTransfer` field (or `Option<AbstractTransfer>`
  for backwards-compat during the migration).
- `src/abstract_interp/mod.rs` — define `AbstractTransfer` as a struct
  with per-parameter → return transforms. For intervals: `(add: i64,
  mul: i64, clamp: Option<(i64, i64)>)` or similar affine-plus-clamp form.
  For strings: `(prefix_from_param: bool, suffix_from_param: bool,
  literal_prefix: Option<String>)`. Keep it small and bounded.
- `src/taint/ssa_transfer.rs` — in pass 1 summary extraction, compute
  `AbstractTransfer` from the callee's optimised SSA `OptimizeResult`
  by inspecting return-block abstract values. In pass 2 summary
  application, apply the transfer at the call site when falling through
  to summary resolution (i.e., when CF-2 inline didn't fire).
- `src/database.rs` — extend the `ssa_function_summaries` serde
  round-trip to include the new field; bump the engine version so older
  DBs are rebuilt.
- `tests/abstract_transfer_tests.rs` (new) — unit tests for the transfer
  construction and serde round-trip.
- `tests/fixtures/cross_file_abstract/` (new) — ~3 fixtures:
    - `port_range/` — Rust. Caller parses `port: u16`; callee in another
      file does `Command::new(...).arg(port.to_string())`. Without this
      phase the structural unguarded-sink still fires (documented); with
      this phase the abstract transfer propagates and the finding is
      suppressed.
    - `url_prefix_lock/` — JS. Caller constructs URL with a locked
      literal prefix; cross-file helper performs `fetch(url)`. Expect no
      SSRF finding.
    - `bounded_index/` — Python. Caller bounds an index to `[0, 10]` via
      `max(...)` / `min(...)`; callee uses the index in a file-write
      path. Expect no FILE_IO finding.

### Files you MUST NOT touch

- CF-1 / CF-2 cross-file body machinery — this phase is orthogonal.
- `src/symex/` — symbolic state does not yet cross summaries; that is
  part of CF-7's scope.
- Existing fixture expectations outside the new directory.

### Tasks

1. **Design `AbstractTransfer`**. Keep the representation **bounded** —
   no expression trees, no unbounded prefix strings. For intervals: a
   small set of forms (`Identity`, `Affine { add, mul }`,
   `Clamped { lo, hi }`, `Top`). For strings: (`Identity`,
   `LiteralPrefix(String)` up to a fixed length, `Unknown`). Add a
   module-level comment enumerating the forms and justifying the size
   bound.
2. **Compute transfers in pass 1.** At the end of `extract_ssa_summaries`
   (or its equivalent), walk each return block's abstract state and
   derive a per-return `AbstractTransfer`. Join across return blocks (at
   the abstract-domain level). Store on `SsaFuncSummary`.
3. **Apply transfers in pass 2.** In the summary-resolution branch of
   `resolve_callee` (CF-2 inline path does not need this — inline already
   reanalyses under the real call-site abstract state), read the
   `AbstractTransfer` and synthesise an abstract value at the call site's
   result. Feed it into `SsaTaintState.abstract_state` so downstream
   `is_abstract_safe_for_sink` checks see the transferred bound.
4. **Serde + DB migration.** Extend the serialised summary schema. Bump
   `CARGO_PKG_VERSION`-driven engine version in `src/database.rs` so
   existing indexed projects rebuild on next scan (existing
   auto-rebuild-on-version-change mechanism handles this).
5. **Unit tests.** Round-trip transfers through serde. Small handwritten
   SSA bodies → derived transfer matches expectation. Interval + string
   + identity cases each covered.
6. **Fixtures.** The three cross-file fixtures above. Each should fail
   without the phase (confirm by temporarily stubbing the transfer to
   `Top`) and pass with it.

### Verification

```bash
cargo test --workspace --all-features
cargo test --test abstract_transfer_tests
cargo bench --bench scan_bench -- --save-baseline post-phase-cf-3
# Precision should improve (FPs on numeric/prefix-locked flows drop).
# Recall should hold. F1 must not regress below the floor.
```

### Definition of done

- [ ] `AbstractTransfer` defined with documented bounded forms.
- [ ] Pass 1 computes transfers for every analysed function.
- [ ] Pass 2 summary resolution applies transfers into
      `SsaTaintState.abstract_state` at call sites.
- [ ] Serde round-trip tested; DB migration is automatic via engine
      version bump.
- [ ] All three cross-file abstract fixtures pass and fail without the
      phase.
- [ ] Benchmark F1 ≥ CI floor; precision should go up.

---

## Phase CF-4 — Per-return-path summary decomposition

**Status:** Landed 2026-04-22 on `release/0.5.0`.  Additive shape:
`SsaFuncSummary` gains `param_return_paths: Vec<(usize, SmallVec<[ReturnPathTransform; 2]>)>`
alongside the existing aggregate `param_to_return`.  Pass 1 emits one
`ReturnPathTransform` per distinct return-block predicate hash (with a
cap of `MAX_RETURN_PATHS = 8` and deterministic join beyond the cap).
Pass 2 summary application uses `effective_param_sanitizer` to filter
entries by caller-side `known_true` / `known_false` envelope and
intersects strip-bits across compatible paths.  Coverage:
7 new unit tests (`cf4_*` in `src/summary/tests.rs`) plus 3 new
cross-file fixtures (`cross_file_phi_validated_branch` /
`_partial_sanitiser` / `_both_branches_safe`) wired through
`tests/cross_file_phi_tests.rs`.
**Estimated effort:** 1 session
**Depends on:** Nothing (independent of CF-1 / CF-2 / CF-3)

### Project context

(See "Shared project context" at the top of this document.)

Additional context: `SsaFuncSummary` today carries aggregated taint
transforms — one `TaintTransform` per parameter position describing the
worst-case effect of the function on that parameter. When the callee has
multiple return paths (e.g. `if validated { return sanitised } else {
return raw }`), the aggregated transform unions the per-path outcomes and
loses the gating predicate. Callers can't reconstruct "tainted on path
A, sanitised on path B."

### Why this phase exists

A large class of cross-file FPs arises because the callee's internal
path-split is invisible to the caller. Decomposing `TaintTransform` into
per-return-path records preserves the structure without requiring the
caller to re-analyse the body. The caller can then consult its own
path-state at the call site and pick (or join) the relevant return-path
transforms.

This is the precision step that most directly narrows the "every cross-
file edge must be conservative" cliff.

### Files you will touch

- `src/taint/domain.rs` — redefine `TaintTransform` as
  `Vec<ReturnPathTransform>` where each entry carries:
  `(path_predicate_hash: u64, origins: SmallBitSet, caps:
  Cap, validated_kinds: SmallBitSet, abstract_contribution: Option<...>)`.
  The `path_predicate_hash` identifies the predicate gate; its semantic
  form lives in a sibling `PredicateSummary` the callee already computes.
- `src/summary/` — update `SsaFuncSummary` serde, merge logic, and
  conflict resolution. Name-collision merges union return-path vectors
  with deduplication, not element-wise union.
- `src/taint/ssa_transfer.rs` — pass 1: change the summary extraction to
  walk each return block and produce one `ReturnPathTransform`
  per block (or join blocks with the same path predicate). Pass 2: change
  the summary-resolution branch to consult the call-site's current
  `SsaTaintState.predicates`. For each
  `ReturnPathTransform`, check whether its predicate is consistent with
  the caller's validated set; apply only consistent entries, then join.
- `src/database.rs` — serialise the new `Vec<ReturnPathTransform>`;
  engine-version bump.
- `tests/fixtures/cross_file_phi/` (new) — ~3 fixtures:
    - `validated_branch/` — Python. Callee returns sanitised on
      `if validated`, raw otherwise. Caller invokes under both sides of
      a predicate. Expect finding only under the raw branch.
    - `partial_sanitiser/` — JS. Callee is a partial sanitiser that only
      clears taint on some input shapes. Expect per-shape resolution.
    - `both_branches_safe/` — Go. Callee validates and returns on both
      branches. Expect no finding at caller.

### Files you MUST NOT touch

- CF-1 / CF-2 machinery — independent.
- Inline analysis path — it already has per-path precision because it
  re-analyses the body. This phase only changes the summary path.
- Benchmark corpus fixtures.

### Tasks

1. **Shape the new `TaintTransform`** as a `SmallVec<[ReturnPathTransform;
   2]>` — most functions have one or two return paths, and heap
   allocation for the common case is wasteful. Put a hard cap (e.g. 8
   entries per function); join beyond the cap.
2. **Pass 1 extraction.** For each function, iterate the SSA body's
   return blocks. Compute the path predicate for each return (already
   derivable from `SsaTaintState.predicates` at that block). Emit one
   `ReturnPathTransform` per distinct predicate; join within-predicate
   across any duplicated returns.
3. **Pass 2 application.** In summary-based `resolve_callee`, inspect
   the caller's current `predicates`. For each candidate
   `ReturnPathTransform`, check `PredicateSummary` compatibility with
   the caller's validated set. Apply only the compatible entries; join
   the applicable set.
4. **Merge logic for `GlobalSummaries`.** Name collisions across files:
   concatenate vectors, dedupe by `(predicate_hash, caps,
   validated_kinds)`. Respect the per-function cap.
5. **Unit tests.** Round-trip via serde; predicate-compatibility
   application; collision merge.
6. **Fixtures.** The three cross-file phi fixtures above.

### Verification

```bash
cargo test --workspace --all-features
cargo test --test integration_tests   # picks up new fixtures
cargo bench --bench scan_bench -- --save-baseline post-phase-cf-4
# Precision should rise on cross-file phi / branched-sanitiser cases.
```

### Definition of done

- [ ] `TaintTransform` is a bounded vector of per-return-path records.
- [ ] Pass 1 emits one entry per distinct return-path predicate per
      function.
- [ ] Pass 2 summary resolution applies predicate-consistent entries
      using the caller's current path-state.
- [ ] Three cross-file phi fixtures pass.
- [ ] Benchmark F1 within floor; precision improves on branched flows.

---

## Phase CF-5 — Cross-file SCC joint fixed-point

**Status:** Landed 2026-04-22 on `release/0.5.0`.  Additive shape:
`callgraph::scc_spans_files` helper plus `FileBatch.cross_file: bool`
(tighter than `has_mutual_recursion`); inline-cache lifecycle hooks
`inline_cache_clear_epoch` / `inline_cache_fingerprint` in
`taint::ssa_transfer`; cross-file-specific cap-hit note prefix
`SCC_UNCONVERGED_CROSS_FILE_NOTE_PREFIX` (strict superset of the
existing prefix).  Coverage: 3 cross-file SCC fixtures
(`cross_file_scc_mutual_recursion/_three_way_cycle/_recursive_with_sanitiser`)
wired through `tests/scc_cross_file_tests.rs`, plus callgraph unit
tests for the new flag, inline-cache unit tests for the lifecycle
hooks, and tag-variant unit tests for the new note prefix.  Benchmark
neutral (F1 unchanged at 0.966) — see `tests/benchmark/RESULTS.md`.
**Estimated effort:** 1 session
**Depends on:** CF-1, CF-2

### Project context

(See "Shared project context" at the top of this document.)

Additional context: `src/commands/scan.rs` (`run_topo_batches`,
`scc_file_batches_with_metadata`) today runs an SCC-level fixed-point
iteration capped at `MAX_SCC_FIXPOINT_ITERS = 3` and a hard safety cap at
`SCC_FIXPOINT_SAFETY_CAP = 64`. Iteration happens at **summary-map
granularity** — each iteration re-runs pass 2 on the SCC's files and
lets the summary union converge. Phase 2a added a low-confidence tag for
findings that hit the safety cap.

### Why this phase exists

Summary-level fixed-point is correct for the summary-based analysis, but
after CF-1 and CF-2 land, cross-file calls have the option of running
through full inline re-analysis, which is strictly more precise than the
summary. Without coordinated iteration, a mutually recursive SCC that
spans files will get summary-level convergence but will re-run inline
analysis on stale body snapshots. The joint fixed-point fixes this by
iterating at the level that combines summaries *and* inline-expanded
callee bodies.

### Files you will touch

- `src/commands/scan.rs` — extend `run_topo_batches` to (a) detect SCCs
  that cross files, (b) within those SCCs, iterate cross-file inline
  analysis alongside summary convergence, (c) use a richer convergence
  check that compares the inline cache's fixpoints across iterations,
  not just `GlobalSummaries`.
- `src/taint/ssa_transfer.rs` — expose the inline cache's state as a
  hashable snapshot so `run_topo_batches` can detect convergence. Add a
  `clear_epoch()` method to invalidate cached callee results between
  iterations.
- `src/callgraph.rs` — add a helper to enumerate SCCs that contain
  edges crossing files (vs pure intra-file SCCs). Reuse existing SCC
  detection.
- `tests/scc_cross_file_tests.rs` (new) — dedicated tests for cross-file
  SCCs with asserted convergence bounds.
- `tests/fixtures/cross_file_scc/` (new) — ~3 fixtures:
    - `mutual_recursion/` — two Python files, each calling a function
      in the other; one side taints, the other sinks. Requires joint
      iteration to find the flow precisely.
    - `three_way_cycle/` — three files. Convergence in ≤ 4
      iterations.
    - `recursive_with_sanitiser/` — cycle where one edge sanitises.
      Expect no finding after joint convergence; summary-only run
      produces FPs.

### Files you MUST NOT touch

- Summary data structures — CF-3 / CF-4 own those.
- Call graph construction — this phase only adds a read-only helper.
- Symex cross-file path — untouched.

### Tasks

1. **Cross-file SCC detection.** Add `scc_spans_files()` helper on the
   call graph. Pass 2 currently batches by SCC; augment the batch
   metadata with a `cross_file: bool` flag.
2. **Iteration loop.** Extend `run_topo_batches`. For each
   cross-file SCC, loop: (a) run pass 2 taint on all files in the SCC
   with current bodies + current cache, (b) collect the new inline
   cache entries, (c) compare to the previous iteration's fixed-point
   hash, (d) break on equality. Respect `MAX_SCC_FIXPOINT_ITERS = 3`
   as the default, allow CLI override via `--scc-max-iters` for
   experiments.
3. **Cache epoch invalidation.** Between iterations, stale cached
   inline results must be dropped. Add `clear_epoch()` on `InlineCache`
   and call it at the head of each iteration of a cross-file SCC.
4. **Convergence diagnostics.** If a cross-file SCC hits the safety cap,
   tag emitted findings as low-confidence with a note
   `"cross-file SCC did not converge within N iterations"`. Reuse the
   Phase 2a tag infrastructure.
5. **Fixtures and tests.** Assert exact iteration counts where
   possible. The mutual-recursion fixture should converge in exactly
   the number you measure on first run — pin it.
6. **Benchmark.** Verify no regression; the precision change on SCC-heavy
   corpora (if any) should be neutral or positive.

### Verification

```bash
cargo test --workspace --all-features
cargo test --test scc_cross_file_tests
cargo bench --bench scan_bench -- --save-baseline post-phase-cf-5
```

### Definition of done

- [ ] Cross-file SCCs are detected and iterated jointly.
- [ ] Inline cache is epoch-invalidated between iterations.
- [ ] Three cross-file SCC fixtures pass with pinned iteration bounds.
- [ ] Low-confidence tagging fires on cap-hit.
- [ ] Benchmark F1 within floor.

---

## Phase CF-6 — Parameter-granularity points-to summaries

**Status:** Not started
**Estimated effort:** 1 session
**Depends on:** CF-4 (summary structure already per-return-path)

### Project context

(See "Shared project context" at the top of this document.)

Additional context: Nyx currently has **no explicit alias modeling**.
Object-field taint is tracked per-field intra-procedurally, but any
summary collapses all fields and the caller sees a single "is this
parameter / return tainted?" answer. When a function mutates a shared
heap object through one parameter and that object is later read via
another alias, the flow is entirely lost across function boundaries.

### Why this phase exists

Whole-program points-to analysis is out of scope — too expensive, too
little ROI for a security scanner. But a minimal parameter-granularity
summary ("param 0 may alias return", "param 1 reaches the heap cell
pointed to by param 0") closes a real and common class of cross-file
flows that no prior phase addresses.

### Files you will touch

- `src/summary/` — add `PointsToSummary` to `SsaFuncSummary`. Minimum
  content: a `SmallVec<[AliasEdge; 4]>` where each edge is
  `(source: ParamOrReturn, target: ParamOrReturn, kind: MayAlias|MustAlias)`.
- `src/ssa/mod.rs` or `src/ssa/points_to.rs` (new) — a small
  flow-insensitive analysis over the SSA body that identifies aliasing
  between parameters and returns. Resist adding a full Steensgaard /
  Andersen solver; parameter-scope only, bounded depth.
- `src/taint/ssa_transfer.rs` — at call sites (summary path), when
  applying taint to a parameter, follow `MayAlias` edges in the
  callee's points-to summary to spread taint to aliased positions.
- `src/database.rs` — serde for the new summary field; engine-version
  bump.
- `tests/points_to_tests.rs` (new) — unit tests on small SSA bodies.
- `tests/fixtures/cross_file_alias/` (new) — ~3 fixtures:
    - `mutating_helper/` — Java. A helper in file A sets a field on its
      first argument; file B calls the helper with user input then reads
      another field from the same object. Taint must propagate through
      the aliased object.
    - `returned_alias/` — JS. Helper returns its first argument
      unchanged; caller uses the return as if fresh. Ensure taint is
      correctly propagated without duplicating findings.
    - `bounded_graph/` — Python. Five-node alias graph inside the helper,
      assert the bounded search doesn't explode.

### Files you MUST NOT touch

- Full points-to analysis machinery — this phase is intentionally
  limited to parameter scope.
- `src/constraint/` and `src/symex/` — heap reasoning there is a separate
  long-range project.

### Tasks

1. **Points-to domain.** Define a small, bounded alias graph type.
   `MayAlias` edges only — `MustAlias` inference is tempting but too
   expensive for this scope. Cap the edge count per summary (e.g. 8)
   and degrade to a conservative "param 0 reaches ⊤" fallback beyond
   the cap.
2. **Analysis.** One pass over the SSA body: whenever a parameter flows
   into a `StoreField` / `StoreIndex` and the base is itself a
   parameter (or derived from one), record an alias edge. Track
   parameter-to-return flow when the return op's base traces back to a
   parameter.
3. **Summary integration.** New `PointsToSummary` field on
   `SsaFuncSummary`. Serde + engine-version bump.
4. **Taint application.** In summary resolution, after applying the
   caller-to-callee taint, follow `MayAlias` edges to mark additional
   positions tainted. Do this *before* checking sinks.
5. **Fixtures.** Three cross-file alias cases. Confirm failure without
   the phase by stubbing the summary to empty.

### Verification

```bash
cargo test --workspace --all-features
cargo test --test points_to_tests
cargo bench --bench scan_bench -- --save-baseline post-phase-cf-6
```

### Definition of done

- [ ] `PointsToSummary` computed for every analysed function, bounded in
      size.
- [ ] Summary-path taint application follows may-alias edges.
- [ ] Three cross-file alias fixtures pass.
- [ ] Benchmark F1 within floor; recall improves on alias-mediated
      flows.

---

## Phase CF-7 — Demand-driven backwards analysis from sinks

**Status:** Not started
**Estimated effort:** 1 full session
**Depends on:** CF-1, CF-2, CF-3, CF-4

### Project context

(See "Shared project context" at the top of this document.)

Additional context: all prior phases are **forward** taint analysis —
start at sources, chase transfers to sinks. Forward analysis is
embarrassingly parallel (pass 2 runs files concurrently under rayon) but
spends analysis budget on many functions that never reach a sink. It
also imposes a hard precision ceiling: every edge on a long
source-to-sink chain must preserve enough precision to produce the
finding, because any single lossy edge drops it.

**Demand-driven backwards** analysis inverts the direction: start at
each sink, walk *reverse* call-graph edges, expand callees inline on
demand, and continue until a source is reached or the path is proven
infeasible. This aligns analysis budget with the actual question a
security scanner cares about ("does any source reach this sink?") and
naturally mixes summary-based and inline-based resolution based on
precision need.

### Why this phase exists

After CF-1..CF-6, the forward summary+inline path is as strong as the
architecture allows. To break through the remaining precision ceiling,
nyx needs a second analysis direction. The forward and backward
analyses are both sound; intersecting their findings gives the strongest
possible story. In the limit, the backward analysis can subsume the
forward one as the primary report path, but this phase does not commit
to that — it adds backwards as a co-equal mode first.

This is the biggest paradigm shift in the plan. Budget the session
accordingly.

### Files you will touch

- `src/taint/backwards.rs` (new) — the backward analysis. Core entry
  point: `fn analyse_sink_backwards(sink_site, global_summaries, ...)
  -> Vec<BackwardFlow>`. Uses the call graph's reverse edges.
- `src/taint/ssa_transfer.rs` — add a small "backwards transfer
  function" for SSA ops: given the taint demand at the result, compute
  the demand on operands. Most ops are simple; phis fan out; calls
  consult summaries or expand bodies on demand.
- `src/commands/scan.rs` — add a config / CLI switch
  `backwards_analysis` under `[analysis.engine]` (default: off for this
  phase, to keep the benchmark stable). When on, run pass 3 after pass
  2: for each sink finding, run the backwards analysis to confirm or
  add attribution detail.
- `src/taint/mod.rs` — merge forward + backward findings. Backward
  findings that confirm a forward finding get a confidence boost.
  Backward findings that have no forward counterpart are emitted as a
  separate rule category (`taint-demand-driven-*`) until the forward
  path catches up.
- `tests/fixtures/demand_driven/` (new) — ~4 fixtures:
    - `reach_source/` — confirms a known forward finding; asserts the
      backwards path produced a matching flow.
    - `prove_infeasible/` — path that forward analysis over-approximates
      as reaching; backwards rules it out via the accumulated path
      constraint.
    - `catch_new_fn/` — a flow forward misses (e.g. deep chain with a
      summary precision cliff) that backwards catches.
    - `no_source/` — sink with no feasible source; no finding in either
      direction.
- `tests/backwards_analysis_tests.rs` (new) — direct tests of the
  backward transfer and driver.
- `docs/advanced-analysis.md` — add a "Demand-driven analysis" section.

### Files you MUST NOT touch

- Forward taint core — this phase is additive. Do not re-plumb the
  forward path around backward's abstractions.
- Ranking / dedup code — finding merge happens at a later stage, before
  ranking.
- Symex — symex is compatible with backwards but wiring them together
  is a follow-up.

### Tasks

1. **Backwards transfer function.** For each `SsaOp`, define the demand
   transfer: given "this result is a sink-demanded value with cap C",
   what's the demand on operands? `Assign`: demand flows 1:1.
   `BinOp`: demand flows to both operands. `Phi`: demand fans out to
   all predecessor values. `Call`: consult summaries (reverse transforms
   from CF-4 decomposition) or inline-expand the callee body.
2. **Driver.** From each sink site, DFS backwards through SSA + call
   graph reverse edges. Track a `DemandState` that accumulates: the cap
   being demanded, the validated predicates, the abstract bounds that
   would suppress the flow, the set of inlined callees (for depth cap
   and cycle detection).
3. **Cross-file handling.** When a backwards walk hits a parameter, it
   must cross into the caller's callers via the reverse call graph.
   Use CF-1's persisted bodies to expand on demand. Cap inline depth
   (start with k=2; too low costs recall, too high costs budget).
4. **Path-constraint integration.** Reuse `src/constraint/` to prove
   path infeasibility. When the accumulated demand constraint is
   unsat, prune the walk. SMT stays optional.
5. **Finding emission.** Each backwards flow that reaches a source
   becomes a finding. Deduplicate against forward findings by
   `(sink_site, source_site, cap_bits)`. Confidence-boost confirmed
   forward findings.
6. **Off by default.** Gate behind `[analysis.engine].backwards_analysis
   = false` (and `--backwards-analysis` / `--no-backwards-analysis`).
   The benchmark runs with it off initially; a follow-up phase can
   tune and enable by default.
7. **Docs.** Extend `docs/advanced-analysis.md` with a "Demand-driven
   analysis" section. Note the precision / cost tradeoff.

### Verification

```bash
cargo build --all-features
cargo test --workspace --all-features
cargo test --test backwards_analysis_tests
# Run benchmark twice: with backwards off (default) and on.
cargo bench --bench scan_bench -- --save-baseline post-phase-cf-7-off
NYX_BACKWARDS=1 cargo bench --bench scan_bench -- --save-baseline post-phase-cf-7-on
# With off: no regression vs post-phase-cf-6.
# With on: precision improves or holds; recall should hold or improve.
```

### Definition of done

- [ ] Backwards transfer implemented for all `SsaOp` variants.
- [ ] Driver reaches across files via reverse call graph + on-demand
      body expansion.
- [ ] Four demand-driven fixtures pass.
- [ ] Feature is off by default; turning it on does not regress
      benchmark F1 vs the off run.
- [ ] `docs/advanced-analysis.md` documents the new mode.

---

## Final cross-file readiness checklist

After all seven phases land, cross-file analysis should satisfy the
following invariants. Use this list to validate the cumulative effect.

- [ ] `GlobalSummaries` carries both cross-file summaries *and* SSA
      bodies; both are consumed by the taint engine.
- [ ] k=1 context-sensitive inline re-analysis fires across file
      boundaries whenever bodies are available and the body-size budget
      permits.
- [ ] Abstract values (intervals, string prefixes, bit domains)
      propagate across file boundaries through summary transfer channels
      and inline re-analysis.
- [ ] Path-split structure inside a callee survives as a per-return-path
      transform vector that callers apply predicate-by-predicate.
- [ ] Cross-file SCCs converge jointly with coordinated summary + inline
      cache fixed-point; cap-hit findings are tagged low-confidence.
- [ ] Parameter-granularity points-to summaries close the most common
      alias-mediated flows.
- [ ] Demand-driven backwards analysis runs co-equal to forward; their
      intersection is the highest-confidence finding set.
- [ ] Benchmark F1 is meaningfully above the post-Phase-2 baseline;
      precision and recall should both improve as cross-file false
      positives drop and alias- / SCC-mediated true positives surface.
- [ ] Every switch (`context_sensitive`, `abstract_interpretation`,
      `backwards_analysis`) has a corresponding config field, CLI flag,
      and documented behaviour in `docs/advanced-analysis.md`.

If any invariant fails, land a follow-up phase before declaring
cross-file "strong."
