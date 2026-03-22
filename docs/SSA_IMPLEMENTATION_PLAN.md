# SSA Implementation Plan — Full Legacy Replacement

> Goal: Make the SSA path the sole taint analysis engine, fully replacing the legacy
> (non-SSA) path for all 10 languages, with equivalent or better detection.

## Current State

**What exists:**
- SSA IR (`src/ssa/ir.rs`): `SsaOp`, `SsaInst`, `Terminator`, `SsaBlock`, `SsaBody`
- Lowering (`src/ssa/lower.rs`): Cytron phi insertion, dominator-tree renaming, scope/nop modes
- SSA taint (`src/taint/ssa_transfer.rs`): block-level worklist, value-keyed lattice, sink detection
- JS two-level solve (`analyse_ssa_js_two_level` in `taint/mod.rs`): per-function SSA bodies seeded from top-level
- Integration gate: SSA is default for non-JS/TS; JS/TS opt-in via `NYX_SSA_JS=1`

**Test status:** 418 unit tests pass, 243 corpus fixtures tested.
11 non-JS/TS divergences, 0 JS/TS divergences (with SSA JS enabled).

**Divergences by root cause:**

| # | Category | Fixtures | SSA behaviour |
|---|----------|----------|---------------|
| 1 | **Taint through string ops** (concat, format) | Go cmdi_http (L18,L20), Go sqli_sprintf (L25) | SSA loses taint across `"prefix " + var` and `Sprintf(fmt, var)` — missing findings |
| 2 | **Exception-path taint flow** | Java deser_cmdi (L8), Java try_catch_sqli (L12), Java xss_response (L17) | Exception edges stripped; catch/multi-method taint lost — missing/wrong findings |
| 3 | **Call with labels skips summary** | PHP ssrf_file_get_contents (L4) | Dual-label call (Source+Sink) skips `resolve_callee()` — emits `cfg-unguarded-sink` instead of `taint-unsanitised-flow` |
| 4 | **Predicate over-suppression** | C cmdi_getenv (L14), C++ cmdi_system (L14), Rust env_to_command (L17) | `strcmp`/`contains` classified as validation → taint killed on "validated" branch; legacy correctly still reports |
| 5 | **Argument-position taint loss** | Python cmdi_subprocess (L18), Python sqli_concat (L19) | Taint from arg position not tracked through call boundary — missing findings |

---

## Phase 1: Fix Critical Transfer Bugs (11 → ≤0 divergences)

These are logic bugs in `ssa_transfer.rs` where the SSA path deviates from legacy semantics.
Each fix is small, targeted, and independently testable.

### 1.1 — Always resolve callee for calls with labels

**File:** `src/taint/ssa_transfer.rs` lines 649–701

**Bug:** When `has_label` (Source or Sanitizer label exists), `resolve_callee()` is skipped entirely.
Legacy always runs `apply_call()` even when labels are present (for propagation/summary sanitizers).

**Fix:** Remove the `if !has_label` guard on callee resolution. Only skip the summary's
*source* caps when explicit Source labels are present (labels take precedence for source behaviour).
Always apply summary propagation and summary sanitizer caps.

```
// Pseudocode of correct logic:
let has_source_label = any Source label;
let has_sanitizer_label = any Sanitizer label;

if let Some(resolved) = resolve_callee(...) {
    // Source caps from summary: only if no explicit Source label
    if !has_source_label && !resolved.source_caps.is_empty() {
        return_bits |= resolved.source_caps;
        push origin...
    }

    // Propagation: ALWAYS apply (this is the critical fix)
    if resolved.propagates_taint {
        let (prop_caps, prop_origins) = collect_args_taint(...);
        return_bits |= prop_caps;
        merge origins...
    }

    // Summary sanitizer: ALWAYS apply
    return_bits &= !resolved.sanitizer_caps;
}

// Explicit sanitizer labels: applied on top (already correct)
if has_sanitizer_label {
    let (use_caps, use_origins) = collect_args_taint(args, receiver, state, &[]);
    return_bits |= use_caps;
    return_bits &= !sanitizer_bits;
}
```

**Expected impact:** Fixes PHP `ssrf_file_get_contents` divergence (dual-label Source+Sink).

**Verification:** Add test with dual-label function. Run equivalence test.

---

### 1.2 — String concatenation and format taint propagation

**Files:** `src/ssa/lower.rs`, `src/taint/ssa_transfer.rs`

**Bug:** Binary expressions like `"prefix " + tainted_var` produce an `SsaOp::Assign` with the
tainted variable in `uses`, but the SSA value for the concatenation result may not carry taint
to the call site because the concatenation node's `defines` doesn't map to the call's `arg_uses`.

**Investigation steps:**
1. Add `NYX_SSA_DEBUG=1` env var to dump SSA body + per-block taint state for a given file
2. Trace Go `exec.Command("sh", "-c", "ping -c 1 "+host)`:
   - Does the concat node define a temp variable?
   - Does that temp flow into the call's `arg_uses`?
   - If `arg_uses` contains only the direct identifier (not the temp), taint is lost
3. Trace Go `fmt.Sprintf("SELECT ... '%s'", userId)`:
   - Does Sprintf's return value carry taint from `userId`?
   - Is the Sprintf node labeled with `propagates_taint` in the summary?

**Fix approach (depends on investigation):**
- If the CFG correctly captures the data flow but SSA lowering loses it: fix lowering
- If the CFG doesn't capture temp variables from string ops: fix `push_node()` in `cfg.rs`
- If the summary for Sprintf is missing `propagating_params`: fix Go label rules

**Expected impact:** Fixes Go cmdi_http (L18, L20), Go sqli_sprintf (L25).

---

### 1.3 — Predicate classification precision

**Files:** `src/taint/path_state.rs` (`classify_condition`), `src/taint/ssa_transfer.rs`

**Bug:** `classify_condition()` may classify `strcmp(cmd, "ls") == 0` and `allowed.contains(&cmd)`
as `ValidationCall` because the function name matches a comparison/check pattern. This causes
`apply_branch_predicates` to mark the tainted variable as `validated_may` on the true branch,
and subsequent sink checks see `all_validated=true` → finding suppressed.

**Investigation steps:**
1. Check what `classify_condition` returns for these condition texts
2. Trace the SSA taint state at the sink node for C/C++/Rust fixtures
3. Check if `validated_may` actually contains the tainted var's SymbolId
4. Compare with legacy state at same node — legacy uses the same `classify_condition`,
   so why doesn't it suppress?

**Hypothesis:** The difference may not be in predicate classification but in how SSA's
block-level phi merging preserves or loses validation state compared to legacy's per-node
join. Legacy may merge validated and non-validated paths, while SSA's precise phi tracking
keeps validation on the "validated" branch only.

**Fix approaches (depending on investigation):**
- If `classify_condition` over-matches: narrow to explicit validation function names
- If the issue is phi merging semantics: adjust SSA predicate join behaviour
- If SSA correctly identifies validated code as safe: update the expect files
  (SSA is *more precise* than legacy — this is an improvement, not a bug)

**Expected impact:** Fixes or reclassifies C, C++, Rust divergences (3 fixtures).

---

### 1.4 — Argument-position taint through calls

**Files:** `src/taint/ssa_transfer.rs`, potentially `src/ssa/lower.rs`

**Bug:** Python subprocess and SQL query calls lose taint from argument positions.

**Investigation steps:**
1. Trace Python `subprocess.run(cmd, shell=True, capture_output=True)` through SSA
2. Check if `cmd` reaches the Call's `args[0]` as an SsaValue
3. Check if the Call's `arg_uses` and `propagating_params` are correctly mapped
4. For `cursor.execute("SELECT ... " + user_id)`: verify concat flows to arg

**Fix (depends on investigation):** Likely same root cause as 1.2 (string concat) or
a positional offset issue in `collect_args_taint()`.

**Expected impact:** Fixes Python cmdi_subprocess (L18), Python sqli_concat (L19).

---

### 1.5 — Exception-path taint seeding

**Files:** `src/taint/ssa_transfer.rs`, `src/ssa/lower.rs`

**Bug:** Exception edges are stripped during SSA lowering. Catch blocks become orphan blocks
initialized with `SsaTaintState::initial()` (empty). This means taint from the try body
doesn't flow into catch handlers.

**Impact:** Java deser_cmdi (L8), Java try_catch_sqli (L12), Java xss_response (L17).

**Fix approach — seed catch blocks from try-body state:**

Rather than modifying the SSA IR to add exception edge terminators (complex, risks destabilizing
the phi/dominator structure), seed orphan catch blocks with taint from their associated try body.

1. During `collect_reachable()`, record which exception edges exist: `(source_node, catch_entry)`
2. Store this mapping in `SsaBody` as `exception_edges: Vec<(NodeIndex, BlockId)>`
3. In `run_ssa_taint_full()`, after Phase 1 convergence:
   - For each exception edge, find the block containing `source_node`
   - Get the converged exit state of that block
   - Clear predicates (matches legacy exception edge semantics)
   - Join this state into the catch block's entry state
   - Re-add the catch block to the worklist
4. Iterate until catch blocks also converge

**Alternative (simpler):** During Phase 1 iteration, when processing a block that contains
a node with an exception edge, proactively push the current taint state (minus predicates)
to the catch block entry. This integrates naturally into the existing worklist.

**Expected impact:** Fixes all 3 Java divergences.

---

## Phase 2: JS/TS SSA Default & Validation (0 divergences → production ready)

### 2.1 — Enable SSA JS/TS by default

Currently JS/TS SSA two-level is opt-in via `NYX_SSA_JS=1`. The equivalence test shows
0 JS/TS divergences when enabled.

**Steps:**
1. Flip default in `analyse_file()`: use SSA for JS/TS, legacy opt-in via `NYX_LEGACY=1`
2. Remove `NYX_SSA_JS` env var
3. Run full test suite + equivalence tests
4. Run benchmark suite to verify no performance regression

### 2.2 — Comprehensive equivalence verification

Before removing legacy code:
1. Add 20+ new taint fixtures covering edge cases:
   - Dual-label calls (Source+Sink, Source+Sanitizer, Sanitizer+Sink)
   - Try-catch with taint in catch handler
   - Nested function calls with string concatenation
   - Multi-method classes (Java, Python)
   - Chained method calls with taint
2. Run equivalence test with `KNOWN_DIVERGENCE_BASELINE: 0`
3. Run on 3+ open-source projects as regression test

---

## Phase 3: SSA-Enabled Precision Improvements

These go beyond legacy equivalence and make SSA *better*.

### 3.1 — Constant propagation

**New file:** `src/ssa/const_prop.rs`

Track `SsaValue → ConstValue` lattice:
```rust
enum ConstValue {
    Top,              // unknown
    Known(String),    // known string literal
    KnownInt(i64),    // known integer
    Bottom,           // unreachable
}
```

**Applications:**
- **Unreachable branch pruning:** If a Branch condition is constant, only visit the taken branch.
  Reduces false positives from dead code paths.
- **Literal sink suppression:** More precise than `all_args_literal` flag — can detect when a
  specific argument position is constant even if others aren't.
- **Gated sink activation:** Resolve `setAttribute("onclick", value)` vs `setAttribute("class", value)`
  via constant arg without `extract_const_string_arg()` heuristic.

**Algorithm:** Standard SSA constant propagation (Wegman-Zadeck):
1. Initialize all SsaValues to Top
2. For Const ops: set to known value
3. For Phi: meet of operands (same → known, different → Top)
4. For Assign/Call: evaluate if all operands known, else Top
5. Worklist until fixed-point

### 3.2 — Dead definition elimination

**File:** `src/ssa/dce.rs` or integrated into lowering

Identify SsaValues with no uses (not referenced by any other instruction, phi operand, or
terminator condition). Remove dead definitions.

**Benefits:**
- Smaller SSA bodies → faster taint analysis
- Eliminates noise from unused variable assignments
- Particularly useful for languages with verbose boilerplate (Java)

**Algorithm:**
1. Build use-count map: for each SsaValue, count references in all instructions + phis
2. Remove instructions with use_count == 0 (except Source, Call with side effects, CatchParam)
3. Iterate until no more removals

### 3.3 — Copy propagation

Replace `v2 = v1` (Assign with single use) with direct use of `v1` in all consumers.

**Benefits:**
- Shorter def-use chains → faster taint convergence
- More precise phi operands (fewer intermediate variables)

**Algorithm:**
1. For each `Assign([single_use])` instruction
2. Replace all uses of `inst.value` with `single_use` throughout the SSA body
3. Mark the copy instruction as dead (cleaned up by DCE)

### 3.4 — Type facts on SSA values

Attach type information inferred from context:
```rust
struct TypeFact {
    kind: TypeKind,    // String, Int, Bool, Object, Array, Null, Unknown
    nullable: bool,
}
```

**Sources of type facts:**
- Const ops: literal type
- Source ops: language-specific return types (e.g., `getenv()` → `String?`)
- Call ops: known return types from summaries
- Phi ops: meet of operand types

**Applications:**
- Type-aware sink classification (SQL injection only relevant for String types)
- Better null-check predicate tracking (type narrowing after null check)

---

## Phase 4: Memory SSA and Heap Tracking

### 4.1 — Memory SSA for field access

**New module:** `src/ssa/memory_ssa.rs`

Model object field assignments with memory SSA:
```rust
enum MemoryOp {
    MemoryDef(SsaValue),                      // obj.field = value
    MemoryUse(SsaValue),                      // x = obj.field
    MemoryPhi(Vec<(BlockId, SsaValue)>),      // merge at join points
}
```

**Why:** Current SSA tracks variables by name, but `obj.field = tainted` followed by
`sink(obj.field)` loses the connection because `obj` and `obj.field` are different "variables".

**Design:**
- Each field access `obj.field` gets a MemoryDef/MemoryUse
- MemoryPhi at dominance frontiers for the field
- Taint transfer: MemoryDef propagates taint to the field, MemoryUse reads it

**Scope:** Start with single-level field access (obj.field), extend to chains (obj.a.b) later.

### 4.2 — Interprocedural SSA summaries

Replace coarse-grained `FuncSummary` (cap-based) with SSA-based summaries:
```rust
struct SsaFuncSummary {
    param_to_return: Vec<(usize, TaintTransform)>,
    param_to_sink: Vec<(usize, Cap)>,
    field_effects: Vec<FieldEffect>,
}

enum TaintTransform {
    Identity,              // param flows unchanged
    StripBits(Cap),        // param flows minus sanitizer bits
    AddBits(Cap),          // param gains source bits
}
```

**Benefits:**
- More precise cross-function taint (knows exactly which bits survive)
- Can express "param 0 flows to return but loses HTML_ESCAPE bit"
- Enables bottom-up taint propagation via call graph

---

## Phase 5: Advanced Analysis

### 5.1 — Path sensitivity via phi structure

Use phi/block structure to determine which branch contributes taint at each merge:
```rust
// At a phi: v5 = phi(B2:v3, B4:v4)
// If v3 is tainted (from true branch) and v4 is not (from false branch),
// we know the taint comes from the true path.
// If the true path has a validation check, we can suppress.
```

Replaces `validated_must`/`validated_may` with structural path sensitivity.

### 5.2 — Loop induction variable optimisation

Detect loop-carried phis where back-edge operand is a simple increment:
```rust
// v3 = phi(B0:v1, B1:v2)  where v2 = v3 + 1
// Induction variable — cannot gain taint from loop body
```

Prune these from taint analysis to avoid false back-edge taint propagation.

### 5.3 — Short-circuit boolean SSA

Lower `a && b` / `a || b` into proper SSA blocks with phi merges:
```
B0: branch(a) → B1(true), B2(false)
B1: branch(b) → B3(true), B2(false)
B2: v_result = phi(B0: false, B1: false)
B3: v_result = phi(B1: true)
```

Enables per-condition predicate tracking.

---

## Phase 6: Legacy Removal

### 6.1 — Remove legacy code

Once divergence count is 0 and SSA is default for all languages:
1. Remove `TaintTransfer` struct and `impl Transfer<TaintState>` from `transfer.rs`
2. Remove `TaintState` lattice (keep `VarTaint` — shared with SSA)
3. Remove `analyse_js_two_level()` legacy function
4. Remove `run_forward()` engine (check if `DefaultTransfer` still needs it)
5. Remove `NYX_LEGACY` env var gate
6. Simplify `analyse_file()` to single SSA path

### 6.2 — Clean up SSA tech debt

- Embed needed NodeInfo fields directly in SSA ops (remove cfg_node backreference dependency)
- Unify `SsaTaintEvent` and `TaintEvent` into single type
- Remove `extract_ssa_exit_state()` projection (make SSA state canonical)
- Inline `ssa_events_to_findings()` into `events_to_findings()`

---

## Implementation Order & Dependencies

```
Phase 1 (no deps, highest ROI — target: 11 → 0 divergences)
  1.1 Fix callee resolution for labeled calls     ← 1 fixture
  1.2 String concat taint propagation              ← 4 fixtures
  1.3 Predicate classification precision           ← 3 fixtures (may be reclassified as SSA improvements)
  1.4 Argument-position taint through calls        ← 2 fixtures (likely same root cause as 1.2)
  1.5 Exception-path taint seeding                 ← 3 fixtures

Phase 2 (after Phase 1, confirm 0 divergences)
  2.1 Enable SSA JS/TS by default                  ← flag flip
  2.2 Comprehensive equivalence verification       ← new fixtures

Phase 3 (independent of Phase 2, SSA-only improvements)
  3.1 Constant propagation
  3.2 Dead definition elimination
  3.3 Copy propagation
  3.4 Type facts

Phase 4 (depends on Phase 3 infrastructure)
  4.1 Memory SSA
  4.2 Interprocedural SSA summaries

Phase 5 (depends on Phase 3+4)
  5.1 Path sensitivity via phis
  5.2 Loop induction optimization
  5.3 Short-circuit boolean SSA

Phase 6 (after Phase 1+2, 0 divergences confirmed)
  6.1 Remove legacy code
  6.2 SSA tech debt cleanup
```

## Verification Strategy

Each phase must:

1. **Unit tests:** Add targeted tests for each fix/feature in `src/taint/tests.rs`
2. **Equivalence test:** Run `cargo test --test ssa_equivalence_tests -- --test-threads=1`
   — divergence count must decrease (never increase)
3. **Expect files:** Update `.expect.json` if SSA produces *better* results (document in commit)
4. **Benchmark:** Run `cargo bench` to check for performance regression
5. **Full suite:** All 418+ unit tests must pass before merge

Target: Phase 1 brings divergences from 11 → 0. Phase 2 confirms production readiness.
Phase 3+ improves detection beyond what legacy could achieve.
