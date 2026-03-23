# Phase 14: Formal Points-To / Pointer Analysis

## Overview

Phase 14 introduces bounded intra-procedural points-to analysis for heap-backed container taint propagation. This replaces the previous approach of merging taint directly onto container SSA values with a formal system that tracks abstract heap object identity through allocation sites.

## Architecture

```
SSA Optimization Pipeline (src/ssa/mod.rs):
  const_prop -> branch_prune -> copy_prop -> alias -> DCE -> type_facts -> points_to

Taint Transfer (src/taint/ssa_transfer.rs):
  SsaTaintState.heap: HeapState    (per-heap-object taint lattice)
  SsaTaintTransfer.points_to: &PointsToResult  (pre-computed points-to sets)
```

### Key Insight

SSA form guarantees unique identifiers per definition. When `items = []` creates `SsaValue(5)` and `items = []` (reassignment) creates `SsaValue(12)`, they are naturally distinct. `b = a` in SSA means `b`'s SsaValue receives `a`'s through Assign/Phi. This allows `HeapObjectId = SsaValue` with zero additional overhead.

## Data Structures (`src/ssa/heap.rs`)

| Type | Description |
|------|-------------|
| `HeapObjectId(SsaValue)` | Abstract heap object keyed by allocation site |
| `PointsToSet` | Bounded sorted set of HeapObjectId (max 8) |
| `HeapTaint { caps, origins }` | Per-object stored taint |
| `HeapState` | Sorted map HeapObjectId -> HeapTaint |
| `PointsToResult` | HashMap<SsaValue, PointsToSet> |

## Boundedness Strategy

- **MAX_POINTSTO = 8**: Per-SSA-value points-to set cap. Union truncates excess.
- **MAX_HEAP_ORIGINS = 4**: Per-object origin list cap (matches MAX_ORIGINS).
- **10-round iteration cap**: Forward propagation fixed-point limit.
- **Sparse representation**: Only container-typed values get PointsToSet entries.

When bounds are exceeded, the system degrades gracefully to the fallback path (direct SSA value taint).

## Allocation Site Detection

Container allocations are detected by:
1. `SsaOp::Const(Some(text))` where text matches `[]`, `{}`, `new ...`, `dict()`, etc.
2. `SsaOp::Call { callee }` where callee is a known container constructor (per-language: ArrayList, Map, Set, list, dict, Vec::new, etc.)

## Solver Algorithm

1. **Seed**: Walk all instructions, create `HeapObjectId(inst.value)` for allocation sites
2. **Propagate** (forward, max 10 rounds):
   - `Assign([x])`: pts(result) = pts(x)
   - `Assign([x, y, ...])`: pts(result) = union(pts(x), pts(y), ...)
   - `Phi(operands)`: pts(result) = union of all operand pts
   - `Call` + Store op (Go append): pts(result) = pts(receiver)
3. **Converge**: Fixed-point when no entries change

## Container Taint Flow

**Store** (`items.push(val)`):
- Look up `pts(items)` -> PointsToSet
- For each HeapObjectId in the set, monotone-merge val's taint into `state.heap`
- Fallback: if no pts entry, merge directly into SSA value (backward compatible)

**Load** (`items.pop()`, `items.join('')`):
- Look up `pts(items)` -> PointsToSet
- Union taint from all heap objects in the set -> result value
- Fallback: copy SSA value taint directly

**Sink** (`exec(container_var)`):
- After normal taint check, also check `state.heap.load_set(pts(v))` for container arguments

## Supported Behavior

| Scenario | Result |
|----------|--------|
| `b = a; a.push(source); sink(b.join(''))` | Detected (shared HeapObjectId) |
| `b = a; a = []; b.push(source); sink(a.join(''))` | Not detected (different HeapObjectIds) |
| `items.push(source); sink(items.join(''))` | Detected (same HeapObjectId, store then load) |
| `items.push(safe_const); sink(items.join(''))` | Not detected (no taint stored) |

## Current Limitations

- **Intra-procedural only**: No cross-function heap identity propagation
- **No field sensitivity**: Object fields not tracked individually (whole-object taint)
- **No index sensitivity**: Array elements not distinguished by index
- **Max 8 aliases**: Points-to sets capped; excess causes precision loss
- **Conservative for unknown callees**: Functions without summary use fallback path

## Future Extension (Stubs in SsaFuncSummary)

Two stub fields prepared for inter-procedural heap analysis:
- `param_container_to_return: Vec<usize>` — which params' container identity flows to return
- `param_to_container_store: Vec<(usize, usize)>` — which params' taint stored into which container params

## Files

| File | Role |
|------|------|
| `src/ssa/heap.rs` | Core module: types, solver, allocation detection |
| `src/ssa/pointsto.rs` | Container constructor detection |
| `src/ssa/mod.rs` | Pipeline integration |
| `src/taint/ssa_transfer.rs` | Taint transfer integration |
| `src/taint/mod.rs` | Transfer construction threading |
| `src/summary/ssa_summary.rs` | Summary extension stubs |
