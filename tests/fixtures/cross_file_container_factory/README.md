# cross_file_container_factory — cross-file container factory + filler

## Flow
`factory.js` exports two helpers:
- `makeBag()` returns a fresh `[]`.
- `fillBag(bag, val)` calls `bag.push(val)` and returns `bag`.

`app.js` composes them — `makeBag()` produces the container, `fillBag()`
stores a tainted environment value into it, and `exec(bag[0])` sinks the
tainted subscript read as a shell command.

## Why this fixture exists (Phase 11)
Covers the factory-pattern cross-file container gap closed by
`PointsToSummary.returns_fresh_alloc`:

- `makeBag` emits `returns_fresh_alloc = true` so the caller synthesises
  a `HeapObjectId` keyed on the call's SSA value.
- `fillBag` emits `param_to_container_store: [(1, 0)]` (val taint stored
  into bag) plus a `Param(0) → Return` alias edge.

Without the fresh-alloc channel the caller's `bag` has no heap identity,
`fillBag`'s `param_to_container_store` replay finds no heap cell to
write into, and `bag[0]` reads back nothing — a false negative that
Phase 11 closes.

Expected finding: `taint-unsanitised-flow` from `process.env.INPUT`
(Source) to `child_process.exec` (Sink) via the cross-file factory +
filler chain.
