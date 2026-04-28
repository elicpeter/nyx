# Deferred CVEs

This file tracks CVE pairs that **live in `cve_corpus/`** and are
**referenced in `ground_truth.json` with `disabled: true`**, but are not
yet counted toward recall because the engine fix they need is too large
to land in a single hunt session.

Each session reads this file FIRST. If a deferred item has become
tractable (the named blocker landed, or you have a new approach to the
deep fix), resolve it before adding new CVEs.

## Format

```
### CVE-YYYY-NNNN — <one-line title>

- **Language / class**: <lang> / <vuln-class>
- **Deferred**: YYYY-MM-DD by <session topic>
- **Engine gap**: <one-paragraph explanation of what the engine is missing>
- **Why shallow fix is unacceptable**: <why we can't bandage>
- **Deep fix sketch**: <what would actually fix this — module(s) touched, scope>
- **Tracking**: ground_truth case_id `<id>`; fixture
  `cve_corpus/<lang>/CVE-YYYY-NNNN/`
```

## Open

### CVE-2024-31450 — Owncast emoji-delete path traversal (Go)

- **Language / class**: go / path_traversal
- **Deferred**: 2026-04-28 by Go hunt session 2; reduced 2026-04-28 by
  session 4 (two of three sub-gaps landed; chained-call lowering
  remains).
- **Engine gap (session 4 update)**: The deferred entry was
  diagnosed as a single bridge problem (writeback writes Heap-Elements
  but FieldProj reads field-cells). Session 4 found the chain has
  three independent gaps that all conspire to suppress this CVE; two
  are now fixed in-tree, one remains.
  1. **(LANDED 2026-04-28)** Field-cell wildcard bridge.
     `ContainerOp::Writeback` now writes
     `(loc, FieldId::ANY_FIELD)` cells for every `loc ∈
     pointer_facts.pt(dest_arg)`. `SsaOp::FieldProj` reads the
     `(loc, *field)` cell first and falls back to
     `(loc, ANY_FIELD)` when the specific cell is absent. ANY_FIELD
     is a new sentinel (`FieldId(u32::MAX - 1)`), distinct from
     `ELEM`, so container-element writes don't pollute struct
     reads. Verified end-to-end via the test_decode2 split form
     (`dec := json.NewDecoder(r.Body); dec.Decode(body); …
     body.Field`) when the body is parseable as separate Calls and
     Go emits FieldProj for the access. (Currently a dead path for
     Owncast because of gap (3), but covered by lib tests and a
     forward-looking improvement.)
  2. **(LANDED 2026-04-28)** Go `if init; cond { }` CFG lowering.
     Tree-sitter exposes the init under the `initializer` field of
     `if_statement`, but `Kind::If` in `src/cfg/mod.rs` ignored it,
     so calls inside `if err := f(); err != nil` disappeared from
     the CFG. Now lowers the init via `build_sub` against the
     incoming `preds` and uses its exits as the condition's
     predecessors. Verified by `tests/benchmark/corpus/go/
     path_traversal/path_traversal_ifinit.go` (vulnerable +
     patched). Pre-fix this fixture had 0 taint findings; post-fix
     `taint-unsanitised-flow` fires on the vulnerable, patched
     stays clean (sanitized via `filepath.Base`).
  3. **(STILL DEFERRED — chained method-call lowering)**
     `json.NewDecoder(r.Body).Decode(emoji)` lowers as a single
     `SsaOp::Call` with callee text
     `"json.NewDecoder(r.Body).Decode"` rather than two separate
     calls (an inner `json.NewDecoder` whose result is the
     receiver of an outer `.Decode`). The inner call's source-flow
     never gets its own SSA value, so the outer `.Decode` has no
     receiver SSA to reference and the writeback's
     `recv_val` resolution fails ("writeback: no receiver SSA
     value for callee `json.NewDecoder(r.Body).Decode`"). This
     is the same chain shape JS handles via
     `find_chained_inner_call` for inner-gate label classification
     — but that helper rebinds the *callee text* of the outer
     call, it does not split the chain into separate SSA Call ops.
     For taint to flow through `inner.result → outer.receiver`,
     the SSA needs each call as a distinct SsaOp::Call.
- **Deep fix sketch (remaining gap 3)**:
  1. In `Kind::CallFn / Kind::CallMethod / Kind::CallMacro` of
     `build_sub`, before pushing the outer call's CFG node, walk
     the function/method receiver. If the receiver is itself a
     CallFn/CallMethod, recursively lower it first (push its own
     CFG node connected to `preds`), then use its exits as the
     outer call's `preds`. The outer call's receiver-SSA channel
     should reference the inner call's return value — which would
     also fix the writeback receiver-resolution path, since the
     receiver SSA value would now exist.
  2. Repeat for Go's `for init; cond; post { }` loops where init
     might also have side effects (`for k, v := range f()` and
     similar).
  3. Audit existing JS/TS tests that depend on chained calls
     resolving as a single Call op (the
     `find_chained_inner_call`-using paths). The SSA split is
     additive only when receiver-resolution works; if it breaks
     existing label classification, gate the split per-language
     and start with Go.
- **Why shallow fix is unacceptable**: A bandaid recognizer that
  hardcodes `os.Remove(filepath.Join(_, dest.Field))` would not help
  the next CVE in this shape, and Go HTTP CRUD handlers overwhelmingly
  use the `json.NewDecoder(r.Body).Decode(&dest)` source pattern.
  Three of the five Go CVE candidates surveyed in session 2 sit on
  the same chained-call lowering gap.
- **Tracking**: ground_truth case_ids `cve-go-2024-31450-vulnerable`,
  `cve-go-2024-31450-patched`; fixture
  `cve_corpus/go/CVE-2024-31450/`; regression fixtures
  `tests/benchmark/corpus/go/path_traversal/path_traversal_ifinit.go`
  and `safe_path_traversal_ifinit.go` (gap 2 verifier);
  `FieldId::ANY_FIELD` sentinel in `src/ssa/ir.rs` (gap 1).

### Historical sub-gaps for CVE-2025-64430 (resolved)

These four engine bugs from the original deferred entry have been
fixed. The CVE chain still does not fire end-to-end because of the
remaining transitive-summary-propagation gap above, but each fix is
a real engine improvement that benefits many other patterns and is
covered by regression tests in `src/taint/tests.rs::cve_2025_64430_*`.

1. **Single-param arrow shorthand had no formal params.** For
   `helper = uri => ...`, tree-sitter exposes the lone identifier
   under the singular `parameter` field rather than wrapping it in
   `formal_parameters`. `extract_param_meta` only consulted the
   plural `parameters` field, so `helper` appeared parameterless to
   the SSA pipeline and cross-function `param_to_sink` resolution
   missed every single-arg arrow helper. Fixed in
   `src/cfg/params.rs::extract_param_meta` with an arrow-function
   fallback to the singular `parameter` field.
2. **Wrapper-with-member-source arg lost cross-function sink
   resolution.** When `first_member_label` rebinds `info.call.callee`
   from `"helper"` to `"req.body.uri"` (so the source label applies)
   and stashes the actual function name in `outer_callee`,
   `resolve_sink_info` only consulted the inner callee. The
   wrapper's `param_to_sink: [(0, SSRF)]` summary was never reached.
   Fixed in `src/taint/ssa_transfer/mod.rs::resolve_sink_info` with
   a strict-additive `outer_callee` fallback that fires only when
   the primary inner-callee resolution produced no sink caps. The
   originally-suspected gap ("gated-sink events do not populate
   `param_to_sink`") was a misdiagnosis: probing `helper(uri) {
   http.get(uri); }` directly produces
   `param_to_sink: [(0, [SinkSite{cap: SSRF}])]` correctly.
3. **Nested arrow callbacks inside `return new Promise(...)` were
   never extracted as bodies.** `cfg/mod.rs`'s Kind::Return arm
   pushed a Call+Return pair but did not call
   `collect_nested_function_nodes`, so any arrow function passed to
   the returned call (Promise executor, `then`/`catch` callbacks,
   etc.) silently disappeared. The CallWrapper / CallFn arms already
   did this. Fixed in `src/cfg/mod.rs` Kind::Return and Kind::Throw
   arms with the same nested-function recursion pattern. The
   lexical-containment closure-capture path in `analyse_multi_body`
   then propagates parent-scope taint into the executor body — so
   when the parent param is auto-seeded (e.g. matches
   `is_js_ts_handler_param_name`) the inner gated http.get sink fires.
4. **Closure-captured params were invisible to the parent's
   `param_to_sink` summary.** `extract_ssa_func_summary` runs on a
   single SSA body; its per-param probe couldn't see sinks living
   in lexically contained child bodies (Promise executors, callback
   arrows). Fixed by adding an `augment_summaries_with_child_sinks`
   pass in `src/taint/mod.rs::lower_all_functions_from_bodies` that
   runs each parent-param probe AND re-runs each child body's
   analysis with the parent's exit state seeded as `global_seed`,
   then ORs the resulting child sink events into the parent's
   `param_to_sink` / `param_to_sink_param`. Single-hop sink wrappers
   (`f(x) { return new Promise(() => http.get(x)) }` called from
   `helper(req.body.uri)`) now detect end-to-end. Also added a
   namespace-tolerant fallback in
   `resolve_callee_full`'s step-0 SSA summary lookup so the
   single-file scan path (where `ssa_summaries` keys use a
   normalised-empty namespace and `local_summaries` keys use the
   raw file path) finds intra-file SSA summaries.

- **Tracking**: ground_truth case_ids `cve-js-2025-64430-vulnerable`,
  `cve-js-2025-64430-patched`; fixture
  `cve_corpus/javascript/CVE-2025-64430/`; regression tests
  `src/taint/tests.rs::cve_2025_64430_*`

## Resolved

### CVE-2025-64430 — Parse Server SSRF via http.get(uri)

- **Language / class**: javascript / ssrf
- **Resolved**: 2026-04-29 by JS hunt session 3 (sub-gaps 5 and 6).
- **Final fixes** (in addition to the four "Resolved sub-gaps" from
  2026-04-28 above):
  5. **Transitive cross-function summary propagation (depth ≥ 2).**
     `lower_all_functions_from_bodies` now runs a second extraction
     pass after `augment_summaries_with_child_sinks`. The new
     `extract_ssa_func_summary_full(..., ssa_summaries: Some(&...))`
     variant lets per-parameter probes resolve callee SSA summaries
     via step 0 of `resolve_callee_full`, so a caller of a
     single-hop sink wrapper picks up the augmented `param_to_sink`
     and propagates it onto its own summary. Sink-only fields are
     OR-merged into existing summaries via `merge_sink_fields`,
     preserving augment-populated entries. Bounded: one
     re-extraction per body. Strict-additive.
     - **Critical sub-fix uncovered along the way:** the previous
       session's diagnosis was a misdirect. The probes resolved the
       augmented summary correctly at step 0 — but
       `collect_tainted_sink_values` saw zero arg taint at the
       call site because SSA lowering of arrow-function bodies
       exposes free-identifier member-access expressions
       (`file._source.uri`) as their own `SsaOp::Param` ops, not as
       `FieldProj` chains derived from the formal `file` param. The
       per-param probe seeded only `BindingKey("file", BodyId(0))`,
       so the actual call-site arg SSA value (a phantom Param named
       `"file._source.uri"`) had no caps and `apply_field_aware_suppression`
       even stripped the formal-param taint. Fixed in
       `extract_ssa_func_summary` by additionally seeding every
       phantom `Param` op whose `var_name` begins with
       `formal_var_name + "."`. Regression covered by
       `cve_2025_64430_two_hop_transitive_summary_propagation`.
  6. **Multi-line dotted method chains lost inner-gate
     classification.** Tree-sitter parses
     `http\n      .get(uri, ...)\n      .on('error', ...)`
     identically to the single-line form structurally, but the
     `text_of` slice for the inner member expression is
     `"http\n      .get"` (with embedded whitespace). The labels
     map keys are literal `"http.get"` etc., so the chained-call
     inner-gate rebinding's `classify_gated_sink` lookup failed
     and the whole chain silently classified as a non-sink. Fixed
     in `find_chained_inner_call` (src/cfg/literals.rs) by
     stripping ASCII whitespace from the extracted inner-callee
     text before returning. Regression covered by
     `cve_2025_64430_multiline_chained_get_classifies_inner_sink`.
- **Test coverage**: 2249 lib tests pass; full upstream
  `vulnerable.js` scan now produces a HIGH SSRF finding from
  `req.body` → `addFileDataIfNeeded`; `patched.js` stays clean.
- **Tracking**: ground_truth case_ids `cve-js-2025-64430-vulnerable`,
  `cve-js-2025-64430-patched` (no longer disabled); fixture
  `cve_corpus/javascript/CVE-2025-64430/`; regression tests
  `src/taint/tests.rs::cve_2025_64430_*` (six tests total).
