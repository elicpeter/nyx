# Nyx Benchmark Results

Current baseline (as of Phase CF-3, 2026-04-22):

| Metric                | File-level | Rule-level | CI floor |
|-----------------------|------------|------------|----------|
| Precision             | 0.941      | 0.940      | 0.777    |
| Recall                | 1.000      | 0.994      | 0.900    |
| F1                    | 0.970      | 0.966      | 0.835    |

Corpus: 256 cases (159 vulnerable, 97 safe) across 10 languages. Scanner 0.5.0, full analysis mode.

Machine-readable per-run data lives in `tests/benchmark/results/` (`latest.json` plus dated snapshots). This file is a narrative changelog — only the two most recent phases are kept in full detail; earlier phases are condensed into the history table at the end.

---

## Phase CF-3 — Abstract-domain transfer channels in summaries (2026-04-22)

### Motivation

Phase 17 abstract interpretation tracks per-SSA-value intervals, string prefix/suffix facts, and known-bit masks during pass 2 and uses them to suppress findings via `is_abstract_safe_for_sink`. None of those facts crossed function boundaries through summaries: a caller that proved `port ∈ [1024, 65535]` lost the bound the moment the value entered a cross-file callee. CF-3 records, per parameter, a bounded symbolic description of how that parameter's abstract value maps to the return, so callers can synthesise the return abstract at summary-path call sites without re-running the callee.

### Changes

1. **`AbstractTransfer` domain** (`src/abstract_interp/mod.rs`) — product of bounded per-subdomain forms: `IntervalTransfer` (`Top` | `Identity` | `Affine { add, mul }` | `Clamped { lo, hi }`), `StringTransfer` (`Unknown` | `Identity` | `LiteralPrefix(String)` capped at `MAX_LITERAL_PREFIX_LEN = 64`). Bit subdomain is intentionally not carried cross-file.
2. **Summary schema** (`src/summary/ssa_summary.rs`): new `SsaFuncSummary.abstract_transfer: Vec<(usize, AbstractTransfer)>`, serde-gated so old DBs deserialise unchanged and only propagating functions contribute bytes.
3. **Pass-1 extraction** (`src/taint/ssa_transfer.rs::derive_abstract_transfer`): structural inference. *Identity* when every return-block return value traces (through single-use `Assign` and same-param `Phi` merges, depth ≤ 8) to the same `SsaOp::Param { index }`. *Clamped / LiteralPrefix* attached when the callee's baseline `return_abstract` has a bounded interval or known prefix.
4. **Pass-2 application** (`SsaOp::Call` arm of `transfer_inst`): runs whenever the callee was resolved via SSA summary. Per-param transfers evaluate on the caller's current abstract value of the argument, joined then `meet`-ed with baseline `return_abstract` (falling back to the less restrictive side if the meet contradicts).

### Fixtures and tests

- `tests/abstract_transfer_tests.rs` (29 tests): serde round-trip, per-subdomain `apply` semantics, join widening, LCP join on shared literal prefixes, and an end-to-end pass-1 structural test.
- `tests/fixtures/cross_file_abstract_port_range/`, `tests/fixtures/cross_file_abstract_bounded_index/`: cross-file summary-path regression guards.
- `tests/fixtures/cross_file_abstract_url_prefix_lock/`: JS literal-prefix SSRF suppression (landed via follow-up below).

#### CF-3 follow-up — JS literal-prefix SSRF suppression fix (2026-04-22)

Two surgical changes downstream of CF-3:

- **`src/ssa/copy_prop.rs`** — copy-prop now skips single-use `Assign` instructions whose CFG node carries `string_prefix`. Without this, copy-prop + DCE eliminated `url = 'lit' + userInput` in pass 2's optimised SSA, rewriting `fetch(url)`'s arg to the bare param and erasing the prefix. Mirrors the existing `is_numeric_length_access` guard.
- **`src/taint/ssa_transfer.rs::transfer_abstract`** — added a `Call` arm symmetric with the Assign-with-prefix arm: when a `Call` instruction's CFG node carries `string_prefix` (e.g. `url = wrapper('lit' + x)`), seed the call result's `StringFact` with the prefix. Lets `axios.get(url)` consume the prefix lock through cross-file identity-passthrough wrappers like CF-3's `asIs`.

Single-file and cross-file `'lit' + userInput → fetch/axios.get` both now produce zero findings.

### Benchmark delta

Byte-for-byte neutral vs pre-CF-3 (P/R/F1 unchanged at 0.940 / 0.994 / 0.966). Expected: the corpus does not yet exercise call chains where an identity-passthrough cross-file callee is the only thing between a caller-side abstract bound and a downstream suppression. The precision win will materialise when broader corpora exercise cross-file integer-bound propagation.

### Known limitations

- Per-return-path decomposition is CF-4's scope. A callee whose return traces to `param_0` on one branch and `param_1` on another yields `identity_consistent = false` and falls back to the baseline-invariant form (or Top).
- Only single-use `Assign` and consistent-origin `Phi` merges are followed by the Identity tracer; richer alias reasoning is CF-6.
- `Affine` is defined in the domain but the pass-1 structural inferrer never emits it yet.

---

## Phase CF-2 — Cross-file k=1 context-sensitive inline taint (2026-04-22)

Intra-file k=1 inline analysis (Phase 11) was extended to fire on cross-file call edges too. Before CF-2 every cross-file call collapsed into the callee's worst-case `SsaFuncSummary`; CF-2 exposes call-site-specific argument taint, call-site constants, and path-predicate structure to cross-file callees.

### Key changes

- **Cross-file body fallback in `inline_analyse_callee`** (`src/taint/ssa_transfer.rs`): intra-file lookup runs first; on miss, resolves the call via `GlobalSummaries.resolve_callee` and loads the body from `transfer.cross_file_bodies`. Body-size budget, k=1 depth cap, and the `context_sensitive` config switch shared with intra-file path via `InlineCache`.
- **Origin source-span pre-fill in param seed**: populate `source_span` from the caller's CFG before origins cross into a callee body, so cross-file inline preserves caller attribution.
- **Indexed-scan parity (CF-2 follow-up)**: `CrossFileNodeMeta` extended to carry full `NodeInfo` snapshot; `rebuild_body_graph` rehydrates a proxy `Cfg` at DB load time. `build_index` now persists `ssa_bodies` rows at index-build time (prior behaviour silently wrote zero bodies). Engine-version salt bumped to `+cf3-xfile-meta`.

### Fixtures

Four cross-file fixtures under `tests/fixtures/cross_file_context_*`: `two_call_sites` (Python, primary CF-2 win), `callback` (JS, callback-as-argument via summary path), `sanitizer` (JS, regression guard that CF-2 inline doesn't add findings where the summary path strips taint), `deep_chain` (Python three-file chain). Each has in-memory and indexed-scan test variants.

### Benchmark delta

Precision **+2.9pp** vs pre-CF-2 (0.911 → 0.940); recall unchanged (0.994); F1 **+1.5pp** (0.951 → 0.966). No per-language regression; Python/Rust/TypeScript at 1.000, others ≥ 0.889. Indexed-scan parity follow-up was neutral (correctness fix, not a precision delta).

### Known limitations

- k=1 is preserved: cross-file inline will not recursively inline the next cross-file hop. CF-5 (SCC joint fixed-point) revisits this for mutually recursive cross-file SCCs.

---

## History

Earlier phases, most recent first. Metrics are rule-level unless noted.

| Date       | Phase                                  | Corpus | P      | R      | F1     | Notes |
|------------|----------------------------------------|--------|--------|--------|--------|-------|
| 2026-04-20 | Rust Weak Spot Fixes                   | 262    | 0.906  | 0.994  | 0.948  | Rust FN→0 across FILE_IO/SSRF/SQL/DESERIALIZE sink families; SHELL_ESCAPE added to Phase 10 type suppression; identity-method peeling for constructor typing; Rust rule-level P/R/F1 jumped +7.8/+21.1/+13.2pp. |
| 2026-04-20 | TypeScript Weak Spot Fixes             | 262    | 0.899  | 0.981  | 0.938  | Closed all three Phase 19 TS weak spots: encodeURIComponent→axios cap-overlap (StringFact prefix-locked SSRF suppression), Fastify framework detection from in-file imports, TSX/JSX grammar wiring. TS rule-level F1 → 1.000. |
| 2026-04-20 | Rust Honesty Expansion                 | 262    | 0.891  | 0.961  | 0.925  | Rust corpus expanded 18→31 cases with honest FNs in classes lacking Rust rules (SQL, deserialize, reqwest builder chains). Correction, not a regression. |
| 2026-04-20 | TypeScript Coverage Expansion          | 246    | 0.904  | 0.986  | 0.944  | TS corpus 0→32 cases (12 vuln classes, adversarial type-system stressors, framework/cap-overlap/interproc cases). |
| 2026-03-24 | Phase 19 — Benchmark Expansion         | 214    | 0.827  | 0.950  | 0.885  | +73 cases (+52%); C, C++, Rust added as first-class languages; interprocedural + path-pruning cases; `buffer_overflow` and `fmt_string` classes for C/C++. Thresholds reset to baseline −5pp. |
| 2026-03-22 | Phase 8.5 — Cross-file SSA validation  | 141    | 0.840  | 0.975  | 0.903  | `param_to_sink_param` field on `SsaFuncSummary`; directory-based multi-file benchmark cases; 6 new cross-file cases across PY/JS/Go (propagation, source detection, wrong-cap sanitizer) — all TP. |
| 2026-03-22 | Ruby Parity                            | 123    | 0.821  | 0.986  | 0.896  | Ruby corpus 1→21 cases across 8 vuln classes; no label rule changes. |
| 2026-03-22 | Phase 5 — SSA Lowering X-lang hardening| 103    | 0.841  | 0.983  | 0.906  | PHP closures + throw; Python try/except + raise; new exception-edge fixtures. Precision +17.0pp vs Phase 30 via confidence scoring / allowlist / type-check guards. |
| 2026-03-21 | Phase 30 — SSRF Semantic Completion    | 103    | 0.671  | 0.966  | 0.792  | New SSRF sink matchers (axios, got, undici, httpx, http.NewRequestWithContext, Net::HTTP, HTTParty, requests.*); `flask_request.*` source; Ruby added to corpus. |
| 2026-03-21 | Phase 22.5b — Constant-arg suppression | 95     | 0.654  | 0.964  | 0.779  | AST + CFG suppression of calls with all-literal args; removed buggy `!source_derived` guard in `guards.rs`. |
| 2026-03-21 | Phase 22.5                             | 95     | 0.624  | 0.964  | 0.757  | py-ssrf-001 rule-ID fix; bare `exec`/`execSync` as JS cmdi sinks; Python `Template` as XSS sink. |
| 2026-03-21 | Phase 22 baseline                      | 95     | 0.620  | 0.891  | 0.731  | First benchmarked baseline post-Phase-22 symbolic strings. |

### Recurring known limitations

- **Variable-receiver method calls** (e.g. `client.send(...)` vs `HttpClient.send(...)`): suffix-matching misses without type-qualified resolution. Partly addressed by Phase 10 type-aware callee resolution; residual cases remain where the receiver has no inferred type.
- **Import aliasing**: arbitrary import aliases (`from flask import request as r`) are not traced; only explicitly listed aliases resolve.
- **No SSRF sanitizers as function calls**: URL-parsing doesn't sanitize; allowlist checks are condition patterns, modelled via `classify_condition()` validation markers rather than call-site credits.
- **Rust structural `cfg-unguarded-sink`** still fires for SHELL_ESCAPE when a source is in scope but not flowing to the sink arg — intentional for high-risk sinks; requires plumbing `TypeFactResult` into `AnalysisContext` to suppress.
- **Rust negative-validation `contains` dominators** and **match-arm guards** are not yet modelled by `classify_condition()`.
- **DNS-rebinding / async callback flows**: out of scope for static analysis without runtime context.
