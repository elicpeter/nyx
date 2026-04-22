# Nyx Benchmark Results

## Phase CF-2 — Cross-file k=1 context-sensitive inline taint (2026-04-22)

Scanner version: 0.5.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 256 cases (159 vulnerable, 97 safe) across 10 languages

### Motivation

Phase CF-1 landed cross-file SSA body availability as pure plumbing: every
cross-file callee now has an in-memory `CalleeSsaBody` reachable through
`GlobalSummaries.bodies_by_key`, but `resolve_callee` never consulted it. CF-2
turns that switch on — intra-file k=1 context-sensitive inline analysis now
fires on cross-file call edges too.

Before CF-2 every cross-file call fell through to the `SsaFuncSummary`
path, so call-site-specific argument taint, call-site constants, and
path-predicate structure were collapsed into the callee's worst-case
summary. Same-file callees already had the richer picture via Phase 11;
CF-2 extends that to cross-file callees without touching the intra-file
machinery.

### Changes

1. **Cross-file body fallback in `inline_analyse_callee`**
   (`src/taint/ssa_transfer.rs`): the intra-file lookup via
   `resolve_local_func_key` + `transfer.callee_bodies` runs first; on
   miss, a second step resolves the call via
   `GlobalSummaries.resolve_callee` and loads the body from
   `transfer.cross_file_bodies`. Body-size budget (`MAX_INLINE_BLOCKS`),
   k=1 depth cap, and the `context_sensitive` config switch are shared
   with the intra-file path via the existing `InlineCache`.

2. **Origin source-span pre-fill in param seed**
   (`src/taint/ssa_transfer.rs`): before origins cross into a callee
   body, `inline_analyse_callee` populates `source_span` from the
   caller's CFG. The callee's `Param`-op transfer remaps `node` to its
   own local `cfg_node` and preserves only `source_span`, so without
   the pre-fill cross-file inline would lose the caller's source line
   and produce different finding attribution than the summary path.
   This is what `parity_full_cross_file_ssa_propagation` guards against.

3. **`bodies_by_key` / inline hit / miss debug logging**
   (`src/taint/ssa_transfer.rs`): CF-1 added per-scan cross-file body
   counters; CF-2 adds per-call hit/miss lines so operators can tell
   "no bodies available" from "bodies available but budget-exceeded".

### Fixtures (new)

Four cross-file fixtures under `tests/fixtures/cross_file_context_*`:

- `cross_file_context_two_call_sites/` — Python. Two calls to the same
  cross-file helper, one tainted (`os.environ.get`) and one with a
  constant literal. Exercises the primary CF-2 win without callback
  binding.
- `cross_file_context_callback/` — JS. Caller passes a labelled sink
  (`child_process.exec`) directly as the callback argument to a
  cross-file `apply(fn, data)` helper. Exercises the callback-argument
  summary resolution through the cross-file summary path; CF-2 inline
  runs alongside but does not regress it.
- `cross_file_context_sanitizer/` — JS. Cross-file `xssSafe` wrapper
  delegates to the `xss` library (HTML_ESCAPE sanitiser). Regression
  guard that CF-2 inline must not introduce a taint finding where the
  summary path already strips the taint.
- `cross_file_context_deep_chain/` — Python. Three-file chain
  (main → middle → sinks). k=1 means the B→C hop resolves via summary;
  the end-to-end finding still surfaces via `py.cmdi`.

Each fixture's `expectations.json` carries required-findings or
forbidden-findings guardrails plus a noise budget.

### Test coverage

- `tests/cross_file_context_tests.rs` — 5 tests: the 4 fixture scans
  plus a direct `GlobalSummaries.bodies_by_key` availability
  assertion.
- `tests/cross_file_context_off_tests.rs` — 4 tests under
  `NYX_CONTEXT_SENSITIVE=0` verifying summary-only fallback still
  satisfies every fixture (CF-2 is strictly additive).

All 1640 lib tests + 9 CF-2 integration tests + 33 parity tests pass.

### Benchmark delta

| Metric         | Pre-CF-2 baseline | Post-CF-2 | Floor  |
|----------------|-------------------|-----------|--------|
| Rule precision | 0.911             | 0.940     | 0.861  |
| Rule recall    | 0.994             | 0.994     | 0.944  |
| Rule F1        | 0.951             | 0.966     | 0.901  |

Precision is up **+2.9pp**; recall is unchanged; F1 is up **+1.5pp**.
No per-language F1 regression. Per-language: Python, Rust, TypeScript
now at 1.000; all other languages ≥ 0.889.

The precision gain is consistent with the CF-2 hypothesis — cross-file
inline with call-site-specific argument taint avoids the summary
path's worst-case union.

### Known limitations

- ~~Cross-file inline fires only when `body_graph` is populated. In the
  indexed-scan path, bodies deserialised from SQLite have
  `body_graph: None` and the taint engine does not yet consume
  `node_meta`, so CF-2 currently falls through to the summary path in
  indexed scans. Surfacing this to full parity is a follow-up.~~
  **Resolved by Phase CF-3 (2026-04-22).** Indexed-scan parity restored;
  cross-file inline now fires on both scan paths. `CrossFileNodeMeta` was
  extended to carry a full `NodeInfo` snapshot, and `rebuild_body_graph`
  rehydrates a proxy `Cfg` from `node_meta` at DB load time. A companion
  fix in `build_index` persists `ssa_bodies` rows at index-build time so
  `--index rebuild` invocations populate the cross-file body cache (prior
  behaviour silently wrote zero bodies).
- k=1 is preserved: cross-file inline will not recursively inline the
  next cross-file hop. CF-5 (SCC joint fixed-point) will revisit this
  for mutually recursive cross-file SCCs.

### CF-3 — Indexed-scan parity for cross-file inline (2026-04-22)

On-disk layout: `CrossFileNodeMeta` now embeds a full `crate::cfg::NodeInfo`
(up from just `bin_op` + `labels`). The engine-version salt was bumped
to `+cf3-xfile-meta` to invalidate stale DBs. Indexed-scan variants of the
four CF-2 fixture tests were added (`*_indexed` in
`tests/cross_file_context_tests.rs`) and pass alongside the in-memory
variants. Benchmark unchanged at rule-level P=0.940, R=0.994, F1=0.966 —
CF-3 is a correctness/parity fix, not a precision delta, because the CF-2
fixtures already exercised the in-memory scan path.

---

## Rust Weak Spot Fixes (2026-04-20)

Scanner version: 0.5.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 262 cases (155 vulnerable, 107 safe) across 10 languages

### Motivation

The 2026-04-20 Rust Honesty Expansion recorded four honest FNs (rs-path-005,
rs-ssrf-003, rs-sqli-001, rs-deser-001) where entire sink-API families had no
rules, plus six FPs (rs-safe-003, -006, -007, -008, -009, -010, -011) where
common Rust safe-patterns were not recognized. Rust rule-level precision and
recall both dropped below threshold (P=0.682, R=0.789, F1=0.732). This phase
closes all four honest FNs and one FP (rs-safe-006) without regressing any
other language or adding fixture-only matchers.

### Changes

1. **Rust sink rule families added** (`src/labels/rust.rs`):
   - `FILE_IO`: `fs::remove_file`, `fs::remove_dir`, `fs::remove_dir_all`,
     `fs::rename`, `fs::copy` — round out the path-traversal sink family.
   - `SSRF`: `reqwest::Client::new`, `reqwest::Client.get/post/head/put/delete`,
     `HttpClient.get/post/send` — reqwest / generic HttpClient builder chain.
   - `SQL_QUERY` (new class for Rust): `rusqlite::Connection.execute/query*`,
     `sqlx::query*`, `diesel::sql_query`, `postgres::Client.execute/query*`,
     `DatabaseConnection.execute/query*`.
   - `DESERIALIZE` (new class for Rust): `serde_yaml::from_str/from_slice/from_reader`,
     `bincode::deserialize`, `rmp_serde::from_slice/from_read`,
     `ciborium::from_reader`, `ron::de::from_str/from_bytes/from_reader`,
     `toml::from_str`. **Not** added: `serde_json::from_str` (per feedback,
     JSON parsing is not intrinsically dangerous deserialization).

2. **Phase 10 type-suppression extended to SHELL_ESCAPE**
   (`src/taint/ssa_transfer.rs`): `is_type_safe_for_sink`,
   `is_abstract_safe_for_sink`, `is_call_abstract_safe`, and
   `type_safe_for_taint_sink` now include `Cap::SHELL_ESCAPE` alongside
   `Cap::SQL_QUERY | Cap::FILE_IO`. Taint flow from a provably int-typed value
   (e.g., `port: u16` from `parse::<u16>()`) into `Command::new(…).arg(port.to_string())`
   is suppressed. Structural `cfg-unguarded-sink` still fires for high-risk
   sinks per the established structural-detection principle.

3. **Identity-method peeling for constructor typing**
   (`src/ssa/type_facts.rs`): new `peel_identity_suffix()` normalizes callee
   text by stripping trailing identity methods (`unwrap`, `expect`, `clone`,
   `as_ref`, `as_str`, `into`, `to_owned`). `constructor_type()` Rust branch
   now matches against the peeled base, so `Connection::open("app.db").unwrap`
   correctly types the result as `DatabaseConnection`. `is_int_producing_callee`
   also peels, and accepts `parse` (Rust idiom).

4. **Stringify-callee leaf tracing** (`src/taint/ssa_transfer.rs`):
   `trace_single_leaf` now recurses through `to_string`, `to_owned`, `format`,
   `String`, and `str` calls to find the actual tainted source leaf. This
   closes rs-safe-006: `port.to_string()` on a typed-safe int propagates the
   typed-safety claim to the underlying parse result.

5. **Character-class validation patterns** (`src/taint/path_state.rs`):
   `classify_condition` now recognizes Rust idioms like
   `.all(|c| c.is_ascii_alphanumeric())`, `.all(char::is_alphanumeric)`, and
   `.all(|c| c.is_numeric())`. (This change compiled and is exercised by the
   path-state test suite, but does not yet close rs-safe-009 — see limitations.)

6. **Rust field-expression receiver plumbing** (`src/cfg.rs`):
   `root_member_receiver` now handles Rust's `field_expression` and its
   wrapping `call_expression`. This was required for the new
   `rusqlite::Connection.execute` and `reqwest::Client.get` receiver-based
   matchers to fire.

### Regression guards (new fixtures)

| Case | Kind | What it proves |
|------|------|----------------|
| `rs-path-005` | TP | `fs::remove_file(user_path)` now flagged — FILE_IO family complete |
| `rs-ssrf-003` | TP | `reqwest::Client::new().get(url).send()` builder chain flagged |
| `rs-sqli-001` | TP | `conn.execute(format!("SELECT … {}", user_id))` flagged (new SQL class) |
| `rs-deser-001` | TP | `serde_yaml::from_str(&payload)` flagged (new DESERIALIZE class) |
| `rs-safe-006` | TN | `parse::<u32>() → Command::new(…).arg(n.to_string())` no longer flagged |

### Rust Metrics (rule-level)

| Metric | Before (Honesty Expansion) | After |
|--------|----------------------------|-------|
| TP     | 15                         | 19    |
| FP     | 7                          | 6     |
| FN     | 4                          | 0     |
| TN     | 5                          | 6     |
| Precision | 68.2%                   | 76.0% |
| Recall | 78.9%                      | 100.0% |
| F1     | 73.2%                      | 86.4% |

Delta: TP +4, FP -1, FN -4, TN +1. Precision +7.8pp, Recall +21.1pp, F1 +13.2pp.

### Overall Metrics

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 155 | 16 | 0 | 90 | 90.6% | 100.0% | 95.1% |
| Rule-level | 154 | 16 | 1 | 90 | 90.6% | 99.4% | 94.8% |

Delta vs Rust Honesty Expansion: TP +7, FP -2, FN -5, TN +3. Precision +1.5pp,
Recall +3.3pp, F1 +2.3pp. All gates pass: P 90.6% ≥ 77.7%, R 99.4% ≥ 90.0%,
F1 94.8% ≥ 83.5%.

### Known Rust Weak Spots (remaining)

The following FPs persist and are bounded by deeper engine work rather than
rule additions:

| Case | Pattern | Why it persists |
|------|---------|-----------------|
| rs-safe-003 | `let _input = …; Command::new("sh").arg(cmd)` where `cmd` is literal | `cfg-unguarded-sink` structural finding fires on SHELL_ESCAPE sink because `env::var` source is present in the same function scope, even when the tainted variable (`_input`) is not used in the sink argument. Structural detection for high-risk sinks is intentional. |
| rs-safe-007 | Nested interprocedural `sanitize_input` via `canonicalize_path` | Rust has no `.replace()` sanitizer rule; the fixture relies on `.replace("..", "")` chains, which the scanner conservatively does not credit as path-traversal sanitizers. |
| rs-safe-008 | `if input.contains(";") \|\| input.contains("\|") { return; }` dominator | Rust `contains` negative-validation return pattern not yet modeled by `classify_condition()`. |
| rs-safe-009 | `match raw.as_str() { s if s.chars().all(is_alphanumeric) => … }` | Match-arm guards produce CFG branches but do not surface as `StmtKind::If` condition nodes, so `classify_condition` is never invoked. New character-class rule added but unreached. |
| rs-safe-010 | `let cmd = static_table.get(key).copied().unwrap_or("safe")` | `HashMap::get().copied().unwrap_or(literal)` is structurally a static lookup with bounded string range; engine does not model map-as-sanitizer semantics. |
| rs-safe-011 | `parse::<u16>() → Command::new(…).arg(port.to_string())` (cfg-unguarded-sink) | Phase 10 type-suppression clears the taint-flow finding. The `cfg-unguarded-sink` LOW structural finding on SHELL_ESCAPE still fires because `AnalysisContext` has no access to `TypeFactResult`. Fixing requires plumbing type facts into cfg-analysis — deferred to preserve structural-detection guarantees for high-risk sinks. |

These are documented rather than suppressed to keep the benchmark honest.

---

## TypeScript Weak Spot Fixes (2026-04-20)

Scanner version: 0.5.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 262 cases (155 vulnerable, 107 safe) across 10 languages

### Motivation

The 2026-04-20 TypeScript Coverage Expansion documented three engine weak
spots. This phase closes all three:

1. `ts-safe-003` false positive: `encodeURIComponent → axios` cap-overlap
2. `ts-ssrf-002` false negative: Fastify framework context only from `package.json`
3. TSX / JSX grammar was not wired

### Changes

1. **Prefix-locked SSRF suppression via StringFact** — extended
   `src/cfg.rs::extract_template_prefix` to also consult the first positional
   argument of a sink call (unwraps `await`/`yield`/`as`/parentheses). When
   the URL argument is a template literal or `"lit" + x` whose leading
   constant contains `scheme://host/`, a `StringFact::from_prefix` is seeded
   on the call node. `is_abstract_safe_for_sink` and `is_call_abstract_safe`
   in `src/taint/ssa_transfer.rs` now consult this node-attached prefix
   directly — the existing `is_string_safe_for_ssrf` host check stays the
   single source of truth for SSRF lock semantics. No caps were widened.
2. **In-file framework detection** — added
   `utils::project::detect_in_file_frameworks` (bounded head scan for
   `'fastify'`/`'express'`/`'koa'` module specifiers in JS/TS).
   `ParsedFile::from_source` now augments `LangAnalysisRules` with rules for
   frameworks revealed by imports but missed by `package.json`.
3. **TSX / JSX grammar** — wired `tree_sitter_typescript::LANGUAGE_TSX` for
   `.tsx` and `tree_sitter_javascript::LANGUAGE` for `.jsx` in
   `lang_for_path`. TSX uses the `typescript` slug (all TS KINDS/RULES/
   PARAM_CONFIG apply). JSX nodes are structural and flow through
   existing lowering.

### Regression guards (new fixtures)

| Case | Kind | What it proves |
|------|------|----------------|
| `ts-ssrf-003` | FN guard | `encodeURIComponent(host)` into `\`https://${encodedHost}/…\`` — prefix `"https://"` has no post-`://` slash, so suppression must NOT fire. Still reports SSRF (TP). |
| `ts-xss-005` | TSX TP | `dangerouslySetInnerHTML={{__html: bio}}` in a `.tsx` file — exercises LANGUAGE_TSX wiring end-to-end. |
| `ts-safe-010` | TSX TN | `<div>{bio}</div>` (React auto-escapes text children). Guards against over-flagging JSX expressions. |

### TypeScript Metrics (rule-level)

| Metric | Before (2026-04-20 Expansion) | After |
|--------|-------------------------------|-------|
| TP     | 22                            | 25    |
| FP     | 1                             | 0     |
| FN     | 1                             | 0     |
| TN     | 8                             | 10    |
| Precision | 95.7%                      | 100.0% |
| Recall | 95.7%                         | 100.0% |
| F1     | 95.7%                         | 100.0% |

### Overall Metrics

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 153 | 17 | 2 | 89 | 90.0% | 98.7% | 94.2% |
| Rule-level | 152 | 17 | 3 | 89 | 89.9% | 98.1% | 93.8% |

All gates pass: Precision 89.9% ≥ 77.7%, Recall 98.1% ≥ 90.0%, F1 93.8% ≥ 83.5%.

### Known Weak Spots (updated)

The three TypeScript weak spots listed under the 2026-04-20 Coverage
Expansion are **closed**. No new TypeScript weak spots have been introduced.

---

## Rust Honesty Expansion (2026-04-20)

Scanner version: 0.5.0
Corpus: 31 Rust cases (19 vulnerable, 12 safe) — previously 18 cases (10 vuln, 8 safe).

### Motivation

The prior Rust corpus reported 100% recall / 71.4% precision, but used a narrow
sampling: every vulnerable case used `env::var` as the source, and coverage was
limited to three classes (cmdi, path_traversal, ssrf). That inflated recall and
hid unsupported classes. This expansion adds realistic adversarial cases,
including honest false negatives in classes with no Rust sink rules.

### Changes

**+13 Rust cases** (9 vulnerable, 4 safe):

| Case | Purpose | Outcome |
|------|---------|---------|
| rs-cmdi-005 | `format!()` interpolation into `sh -c` | TP |
| rs-cmdi-006 | `match` expression binding `env::var` | TP |
| rs-cmdi-007 | `String` + `&str` concat via `+` | TP |
| rs-cmdi-cross-001 | Cross-file helper propagation (`mod transform`) | TP |
| rs-path-005 | `fs::remove_file(user)` — no sink rule | **FN** (honest gap) |
| rs-ssrf-003 | `reqwest::Client::new().get().send()` builder chain | **FN** (honest gap) |
| rs-sqli-001 | `rusqlite::Connection.execute` with `format!` | **FN** (class has no Rust rules) |
| rs-deser-001 | `serde_yaml::from_str(tainted)` | **FN** (class has no Rust rules) |
| rs-xss-001 | Axum `Path<String>` → `Html(format!(…))` (framework) | TP |
| rs-safe-009 | `match` guard restricting to ASCII alphanumeric | **FP** |
| rs-safe-010 | `HashMap::get` with tainted key, static value | **FP** |
| rs-safe-011 | `parse::<u16>()` type-narrowing before Command | **FP** |
| rs-safe-cross-001 | Cross-file `sanitize_shell` helper | TN |

The four FN cases are intentional: they exercise vulnerability classes and API
shapes the Rust ruleset does not currently cover. Recording them as FN keeps
the benchmark honest rather than pretending Rust has coverage it lacks.

### Rust metrics (rule-level)

| Scope | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| Rust (prior) | 10 | 4 | 0 | 4 | 71.4% | 100.0% | 83.3% |
| Rust (current) | 15 | 7 | 4 | 5 | **68.2%** | **78.9%** | **73.2%** |

Delta: TP +5, FP +3, FN +4, TN +1. Precision −3.2pp, Recall −21.1pp, F1 −10.1pp.
The headline drop is a correction, not a regression: the prior numbers
understated both the scanner's weak spots (ssrf builder chains, missing
`remove_file` sink) and its unsupported classes (SQLi, deserialization).

### Rust by vuln class (rule-level)

| Class | TP | FP | FN | Precision | Recall | F1 |
|-------|----|----|----|-----------|--------|----|
| cmdi | 8 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| path_traversal | 4 | 0 | 1 | 100.0% | 80.0% | 88.9% |
| ssrf | 2 | 0 | 1 | 100.0% | 66.7% | 80.0% |
| xss | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| sqli | 0 | 0 | 1 | — | 0.0% | 0.0% |
| deser | 0 | 0 | 1 | — | 0.0% | 0.0% |
| safe | 0 | 7 | 0 | 0.0% | — | — |

### What the Rust corpus still does not cover

- Unsafe FFI / `std::mem::transmute` — no rule, not benchmarked
- Tokio `process::Command` async variants — not distinguished from sync
- `std::fs::copy`, `std::fs::rename`, `remove_dir_all` — no sink rules
- `hyper`, `surf`, `ureq` SSRF clients — not in `reqwest` rule family
- Rocket / Actix framework positives — rules exist, no benchmark cases yet

### Overall corpus metrics after this expansion (rule-level)

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 148 | 18 | 5 | 87 | 89.2% | 96.7% | 92.8% |
| Rule-level | 147 | 18 | 6 | 87 | 89.1% | 96.1% | 92.5% |

Thresholds (Phase 19 baseline minus 5pp) still hold: P≥0.777, R≥0.900, F1≥0.835.

---

## TypeScript Coverage Expansion (2026-04-20)

Scanner version: 0.5.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 246 cases (144 vulnerable, 102 safe) across 10 languages

### Changes from Phase 19
- **TypeScript corpus expansion**: 0 → 32 cases (23 vulnerable + 9 safe) — TS is now a first-class benchmarked language
- **12 vuln classes covered for TS**: xss, sqli, cmdi, code_injection, ssrf, open_redirect, path_traversal, crypto, secrets, insecure_config, prototype, interproc, type_system
- **Adversarial cases included**: type-system stressors (generics, interface dispatch, decorators, discriminated unions, optional chaining, `as any` casts), framework context (Fastify), cap-overlap sanitizers, interprocedural sanitizer wrapping, parameterized queries

### Overall Metrics

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 143 | 15 | 1 | 86 | 90.5% | 99.3% | 94.7% |
| Rule-level | 142 | 15 | 2 | 86 | 90.4% | 98.6% | 94.4% |

Delta vs Phase 19: TP +27, FP -9, FN -4, TN +18. Precision +7.7pp, Recall +3.6pp, F1 +5.9pp. New TS cases lift aggregate quality while exposing engine weak spots.

### TypeScript Metrics (rule-level)

| Metric | Value |
|--------|-------|
| TP | 22 |
| FP | 1 |
| FN | 1 |
| TN | 8 |
| Precision | 95.7% |
| Recall | 95.7% |
| F1 | 95.7% |

### Per Language (rule-level)

| Language | TP | FP | FN | TN | Precision | Recall | F1 |
|----------|----|----|----|----|-----------|--------|----|
| C | 12 | 2 | 0 | 6 | 85.7% | 100.0% | 92.3% |
| C++ | 12 | 3 | 0 | 5 | 80.0% | 100.0% | 88.9% |
| Go | 16 | 1 | 0 | 11 | 94.1% | 100.0% | 97.0% |
| Java | 13 | 1 | 0 | 9 | 92.9% | 100.0% | 96.3% |
| JavaScript | 15 | 1 | 0 | 11 | 93.8% | 100.0% | 96.8% |
| PHP | 13 | 2 | 0 | 9 | 86.7% | 100.0% | 92.9% |
| Python | 17 | 0 | 0 | 12 | 100.0% | 100.0% | 100.0% |
| Ruby | 12 | 0 | 1 | 11 | 100.0% | 92.3% | 96.0% |
| Rust | 10 | 4 | 0 | 4 | 71.4% | 100.0% | 83.3% |
| TypeScript | 22 | 1 | 1 | 8 | 95.7% | 95.7% | 95.7% |

### TypeScript Case Breakdown

| Vuln Class | Cases | TP | FP | FN | TN |
|------------|-------|----|----|----|----|
| xss | 4 | 4 | 0 | 0 | 0 |
| sqli | 2 | 2 | 0 | 0 | 0 |
| cmdi | 2 | 2 | 0 | 0 | 0 |
| code_injection | 2 | 2 | 0 | 0 | 0 |
| ssrf | 2 | 1 | 0 | 1 | 0 |
| open_redirect | 1 | 1 | 0 | 0 | 0 |
| path_traversal | 1 | 1 | 0 | 0 | 0 |
| crypto | 1 | 1 | 0 | 0 | 0 |
| secrets | 1 | 1 | 0 | 0 | 0 |
| insecure_config | 2 | 2 | 0 | 0 | 0 |
| prototype | 1 | 1 | 0 | 0 | 0 |
| interproc | 1 | 1 | 0 | 0 | 0 |
| type_system | 3 | 3 | 0 | 0 | 0 |
| safe | 9 | 0 | 1 | 0 | 8 |

### TypeScript Adversarial Cases (engine weak spots exposed)

| Case | Category | Outcome | What it tests |
|------|----------|---------|---------------|
| ts-xss-003 | type_system | TP | Generic identity function `identity<T>(x: T): T` — taint flows through erased generic |
| ts-xss-004 | type_system | TP | Optional chain adversarial source `req?.query?.name` |
| ts-type_system-001 | type_system | TP | Discriminated union narrowing (`kind==='ping'`) then exec |
| ts-type_system-002 | type_system | TP | Interface dispatch via `impl: Runner = new ShellRunner()` |
| ts-type_system-003 | type_system | TP | Decorator `@log` wrapping Service.run → exec |
| ts-safe-003 | cap-overlap | FP | encodeURIComponent (Cap::URL_ENCODE) → axios (Cap::SSRF) — caps don't match, sanitizer not credited |
| ts-safe-007 | interproc | TN | Interprocedural `cleanHtml()` wrapping DOMPurify — engine correctly credits wrapper |
| ts-safe-009 | parameterized | TN | `pool.query('... WHERE id = $1', [id])` — parameterized query not flagged |
| ts-ssrf-002 | framework | FN | Fastify `request.query.url` → fetch — Fastify context requires package.json presence |

### TypeScript Known Weak Spots

All three weak spots below were closed in the **TypeScript Weak Spot Fixes
(2026-04-20)** phase — see that section for implementation detail.

- ~~**Cap-overlap sanitizers**~~: `encodeURIComponent → axios` false positive
  closed by extending `StringFact`-backed prefix-locked SSRF suppression to
  inline template-literal call arguments. Caps were **not** widened.
- ~~**Framework context detection** (Fastify)~~: closed by per-file import
  detection (`detect_in_file_frameworks`) that augments `LangAnalysisRules`
  when `package.json` isn't available.
- ~~**TSX/JSX not supported**~~: closed by wiring
  `tree_sitter_typescript::LANGUAGE_TSX` and `tree_sitter_javascript::LANGUAGE`
  for `.tsx` / `.jsx` respectively.

### Thresholds

Regression thresholds unchanged from Phase 19 baseline.

| Metric | Baseline | Threshold |
|--------|----------|-----------|
| Rule-level Precision | 90.4% | 77.7% |
| Rule-level Recall | 98.6% | 90.0% |
| Rule-level F1 | 94.4% | 83.5% |

---

## Phase 19 — Benchmark Expansion and Precision Gate (2026-03-24)

Scanner version: 0.5.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 214 cases (122 vulnerable, 92 safe) across 9 languages

### Changes from Phase 8.5
- **Corpus expansion**: 141 → 214 cases (+73 new cases, +52%)
- **3 new languages**: C (20 cases), C++ (20 cases), Rust (18 cases)
- **Interprocedural benchmark cases**: 12 cases across 6 languages (sanitizer wrapping + taint propagation through helpers)
- **Path-pruning benchmark cases**: 3 cases (JS, Python, Go — allowlist-gated command execution)
- **New vulnerability classes**: buffer_overflow (C/C++ sprintf/strcpy/strcat), fmt_string (C/C++ printf/fprintf)
- **Regression thresholds updated** to Phase 19 baseline minus 5pp

### Overall Metrics

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 119 | 24 | 2 | 68 | 83.2% | 98.3% | 90.2% |
| Rule-level | 115 | 24 | 6 | 68 | 82.7% | 95.0% | 88.5% |

Delta vs Phase 8.5: TP +36, FP +9, FN +4, TN +24. Precision -1.3pp, Recall -2.5pp, F1 -1.8pp. Note: deltas reflect new harder cases (interprocedural, path-pruning) and new language coverage, not regressions.

### Per Language (rule-level)

| Language | TP | FP | FN | TN | Precision | Recall | F1 |
|----------|----|----|----|----|-----------|--------|----|
| C | 11 | 2 | 1 | 6 | 84.6% | 91.7% | 88.0% |
| C++ | 10 | 3 | 2 | 5 | 76.9% | 83.3% | 80.0% |
| Go | 16 | 5 | 0 | 7 | 76.2% | 100.0% | 86.5% |
| Java | 11 | 1 | 2 | 9 | 91.7% | 84.6% | 88.0% |
| JavaScript | 15 | 5 | 0 | 7 | 75.0% | 100.0% | 85.7% |
| PHP | 13 | 2 | 0 | 9 | 86.7% | 100.0% | 92.9% |
| Python | 17 | 1 | 0 | 11 | 94.4% | 100.0% | 97.1% |
| Ruby | 12 | 1 | 1 | 10 | 92.3% | 92.3% | 92.3% |
| Rust | 10 | 4 | 0 | 4 | 71.4% | 100.0% | 83.3% |

### Per Vulnerability Class (rule-level)

| Class | TP | FP | FN | Precision | Recall | F1 |
|-------|----|----|----|-----------|---------|----|
| buffer_overflow | 5 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| cmdi | 30 | 0 | 2 | 100.0% | 93.8% | 96.8% |
| code_injection | 8 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| deser | 6 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| fmt_string | 5 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| path_traversal | 15 | 0 | 1 | 100.0% | 93.8% | 96.8% |
| sqli | 17 | 0 | 2 | 100.0% | 89.5% | 94.4% |
| ssrf | 15 | 0 | 1 | 100.0% | 93.8% | 96.8% |
| xss | 14 | 0 | 0 | 100.0% | 100.0% | 100.0% |

### New Language Coverage

| Language | Vuln Classes Covered | Cases | Recall |
|----------|---------------------|-------|--------|
| C | cmdi, path_traversal, fmt_string, ssrf, buffer_overflow | 20 | 91.7% |
| C++ | cmdi, path_traversal, fmt_string, ssrf, buffer_overflow | 20 | 83.3% |
| Rust | cmdi, path_traversal, ssrf | 18 | 100.0% |

### False Negatives (new)

| Case | File | Notes |
|------|------|-------|
| c-cmdi-004 | c/cmdi/cmdi_fgets.c | fgets→array→system taint chain: rule ID mismatch (AST match only) |
| cpp-cmdi-003 | cpp/cmdi/cmdi_getline.cpp | std::getline→string→system: c_str() method breaks taint chain |
| cpp-ssrf-002 | cpp/ssrf/ssrf_connect.cpp | connect() via socket API not detected (complex multi-step setup) |
| java-interproc-001 | java/interprocedural/InterprocTaintPropagation.java | Interprocedural taint through buildQuery() detected at file level but rule ID mismatch |
| rb-interproc-001 | ruby/interprocedural/interproc_taint_propagation.rb | Same — interprocedural taint detected but rule ID mismatch |

### False Positives (new safe cases flagged)

| Case | File | Pattern |
|------|------|---------|
| c-safe-006 | c/safe/safe_validated.c | strstr() path validation not recognized as guard |
| c-safe-008 | c/safe/safe_sanitize_func.c | Forward-declared sanitize_input() not tracked |
| cpp-safe-006 | cpp/safe/safe_validated.cpp | strstr() path validation not recognized |
| cpp-safe-007 | cpp/safe/safe_sanitize_func.cpp | Forward-declared sanitize_input() not tracked |
| cpp-safe-008 | cpp/safe/safe_strtol.cpp | C-style strtol() not in C++ sanitizer rules |
| rs-safe-003 | rust/safe/safe_reassigned.rs | Tainted variable unused but Command still flagged |
| rs-safe-006 | rust/safe/safe_type_check.rs | parse::<u32>() type narrowing not tracked |
| rs-safe-007 | rust/safe/safe_interprocedural.rs | Interprocedural sanitize_input() not resolved |
| rs-safe-008 | rust/safe/safe_dominated.rs | Validation guard not recognized |
| js-interproc-safe-001 | javascript/interprocedural/interproc_sanitizer_wrap.js | Interprocedural encodeURIComponent wrapper not resolved |
| js-pathprune-safe-001 | javascript/path_pruning/safe_early_return.js | Allowlist early-return not pruned |
| go-pathprune-safe-001 | go/path_pruning/safe_early_return.go | Allowlist early-return not pruned |
| php-interproc-safe-001 | php/interprocedural/interproc_sanitizer_wrap.php | Interprocedural htmlspecialchars wrapper not resolved |

### Thresholds

Regression thresholds set 5pp below Phase 19 baseline.

| Metric | Baseline | Threshold |
|--------|----------|-----------|
| Rule-level Precision | 82.7% | 77.7% |
| Rule-level Recall | 95.0% | 90.0% |
| Rule-level F1 | 88.5% | 83.5% |

---

## Phase 8.5 — Cross-File SSA Benchmark Validation (2026-03-22)

Scanner version: 0.4.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 141 cases (81 vulnerable, 60 safe)

### Changes from Ruby Parity
- **`param_to_sink_param` field** added to `SsaFuncSummary` — tracks which caller param flows to which sink argument position with caps
- **Multi-file benchmark support**: `scan_corpus_file()` now handles directory-based test cases via `copy_dir_recursive()`
- **6 new cross-file benchmark cases** across 3 languages (Python, Go, JavaScript):
  - Pattern A (propagation): `py-cmdi-cross-001`, `js-xss-cross-001`
  - Pattern B (source detection): `py-cmdi-cross-002`, `go-cmdi-cross-001`
  - Pattern C (wrong-cap sanitizer): `py-cmdi-cross-003`, `go-path_traversal-cross-001`
- All 6 cases are TP — cross-file SSA summaries correctly propagate taint

### Overall Metrics

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 79 | 15 | 2 | 44 | 84.0% | 97.5% | 90.3% |
| Rule-level | 79 | 15 | 2 | 44 | 84.0% | 97.5% | 90.3% |

Delta vs Ruby Parity: TP +10 (6 new cross-file + 4 from corpus expansion), FP unchanged, TN +6. Precision +1.9pp, Recall -1.1pp, F1 +0.7pp.

### Per Language (rule-level)

| Language | TP | FP | FN | TN | Precision | Recall | F1 |
|----------|----|----|----|----|-----------|--------|----|
| Go | 15 | 5 | 0 | 5 | 75.0% | 100.0% | 85.7% |
| Java | 10 | 1 | 2 | 8 | 90.9% | 83.3% | 87.0% |
| JavaScript | 14 | 3 | 0 | 7 | 82.4% | 100.0% | 90.3% |
| PHP | 12 | 1 | 0 | 9 | 92.3% | 100.0% | 96.0% |
| Python | 16 | 1 | 0 | 9 | 94.1% | 100.0% | 97.0% |
| Ruby | 12 | 4 | 0 | 6 | 75.0% | 100.0% | 85.7% |

### Per Vulnerability Class (rule-level)

| Class | TP | FP | FN | Precision | Recall | F1 |
|-------|----|----|----|-----------|---------|----|
| cmdi | 18 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| code_injection | 8 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| deser | 6 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| fmt_string | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| path_traversal | 7 | 0 | 1 | 100.0% | 87.5% | 93.3% |
| sqli | 15 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| ssrf | 10 | 0 | 1 | 100.0% | 90.9% | 95.2% |
| xss | 14 | 0 | 0 | 100.0% | 100.0% | 100.0% |

### Cross-File Cases (all TP)

| Case | Pattern | Language | Status |
|------|---------|----------|--------|
| py-cmdi-cross-001 | Propagation | Python | TP |
| py-cmdi-cross-002 | Source detection | Python | TP |
| py-cmdi-cross-003 | Wrong-cap sanitizer | Python | TP |
| js-xss-cross-001 | Propagation | JavaScript | TP |
| go-cmdi-cross-001 | Source detection | Go | TP |
| go-path_traversal-cross-001 | Wrong-cap sanitizer | Go | TP |

### Thresholds

| Metric | Baseline | Threshold |
|--------|----------|-----------|
| Rule-level Precision | 84.0% | 60.4% |
| Rule-level Recall | 97.5% | 91.4% |
| Rule-level F1 | 90.3% | 72.9% |

## Ruby Parity — Benchmark Corpus Expansion (2026-03-22)

Scanner version: 0.5.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 123 cases (70 vulnerable, 53 safe)

### Changes from Phase 5
- **Ruby corpus expansion**: 1 → 21 cases (8 safe + 1 SSRF-safe + 11 vulnerable + existing ssrf-001)
- **Vuln class coverage**: cmdi(2), code_injection(1), deser(2), path_traversal(1), sqli(2), ssrf(2+1safe), xss(2), safe(8)
- **No label rule changes** — all Ruby rules already covered the new vuln classes

### Overall Metrics

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 69 | 15 | 1 | 38 | 82.1% | 98.6% | 89.6% |
| Rule-level | 69 | 15 | 1 | 38 | 82.1% | 98.6% | 89.6% |

Delta vs Phase 5: TP +11 (new Ruby vuln cases), FP +4 (new Ruby safe FPs), TN +5 (new Ruby safe TNs). Precision -2.0pp, Recall +0.3pp, F1 -1.0pp.

### Per Language (rule-level)

| Language | TP | FP | FN | TN | Precision | Recall | F1 |
|----------|----|----|----|----|-----------|--------|----|
| Go | 12 | 5 | 0 | 4 | 70.6% | 100.0% | 82.8% |
| Java | 10 | 1 | 1 | 7 | 90.9% | 90.9% | 90.9% |
| JavaScript | 12 | 3 | 0 | 6 | 80.0% | 100.0% | 88.9% |
| PHP | 11 | 1 | 0 | 8 | 91.7% | 100.0% | 95.7% |
| Python | 12 | 1 | 0 | 8 | 92.3% | 100.0% | 96.0% |
| Ruby | 12 | 4 | 0 | 5 | 75.0% | 100.0% | 85.7% |

### Per Vulnerability Class (rule-level)

| Class | TP | FP | FN | Precision | Recall | F1 |
|-------|----|----|----|-----------|---------|----|
| cmdi | 13 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| code_injection | 8 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| deser | 6 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| fmt_string | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| path_traversal | 7 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| sqli | 13 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| ssrf | 10 | 0 | 1 | 100.0% | 90.9% | 95.2% |
| xss | 11 | 0 | 0 | 100.0% | 100.0% | 100.0% |

### Ruby False Positives (4 safe cases flagged)

| Case | File | Pattern |
|------|------|---------|
| ruby-safe-002 | safe_dominated.rb | Allowlist guard not recognized |
| ruby-safe-003 | safe_interprocedural.rb | Interprocedural sanitization not tracked |
| ruby-safe-007 | safe_type_check.rb | `is_a?` type guard not recognized |
| ruby-safe-008 | safe_validated.rb | Allowlist validation not recognized |

### False Negatives (missed vulnerabilities)

| Case | File | Notes |
|------|------|-------|
| java-ssrf-002 | java/ssrf/SsrfHttpClient.java | `client.send(...)` — variable receiver doesn't suffix-match `HttpClient.send`; requires type resolution |

### Thresholds

| Metric | Baseline | Threshold |
|--------|----------|-----------|
| Rule-level Precision | 82.1% | 60.4% |
| Rule-level Recall | 98.6% | 91.4% |
| Rule-level F1 | 89.6% | 72.9% |

## Phase 5 — SSA Lowering Cross-Language Hardening (2026-03-22)

Scanner version: 0.5.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 103 cases (59 vulnerable, 44 safe)

### Changes from Phase 30
- **PHP anonymous functions**: `anonymous_function_creation_expression` and `arrow_function` → `Kind::Function` (scope isolation for closures)
- **PHP throw**: `throw_expression` → `Kind::Throw` (exception edges wired to catch handlers)
- **Python try/except**: `try_statement` → `Kind::Try`, `raise_statement` → `Kind::Throw` (exception edges and handler wiring)
- **Python except_clause**: `build_try()` now collects `except_clause` children; `extract_catch_param_name()` handles Python `alias` field
- **Ruby TODO**: Documented deferred begin/rescue/ensure gap (structurally incompatible with `build_try()`)
- **New fixtures**: 4 (php/closure_taint, php/throw_in_try, python/try_except_taint, python/raise_in_try)

### Overall Metrics

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 58 | 11 | 1 | 33 | 84.1% | 98.3% | 90.6% |
| Rule-level | 58 | 11 | 1 | 33 | 84.1% | 98.3% | 90.6% |

Delta vs Phase 30: TP +1 (php-xss-001 now TP), FP -17 (confidence scoring, allowlist, type-check guards), TN +17. Precision +17.0pp, Recall +1.7pp, F1 +11.4pp.

### Per Language (rule-level)

| Language | TP | FP | FN | TN | Precision | Recall | F1 |
|----------|----|----|----|----|-----------|--------|----|
| Go | 12 | 5 | 0 | 4 | 70.6% | 100.0% | 82.8% |
| Java | 10 | 1 | 1 | 7 | 90.9% | 90.9% | 90.9% |
| JavaScript | 12 | 3 | 0 | 6 | 80.0% | 100.0% | 88.9% |
| PHP | 11 | 1 | 0 | 8 | 91.7% | 100.0% | 95.7% |
| Python | 12 | 1 | 0 | 8 | 92.3% | 100.0% | 96.0% |
| Ruby | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |

### Per Vulnerability Class (rule-level)

| Class | TP | FP | FN | Precision | Recall | F1 |
|-------|----|----|----|-----------|---------|----|
| cmdi | 11 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| code_injection | 7 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| deser | 4 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| fmt_string | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| path_traversal | 6 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| sqli | 11 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| ssrf | 9 | 0 | 1 | 100.0% | 90.0% | 94.7% |
| xss | 9 | 0 | 0 | 100.0% | 100.0% | 100.0% |

### False Negatives (missed vulnerabilities)

| Case | File | Notes |
|------|------|-------|
| java-ssrf-002 | java/ssrf/SsrfHttpClient.java | `client.send(...)` — variable receiver doesn't suffix-match `HttpClient.send`; requires type resolution |

### Thresholds

| Metric | Baseline | Threshold |
|--------|----------|-----------|
| Rule-level Precision | 84.1% | 60.4% |
| Rule-level Recall | 98.3% | 91.4% |
| Rule-level F1 | 90.6% | 72.9% |

## Phase 30 — SSRF Semantic Completion (2026-03-21)

Scanner version: 0.4.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 103 cases (59 vulnerable, 44 safe)

### Changes from Phase 22.5b
- **New SSRF sink matchers**: `axios`, `got`, `undici.request` (JS/TS), `httpx.post` + verb variants (Python), `http.NewRequestWithContext` (Go), `Net::HTTP.post`, `HTTParty.post` (Ruby), `requests` verb variants (Python)
- **`flask_request.*` source matchers** (Python): common Flask import alias `from flask import request as flask_request` now recognized
- **New benchmark cases**: 4 vulnerable (js-ssrf-002, py-ssrf-002, go-ssrf-002, ruby-ssrf-001) + 4 safe (js-ssrf-safe-001, py-ssrf-safe-001, go-ssrf-safe-001, php-ssrf-safe-001)
- **Ruby added** to benchmark corpus (first Ruby benchmark case)

### Overall Metrics

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 57 | 28 | 2 | 16 | 67.1% | 96.6% | 79.2% |
| Rule-level | 57 | 28 | 2 | 16 | 67.1% | 96.6% | 79.2% |

Delta vs Phase 22.5b: TP +4, TN +4, FN +0, FP +0. Precision +1.7pp, Recall +0.2pp, F1 +1.3pp.

### Per Language (rule-level)

| Language | TP | FP | FN | TN | Precision | Recall | F1 |
|----------|----|----|----|----|-----------|--------|----|
| Go | 12 | 6 | 0 | 3 | 66.7% | 100.0% | 80.0% |
| Java | 10 | 7 | 1 | 1 | 58.8% | 90.9% | 71.4% |
| JavaScript | 12 | 6 | 0 | 3 | 66.7% | 100.0% | 80.0% |
| PHP | 10 | 3 | 1 | 6 | 76.9% | 90.9% | 83.3% |
| Python | 12 | 6 | 0 | 3 | 66.7% | 100.0% | 80.0% |
| Ruby | 1 | 0 | 0 | 0 | 100.0% | 100.0% | 100.0% |

### Per Vulnerability Class (rule-level)

| Class | TP | FP | FN | Precision | Recall | F1 |
|-------|----|----|----|-----------|---------|----|
| cmdi | 11 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| code_injection | 7 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| deser | 4 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| fmt_string | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| path_traversal | 6 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| sqli | 11 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| ssrf | 9 | 0 | 1 | 100.0% | 90.0% | 94.7% |
| xss | 8 | 0 | 1 | 100.0% | 88.9% | 94.1% |

### SSRF-Specific Metrics

| Language | TP | FN | Recall |
|----------|----|----|--------|
| Go | 2 | 0 | 100.0% |
| Java | 1 | 1 | 50.0% |
| JavaScript | 2 | 0 | 100.0% |
| PHP | 1 | 0 | 100.0% |
| Python | 2 | 0 | 100.0% |
| Ruby | 1 | 0 | 100.0% |

SSRF overall: 9/10 detected (90.0% recall), 100% precision (0 false positives).

### False Negatives (missed vulnerabilities)

| Case | File | Notes |
|------|------|-------|
| java-ssrf-002 | java/ssrf/SsrfHttpClient.java | `client.send(...)` — variable receiver doesn't suffix-match `HttpClient.send`; requires type resolution |
| php-xss-001 | php/xss/xss_reflected.php | `echo` is a language construct, not a function call |

### False Positives (safe code flagged)

28 of 44 safe cases were incorrectly flagged as vulnerable. Remaining FPs are
dominated by taint not recognizing sanitization, reassignment, validation, and
type-check patterns.

| Language | Safe cases | TN | FP | TN rate |
|----------|-----------|----|----|---------|
| Go | 9 | 3 | 6 | 33.3% |
| Java | 8 | 1 | 7 | 12.5% |
| JavaScript | 9 | 3 | 6 | 33.3% |
| PHP | 9 | 6 | 3 | 66.7% |
| Python | 9 | 3 | 6 | 33.3% |

### SSRF Known Limitations

- **Variable-receiver method calls**: `client.send(...)` vs `HttpClient.send(...)` — the scanner uses suffix matching on the call text, so variable receivers don't match type-qualified sink names. Fixing requires type-aware resolution (out of scope for static analysis without type inference).
- **Import aliasing** (general): arbitrary import aliases are not traced. `flask_request` is explicitly supported, but other aliases (e.g., `from flask import request as r`) are not.
- **No SSRF sanitizers**: URL-parsing functions (`urlparse`, `new URL`) parse URLs but don't make them safe. Allowlist checks are if-condition patterns that can't be modeled as function-call sanitizers without engine changes. The existing `classify_condition()` validation system marks `path_validated=true` for conditions containing "valid"/"check"/etc.
- **Deep builder patterns**: Request object construction chains (e.g., `HttpRequest.newBuilder().uri(...).build()`) may not propagate taint through all intermediate steps.
- **DNS-resolution-aware blocking**: Internal IP blocking (TOCTOU with DNS rebinding) is out of scope for static analysis.
- **Async/callback flows**: URLs set in callbacks or resolved asynchronously may not be tracked through the full async chain.

### Thresholds

Thresholds unchanged from Phase 22.5b baseline.

| Metric | Baseline | Threshold |
|--------|----------|-----------|
| Rule-level Precision | 65.4% | 60.4% |
| Rule-level Recall | 96.4% | 91.4% |
| Rule-level F1 | 77.9% | 72.9% |

## Phase 22.5b (2026-03-21)

Scanner version: 0.4.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 95 cases (55 vulnerable, 40 safe)

### Changes from Phase 22.5
- **Constant-arg AST suppression**: Security AST pattern rules now suppressed when all call arguments are provably literal constants (tree-sitter level check)
- **CFG constant suppression fix**: Removed buggy `!source_derived` guard from `is_all_args_constant` check in `guards.rs`; fixed callee-parts matching to strip parenthesized arg portions; added function parameter acceptance

### FP→TN conversions
- `go-safe-001`: constant args to `exec.Command` — CFG suppression + AST suppression
- `go-safe-005`: reassigned to constant — CFG one-hop trace
- `php-safe-001`: constant arg to `system()` — AST suppression
- `py-safe-001`: constant arg to `os.system()` — AST suppression

### Overall Metrics

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 53 | 28 | 2 | 12 | 65.4% | 96.4% | 77.9% |
| Rule-level | 53 | 28 | 2 | 12 | 65.4% | 96.4% | 77.9% |

### Per Language (rule-level)

| Language | TP | FP | FN | TN | Precision | Recall | F1 |
|----------|----|----|----|----|-----------|--------|----|
| Go | 11 | 6 | 0 | 2 | 64.7% | 100.0% | 78.6% |
| Java | 10 | 7 | 1 | 1 | 58.8% | 90.9% | 71.4% |
| JavaScript | 11 | 6 | 0 | 2 | 64.7% | 100.0% | 78.6% |
| PHP | 10 | 3 | 1 | 5 | 76.9% | 90.9% | 83.3% |
| Python | 11 | 6 | 0 | 2 | 64.7% | 100.0% | 78.6% |

### Per Vulnerability Class (rule-level)

| Class | TP | FP | FN | Precision | Recall | F1 |
|-------|----|----|----|-----------|---------|----|
| cmdi | 11 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| code_injection | 7 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| deser | 4 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| fmt_string | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| path_traversal | 6 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| sqli | 11 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| ssrf | 5 | 0 | 1 | 100.0% | 83.3% | 90.9% |
| xss | 8 | 0 | 1 | 100.0% | 88.9% | 94.1% |

### False Negatives (missed vulnerabilities)

| Case | File | Notes |
|------|------|-------|
| java-ssrf-002 | java/ssrf/SsrfHttpClient.java | HttpClient.send() not in Java sink rules |
| php-xss-001 | php/xss/xss_reflected.php | echo is a language construct, not a function call |

### False Positives (safe code flagged)

28 of 40 safe cases were incorrectly flagged as vulnerable. Down from 32 in
Phase 22.5. Remaining FPs are dominated by taint not recognizing sanitization,
reassignment, validation, and type-check patterns.

| Language | Safe cases | TN | FP | TN rate |
|----------|-----------|----|----|---------|
| Go | 8 | 2 | 6 | 25.0% |
| Java | 8 | 1 | 7 | 12.5% |
| JavaScript | 8 | 2 | 6 | 25.0% |
| PHP | 8 | 5 | 3 | 62.5% |
| Python | 8 | 2 | 6 | 25.0% |

### Thresholds

Regression thresholds are set 5 percentage points below baseline scores.
These are enforced in `tests/benchmark_test.rs`.

| Metric | Baseline | Threshold |
|--------|----------|-----------|
| Rule-level Precision | 65.4% | 60.4% |
| Rule-level Recall | 96.4% | 91.4% |
| Rule-level F1 | 77.9% | 72.9% |

## Phase 22.5 (2026-03-21)

Scanner version: 0.4.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 95 cases (55 vulnerable, 40 safe)

### Changes from Phase 22 baseline
- Fixed py-ssrf-001 rule-ID mismatch (cfg-unguarded-sink now accepted)
- Added bare `exec`/`execSync` as JS command injection taint sinks
- Added `Template` as Python SSTI/XSS taint sink

### Overall Metrics

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 53 | 32 | 2 | 8 | 62.4% | 96.4% | 75.7% |
| Rule-level | 53 | 32 | 2 | 8 | 62.4% | 96.4% | 75.7% |

## Phase 22 baseline (2026-03-21)

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| Rule-level | 49 | 30 | 6 | 10 | 62.0% | 89.1% | 73.1% |
