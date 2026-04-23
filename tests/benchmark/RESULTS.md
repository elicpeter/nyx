# Nyx Benchmark Results

Current baseline (as of Phase 15 real-CVE language-gap expansion, 2026-04-23):

| Metric                | File-level | Rule-level | CI floor |
|-----------------------|------------|------------|----------|
| Precision             | 0.945      | 0.945      | 0.861    |
| Recall                | 1.000      | 0.994      | 0.944    |
| F1                    | 0.972      | 0.969      | 0.901    |

Corpus: 295 cases across 10 languages — 267 synthetic + 28 real-CVE cases (14 vulnerable/patched pairs). Scanner 0.5.0, full analysis mode. CI floors are unchanged from Phase CF-7; the Phase 15 delta is within 1 pp and does not warrant tightening.

Machine-readable per-run data lives in `tests/benchmark/results/` (`latest.json` plus dated snapshots). This file is a narrative changelog — only the two most recent phases are kept in full detail; earlier phases are condensed into the history table at the end.

---

## Phase 15 — Real-CVE language-gap expansion (2026-04-23)

### Motivation

Phase 13 and Phase 14 covered 9 CVEs across Python, JavaScript, TypeScript, Go, Java, Ruby, and PHP — every Stable and Beta tier language. The Preview-tier languages (C, C++) had zero real-CVE coverage, so the memory-safety and command-injection pattern rules for those languages were defended only by synthetic micro-fixtures. Phase 15 fills that gap with 4 Preview-tier CVEs (2 C, 2 C++) and adds a second Java CVE in the Runtime.exec class (to complement the existing Commons Collections deserialization case). Rust was considered but dropped: its code-quality pattern rules (`rs.memory.*`, `rs.quality.*`) are not CVE-class, and the taint-flow sink set (sqlx / rusqlite / diesel / reqwest / `std::process::Command`) did not yield a permissive-licensed, well-documented CVE reducible to ~30 LOC with a clean patched variant. Go was considered for a second CVE but dropped: idiomatic prepared statements make Go SQLi CVEs rare, `gob` decoding is niche, and published `InsecureSkipVerify` CVEs mostly describe receiver-side TLS bypass rather than the client-side pattern the rule detects.

### What changed

- **Five additional CVE pairs** added to `tests/benchmark/cve_corpus/` (10 fixture files, vulnerable + patched per CVE). Same header convention, same minimal-reproducer discipline, same `provenance: "real_cve"` marker. First entries ever for `cve_corpus/c/` and `cve_corpus/cpp/`.
- **Ground truth**: 10 new cases; `corpus_size` bumped 285 → 295. Vulnerable fixtures assert on an `expected_rule_ids` entry (the pattern-rule that fires on the disclosed sink) plus `taint-unsanitised-flow` as an acceptable alternative. Patched fixtures assert on `forbidden_rule_ids` (the CVE's class-specific rule plus the cross-cutting taint ID) so Nyx does not refire on the fix.
- **No harness changes**: the `cve_corpus/` path resolution and `real_cve` provenance scaffolding landed in Phase 13; Phase 15 is pure fixture + ground-truth expansion.
- **Regression thresholds unchanged**: floors stay at `P≥0.861 R≥0.944 F1≥0.901`.

### Real-CVE Corpus

| CVE              | Language   | Project                      | License              | Vuln class       | Vulnerable outcome | Patched outcome |
|------------------|------------|------------------------------|----------------------|------------------|--------------------|-----------------|
| CVE-2023-48022   | Python     | Ray                          | Apache-2.0           | CMDI             | TP (rule + line)   | TN              |
| CVE-2017-18342   | Python     | PyYAML                       | MIT                  | Deserialization  | TP (rule + line)   | TN              |
| CVE-2019-14939   | JavaScript | mongo-express                | MIT                  | code_exec        | TP (rule + line)   | TN              |
| CVE-2023-26159   | TypeScript | follow-redirects             | MIT                  | SSRF             | TP (rule + line)   | TN              |
| CVE-2022-30323   | Go         | hashicorp/go-getter          | MPL-2.0              | CMDI             | TP (rule + line)   | TN              |
| CVE-2015-7501    | Java       | Apache Commons Collections   | Apache-2.0           | Deserialization  | TP (rule + line)   | TN              |
| CVE-2013-0156    | Ruby       | Ruby on Rails                | MIT                  | Deserialization  | TP (rule)          | TN              |
| CVE-2017-9841    | PHP        | PHPUnit                      | BSD-3-Clause         | code_exec        | TP (rule + line)   | TN              |
| CVE-2018-15133   | PHP        | Laravel                      | MIT                  | Deserialization  | TP (rule + line)   | TN              |
| CVE-2016-3714    | C          | ImageMagick (ImageTragick)   | ImageMagick License  | CMDI             | TP (rule + line)   | TN              |
| CVE-2019-18634   | C          | sudo (pwfeedback)            | ISC                  | memory_safety    | TP (rule + line)   | TN              |
| CVE-2019-13132   | C++        | ZeroMQ libzmq                | MPL-2.0              | memory_safety    | TP (rule + line)   | TN              |
| CVE-2022-1941    | C++        | Protocol Buffers             | BSD-3-Clause         | memory_safety    | TP (rule + line)   | TN              |
| CVE-2017-12629   | Java       | Apache Solr                  | Apache-2.0           | CMDI             | TP (rule + line)   | TN              |

New-in-Phase-15 detail:

- **CVE-2016-3714** (ImageMagick "ImageTragick" delegate RCE). Vulnerable fixture: user-controlled filename is substituted into a shell template and handed to `system()` — Nyx fires `c.cmdi.system` at the documented sink line. Patched fixture: in-process coder + basename check, no `system()` path — zero findings.
- **CVE-2019-18634** (sudo pwfeedback stack overflow). Vulnerable fixture: stdin-sourced token `strcpy`'d into a fixed on-stack feedback buffer — Nyx fires `c.memory.strcpy`. Patched fixture: a bounded `copy_bounded` helper replaces the unchecked copy — zero findings.
- **CVE-2019-13132** (ZeroMQ libzmq V2 metadata overflow). Vulnerable fixture: peer-controlled bytes `strcpy`'d into a fixed on-stack identity buffer, mirroring the ZMTP v2 decode path — Nyx fires `cpp.memory.strcpy`. Patched fixture: bounded `std::string.assign` + hard length cap — zero findings.
- **CVE-2022-1941** (Protocol Buffers C++ `ParseContext` unknown-field overflow). Vulnerable fixture: wire-declared length trusted and `strcpy`'d into a scratch buffer — Nyx fires `cpp.memory.strcpy`. Patched fixture: bounded `std::string.assign` + `MAX_LABEL` cap — zero findings.
- **CVE-2017-12629** (Apache Solr XSLT response writer RCE). Vulnerable fixture: `req.getParameter("tr") → Runtime.getRuntime().exec(new String[]{"/bin/sh","-c","xsltproc "+tr})` — Nyx fires `java.cmdi.runtime_exec` and `taint-unsanitised-flow` (source line 29 → sink line 33). Patched fixture: fixed allowlist of transformer names mapped to classpath resources, no `Runtime.exec` path — zero findings.

Per-CVE precision/recall: each vulnerable case contributes 1 TP (Java CVE-2017-12629 contributes 2 — pattern-rule + taint edge) and its patched sibling 1 TN, so per-CVE precision and recall are both 1.000 at the rule level.

### Delta

Aggregate rule-level F1 on the 295-case corpus is **0.969** (P=**0.945**, R=**0.994**), a +0.001 delta vs the Phase 14 baseline (F1=0.968, P=0.944, R=0.994). File-level F1 **0.972** (P=0.945, R=1.000). The precision win is the ten new cases contributing 10 TP + 5 TN with no spurious firings on the fixes, diluting the existing FP rate slightly.

### Notes on selection

Phase 15 followed the same criteria as Phase 13/14: publicly disclosed CVE with a stable NVD advisory URL, vulnerability class already covered by a Nyx pattern rule so the vulnerable fixture produces a concrete `expected_rule_ids` hit (not just a generic `taint-unsanitised-flow`), extractable to ~30 LOC, permissive upstream license. The C/C++ picks target the two most abundant CVE classes for those languages — unchecked-copy memory-safety bugs (`strcpy` / `sprintf`-family) and shell-injection command-execution (`system()`-family). Each picked CVE is a well-known, historically damaging bug: ImageTragick mass-exploited image-upload endpoints in 2016, sudo pwfeedback gave any local user root on default-configured Linux distros in 2019, libzmq CVE-2019-13132 was pre-auth RCE on curve-disabled sockets, protobuf CVE-2022-1941 exposed every gRPC or Envoy binary decoding untrusted bytes, and Solr CVE-2017-12629 was a flagship unauthenticated-RCE vector for the entire Lucene / Solr fleet. Fixtures are minimal reproducers of the unsafe sink pattern, with explicit disclaimers — they are not verbatim excerpts of upstream internals.

---

## Phase 14 — Real-CVE corpus expansion (2026-04-23)

### Motivation

Phase 13 seeded the real-CVE subtree with one CVE per stable-tier language (Python / JavaScript / TypeScript). Six fixtures is enough to demonstrate the mechanism but not enough to defend the Beta- and Preview-tier languages against regressions on real-world code. Phase 14 extends the subtree to cover Go, Java, Ruby, and PHP, plus a second Python CVE in a different vulnerability class (deserialization, not CMDI). The goal is the same as Phase 13: regression protection on demonstrably real disclosed bugs, not synthetic analogues.

### What changed

- **Six additional CVE pairs** added to `tests/benchmark/cve_corpus/` (12 fixture files, vulnerable + patched per CVE). Same header convention, same minimal-reproducer discipline, same `provenance: "real_cve"` marker.
- **Ground truth**: 12 new cases; `corpus_size` bumped 273 → 285. Vulnerable fixtures assert on an `expected_rule_ids` entry (the pattern-rule that fires on the disclosed sink) plus `taint-unsanitised-flow` as an acceptable alternative. Patched fixtures assert on `forbidden_rule_ids` (the CVE's class-specific rule) so Nyx does not refire on the fix.
- **No harness changes**: the `cve_corpus/` path resolution and `real_cve` provenance scaffolding landed in Phase 13; Phase 14 is pure fixture + ground-truth expansion.
- **Regression thresholds unchanged**: floors stay at `P≥0.861 R≥0.944 F1≥0.901`.

### Real-CVE Corpus

| CVE              | Language   | Project                      | License      | Vuln class       | Vulnerable outcome | Patched outcome |
|------------------|------------|------------------------------|--------------|------------------|--------------------|-----------------|
| CVE-2023-48022   | Python     | Ray                          | Apache-2.0   | CMDI             | TP (rule + line)   | TN              |
| CVE-2017-18342   | Python     | PyYAML                       | MIT          | Deserialization  | TP (rule + line)   | TN              |
| CVE-2019-14939   | JavaScript | mongo-express                | MIT          | code_exec        | TP (rule + line)   | TN              |
| CVE-2023-26159   | TypeScript | follow-redirects             | MIT          | SSRF             | TP (rule + line)   | TN              |
| CVE-2022-30323   | Go         | hashicorp/go-getter          | MPL-2.0      | CMDI             | TP (rule + line)   | TN              |
| CVE-2015-7501    | Java       | Apache Commons Collections   | Apache-2.0   | Deserialization  | TP (rule + line)   | TN              |
| CVE-2013-0156    | Ruby       | Ruby on Rails                | MIT          | Deserialization  | TP (rule)          | TN              |
| CVE-2017-9841    | PHP        | PHPUnit                      | BSD-3-Clause | code_exec        | TP (rule + line)   | TN              |
| CVE-2018-15133   | PHP        | Laravel                      | MIT          | Deserialization  | TP (rule + line)   | TN              |

New-in-Phase-14 detail:

- **CVE-2017-18342** (PyYAML `yaml.load` default loader). Vulnerable fixture: `request.get_data → yaml.load` — Nyx fires `py.deser.yaml_load` and `taint-unsanitised-flow` at the documented sink line. Patched fixture: `yaml.safe_load` — zero findings.
- **CVE-2022-30323** (hashicorp/go-getter URL → git argv injection). Vulnerable fixture: `r.URL.Query().Get("src") → exec.Command("git", "clone", url, ...)` — Nyx fires `go.cmdi.exec_command` and `taint-unsanitised-flow`. Patched fixture: scheme allowlist + in-process go-git `PlainClone` removes the `exec.Command` path entirely — zero findings.
- **CVE-2015-7501** (Apache Commons Collections `InvokerTransformer` gadget chain). Vulnerable fixture: `req.getInputStream → new ObjectInputStream(...).readObject()` — Nyx fires `java.deser.readobject` and `taint-unsanitised-flow`. Patched fixture: Jackson JSON codec replaces native Java deserialization — zero findings.
- **CVE-2013-0156** (Rails XML-params YAML tag RCE). Vulnerable fixture: `YAML.load(params[:prefs])` — Nyx fires `rb.deser.yaml_load` (no taint edge because Ruby `params[...]` is not currently labeled as a taint source; the AST pattern is what catches this class). Patched fixture: `JSON.parse` replaces `YAML.load` — zero findings.
- **CVE-2017-9841** (PHPUnit `eval-stdin.php` webshell). Vulnerable fixture: `file_get_contents('php://input') → eval(...)` — Nyx fires `php.code_exec.eval` and `taint-unsanitised-flow`. Patched fixture: SAPI guard and the eval sink removed — zero findings.
- **CVE-2018-15133** (Laravel cookie `unserialize` on leaked APP_KEY). Vulnerable fixture: `$_COOKIE['XSRF-TOKEN'] → base64_decode → unserialize` — Nyx fires `php.deser.unserialize` and `taint-unsanitised-flow`. Patched fixture: HMAC-verified JSON payload — zero findings.

Per-CVE precision/recall: each vulnerable case contributes 1 TP and its patched sibling 1 TN, so per-CVE precision and recall are both 1.000 at the rule level.

### Delta

Aggregate rule-level F1 on the 285-case corpus is **0.968** (P=**0.944**, R=**0.994**), a +0.001 delta vs the Phase 13 baseline (F1=0.967, P=0.942, R=0.994). File-level F1 **0.971** (P=0.944, R=1.000). The precision win is the twelve new cases contributing 6 TP + 6 TN with no spurious firings on the fixes, diluting the existing FP rate slightly.

### Notes on selection

Phase 14's picks followed the Phase 13 criteria: publicly disclosed CVE with a known patch, vulnerability class already covered by a Nyx pattern rule (so the vulnerable fixture produces a concrete `expected_rule_ids` hit, not just a generic `taint-unsanitised-flow`), extractable to ~30 LOC, permissive upstream license. Each added CVE is a well-known, historically damaging bug — mass-scanned webshells (PHPUnit 2017), pre-auth RCE on every Rails app (2013-0156), the original Java deserialization gadget chain (Commons Collections 2015), the go-getter fleet-wide Terraform/Packer/Nomad/Vault exposure (2022), and a textbook Laravel cookie-forgery chain (2018).

---

## Phase 13 — Real-CVE replay corpus (2026-04-23)

### Motivation

The corpus up to Phase CF-7 was 267 synthetic micro-fixtures (8–20 LOC each). A 95% F1 on toy code does not imply a 95% F1 on real applications. Phase 13 adds a small number of *real* historical CVEs — vulnerable code extracted from the patched upstream project and held under a stable expected rule — so the benchmark floor is now defended by regression protection on demonstrably real bugs, not just synthetic analogues.

### What changed

- **New subtree**: `tests/benchmark/cve_corpus/<lang>/<CVE-ID>/` with a `vulnerable.*` and a `patched.*` file per CVE. Each file carries a header comment with the CVE ID, upstream project, upstream license, and advisory link.
- **Harness**: `tests/benchmark_test.rs::scan_corpus_file` now resolves any `file` entry whose path starts with `cve_corpus/` from the `benchmark_dir` (one level above `corpus/`) instead of the synthetic-corpus root. The change is a single if-branch; all existing synthetic cases are unaffected.
- **Ground truth**: six new cases added with `provenance: "real_cve"`. Vulnerable fixtures assert on `expected_rule_ids`; patched fixtures assert on `forbidden_rule_ids` so Nyx does not *refire* on the fix.
- **Regression thresholds unchanged**: floors stay at `P≥0.861 R≥0.944 F1≥0.901`. The Phase 13 rule-level F1 delta is +0.001 against the CF-7 baseline — the repo's policy ("tighten on durable, measurable improvements") does not justify movement on a corpus-expansion phase.

### Real-CVE Corpus

| CVE              | Language   | Project         | License    | Vuln class | Vulnerable outcome | Patched outcome |
|------------------|------------|-----------------|------------|------------|--------------------|-----------------|
| CVE-2023-48022   | Python     | Ray             | Apache-2.0 | CMDI       | TP (rule + line)   | TN              |
| CVE-2019-14939   | JavaScript | mongo-express   | MIT        | code_exec  | TP (rule + line)   | TN              |
| CVE-2023-26159   | TypeScript | follow-redirects | MIT        | SSRF       | TP (rule + line)   | TN              |

- **CVE-2023-48022** (Ray job-submission RCE). Vulnerable fixture: `request.get_json → os.system` with shell concatenation — Nyx fires `py.cmdi.os_system` and the cross-cutting `taint-unsanitised-flow` at the documented sink line. Patched fixture: `shlex.split → subprocess.run(argv, shell=False)` — zero findings.
- **CVE-2019-14939** (mongo-express `/checkValid` eval RCE). Vulnerable fixture: `req.body.document → eval("(" + document + ")")` — Nyx fires `js.code_exec.eval` and `taint-unsanitised-flow`. Patched fixture: `EJSON.parse(document)` inside a try/catch — zero findings.
- **CVE-2023-26159** (follow-redirects credential-leak / SSRF surface). Vulnerable fixture: `req.query.url → axios.get(target)` — Nyx fires `taint-unsanitised-flow` (no TypeScript SSRF-specific rule ID is emitted on this sink, which matches the rest of the TS SSRF corpus). Patched fixture: allowlist check over the parsed host + fixed internal URL handed to axios — zero findings.

Per-CVE precision/recall: each vulnerable case contributes 1 TP (and its patched sibling 1 TN), so per-CVE precision and recall are both 1.000 at the rule level.

### Delta

Aggregate rule-level F1 on the new 273-case corpus is 0.967 (P=0.942, R=0.994) — a hair above the pre-Phase-13 baseline of 0.966, and materially above the rule-level precision floor (0.894). The win is concentrated in honest regression protection on real code; precision edges up because the six new cases contribute 3 TP + 3 TN and no spurious firings on the fixes.

### Notes on selection

The starter set is intentionally small (1 CVE per stable-tier language, vulnerable + patched pair per CVE). Criteria applied when choosing each CVE: publicly disclosed with a known patch, vulnerability class that Nyx's existing rules cover (CMDI / code_exec / SSRF), extractable to ~30 LOC of representative code, permissive upstream license (Apache-2.0 / MIT) so the attribution header is sufficient. Fixtures are minimal reproducers of the *unsafe sink pattern*, not verbatim excerpts of upstream internals — the goal is regression protection on the documented pattern, not re-running the original exploit end-to-end.

---

## Phase CF-7 — Demand-driven backwards analysis (2026-04-22)

### Motivation

The forward taint engine proceeds source-to-sink, spending budget on
every function the source might touch.  Its precision ceiling is fixed
by what summaries + inline re-analysis can preserve on every edge of a
flow — a single lossy edge drops the finding.  This phase adds the
opposite direction: start at each sink value and walk *reverse* SSA
edges (and cross-file callee bodies via
`GlobalSummaries.bodies_by_key`) until a source is reached, the
accumulated predicate renders the flow infeasible, or a budget is
exhausted.  Off by default; benchmark is neutral.

### Changes

1. **`src/taint/backwards.rs`** — new module with the core types:
   `DemandState` (sink-side demand: caps + validated-predicate bits +
   cross-function depth), `BackwardFlow` (the reached verdict per
   walked value), `BackwardsCtx` (minimal driver-inputs view),
   `FindingVerdict` (Confirmed / Inconclusive / Infeasible /
   BudgetExhausted), and the `analyse_sink_backwards` driver.  The
   backwards transfer handles every `SsaOp` variant — `Assign`/`Phi`
   fan out to operands, `Call` tries cross-file body expansion before
   falling back to arg-fanout, `Source`/`Const`/`Param`/`CatchParam`
   terminate.  Source recognition also consults the defining CFG
   node's `DataLabel::Source(_)` so Python-style call-sites like
   `request.args.get` are treated as source terminals.  Budgets:
   `DEFAULT_BACKWARDS_DEPTH = 2`, `BACKWARDS_VALUE_BUDGET = 1024`,
   `MAX_BACKWARDS_CALLEE_BLOCKS = 500`.
2. **Finding annotation** (`src/taint/mod.rs`): after forward taint
   and symex complete, if `analysis.engine.backwards_analysis` is on,
   the pass walks each finding's sink and writes its verdict onto
   `Finding.symbolic.cutoff_notes` via `annotate_finding`.  Placed
   after symex so its witness-style `symbolic` output survives;
   backwards layers `backwards-confirmed` / `backwards-infeasible` /
   `backwards-budget-exhausted` onto the notes vector.
3. **Confidence integration** (`src/evidence.rs`):
   `compute_taint_confidence` treats `backwards-confirmed` as a
   `+1` signal and `backwards-infeasible` as a `-3` penalty (a
   smaller-magnitude signal than the symex verdict, which reasons
   about concrete payloads).  `compute_confidence_limiters` surfaces
   infeasible/budget verdicts as user-readable strings.
4. **Switch surfaces**: new `AnalysisOptions.backwards_analysis` field
   (default `false`), CLI pair
   `--backwards-analysis / --no-backwards-analysis`, and legacy
   env-var `NYX_BACKWARDS=1`.  Same tri-state pattern as the other
   engine toggles.
5. **Docs** (`docs/advanced-analysis.md`): new "Demand-driven
   analysis" section documents the pass, how to enable it, and the
   first-cut limitations (no reverse-call-graph expansion past
   `ReachedParam`; constraint pruning uses predicate-summary bits
   only, not the full SMT backend; depth-bounded at k=2).

### Test coverage

* **Unit tests** (`src/taint/backwards.rs` — 12 tests): demand-state
  seeding, backward transfer per op (`Source`, `Const`, `Param`,
  `Assign`, `Phi`), driver end-to-end on a trivial
  Source→Assign→sink body, phi fan-out producing per-predecessor
  flows, verdict aggregation (`Confirmed` beats `Infeasible`), and
  `annotate_finding` idempotence + inconclusive no-op.
* **Integration** (`tests/backwards_analysis_tests.rs` + 4 fixtures):
  `demand_driven_reach_source` confirms a SQL-injection source is
  reached and picks up `backwards-confirmed` when the switch is on;
  `demand_driven_prove_infeasible` locks in first-cut structural
  behaviour (SMT-backed prune is a follow-up); `demand_driven_catch_new_fn`
  locks in the first-cut ReachedParam termination; `demand_driven_no_source`
  regression-guards against synthetic findings on source-free code.  A
  fifth sub-case asserts backwards OFF is a strict no-op (no
  annotations appear).

### Benchmark delta

Off-by-default posture preserves the benchmark floor byte-for-byte
(P=0.940, R=0.994, F1=0.966 rule-level; P=0.941, R=1.000, F1=0.970
file-level).  On-path precision improvements require two follow-ups:
reverse-call-graph expansion for flows that escape a function's
`ReachedParam` boundary, and full SMT integration for the infeasible
path class.  Both are tracked as CF-7 follow-up work; the
off-by-default switch lets operators opt in without disturbing CI.

---

## Phase CF-6 — Parameter-granularity points-to summaries (2026-04-22)

### Motivation

Prior to CF-6, the cross-file summary channel had no way to express
"callee mutates a shared heap object through one parameter so another
parameter's alias sees the new taint."  Container-op patterns (`push`,
`set`, …) were already captured through `param_to_container_store`, but
direct field writes — `obj.x = val` — fell outside
`classify_container_op`'s recognised-method list, so a common class of
flow (void helper that stores through a parameter) was invisible to
cross-file taint.  Whole-program points-to is out of scope for a
security scanner; a minimal parameter-granularity summary closes the
real flows at a negligible cost.

### Changes

1. **`PointsToSummary` data type** (`src/summary/points_to.rs`):
   bounded `SmallVec<[AliasEdge; 4]>` of directed `(source, target,
   kind)` edges where endpoints are `AliasPosition::Param(u32)` or
   `AliasPosition::Return` and `AliasKind` is `MayAlias` only for CF-6.
   Edge count is capped at `MAX_ALIAS_EDGES = 8`; overflow sets an
   `overflow` flag that callers honour as "any param aliases any other
   param and the return" — the conservative greatest-lower-bound over
   the alias lattice.
2. **Intra-procedural analysis** (`src/ssa/param_points_to.rs`): a
   single bounded pass over the SSA body.  For each `SsaOp::Assign`
   whose `var_name` is a dotted/indexed path, we resolve the root base
   to a formal-parameter index via `formal_param_names` (authoritative
   declaration-order map) and trace the RHS through Assign/Phi chains to
   another parameter, emitting `Param(src) → Param(dst)`.  For each
   `Terminator::Return(Some(v))` whose value traces to a parameter we
   emit `Param(i) → Return`.  Declaration-order indexing matters: SSA
   lowering skips formal params that are never read, so SSA-level
   indices and caller-side positional indices can diverge.  Trusting
   formal-order is the only way to keep the summary's edges aligned with
   the caller's `args[i]` slots.
3. **`SsaFuncSummary.points_to`** (`src/summary/ssa_summary.rs`): new
   `#[serde(default, skip_serializing_if = PointsToSummary::is_empty)]`
   field.  Legacy on-disk rows deserialise cleanly with an empty
   summary, so no engine-version bump is required.
4. **Summary application at cross-file call sites**
   (`src/taint/ssa_transfer.rs`): `resolved_points_to` is captured
   alongside the other cross-file fields before `callee_summary` is
   moved into the main taint branch.  Each `Param(src) → Param(dst)`
   edge unions caller-`args[src]`'s taint into the heap of caller-
   `args[dst]`'s points-to set *and* directly taints the dst SSA
   value — the direct channel is necessary when the caller's heap
   analysis has no allocation site for the arg (common for plain
   constructors in Python / JS / Java).  Each `Param(src) → Return`
   edge threads caller-`args[src]`'s points-to set through
   `dynamic_pts` onto the call's return value.  Overflow synthesises
   the conservative all-pairs graph.
5. **`ssa_summary_fits_arity`** (`src/summary/mod.rs`): arity filter
   extended to reject points-to entries referencing parameters past the
   key's declared arity (same guard that `param_to_return` /
   `param_to_sink` already use).  Prevents synthetic-capture
   mis-attributions from leaking into cross-file resolution.
6. **Observable-effects filter** (`src/taint/mod.rs`): summary
   filtering in `lower_all_functions` now treats a non-empty
   `PointsToSummary` as an observable effect so void helpers whose only
   signal is a parameter alias survive the "no effects, skip" filter.

### Test coverage

* **Unit tests** (`src/summary/points_to.rs`): data-structure
  invariants (dedup, overflow promotion, serde round-trip, legacy JSON
  decodes).
* **Unit tests** (`src/ssa/param_points_to.rs`): 5 structural shapes
  (field-write emits edge, return-alias emits edge, self-alias is
  dropped, out-of-range param rejected, bounded graph terminates).
* **Summary serde + arity** (`src/summary/tests.rs`): round-trip with
  points_to populated, legacy JSON deserialises with empty points_to,
  arity filter rejects out-of-range param indices.
* **Cross-file integration** (`tests/cross_file_alias_tests.rs` + 3
  fixtures): `cross_file_alias_mutating_helper` (Python void helper →
  py.cmdi finding through param alias), `cross_file_alias_returned_alias`
  (JS passthrough → shell-exec finding through return alias),
  `cross_file_alias_bounded_graph` (Python 20-edge graph → scan
  terminates under the overflow fallback).

### Benchmark

Rule-level F1 unchanged at 0.966 (P=0.940, R=0.994); file-level F1
unchanged at 0.970 (P=0.941, R=1.000).  Neutral, as expected: the
existing benchmark corpus does not exercise cross-file field-alias
flows, so CF-6's precision win is latent and will surface as the corpus
grows.  All 2173 tests pass (1687 lib + 486 integration).

---

## Phase CF-5 — Cross-file SCC joint fixed-point (2026-04-22)

### Motivation

The pass-2 orchestrator already iterates mutually-recursive SCCs to
convergence on merged summaries (`MAX_SCC_FIXPOINT_ITERS`-bounded with a
`SCC_FIXPOINT_SAFETY_CAP = 64` guard).  Post-CF-1/CF-2, those iterations
run cross-file inline re-analysis under the *current* merged summaries on
each iteration, so the summary-equality convergence predicate implicitly
covers inline convergence for monotone summaries.  What was missing was
an explicit signal distinguishing *cross-file* SCCs (where the recursion
crosses file boundaries and the inline+summary interaction is what drives
precision) from *intra-file* SCCs (where the iteration is purely about
summary fixpoint).  Without that signal, cap-hit diagnostics conflated
the two root causes and the orchestrator could not target cross-file
SCCs for specialised handling.

### Changes

1. **`scc_spans_files()` helper + `FileBatch.cross_file` flag**
   (`src/callgraph.rs`): an SCC is flagged cross-file when its nodes
   belong to more than one namespace.  `scc_file_batches_with_metadata`
   unions the flag across all SCCs contributing to each topo batch.
   `cross_file ⊆ has_mutual_recursion` by construction (a non-recursive
   cross-file chain resolves topologically and is not batched).
2. **Inline cache lifecycle hooks** (`src/taint/ssa_transfer.rs`): new
   `inline_cache_clear_epoch()` and `inline_cache_fingerprint()` helpers
   give the SCC orchestrator a concrete contract for per-iteration cache
   semantics.  The per-file cache is already reconstructed fresh inside
   `analyse_file`, so today these are no-op plumbing — kept explicit so
   any future shared-cache refactor has a pre-agreed API.
3. **Cross-file-specific cap-hit tag** (`src/commands/scan.rs`):
   `SCC_UNCONVERGED_CROSS_FILE_NOTE_PREFIX` is a strict superset of
   `SCC_UNCONVERGED_NOTE_PREFIX`; callers filtering on the base prefix
   still match, while consumers that want the narrower cross-file case
   can match on the longer constant.  `tag_unconverged_findings()`
   takes a `cross_file: bool` switch and `run_topo_batches()` threads
   the batch flag through.
4. **Observability**: cross-file SCCs emit a dedicated `debug!` log at
   iteration start; cap-hit warnings carry the `cross_file = {bool}`
   field so operators can root-cause imprecision quickly.

### Fixtures and tests

- `tests/fixtures/cross_file_scc_mutual_recursion/` (Python, 2-file
  mutual recursion with CMDI sink): transitive taint must reach the
  caller across the cycle.
- `tests/fixtures/cross_file_scc_three_way_cycle/` (Python, 3-file
  cycle): pinned iteration envelope proves the SCC fix-point loop does
  the work, not topo order.
- `tests/fixtures/cross_file_scc_recursive_with_sanitiser/` (Python,
  2-file sanitised cycle): joint convergence carries the `shlex.quote`
  sanitizer across the cycle and suppresses the caller's CMDI.
- `tests/scc_cross_file_tests.rs`: wires the three fixtures into the
  integration harness.
- Callgraph unit tests: `scc_file_batches_with_metadata_marks_cross_file`,
  `scc_file_batches_with_metadata_intra_file_scc_not_cross_file`,
  `scc_spans_files_single_node`.
- Inline-cache lifecycle unit tests
  (`inline_cache_epoch_tests` in `src/taint/ssa_transfer.rs`):
  `clear_epoch_drops_all_entries`,
  `fingerprint_is_order_independent`,
  `fingerprint_changes_when_return_caps_change`,
  `fingerprint_tracks_missing_return_taint_as_zero`.
- Tag-variant unit tests (`scc_tagging_tests` in `src/commands/scan.rs`):
  cross-file and non-cross-file variants emit the expected prefixes.

### Benchmark delta

Byte-for-byte neutral vs CF-3 (P/R/F1 unchanged at 0.940 / 0.994 /
0.966).  The corpus exercises cross-file SCCs that already converge
cleanly under the existing summary-snapshot loop, so CF-5's value is
diagnostic clarity (tighter cap-hit tag, `cross_file` metric) and an
API surface the future joint-cache refactor can hook into — not a
precision shift on today's fixtures.

### Known limitations

- `inline_cache_clear_epoch` is a semantic hook, not a shared-cache
  lifecycle: the per-file cache is already ambient-cleared at each
  iteration via `analyse_file` reconstruction.  A true cross-file
  shared cache would be a more involved refactor (rayon-safe shared
  `RefCell<InlineCache>` across SCC files, epoch-tag invalidation on
  cache miss/hit).
- Benchmark-visible precision win will require corpus fixtures that
  specifically exercise cross-file SCCs with precision-degrading
  summary approximation; the current corpus's cross-file cycles all
  converge in 0–5 iterations and land on the same answer at both the
  summary and inline path.

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
