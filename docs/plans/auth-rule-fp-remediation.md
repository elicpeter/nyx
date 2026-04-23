# Auth Rule FP Remediation Plan — `rs.auth.missing_ownership_check`

> **How to use this document.** Each numbered item (A1, A2, A3, B1, …) is a self-contained unit of work. Read §1–§4 once for context, then pick a phase and implement it end to end using the Acceptance Criteria as your done-signal. Fresh Claude Code sessions: you have no prior context beyond this file and the repo; everything you need is here or cited with file:line. Run `cargo test --test auth_analysis_tests` after any change.

---

## 1. Background

### The report
A user ran nyx against a real-world Axum/Rust web service (`src/handlers/recaps.rs`, `src/handlers/reviews.rs` in their codebase) and found that **34 of 34** HIGH-severity findings for rule `rs.auth.missing_ownership_check` were false positives. The rule fires on any operation that takes a scoped identifier (`*_id`) without a visibly preceding ownership/membership check, but the codebase routinely enforces authorization through five patterns the rule fails to recognize — so it flags correct code.

### Why the current rule is noisy — root cause
`src/auth_analysis/` is a **standalone AST pattern-matching subsystem** that runs alongside, not inside, nyx's SSA/taint engine. It ignores every piece of infrastructure the rest of the scanner uses: type facts (Phase 10), cross-file summaries (CF-5), symbolic strings (Phase 22), per-return-path sanitizers (CF-4), points-to (CF-6). Four concrete gaps drive the FPs:

| # | Gap | Evidence |
|---|-----|----------|
| 1 | **No receiver-type awareness.** `matches_name("map.insert", "insert") == matches_name("db.insert", "insert")`. The receiver chain is discarded. | `src/auth_analysis/config.rs:836-842` |
| 2 | **No sink categorization.** `mutation_indicator_names = ["insert","add","set","remove",…]` matches any call, regardless of target. | `src/auth_analysis/config.rs:647-662` |
| 3 | **Intraprocedural only.** `has_prior_subject_auth` looks at `unit.auth_checks` in the same function body; helpers that internally call `require_*` are invisible. | `src/auth_analysis/checks.rs:283-303` |
| 4 | **No row-ownership equality recognition.** `if owner_id != user.id { return 403 }` produces a `condition_text` but never an `AuthCheck`. | `src/auth_analysis/extract/common.rs:449-497` |
| 5 | **`user.id` isn't self in Rust.** `is_self_scoped_session_subject` hardcodes JS/Node bases (`req.user`, `ctx.session.user`); Rust `let user = require_auth(…).await?` bindings aren't recognized. | `src/auth_analysis/checks.rs:408-434` |

### The 5 FP patterns (and the std::collections noise)
Roughly 60% of the 34 FPs (~20) are `HashMap`/`HashSet`/`BTreeMap` method calls on local collections — these are never authorization-relevant. The remaining ~14 split across:

| Pattern | Shape | Fixture |
|---------|-------|---------|
| **P0 — std::collections on local var** | `let mut m = HashMap::new(); m.insert(widget_id, …)` | `hashmap_local_noise.rs` |
| **P1 — SQL JOIN through ACL table** | `SELECT … FROM items i JOIN group_members gm ON i.group_id = gm.group_id WHERE gm.user_id = ?1` → returned `widget_id` used downstream | `sql_join_acl.rs` |
| **P2 — Transitive helper check** | Handler calls `validate_target(db, widget_id, user.id)` which internally calls `authz::require_group_member` | `transitive_helper.rs` |
| **P3 — Row-level ownership equality** | `let row = db.query("SELECT user_id, group_id FROM docs WHERE id = ?1"); if row.user_id != user.id { return 403 }` → `row.group_id` used downstream | `row_ownership_equality.rs` |
| **P4 — Helper takes scoped IDs as params** | `async fn get_friend_ids(db, user_id, other_ids) { set.insert(…) }` — internal collection ops flagged | `helper_scoped_params.rs` |
| **P5 — `user.id` is self** | `let user = auth::require_auth(&req).await?; get_friend_ids(&db, user.id)` — flagged because `user.id` looks scoped | `self_scoped_user.rs` |

Anonymized reproducers for each pattern are in §8. A **positive control** (a real missing-ownership bug — should still flag after all fixes) is `true_positive_missing_check.rs` in §8.

---

## 2. Architecture primer (for fresh sessions)

Nyx is a multi-language vulnerability scanner in Rust. Two major analyses run per file:

1. **Taint/SSA engine** — `src/taint/`, `src/ssa/`, `src/labels/` — the main machinery. Language-agnostic CFG → SSA IR → block-level worklist taint with `Cap`-based flow. Has cross-file summaries (`src/summary.rs`, `GlobalSummaries`), type facts (`src/type_facts.rs`), points-to (`src/points_to.rs`), symbolic strings (`src/symex/`).

2. **Auth analysis** — `src/auth_analysis/` — **standalone AST pattern-matcher**. Entry: `auth_analysis::run_auth_analysis(tree, bytes, lang, path, cfg)` called from `src/ast.rs:1170`. Does NOT use the SSA/taint engine. Its internal pipeline:

   ```
   tree → extract::extract_authorization_model() → AuthorizationModel { routes, units }
        → checks::run_checks(model, rules) → Vec<AuthFinding> → Vec<Diag>
   ```

   Per-language extractors live in `src/auth_analysis/extract/{axum,actix_web,rocket,…}.rs` with shared helpers in `extract/common.rs`. Rules for each language are built in `src/auth_analysis/config.rs::build_auth_rules(cfg, lang)`.

### Key types (to orient in `src/auth_analysis/model.rs`)

- `AnalysisUnit` — a function body; holds `auth_checks`, `operations`, `call_sites`, `condition_texts`, `context_inputs`
- `AuthCheck { kind: AuthCheckKind, callee, subjects, line, … }` — something that proved authorization at a given line
- `SensitiveOperation { kind: OperationKind::{Read,Mutation,TokenLookup}, callee, subjects, line, text }` — a candidate sink
- `ValueRef { source_kind: ValueSourceKind, name, base, field, index }` — an argument/subject, tagged by how it was sourced (`RequestParam`, `RequestBody`, `Session`, `Identifier`, …)

### Current Rust rule configuration
`src/auth_analysis/config.rs:605-706`. Fields to know:

- `authorization_check_names`: `check_ownership`, `has_ownership`, `require_ownership`, `ensure_ownership`, `is_owner`, `authorize`, `verify_access`, `has_permission`, `can_access`, `can_manage`, plus `*_membership` variants
- `login_guard_names`: `require_login`, `require_auth`, `CurrentUser`, `SessionUser`, `AuthUser`, `RequireAuth`, …
- `mutation_indicator_names`: `update`, `delete`, `destroy`, `create`, `save`, `archive`, `publish`, `remove`, `insert`, `add`, `confirm`, `invite`, `accept`, `set`
- `read_indicator_names`: `find`, `find_by_id`, `get`, `load`, `fetch`, `lookup`, `list`, `read`, `query`

### Name matching helper
`src/auth_analysis/config.rs:836` — `matches_name(name, pattern)` takes the last `.` segment of each and does canonical (alphanumeric-lowercase) equality OR prefix match. **This is where receiver info is discarded.**

### Test harness
- Fixtures live one-per-file in `tests/fixtures/auth_analysis/*.{rs,js,py,go,rb,java}`.
- Integration tests in `tests/auth_analysis_tests.rs`. Pattern:
  ```rust
  assert_has("fixture_file.rs", "rs.auth.missing_ownership_check");   // must flag
  assert_absent("fixture_file.rs", "rs.auth.missing_ownership_check"); // must NOT flag
  ```
- Helpers `auth_fixture_dir`, `scan_all_fixtures`, `assert_has`, `assert_absent` are already defined at the top of the test file.
- Run only the auth tests: `cargo test --test auth_analysis_tests`
- Run one test: `cargo test --test auth_analysis_tests axum_admin_route_missing_admin_check`

---

## 3. File inventory for this work

Any phase here touches some subset of:

```
src/auth_analysis/
├── mod.rs           — entry point; run_auth_analysis
├── config.rs        — AuthAnalysisRules, matches_name, build_auth_rules
├── model.rs         — AnalysisUnit, AuthCheck, SensitiveOperation, ValueRef enums
├── checks.rs        — run_checks + the 5 rule implementations
└── extract/
    ├── common.rs    — shared AST walker, call_name, collect_condition, extract_value_refs
    ├── axum.rs      — Rust/Axum-specific extraction
    ├── actix_web.rs
    └── rocket.rs

tests/auth_analysis_tests.rs                       — integration test entry
tests/fixtures/auth_analysis/                      — one .rs file per fixture
src/utils/config.rs::LanguageAnalysisConfig.auth   — user-facing config surface (nyx.toml)
```

Cross-cutting reads for Phase B+:
```
src/type_facts.rs            — TypeKind, TypeFactResult (Phase 10)
src/summary.rs               — FuncSummary, SsaFuncSummary, GlobalSummaries (CF-5)
src/symex/strings.rs         — symbolic string model (Phase 22)
src/labels/rust.rs           — RULES/KINDS for Rust in the taint engine
```

---

## 4. The five user patterns — intended end state

After all of Phase A ships, these should all be clean (no `rs.auth.missing_ownership_check`):

- **P0** (std::collections): A1 receiver-variable/type gate.
- **P1** (SQL JOIN): punted to B3/C3. Phase A does *not* fix this; document it.
- **P2** (transitive helper): punted to B4. Phase A does *not* fix this; document it.
- **P3** (row-ownership equality): A2.
- **P4** (helper with scoped-ID params): partial — A1 removes the internal `set.insert` noise; B4 removes the remaining flags.
- **P5** (`user.id` is self): A3.

So after Phase A: ~25/34 of the original FPs are gone (P0 + P3 + P5). Phase B eliminates the rest (P1 + P2 + P4). Phase D makes this numerically measurable.

---

## 5. Phase A — Precision wins (target: Week 1)

Ship order: **A1 → A2 → A3**. Each is independently valuable and independently testable.

### A1. Receiver-type/variable gate on sink classification

**Problem.** `matches_name("map.insert", "insert")` returns true (config.rs:836). Every `HashMap::insert`/`HashSet::insert`/`Vec::push` on a local collection is treated identically to `db.insert`. This is ~60% of the user's FPs.

**Goal.** Return false from `is_mutation` and `is_read` when the receiver is a local collection variable of a known non-sink type, or a variable whose name/binding strongly implies it.

**Files to modify.**
- `src/auth_analysis/config.rs` — add non-sink receiver lists and a new helper `callee_has_non_sink_receiver(callee, unit_hints)`; modify `is_mutation` / `is_read` to call it.
- `src/auth_analysis/model.rs` — add `UnitState::non_sink_vars: HashSet<String>` (or equivalent on `AnalysisUnit`).
- `src/auth_analysis/extract/common.rs` — populate `non_sink_vars` when a `let`/binding is a `HashMap::new()`, `HashSet::new()`, `Vec::new()`, etc., or when the explicit type annotation is one of those.
- `src/utils/config.rs::AuthAnalysisConfig` — expose user-tunable `non_sink_receiver_types: Vec<String>` and `non_sink_receiver_name_prefixes: Vec<String>`.

**What "non-sink receiver" means (Rust default lists).**

*Types (last path segment, case-sensitive):*
```
HashMap, HashSet, BTreeMap, BTreeSet, Vec, VecDeque, BinaryHeap,
IndexMap, IndexSet, LinkedList, SmallVec, FxHashMap, FxHashSet,
DashMap, DashSet
```

*Construction RHS to recognize (any of these → mark LHS var as non-sink):*
```
HashMap::new, HashMap::with_capacity, HashSet::new, HashSet::with_capacity,
BTreeMap::new, BTreeSet::new, Vec::new, Vec::with_capacity, vec![],
VecDeque::new, IndexMap::new, IndexSet::new, SmallVec::new, SmallVec::from
```

*Variable-name prefix fallback (when type/binding can't be resolved):*
```
local_map, local_set, local_cache, visited, seen, idx_, index_, lookup_,
_tmp_map, counts, buckets, pending, queue, stack
```
(Note: keep `cache` **without** the `local_` prefix as ambiguous — Redis clients are often named `cache`.)

**Algorithm sketch.**

1. In `collect_unit_state` (or the Rust-specific extractor), walk `let_declaration` / `assignment_expression` nodes. Record `var_name → non_sink` when:
   - RHS is a `call_expression` whose `call_name` matches a constructor from the list above, OR
   - the `let` has an explicit type annotation whose last path segment is in the non-sink type list, OR
   - the binding is via a `match` on a `HashMap`/etc. result.
2. In `collect_call` (common.rs:390), extract the callee's receiver chain (already computed by `call_name`). Split on `.`; take the first segment.
3. Pass the unit's `non_sink_vars` (or stash it on `UnitState`) through to `is_mutation`/`is_read`. A match hits the non-sink gate if:
   - first segment is in `non_sink_vars`, OR
   - first segment name-prefix-matches one of the configured prefixes.
4. If the gate hits, skip classification entirely (neither Read nor Mutation). Do **not** set `None` if there are other sink signals; the gate is specifically for the std::collections case.

**Acceptance criteria.**
- `cargo test --test auth_analysis_tests` still passes.
- Fixtures added: `hashmap_local_noise.rs` (P0, §8.1), `helper_scoped_params.rs` (P4 partial, §8.5). Both MUST NOT emit `rs.auth.missing_ownership_check`.
- Existing positive test `actix_scoped_write_without_membership_check` still flags `actix_scoped_write_missing.rs` with `rs.auth.missing_ownership_check` (a `db.insert` on a scoped id without an auth check — this fixture is the regression guard for A1).
- Unit test in `config.rs` for the new helper covering: `"map.insert"` when `map` ∈ non_sink_vars → skipped; `"db.insert"` when `db` ∉ non_sink_vars → classified; `"self.cache.insert"` (deep receiver) → configurable prefix match on first segment `"self"` → ambiguous, not skipped.

**Pitfalls / non-goals.**
- Do NOT conditionally call `is_mutation`/`is_read` from anywhere other than `collect_call`. There are no other call sites but if code adds them, the gate must go with them.
- Do NOT use the `non_sink_vars` set to suppress `AuthCheck` emission — only sink classification.
- Do NOT remove the existing `mutation_indicator_names` / `read_indicator_names` lists; they remain the name filter. A1 is additive.

---

### A2. Recognize row-level ownership equality as an `AuthCheck`

**Problem.** Pattern P3:
```rust
let existing = db.query_one("SELECT user_id, group_id FROM docs WHERE id = ?1", &[doc_id])?;
let owner_id: i64 = existing.get("user_id")?;
if owner_id != user.id {
    return json_err("not your doc", 403);
}
let group_id: i64 = existing.get("group_id")?;
// ... later: realtime::publish_to_group(group_id, …)  <-- current rule flags this
```
The `if owner_id != user.id { return … 403 }` guard is an explicit ownership check, but `collect_condition` only records it as `condition_text` and never emits an `AuthCheck`.

**Goal.** Emit a synthetic `AuthCheck { kind: Ownership }` when the scanner sees an equality-guard pattern against the actor's id with an early-exit.

**Files to modify.**
- `src/auth_analysis/extract/common.rs` — in `collect_condition` (line 449), add a new detector function `detect_ownership_equality_check(node, condition_text, bytes, rules, state)`.
- `src/auth_analysis/checks.rs::auth_check_covers_subject` — ensure the new AuthCheck's subject covers downstream uses of the DB row (see "Subject linking" below).

**Detection rule.**

An `if_expression` qualifies if *all* hold:
1. Condition is a binary comparison, either `!=` / `==` / `ne` / `eq`.
2. One side (call it `OWNER`) resolves via `extract_value_refs` to a `ValueRef` whose canonical field name is in:
   ```
   user_id, owner_id, author_id, created_by, uploader_id, updated_by,
   submitted_by, assigned_to, creator_id, posted_by
   ```
3. The other side (`SELF`) canonicalizes to one of:
   - `user.id`, `current_user.id`, `session.user.id`
   - a variable previously tagged as a self-actor by A3 (once A3 ships)
4. The branch taken **when the equality check fails** contains a control-flow exit:
   - `return`, `return Err(...)`, `return json_err(..., 403|401|…)`
   - `?` applied to an expression that unconditionally errors (conservative: just detect `return` and `Err(...)` literals; skip `?` handling in A2)

**Subject linking (how this covers downstream fields).**

The resulting `AuthCheck` needs `subjects: Vec<ValueRef>` set to the *base row identifier* that `OWNER` was read from. Example:

```rust
let existing = db.query_one("…", &[doc_id])?;   // bind "existing"
let owner_id: i64 = existing.get("user_id")?;   // owner_id.base = "existing"
if owner_id != user.id { return ...; }          // emits AuthCheck{subjects:[row_ref(existing, via doc_id)]}
let group_id: i64 = existing.get("group_id")?;  // later use of other col from "existing"
```

For A2, the synthesized `AuthCheck.subjects` should include:
- a `ValueRef` whose `name == "existing"` (or whatever the row binding was), and
- every `ValueRef` whose `base == "existing"` seen *in the handler so far*.

`auth_check_covers_subject` (checks.rs:330) already does base-matching, so if we record the row binding name correctly, downstream `existing.get("group_id")` propagated as a subject with `base = "existing"` will match.

If `owner_id` was assigned from `existing.get("user_id")`, the assignment graph is needed. For A2, approximate: scan up to 10 lines before the condition for `let owner_id = <row>.get(…)` or `let owner_id: _ = <row>.<field>` and record `<row>` as the row-binding. If not found, fall back to adding just `OWNER` as the subject (still covers owner_id itself).

**Acceptance criteria.**
- New fixture `row_ownership_equality.rs` (§8.3) passes: MUST NOT emit `rs.auth.missing_ownership_check` on the `group_id` use.
- New negative fixture `row_ownership_no_early_exit.rs`: same shape but without `return` — MUST still flag (ownership check without effect is not a check).
- Existing positive fixture still flags.
- Unit test in `checks.rs` for `detect_ownership_equality_check` on hand-rolled `ValueRef` triples.

**Pitfalls.**
- Do NOT accept arbitrary `if x != y` — both sides must resolve to recognized owner/self shapes.
- Do NOT accept `if let Ok(_) = …` style patterns as equality checks.
- Early-exit detection is intentionally conservative for A2 — false negatives (missing some real checks) are acceptable; false positives (synthesizing an `AuthCheck` where none exists) are not.

---

### A3. Recognize `user.id` bound from `require_auth()` as self-actor

**Problem.** Pattern P5:
```rust
pub async fn handle_list(req: Request, ctx: Ctx) -> Result<_> {
    let user = auth::require_auth(&req, &ctx.env).await?;
    let db = ctx.env.d1("DB")?;
    let friends = get_friend_ids(&db, user.id).await?;  // flagged: user.id looks like a scoped id
    …
}
```

`checks.rs:408-434` (`is_self_scoped_session_subject`) only recognizes hard-coded JS/Node bases like `req.user`, `ctx.session.user`. Rust code that binds the authenticated user locally is invisible.

**Goal.** Tag any variable `V` bound from a call matching `login_guard_names` ∪ `authorization_check_names` as a **self-actor**. Treat `V.id`, `V.user_id`, and similar as `is_actor_context_subject = true`.

**Files to modify.**
- `src/auth_analysis/model.rs` — add `AnalysisUnit.self_actor_vars: HashSet<String>`.
- `src/auth_analysis/extract/common.rs` — populate `self_actor_vars` during unit walk. At every `let_declaration` whose RHS is a `call_expression` (or `.await` chain or `?` chain containing one) whose `call_name` matches `rules.is_login_guard` or `rules.is_authorization_check`, insert LHS name.
- `src/auth_analysis/checks.rs::is_actor_context_subject` — extend:
  ```rust
  fn is_actor_context_subject(subject: &ValueRef, unit: &AnalysisUnit) -> bool {
      if is_self_scoped_session_subject(subject) { return true; }
      if let Some(base) = subject.base.as_deref() {
          let root = base.split('.').next().unwrap_or(base);
          if unit.self_actor_vars.contains(root) { return true; }
      }
      matches!(
          subject_identity_key(subject).as_deref(),
          Some("ownerid" | "authorid" | … )
      )
  }
  ```
  All callers of `is_actor_context_subject` (there's one, in `is_relevant_target_subject`) need the `unit` threaded through.
- Also extend to recognize **typed extractor parameters**: if a route handler declares a parameter with a type whose last path segment is in:
  ```
  CurrentUser, SessionUser, AuthUser, AdminUser, AuthenticatedUser,
  RequireAuth, RequireLogin, Authenticated
  ```
  then that parameter name is added to `self_actor_vars`.

**Acceptance criteria.**
- New fixture `self_scoped_user.rs` (§8.6) passes: MUST NOT emit `rs.auth.missing_ownership_check`.
- Existing `actix_scoped_write_missing.rs` still flags (regression guard — it uses a non-self id).
- `cargo test --test auth_analysis_tests` green.

**Pitfalls.**
- Do NOT accept arbitrary `let user = …` — the RHS must be a guard/auth call.
- `.await?` / `.await` / `?` chains are common in Rust; make sure the detector walks through them (the tree-sitter `call_expression` node is typically buried inside `try_expression` / `await_expression`).
- Do NOT treat `user.group_id` as self — only the actor's own id. The `is_actor_context_subject` check combined with `is_id_like` already gates this correctly; A3 just widens the "who counts as actor" set.

---

## 6. Phase B — Structural fixes (Weeks 2–5)

Phase A is additive and survives into Phase B. Phase B generalizes:

### B1. Sink categorization (replace stringly-typed mutation names)

Introduce `enum SinkClass { DbMutation, DbCrossTenantRead, RealtimePublish, OutboundNetwork, CacheCrossTenant, InMemoryLocal }` on `SensitiveOperation`. Replace the flat `mutation_indicator_names` / `read_indicator_names` lists with a `SinkRegistry` keyed by `(callee_pattern, receiver_type_or_prefix) -> SinkClass`.

`check_ownership_gaps` only fires on `{DbMutation, DbCrossTenantRead, RealtimePublish, OutboundNetwork, CacheCrossTenant}`. `InMemoryLocal` is never a sink — subsumes A1 correctly.

**Files.** `src/auth_analysis/model.rs`, `src/auth_analysis/config.rs`, `src/auth_analysis/checks.rs`, all `extract/*.rs` extractors (small change — just set the class).

**Effort.** ~3 days. Do this before B2.

### B2. Receiver-type inference via Phase 10 TypeFacts

Today A1 guesses type from name/construction. The principled version uses `src/type_facts.rs::TypeFactResult`, which is already computed per-file in `src/ast.rs`. Thread `&TypeFactResult` into `run_auth_analysis` and let the sink gate use `TypeKind` directly.

This fixes variables that don't match A1's name heuristics (e.g., `results`, `output`, `state` bound to a `HashMap`).

**Files.** `src/auth_analysis/mod.rs::run_auth_analysis` (new param), `src/ast.rs:1170` (pass facts), `src/auth_analysis/config.rs` (consume).

**Dependency.** Requires B1 first (the sink gate needs somewhere to hook).

**Effort.** ~1 week incl. fixture coverage for all Rust collection types.

### B3. SQL literal semantics — JOIN-through-ACL detection

The user's pattern P1 authenticates via a SQL JOIN. On `db.prepare(lit)`, `sqlx::query!(lit)`, `conn.execute(lit)`, etc., parse `lit` with a lightweight SQL lexer/parser and detect:

```
SELECT … FROM <T> JOIN <ACL> ON … WHERE <ACL>.user_id = ?<N>
```
where `<ACL>` ∈ a configurable `auth.acl_tables` list (default `["group_members", "org_memberships", "workspace_members", "tenant_members", "members", "share_grants"]` — user should tune per-codebase). Also detect `WHERE id = ?M AND user_id = ?N` as a direct-ownership query.

When matched, bind-parameter `?N` is verified to be the current-user id. Tag the query's **returned columns** as `authorized` — downstream uses of those IDs do not need an ownership check.

Leverage `src/symex/strings.rs::classify_string_method` (Phase 22 symbolic strings) — SQL strings often come from concatenation and symex already tracks prefix/suffix.

**Files.** New `src/auth_analysis/sql_semantics.rs`. Wire into `collect_call` when callee is a DB prepare/query.

**Effort.** ~1.5 weeks.

### B4. Interprocedural helper lifting

Patterns P2 and P4 require seeing through helper calls. Approach:

1. At unit-build time (`collect_unit_state`), compute per-function **auth-check summaries**: for each function `H`, a map `param_index → AuthCheckKind` recording "param N is auth-checked in this function's body".
2. At call-site analysis, when `H(…, subject, …)` is called and `H`'s summary says "param K is auth-checked", synthesize an `AuthCheck` at the call site over `subject` (the argument at position K).

Single-file first (much simpler), then lift to cross-file using the same SQLite persistence layer as `FuncSummary` (see `src/database.rs::replace_summaries_for_file`).

**Files.** `src/auth_analysis/model.rs` (new `AuthCheckSummary`), `src/auth_analysis/extract/common.rs` (build summaries during unit walk), `src/auth_analysis/checks.rs` (consult summaries in `has_prior_subject_auth`). Cross-file: `src/database.rs`.

**Effort.** ~1 week single-file + ~1 week cross-file.

### B5. Benchmark coverage for the rule

Today `rs.auth.missing_ownership_check` is NOT tracked in `tests/benchmark/ground_truth.json`. Add:
- Positive entries for `actix_scoped_write_missing.rs` and a new fixture `true_positive_missing_check.rs` (§8.7).
- Negative entries (noise_budget 0) for all Phase A fixtures.
- Wire the auth category into the P/R/F1 report in `tests/benchmark/RESULTS.md`.

**Effort.** ~3 days.

---

## 7. Phase C — Long-term: auth-as-taint

Once Phase B lands, fold `auth_analysis` into the SSA/taint engine as a new cap and set of label rules. Design notes:

- **Cap**: `Cap::UNAUTHORIZED_ID` added to `src/labels/mod.rs::Cap` bitflags.
- **Sources**: request-bound identifiers (`RequestParam`/`RequestBody`/`RequestQuery` whose field name is id-like) emit `Cap::UNAUTHORIZED_ID` via label rules in `src/labels/rust.rs` (and other langs).
- **Sinks**: the sink classes from B1 declared as label Sinks with `Cap::UNAUTHORIZED_ID` in their required-cap set.
- **Sanitizers**:
  - `authz::require_*(…, id, user_id)` emits `TaintTransform::ClearCapOnParams` in its `SsaFuncSummary`.
  - SQL auth-gated queries (B3) emit per-return-path sanitizers (see CF-4 `ReturnPathTransform`).
  - Row-ownership equality (A2 generalization) uses Phase 5.1 path-sensitive phi evaluation.
  - Self-actor IDs (A3 generalization) emit with an empty cap from the source side.

**Benefits**: SSA flow (no more line-order), cross-file via existing `GlobalSummaries`, per-return-path granularity, symbolic-string SQL recognition — all free.

**Effort.** ~6 weeks. Land only after B1–B4 prove the sink/sanitizer model.

---

## 8. Anonymized fixture corpus

> The user's 34 FPs came from two Rust handler files in their private codebase. Domain names have been anonymized: `trip → group`, `recap → doc`, `review → comment`, `friend → peer`, specific IDs genericized. Create these files under `tests/fixtures/auth_analysis/`.

### 8.1 `hashmap_local_noise.rs` — **P0, MUST NOT flag after A1**

```rust
use std::collections::{HashMap, HashSet};

struct Ctx;
struct Req;
struct User { id: i64 }

mod auth { pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> { Ok(super::User{id:1}) } }

pub async fn handle_list_peer_docs(req: Req, ctx: Ctx) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let doc_ids: Vec<i64> = vec![1, 2, 3];

    // Pure in-memory bookkeeping — no authorization decision here.
    let mut counts: HashMap<i64, usize> = HashMap::new();
    let mut seen: HashSet<i64> = HashSet::new();
    for doc_id in &doc_ids {
        counts.insert(*doc_id, 0);      // P0: currently flagged
        seen.insert(*doc_id);            // P0: currently flagged
        if seen.contains(doc_id) {
            counts.get(doc_id);          // P0: currently flagged as read
        }
    }
    let _ = user;
    Ok(format!("{} {}", counts.len(), seen.len()))
}
```

### 8.2 `sql_join_acl.rs` — **P1, flags today; MUST NOT flag after B3**

```rust
struct Ctx; struct Req; struct User { id: i64 } struct Db;
impl Db { fn prepare(&self, _s: &str) -> Query { Query } }
struct Query;
impl Query { fn bind(&self, _v: i64) -> Self { Query } fn all(&self) -> Vec<Row> { vec![] } }
struct Row;
impl Row { fn get(&self, _c: &str) -> i64 { 0 } }
mod auth { pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> { Ok(super::User{id:1}) } }
mod realtime { pub fn publish_to_group(_g: i64, _m: &str) {} }

pub async fn handle_list_group_docs(req: Req, ctx: Ctx) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;

    // Authorization enforced at the SQL layer: the JOIN on group_members
    // with WHERE gm.user_id = ?1 proves every returned row is membership-gated.
    let rows = db
        .prepare("SELECT d.id, d.group_id, d.title
                  FROM docs d
                  JOIN group_members gm ON gm.group_id = d.group_id
                  WHERE gm.user_id = ?1
                  ORDER BY d.updated_at DESC")
        .bind(user.id)
        .all();

    for row in rows {
        let group_id: i64 = row.get("group_id");
        // Downstream use: group_id is already authorized.
        realtime::publish_to_group(group_id, "doc_listed");  // currently flagged
    }
    Ok("ok".into())
}
```

### 8.3 `row_ownership_equality.rs` — **P3, MUST NOT flag after A2**

```rust
struct Ctx; struct Req; struct User { id: i64 } struct Db;
impl Db { fn query_one(&self, _s: &str, _a: &[i64]) -> Row { Row } }
struct Row;
impl Row { fn get_i64(&self, _c: &str) -> i64 { 0 } }
mod auth { pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> { Ok(super::User{id:1}) } }
mod realtime { pub fn publish_to_group(_g: i64, _m: &str) {} }

fn json_err(_msg: &str, _code: u16) -> Result<String, ()> { Err(()) }

pub async fn handle_delete_doc(req: Req, ctx: Ctx, doc_id: i64) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;

    let existing = db.query_one(
        "SELECT user_id, group_id FROM docs WHERE id = ?1",
        &[doc_id],
    );
    let owner_id = existing.get_i64("user_id");
    if owner_id != user.id {
        return json_err("cannot delete another user's doc", 403);
    }

    // By construction, the row belongs to `user` — so any id read from it is authorized.
    let group_id = existing.get_i64("group_id");
    realtime::publish_to_group(group_id, "doc_deleted");  // currently flagged
    Ok("ok".into())
}
```

### 8.4 `transitive_helper.rs` — **P2, flags today; MUST NOT flag after B4**

```rust
struct Ctx; struct Req; struct User { id: i64 } struct Db;
impl Db { fn exec(&self, _s: &str, _a: &[i64]) {} }
mod auth { pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> { Ok(super::User{id:1}) } }
mod authz { pub async fn require_group_member(_db: &super::Db, _group: i64, _user: i64) -> Result<(), ()> { Ok(()) } }

async fn validate_target(db: &Db, group_id: i64, user_id: i64) -> Result<(), ()> {
    // Helper encapsulates the ownership check.
    authz::require_group_member(db, group_id, user_id).await?;
    Ok(())
}

pub async fn handle_create_comment(req: Req, ctx: Ctx, group_id: i64, body: String) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;

    // Authorization happens inside validate_target — current rule can't see this.
    validate_target(&db, group_id, user.id).await?;

    db.exec("INSERT INTO comments (group_id, body) VALUES (?1, ?2)", &[group_id]);  // currently flagged
    Ok("ok".into())
}
```

### 8.5 `helper_scoped_params.rs` — **P4, internal noise MUST NOT flag after A1**

```rust
use std::collections::HashSet;

struct Db;
impl Db { fn query(&self, _s: &str, _a: &[i64]) -> Vec<i64> { vec![] } }

// Library-style helper. Authorization is the caller's responsibility.
pub async fn get_peer_ids(db: &Db, user_id: i64, other_ids: &[i64]) -> HashSet<i64> {
    let mut result: HashSet<i64> = HashSet::new();
    for &other_id in other_ids {
        // Pure in-memory work: result.insert on a local set.
        if !result.contains(&other_id) {
            result.insert(other_id);                           // currently flagged
        }
    }
    let direct = db.query("SELECT peer_id FROM peers WHERE user_id = ?1", &[user_id]);
    for peer in direct {
        result.insert(peer);                                   // currently flagged
    }
    result
}
```

### 8.6 `self_scoped_user.rs` — **P5, MUST NOT flag after A3**

```rust
use std::collections::HashSet;

struct Ctx; struct Req; struct User { id: i64 } struct Db;
impl Db { fn query(&self, _s: &str, _a: &[i64]) -> Vec<i64> { vec![] } }
mod auth { pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> { Ok(super::User{id:1}) } }

async fn get_peer_ids(db: &Db, user_id: i64) -> HashSet<i64> {
    let _ = db.query("SELECT peer_id FROM peers WHERE user_id = ?1", &[user_id]);
    HashSet::new()
}

pub async fn handle_list_peers(req: Req, ctx: Ctx) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;
    // user.id is the authenticated caller — by definition authorized to query its own data.
    let peers = get_peer_ids(&db, user.id).await;             // currently flagged
    Ok(format!("{}", peers.len()))
}
```

### 8.7 `true_positive_missing_check.rs` — **positive control, MUST flag after all phases**

```rust
struct Ctx; struct Req; struct User { id: i64 } struct Db;
impl Db { fn exec(&self, _s: &str, _a: &[i64]) {} }
mod auth { pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> { Ok(super::User{id:1}) } }
mod realtime { pub fn publish_to_group(_g: i64, _m: &str) {} }

pub async fn handle_delete_any_doc(req: Req, ctx: Ctx, doc_id: i64, group_id: i64) -> Result<String, ()> {
    let _user = auth::require_auth(&req, &ctx).await?;
    let db = Db;

    // BUG: no ownership/membership check on group_id or doc_id.
    // User might not be a member of `group_id` and might not own `doc_id`.
    db.exec("DELETE FROM docs WHERE id = ?1", &[doc_id]);
    realtime::publish_to_group(group_id, "doc_deleted");  // should flag
    Ok("ok".into())
}
```

### 8.8 `row_ownership_no_early_exit.rs` — **A2 regression guard, MUST flag after A2**

```rust
struct Ctx; struct Req; struct User { id: i64 } struct Db;
impl Db { fn query_one(&self, _s: &str, _a: &[i64]) -> Row { Row } fn exec(&self, _s: &str, _a: &[i64]) {} }
struct Row;
impl Row { fn get_i64(&self, _c: &str) -> i64 { 0 } }
mod auth { pub async fn require_auth(_r: &super::Req, _c: &super::Ctx) -> Result<super::User, ()> { Ok(super::User{id:1}) } }

pub async fn handle_update_doc(req: Req, ctx: Ctx, doc_id: i64) -> Result<String, ()> {
    let user = auth::require_auth(&req, &ctx).await?;
    let db = Db;
    let existing = db.query_one("SELECT user_id, group_id FROM docs WHERE id = ?1", &[doc_id]);
    let owner_id = existing.get_i64("user_id");

    // BUG: equality *compared* but no early exit — the check has no effect.
    if owner_id != user.id {
        // missing return
        println!("not your doc (but proceeding anyway)");
    }

    db.exec("UPDATE docs SET updated = 1 WHERE id = ?1", &[doc_id]);  // should still flag
    Ok("ok".into())
}
```

---

## 9. Phase D — Evaluation infrastructure (start immediately, parallel to A)

### D1. Fixture corpus
Materialize §8.1–§8.8 into `tests/fixtures/auth_analysis/`. Add tests to `tests/auth_analysis_tests.rs`:

```rust
#[test] fn hashmap_local_noise_is_clean() {
    assert_absent("hashmap_local_noise.rs", "rs.auth.missing_ownership_check");
}
#[test] fn row_ownership_equality_is_clean() {
    assert_absent("row_ownership_equality.rs", "rs.auth.missing_ownership_check");
}
#[test] fn self_scoped_user_is_clean() {
    assert_absent("self_scoped_user.rs", "rs.auth.missing_ownership_check");
}
#[test] fn true_positive_missing_check_flags() {
    assert_has("true_positive_missing_check.rs", "rs.auth.missing_ownership_check");
}
#[test] fn row_ownership_no_early_exit_flags() {
    assert_has("row_ownership_no_early_exit.rs", "rs.auth.missing_ownership_check");
}
#[test] fn helper_scoped_params_is_clean() {  // after A1
    assert_absent("helper_scoped_params.rs", "rs.auth.missing_ownership_check");
}
// After B3/B4:
#[test] fn sql_join_acl_is_clean() {
    assert_absent("sql_join_acl.rs", "rs.auth.missing_ownership_check");
}
#[test] fn transitive_helper_is_clean() {
    assert_absent("transitive_helper.rs", "rs.auth.missing_ownership_check");
}
```

Initially, the `assert_absent` tests for P0/P3/P5 will fail (that's the point — they characterize the bug). They go green in order as A1/A2/A3 land.

### D2. P/R/F1 tracking
Add entries for each fixture to `tests/benchmark/ground_truth.json`:
```json
{
  "file": "tests/fixtures/auth_analysis/true_positive_missing_check.rs",
  "expected_findings": [{ "rule": "rs.auth.missing_ownership_check", "line": 14 }],
  "noise_budget": 0
}
```
Wire the "auth" category into `tests/benchmark/RESULTS.md` generation.

### D3. Triage baseline
Once A1 ships, rerun against the user's private codebase (or the fixtures here) and record FP count in `tests/benchmark/RESULTS.md` under a new "Auth rule FP regression" table. Each subsequent phase updates this table.

---

## 10. Command reference

```bash
# Build
cargo build --release

# Run only auth-rule integration tests
cargo test --test auth_analysis_tests

# Run a single test
cargo test --test auth_analysis_tests -- row_ownership_equality_is_clean --exact

# Run unit tests in auth_analysis module
cargo test --lib auth_analysis::

# Full test suite (≈1k tests, slow — use before PR)
cargo test

# Run benchmark harness (after D1/D2)
cargo test --test bench_runner -- --nocapture

# Scan a specific file and see findings locally
cargo run --release -- scan path/to/file.rs --format json | jq '.findings[] | select(.id | startswith("rs.auth."))'
```

### Where rule IDs come from
`rule_id("missing_ownership_check")` = `"{finding_prefix}.auth.missing_ownership_check"`. The prefix comes from `AuthAnalysisRules.finding_prefix` (set by `build_auth_rules` based on lang). For Rust: `"rs"`, so the full id is `rs.auth.missing_ownership_check`.

### Config surface (`nyx.toml`)
```toml
[analysis.languages.rust.auth]
admin_guard_names = ["require_admin", "AdminUser"]
authorization_check_names = ["require_group_member", "check_acl"]
# After A1:
non_sink_receiver_types = ["HashMap", "HashSet", "Vec", "BTreeMap"]
non_sink_receiver_name_prefixes = ["local_", "visited", "seen", "counts"]
# After B3:
acl_tables = ["group_members", "org_memberships"]
```

---

## 11. Progress tracker

Update this table as phases land (append a new line; don't rewrite history):

| Date | Phase | Landed | FP count on user corpus | Notes |
|------|-------|--------|-------------------------|-------|
| 2026-04-23 | — | baseline | 34 | before any fix |
| 2026-04-23 | A1 | ✅ | — | receiver-type/variable gate on sink classification (Rust); 2 new fixtures + 3 unit tests; 84 auth tests green |
| 2026-04-23 | A2 | ✅ | — | row-level ownership-equality detector; AnalysisUnit.row_field_vars + row_population_data; back-dates AuthCheck to row's `let` line and merges fetch args into subjects; 2 new fixtures + 2 helper unit tests; 86 auth tests green |
| 2026-04-23 | A3 | ✅ | — | self-actor recognition: `let user = require_auth(..).await?` and typed extractor params (`CurrentUser`/`AuthUser`/…) seed `AnalysisUnit.self_actor_vars`; `is_actor_context_subject` widens to `V.id`/`V.user_id`/`V.uid` while `V.group_id` still flags; 2 new fixtures (`self_scoped_user.rs`, `true_positive_missing_check.rs`) + 3 helper unit tests; 88 auth tests + 10 auth lib tests green |
| 2026-04-23 | B1 | ✅ | — | `SinkClass` enum (`DbMutation`/`DbCrossTenantRead`/`RealtimePublish`/`OutboundNetwork`/`CacheCrossTenant`/`InMemoryLocal`) on `SensitiveOperation`; `classify_sink_class` registry keyed by callee name + receiver prefix lists (`realtime_receiver_prefixes`, `outbound_network_receiver_prefixes`, `cache_receiver_prefixes` wired through `AuthAnalysisConfig`); `check_ownership_gaps`/`check_partial_batch_authorization`/`check_stale_authorization` skip `InMemoryLocal`, subsuming A1; 2 new unit tests; 88 auth integration + 13 auth lib tests green |
| 2026-04-23 | B2 | ✅ | — | SSA `TypeFactResult` threaded into `run_auth_analysis` via per-file `var_name → TypeKind` map (merged across all bodies, conflicts dropped); new `TypeKind::LocalCollection` variant + Rust `constructor_type` recognition for std/indexmap/smallvec/dashmap collection constructors (through `peel_identity_suffix` so `.unwrap()`/`.clone()` chains resolve); `apply_var_types_to_model` overrides `sink_class` by receiver root — `HttpClient` → `OutboundNetwork`, `DatabaseConnection` → `DbMutation`/`DbCrossTenantRead` (by verb), `LocalCollection` → `InMemoryLocal`; 1 new fixture (`db_connection_type_inferred.rs`) + 4 mod-level unit tests; 89 auth integration + 17 auth lib tests green; 2276 workspace tests green |
| 2026-04-23 | B3 | ✅ | — | new `src/auth_analysis/sql_semantics.rs` (no SQL parser dependency) classifies `SELECT … FROM <T> JOIN <ACL> ON … WHERE <ACL>.user_id = ?N` and direct-table `WHERE … user_id = ?N` as auth-gated; configured ACL tables on `AuthAnalysisRules`/`AuthAnalysisConfig` (`acl_tables`); `collect_sql_authorized_binding` walks chained `let X = db.prepare(LIT)…` calls + propagates `authorized_sql_vars` through `for ROW in X` and `let Y = ROW.get(..)`; `auth_check_covers_subject` walks `row_field_vars` transitively to anchor the SQL-synth check; 11 SQL-semantics unit tests + 2 fixtures (`sql_join_acl.rs` clean, `sql_no_acl_join_flags.rs` regression guard); 91 auth integration + workspace tests green |
| 2026-04-23 | B4 | ✅ | — | helper-summary lifting (`apply_helper_lifting` in `src/auth_analysis/mod.rs`): builds per-function `AuthCheckSummary { param_index → AuthCheckKind }` from each unit's auth checks, then synthesises an `AuthCheck` at every caller's helper-call site whose subjects are pulled from per-positional `args_value_refs` on `CallSite`; iterated to a small fixpoint (MAX_ROUNDS=4) so transitive helper chains are covered; new Rust `authorization_check_names` defaults include `require_{group,org,workspace,tenant,team}_member`; 2 new fixtures (`transitive_helper.rs` clean, `helper_no_auth_lift.rs` regression guard); 93 auth integration + 1754 lib tests green |
| 2026-04-23 | B5 | ✅ | — | mirrored 10 auth fixtures into `tests/benchmark/corpus/rust/auth/` (3 positive + 7 negative); 10 new ground-truth cases (`rs-auth-001..003`, `rs-auth-101..107`); `corpus_size` 295→305; rule-level metrics moved from P=0.945/R=0.994/F1=0.969 to **P=0.946/R=0.994/F1=0.970** (+1pp precision via dilution); `by_vuln_class` now exposes `auth: 1.0/1.0/1.0`; `RESULTS.md` updated with a dedicated Phase B5 section + per-case table |

---

## 12. Open questions (for the user, not the agent)

1. Fixtures in §8 are **synthesized** from the user's prose description of the 34 FPs. If the user is able to contribute minimally-reduced real snippets, swap §8's contents in-place and update `ground_truth.json`.
2. Should Phase A be gated behind an env flag (`NYX_AUTH_RECEIVER_GATE=1`) during rollout, or enabled unconditionally? Default of this plan: enabled unconditionally, since all three changes are semantically correct and break no existing tests.
3. Are there codebases other than the user's website with similar FP shapes? Additional fixtures welcome.
