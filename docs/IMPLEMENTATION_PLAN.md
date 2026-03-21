# Nyx Phase 1 Hardening — Implementation Plan

> **Purpose**: Concrete, phase-by-phase execution plan to harden Nyx's static analysis
> engine before any Phase 2 dynamic work.
>
> **Based on**: Full repository audit (March 2026) covering correctness, validation,
> rule quality, architecture, and product credibility.

---

## Strategy overview

The work is ordered to maximize trustworthiness early:

1. **Measure first** — build evaluation infrastructure so every subsequent change can be measured
2. **Fix precision** — eliminate false-positive sources that erode trust
3. **Fix recall** — close the correctness gaps that cause real vulnerabilities to be missed
4. **Deepen rules** — expand coverage for commercially important languages and vulnerability classes
5. **Refactor for maintainability** — pay down technical debt that slows future work
6. **Harden product credibility** — align documentation claims with reality

Each phase is designed to be:
- **Small**: 1 focused session (typically 1–3 files changed)
- **Self-contained**: compiles and passes tests independently
- **Measurable**: has a clear definition of done
- **Safe**: limited blast radius, no architectural rewrites

---

## Phase ordering

| #    | Title | Category | Est. size |
|------|-------|----------|-----------|
| 1    | Negative taint test suite | evaluation | S |
| 2    | Categorise unexpected real-world findings | evaluation | S |
| 3    | Extract shared taint→Diag construction | refactor | S |
| 4    | Fix Cap mismatch: SQL and eval sinks | precision | S |
| 5    | Fix Ruby receiver-qualified call classification | core correctness | S |
| 6    | Expand Cap bitflags to u16 | core correctness | M |
| 7    | Add SSRF vulnerability class | rule depth | M |
| 8    | Add deserialization sinks (Python, Ruby, Java) | rule depth | S |
| 9    | Per-argument taint propagation — summary model | core correctness | M |
| 10   | Per-argument taint propagation — transfer wiring | core correctness | M |
| 11   | Wire call graph topo ordering into pass 2 | core correctness | S |
| 12   | Fix JS two-level solve stale seed | core correctness | M |
| 13   | Add state analysis fixtures for Python and JS | evaluation | S |
| 14   | Express.js framework rule pack | rule depth | M |
| 14.5 | Per-rule case-sensitive matching | matcher precision | S |
| 15   | Flask/Django framework rule pack | rule depth | M |
| 16   | Expand JS/TS DOM and browser API sinks | rule depth | S |
| 16.5 | Argument-sensitive sink modeling | precision | M |
| 16.6 | Argument-role-aware sink modeling | precision | M |
| 17   | Model try/catch in CFG — Java and JavaScript | core correctness | L |
| 18   | Model try/catch in taint transfer | core correctness | M |
| 19   | Method receiver taint propagation | core correctness | M |
| 19.5 | Multi-label classification for taint labels | core correctness | M |
| 20   | Short-circuit evaluation in CFG | core correctness | M |
| 21   | Evaluation benchmark corpus (50 known vulns) | evaluation | L |
| 22   | Run benchmark and publish baseline numbers | evaluation | M |
| 23   | README and docs claims audit | product credibility | S |
| 24   | Expand Go rule depth (SSRF, template, crypto) | rule depth | S |
| 25   | Expand Java rule depth (Spring, JPA, logging) | rule depth | M |
| 26   | Expand Ruby rule depth (Rails, ERB) | rule depth | S |
| 27   | Constant-argument sink suppression | precision | M |
| 28   | Scan path deduplication refactor | refactor | M |
| 29   | Re-run benchmark and measure improvement | evaluation | S |
| 30   | SSRF semantic completion | rule depth | L |
| 31   | Phase 2 readiness assessment | evaluation | S |

---

## Phase-by-phase implementation plan

---

### Phase 1 — Negative taint test suite

**Category**: evaluation

**Why**: The test suite validates finding *presence* but not *absence*. There are no
dedicated "this code is safe, verify zero taint findings" scenarios. The 267 unexpected
findings in the real-world suite suggest precision is uncalibrated. We need a baseline
for false-positive measurement before changing the engine.

**Goals**:
- Create 30 negative taint test fixtures (3 per language) containing safe code patterns
  that resemble vulnerable code but should NOT trigger taint findings
- Assert exactly zero taint findings on each fixture

**Files to touch**:
- `tests/fixtures/real_world/{lang}/taint/` — new `safe_*.{ext}` + `.expect.json` files
- `tests/real_world_tests.rs` — verify the fixture discovery works (no code changes
  expected; the existing discovery mechanism should pick up new fixtures automatically)

**Implementation tasks**:
1. For each of the 10 languages, create 3 safe-code fixtures:
   - **safe_constant_args**: calls to sinks with hardcoded string literals (e.g.,
     `subprocess.call(["ls", "-la"])` in Python, `exec.Command("ls")` in Go)
   - **safe_sanitized_flow**: tainted source → sanitizer → sink (e.g.,
     `let clean = html_escape(user_input); sink(clean)`)
   - **safe_no_source**: sink calls that don't touch any tainted source (e.g.,
     `Command::new("echo").arg("hello")` in Rust)
2. Each fixture gets an `.expect.json` with `"expected": []` and `"must_match": true`
   equivalent (empty expected list means no hard-match findings)
3. Run `cargo test real_world` and verify all 30 fixtures pass with zero hard failures

**Test tasks**:
- All 30 fixtures must produce 0 matched findings and 0 hard failures
- Existing 160 fixtures must continue to pass unchanged

**Definition of done**:
- 30 new fixture files + 30 `.expect.json` files committed
- `cargo test real_world` passes
- `cargo test` passes (full suite)

**Risks / gotchas**:
- Some "safe" patterns may currently trigger findings (false positives). Document these
  as `must_match: false` soft expectations with a note explaining the false positive.
  This is valuable data.
- Fixture file extensions must match `find_source_file()` logic in `real_world_tests.rs`

**Dependencies**: None (first phase)

---

### Phase 2 — Categorise unexpected real-world findings

**Category**: evaluation

**Why**: The real-world test suite currently reports 267 unexpected findings. These are
neither tracked as true positives nor flagged as false positives. Until they're
categorised, we don't know whether precision or recall is the bigger problem.

**Goals**:
- Review every unexpected finding from the real-world suite
- Classify each as: true positive (add to `.expect.json`), false positive (add as
  `must_match: false` with note explaining the FP), or noise (low-value finding
  worth suppressing)
- Produce a summary count: TP / FP / noise

**Files to touch**:
- `tests/fixtures/real_world/*/taint/*.expect.json` — update expected arrays
- `tests/fixtures/real_world/*/cfg/*.expect.json` — update expected arrays
- `tests/fixtures/real_world/*/state/*.expect.json` — update expected arrays
- `tests/fixtures/real_world/*/mixed/*.expect.json` — update expected arrays

**Implementation tasks**:
1. Run the real-world test suite with `NYX_TEST_VERBOSE=1` to capture all unexpected findings
2. For each unexpected finding:
   - Read the corresponding source fixture
   - Determine if the finding is a true positive, false positive, or low-value noise
   - If TP: add to `.expect.json` as `must_match: true`
   - If FP: add to `.expect.json` as `must_match: false` with `notes` explaining the FP source
   - If noise: add to `.expect.json` as `must_match: false` with `notes: "noise: ..."`
3. Tally the results: `TP count / FP count / noise count`
4. Add a comment at the top of each updated `.expect.json` in the `description` field
   noting the categorisation date

**Test tasks**:
- `cargo test real_world` passes with 0 hard failures
- Unexpected findings count should drop significantly (ideally to near-zero)

**Definition of done**:
- All 267+ unexpected findings categorised in `.expect.json` files
- Summary counts documented in a commit message or brief note
- `cargo test` passes

**Risks / gotchas**:
- This is tedious but high-value work. It directly measures the scanner's current
  quality and informs every subsequent phase.
- Some findings may be ambiguous (depends on threat model). Use your best judgement
  and note the ambiguity.
- The fixture source code may need to be read carefully to determine TP vs FP.

**Dependencies**: None (can run in parallel with Phase 1)

---

### Phase 3 — Extract shared taint→Diag construction

**Category**: refactor

**Why**: `src/ast.rs` has ~100 lines of taint finding→Diag construction duplicated
between `run_rules_on_bytes()` (lines 250-352) and `analyse_file_fused()` (lines
646-744). These will diverge over time, causing inconsistent output between indexed
and non-indexed scan modes.

**Goals**:
- Extract a single `fn build_taint_diag(...)` helper function
- Both call sites delegate to it
- Zero behaviour change — output must be identical

**Files to touch**:
- `src/ast.rs` — extract helper, update both call sites

**Implementation tasks**:
1. Read `src/ast.rs` lines 250-352 and 646-744 carefully
2. Identify the minimal parameter set:
   - `&Cfg` (cfg_graph)
   - `&Finding`
   - `&Tree` (for `byte_offset_to_point`)
   - `&Path` (file path)
   - `Option<&Path>` (scan_root, for namespace — only used in one path but pass through)
3. Create `fn build_taint_diag(cfg: &Cfg, finding: &Finding, tree: &Tree, path: &Path) -> Diag`
   as a private function in `ast.rs`
4. Replace both duplicated blocks with calls to `build_taint_diag()`
5. Verify identical output by running the full test suite

**Test tasks**:
- `cargo test` must pass with zero changes to test expectations
- Run `cargo test real_world` — findings must be identical (same count, same content)

**Definition of done**:
- Single `build_taint_diag()` function in `ast.rs`
- Both `run_rules_on_bytes()` and `analyse_file_fused()` call it
- All tests pass
- No new warnings from `cargo clippy`

**Risks / gotchas**:
- The two copies have slightly different variable names (`file_path_owned` vs
  `fused_file_path`, `evidence_notes` vs `fused_evidence_notes`). Unify these.
- The `tree` variable is named `_tree` in `run_rules_on_bytes` (underscore-prefixed
  because it was only used for byte offset conversion). The shared helper will use it
  directly, so remove the underscore prefix.

**Dependencies**: None

---

### Phase 4 — Fix Cap mismatch: SQL and eval sinks

**Category**: precision

**Why**: Several language label files use `SHELL_ESCAPE` as the cap for SQL injection
sinks (e.g., Java's `executeUpdate`, Python's `cursor.execute`, Go's `db.Query`) and
for eval/code injection sinks. This means a shell-escape sanitizer incorrectly
neutralises SQL injection taint, causing **false negatives**. Conversely, a
URL-encode sanitizer doesn't neutralise them when it should, causing **false
positives**.

**Goals**:
- Change all SQL injection sinks to use `Cap::all()` so they match any taint source
- Change all eval/code injection sinks to use `Cap::all()` so they match any taint source
- Verify existing tests still pass (with possible expected finding adjustments)

**Files to touch**:
- `src/labels/java.rs` — SQL sinks, reflection sinks
- `src/labels/python.rs` — `cursor.execute` sink
- `src/labels/go.rs` — `db.Query`, `db.Exec` sinks
- `src/labels/php.rs` — `mysqli_query` sink, eval sinks
- `src/labels/javascript.rs` — `eval` sink
- `src/labels/typescript.rs` — `eval` sink
- `src/labels/ruby.rs` — `eval` sink

**Implementation tasks**:
1. Audit every `LabelRule` across all 10 language files
2. For each rule where the sink cap is `SHELL_ESCAPE` but the vulnerability class is
   SQL injection or code injection (eval/exec), change to `Cap::all()`
3. Leave command injection sinks (system, exec, spawn) as `SHELL_ESCAPE` — this is correct
4. For sinks that could be multiple vulnerability classes (e.g., `os.system` is both
   CMDI and code exec), use `Cap::all()`

**Test tasks**:
- `cargo test` must pass
- Some taint tests may now find additional flows (previously masked by cap mismatch).
  Update `.expect.json` files if needed.

**Definition of done**:
- No SQL injection sink uses `SHELL_ESCAPE` alone
- No eval/code injection sink uses `SHELL_ESCAPE` alone
- All tests pass
- `cargo clippy` clean

**Risks / gotchas**:
- Using `Cap::all()` is more conservative (matches everything) which could increase
  findings. This is intentionally trading precision for recall on high-severity vulns.
- The better long-term fix is Phase 6 (expand Cap to u16 with dedicated SQL/EVAL bits),
  but `Cap::all()` is correct now and doesn't require schema changes.

**Dependencies**: None

---

### Phase 5 — Fix Ruby receiver-qualified call classification

**Category**: core correctness

**Why**: Phase 1 negative taint fixtures revealed that `Shellwords.escape`, `CGI.escapeHTML`,
and `ERB::Util.html_escape` are never recognised as sanitizers in Ruby. The root cause
is in `src/labels/ruby.rs`: the tree-sitter `call` node type is mapped to
`Kind::CallFn`, but tree-sitter Ruby uses the same `call` node for both bare calls
(`system("ls")`) and receiver-qualified calls (`Shellwords.escape(tool)`). The
`CallFn` code path in `cfg.rs` extracts only the `method` field (`"escape"`), discarding
the `receiver` field (`"Shellwords"`). The sanitizer matcher `"Shellwords.escape"`
requires the full qualified name, so `classify("ruby", "escape", ...)` finds no match
and the sanitizer is invisible to the taint engine.

The `CallMethod` code path correctly builds `"{receiver}.{method}"` and tries both the
`object` and `receiver` field names, which covers Ruby's grammar. Bare calls (no
receiver) degrade gracefully: `receiver = None` → just the method name is returned.

This was discovered as a false positive in `tests/fixtures/real_world/ruby/taint/safe_sanitized_flow.rb`
(`taint-unsanitised-flow` fires despite `Shellwords.escape`).

**Goals**:
- Change Ruby `call` from `Kind::CallFn` to `Kind::CallMethod` in the KINDS map
- Verify all receiver-qualified label rules (`Shellwords.escape`, `Shellwords.shellescape`,
  `CGI.escapeHTML`, `ERB::Util.html_escape`) are now recognised
- Verify bare calls (`system`, `exec`, `eval`, `puts`, `print`, `gets`) still match

**Files to touch**:
- `src/labels/ruby.rs` — change `"call" => Kind::CallFn` to `"call" => Kind::CallMethod`
- `tests/fixtures/real_world/ruby/taint/safe_sanitized_flow.expect.json` — remove the
  `must_match: false` FP entry (the finding should no longer appear)

**Implementation tasks**:
1. In `src/labels/ruby.rs`, change line 69:
   ```rust
   "call"  => Kind::CallMethod,  // was Kind::CallFn
   ```
2. Verify that `Kind::CallMethod` in `cfg.rs` `first_call_ident()` (line 136-149)
   and `find_classifiable_inner_call()` (line 187-200) both:
   - Try `child_by_field_name("method")` for the function name
   - Try `child_by_field_name("object")` then `child_by_field_name("receiver")` for
     the receiver, then call `root_receiver_text()`
   - Build `"{receiver}.{method}"` when both are present
   - Return just `"{method}"` when receiver is absent (bare call case)
3. Run `NYX_TEST_LANG=ruby NYX_TEST_VERBOSE=1 cargo test real_world_fixture_suite`
   to verify:
   - `safe_sanitized_flow` no longer produces `taint-unsanitised-flow`
   - All existing Ruby taint fixtures still pass (no regressions)
4. Update `safe_sanitized_flow.expect.json` to remove the `must_match: false` entry
5. Run `cargo test` for full suite

**Test tasks**:
- `safe_sanitized_flow.rb`: zero `taint-unsanitised-flow` findings (sanitizer recognised)
- All 9 existing Ruby taint fixtures: same results as before
- All 19 Ruby fixtures (taint + cfg + state + mixed): pass unchanged
- `cargo test` passes (full suite, all languages)

**Definition of done**:
- `"call" => Kind::CallMethod` in `ruby.rs`
- `safe_sanitized_flow.expect.json` has empty `expected` array (FP resolved)
- All tests pass
- `cargo clippy` clean

**Risks / gotchas**:
- **All Ruby call classification changes**: this affects every Ruby `call` node, not
  just sanitizers. Receiver-qualified sources and sinks (if any exist or are added
  later) will also start matching their full qualified names. This is the correct
  behaviour but must be verified against all existing Ruby fixtures.
- **Chained calls**: `foo.bar.baz(x)` will produce `"foo.baz"` (root receiver + method)
  via `root_receiver_text()`. This is consistent with how other languages handle chained
  calls (e.g., Java's `Runtime.getRuntime().exec()` → `"Runtime.exec"`). Verify this
  doesn't break any existing Ruby patterns.
- **Ruby `method_call` vs `call`**: tree-sitter Ruby may have other call-like node types
  (e.g., `command`, `command_call`). These are not in the current KINDS map and are
  unaffected by this change. If they need similar treatment, that's a follow-up.

**Dependencies**: None (but blocks Phase 25: Expand Ruby rule depth — receiver-qualified
Rails patterns like `ActiveRecord.where`, `Net::HTTP.get` will need this fix to be
recognised)

---

### Phase 6 — Expand Cap bitflags to u16

**Category**: core correctness

**Why**: The current 7-bit `Cap: u8` system can't distinguish SSRF from command injection,
SQL injection from shell injection, or deserialization from code injection. Adding new
vulnerability classes requires more bits. This is a prerequisite for Phases 7, 8, and
all future rule depth work.

**Goals**:
- Change `Cap` from `u8` to `u16`
- Add new cap bits: `SQL_QUERY`, `DESERIALIZE`, `SSRF`, `CODE_EXEC`, `CRYPTO`
- Update `FuncSummary` serialisation (change `source_caps: u8` etc. to `u16`)
- Update database schema if caps are stored as u8

**Files to touch**:
- `src/labels/mod.rs` — `Cap` bitflags definition, `parse_cap()` function
- `src/summary/mod.rs` — `FuncSummary` struct fields (u8 → u16), accessor methods
- `src/database.rs` — schema and serialisation (summaries stored as JSON, so the
  serde-derived format handles it, but verify)
- `src/cfg.rs` — `LocalFuncSummary` uses `Cap` directly (no u8 cast needed)
- `src/taint/transfer.rs` — uses `Cap` directly (no changes expected)
- All `src/labels/{lang}.rs` files — update rules to use new cap constants where
  appropriate (SQL sinks → `SQL_QUERY`, eval → `CODE_EXEC`, etc.)

**Implementation tasks**:
1. In `src/labels/mod.rs`, change `pub struct Cap: u8` to `pub struct Cap: u16` and add:
   ```rust
   const SQL_QUERY   = 0b0000_0000_1000_0000;
   const DESERIALIZE = 0b0000_0001_0000_0000;
   const SSRF        = 0b0000_0010_0000_0000;
   const CODE_EXEC   = 0b0000_0100_0000_0000;
   const CRYPTO      = 0b0000_1000_0000_0000;
   ```
2. In `src/summary/mod.rs`, change `source_caps: u8`, `sanitizer_caps: u8`,
   `sink_caps: u8` to `u16`. Update the accessor methods that call `Cap::from_bits_truncate`.
3. In `src/labels/mod.rs`, update `parse_cap()` to handle new cap names from config.
4. Migrate existing language rules:
   - SQL sinks (Java `executeUpdate`, Python `cursor.execute`, Go `db.Query`,
     PHP `mysqli_query`) → `Cap::SQL_QUERY`
   - Eval/exec sinks (JS/TS `eval`, PHP `eval`, Python `eval`/`exec`,
     Ruby `eval`) → `Cap::CODE_EXEC`
   - Keep `Cap::all()` on sinks set in Phase 4 until this phase replaces them with
     specific caps
5. Run full test suite and update any expectations that change due to cap values

**Test tasks**:
- `cargo test` must pass
- Add unit tests in `labels/mod.rs` tests: `parse_cap("sql_query") == Some(Cap::SQL_QUERY)`
  for each new cap
- Verify serialisation round-trip: create a `FuncSummary` with new caps, serialise to
  JSON, deserialise, compare

**Definition of done**:
- `Cap: u16` with 12 defined bits (7 old + 5 new)
- `FuncSummary` uses `u16` for cap fields
- All language rules use semantically correct caps
- All tests pass
- Database schema migration handled (drop and recreate summaries table if needed —
  the existing migration logic in `database.rs` handles this)

**Risks / gotchas**:
- **Database migration**: existing SQLite databases have summaries with u8 caps. The
  JSON serialisation stores caps as integers. Loading a u8 value into a u16 field via
  serde is backward-compatible (zero-extends). Verify this.
- **Performance**: u16 is still tiny; no performance impact expected.
- This is a prerequisite for Phases 7 and 8 but can be implemented before the audit
  benchmark (Phase 20) since it's a correctness fix.

**Dependencies**: Phase 4 (some rules were changed to `Cap::all()` as temporary measure)

---

### Phase 7 — Add SSRF vulnerability class

**Category**: rule depth

**Why**: SSRF is the #1 missing vulnerability class — zero coverage across all 10
languages. This is a high-impact, frequently exploited vulnerability class (OWASP
Top 10 #10, responsible for major breaches like Capital One).

**Goals**:
- Add HTTP client sinks labelled with `Cap::SSRF` to all applicable languages
- Add test fixtures proving SSRF detection works end-to-end

**Files to touch**:
- `src/labels/javascript.rs` — add `fetch`, `axios`, `http.request`, `XMLHttpRequest`
- `src/labels/typescript.rs` — same as JS
- `src/labels/python.rs` — add `urllib.urlopen`, `requests.get/post`, `httpx.get`
- `src/labels/java.rs` — add `HttpURLConnection`, `HttpClient`, `RestTemplate`
- `src/labels/go.rs` — add `http.Get`, `http.Post`, `http.NewRequest`
- `src/labels/php.rs` — add `file_get_contents`, `curl_exec`, `fopen` (URL)
- `src/labels/ruby.rs` — add `Net::HTTP`, `open-uri`, `HTTParty`
- `src/labels/rust.rs` — add `reqwest::get`, `hyper::Client`
- `src/labels/c.rs` — add `curl_easy_perform` (libcurl)
- `src/labels/cpp.rs` — add `curl_easy_perform`
- `tests/fixtures/real_world/{lang}/taint/` — new SSRF fixtures

**Implementation tasks**:
1. For each language, add 1-3 `LabelRule` entries for HTTP client functions as
   `Sink(Cap::SSRF)`:
   - JS/TS: `["fetch", "axios.get", "axios.post", "http.request", "https.request"]`
   - Python: `["urllib.request.urlopen", "requests.get", "requests.post", "httpx.get"]`
   - Java: `["openConnection", "newHttpClient", "HttpClient.send", "getForObject"]`
   - Go: `["http.Get", "http.Post", "http.NewRequest"]`
   - PHP: `["file_get_contents", "curl_exec", "curl_setopt"]`
   - Ruby: `["Net::HTTP.get", "open", "HTTParty.get"]`
   - Rust: `["reqwest::get", "reqwest::Client"]`
   - C/C++: `["curl_easy_perform"]`
2. For each language, create an SSRF taint fixture:
   - Source: user input / env var
   - Sink: HTTP client call with tainted URL
   - Expected: `taint-unsanitised-flow` finding
3. Create corresponding `.expect.json` files

**Test tasks**:
- Each SSRF fixture must produce at least one taint finding
- Existing tests must not regress
- `cargo test` passes

**Definition of done**:
- SSRF sinks defined in all 10 language files
- 10 new test fixtures with expectations
- All tests pass

**Risks / gotchas**:
- Some function names (like `open` in Ruby, `file_get_contents` in PHP) are
  multi-purpose. They may trigger on file operations that aren't SSRF. This is
  acceptable — the Cap system will ensure only URL-sourced taint matches.
- `fetch` in JS is a browser global; in Node.js it's `node-fetch` or built-in.
  The string matcher handles both.

**Dependencies**: Phase 6 (requires `Cap::SSRF` bit)

---

### Phase 8 — Add deserialization sinks (Python, Ruby, Java)

**Category**: rule depth

**Why**: Deserialization is covered only for PHP (`unserialize`). Python's `pickle.loads`,
Ruby's `Marshal.load`, and Java's `ObjectInputStream.readObject` are critical missing
sinks. Insecure deserialization is OWASP Top 10 #8.

**Goals**:
- Add deserialization sinks with `Cap::DESERIALIZE` to Python, Ruby, Java
- Add YAML unsafe load sinks where applicable
- Add test fixtures

**Files to touch**:
- `src/labels/python.rs` — add `pickle.loads`, `pickle.load`, `yaml.unsafe_load`,
  `yaml.full_load`, `shelve.open`
- `src/labels/ruby.rs` — add `Marshal.load`, `Marshal.restore`, `YAML.load`
  (without safe_load)
- `src/labels/java.rs` — add `readObject`, `readUnshared`, `XMLDecoder`,
  `ObjectInputStream`
- `src/labels/php.rs` — change existing `unserialize` from `SHELL_ESCAPE` to
  `Cap::DESERIALIZE`
- `tests/fixtures/real_world/{lang}/taint/` — new deser fixtures

**Implementation tasks**:
1. Add `LabelRule` entries as `Sink(Cap::DESERIALIZE)`:
   - Python: `["pickle.loads", "pickle.load", "yaml.unsafe_load", "yaml.full_load", "shelve.open"]`
   - Ruby: `["Marshal.load", "Marshal.restore", "YAML.load"]`
   - Java: `["readObject", "readUnshared", "XMLDecoder.readObject"]`
   - PHP: update existing `unserialize` rule cap to `Cap::DESERIALIZE`
2. For Python, Ruby, and Java, create a deserialization taint fixture:
   - Source: user input / file read
   - Sink: deserialization call with tainted data
   - Expected: taint finding
3. Create `.expect.json` files

**Test tasks**:
- New fixtures produce taint findings
- Existing deser tests (PHP) still pass with updated cap
- `cargo test` passes

**Definition of done**:
- Deserialization sinks in Python, Ruby, Java, PHP (updated)
- 3+ new test fixtures with expectations
- All tests pass

**Risks / gotchas**:
- Python's `yaml.load` changed behaviour across PyYAML versions. `yaml.safe_load` is
  the safe variant. Only flag `yaml.load` and `yaml.unsafe_load`.
- Java's `readObject` is a method name that could appear on non-ObjectInputStream
  receivers. Without receiver type tracking this may cause false positives. Acceptable
  for now; note in fixture expectations.

**Dependencies**: Phase 6 (requires `Cap::DESERIALIZE` bit)

---

### Phase 9 — Per-argument taint propagation: summary model

**Category**: core correctness

**Why**: `propagates_taint: bool` is the single largest source of false positives in
cross-file taint analysis. `func(tainted, safe)` incorrectly taints the return value
when only one argument actually flows through. This phase updates the data model; the
next phase wires it into the transfer function.

**Goals**:
- Replace `propagates_taint: bool` with `propagating_params: Vec<usize>` in
  `FuncSummary` and `LocalFuncSummary`
- Maintain backward compatibility: treat `propagates_taint: true` (old format) as
  "all params propagate" when deserialising old summaries
- Update summary extraction in `cfg.rs` to populate `propagating_params`

**Files to touch**:
- `src/summary/mod.rs` — `FuncSummary` struct, merge logic, serialisation
- `src/cfg.rs` — `LocalFuncSummary` struct, `export_summaries()`, dominance-based
  propagation detection
- `src/database.rs` — verify JSON serialisation handles the new field

**Implementation tasks**:
1. In `FuncSummary`, replace:
   ```rust
   pub propagates_taint: bool,
   ```
   with:
   ```rust
   pub propagating_params: Vec<usize>,  // which param indices flow to return
   ```
2. Add serde compat: `#[serde(default)]` on `propagating_params` and keep
   `propagates_taint` as a `#[serde(default)]` read-only field for backward compat
   during deserialisation. Add a `fn propagates_any(&self) -> bool` convenience method.
3. In `LocalFuncSummary`, make the same change.
4. In `cfg.rs` `export_summaries()`: instead of setting `propagates_taint = true` when
   any parameter reaches the return, record *which* parameter indices do so in
   `propagating_params`.
5. In `GlobalSummaries::insert()` merge logic: union `propagating_params` vectors
   (same as current `propagates_taint |= other.propagates_taint` but per-index).
6. Update all test assertions that reference `propagates_taint`.

**Test tasks**:
- All existing summary merge tests pass
- New unit test: function with 2 params where only param 0 flows to return →
  `propagating_params == vec![0]`
- New unit test: merge two summaries with different propagating params → union
- Serialisation round-trip test with new field

**Definition of done**:
- `propagating_params: Vec<usize>` in both summary types
- `export_summaries()` populates it correctly
- Merge logic unions correctly
- All tests pass

**Risks / gotchas**:
- The dominance-based detection in `cfg.rs` currently checks whether *any* parameter
  node dominates the return node. To make this per-parameter, iterate each param and
  check dominance individually. This may be slightly slower but is still O(params × CFG).
- Old databases with `propagates_taint: true` in JSON will deserialise with empty
  `propagating_params` and `propagates_taint: true`. The transfer function (Phase 10)
  must handle this fallback.

**Dependencies**: None (model change only; existing behaviour preserved until Phase 10)

---

### Phase 10 — Per-argument taint propagation: transfer wiring

**Category**: core correctness

**Why**: Phase 9 added the data model. This phase makes the taint transfer function
use it, eliminating false positives from `func(tainted, safe)` returning tainted.

**Goals**:
- Update `apply_call()` in `taint/transfer.rs` to check which arguments are tainted
  and only propagate if they match `propagating_params`
- Update `ResolvedSummary` to carry `propagating_params`
- Handle backward compat: if `propagating_params` is empty but old
  `propagates_taint` is true, treat as "all params propagate" (old behaviour)

**Files to touch**:
- `src/taint/transfer.rs` — `apply_call()`, `resolve_callee()`, `ResolvedSummary`

**Implementation tasks**:
1. Add `propagating_params: Vec<usize>` to `ResolvedSummary`.
2. In `resolve_callee()`, populate it from the resolved `FuncSummary` or
   `LocalFuncSummary`.
3. In `apply_call()`, replace:
   ```rust
   if resolved.propagates_taint {
       let (use_caps, use_origins) = self.collect_uses_taint(info, state);
       return_bits |= use_caps;
       ...
   }
   ```
   with logic that:
   - Iterates `info.uses` (the call arguments in order)
   - For each use at index `i`, checks if `i` is in `resolved.propagating_params`
   - Only collects taint from matching arguments
   - Backward compat: if `propagating_params` is empty and old `propagates_taint` was
     true, fall back to collecting from all uses (preserving old behaviour)
4. Similarly update `collect_tainted_sink_vars()` to use `tainted_sink_params` from
   the resolved summary — check which argument positions are marked as flowing to sinks.

**Test tasks**:
- New unit test: `func(tainted, safe)` where only param 0 propagates → return NOT tainted
- New unit test: `func(safe, tainted)` where only param 0 propagates → return NOT tainted
- New unit test: `func(tainted, safe)` where param 0 propagates → return IS tainted
- New unit test: backward compat — old summary with `propagates_taint: true` → all params propagate
- All existing taint tests pass

**Definition of done**:
- `apply_call()` uses per-argument propagation
- False positives from unrelated tainted arguments eliminated
- Backward compatibility preserved
- All tests pass

**Risks / gotchas**:
- `info.uses` order must match parameter order. In `cfg.rs`, uses are collected by
  iterating the call's argument children in tree-sitter order. Verify this matches
  `param_names` order in the summary.
- Some call patterns (named args, spread args) may not have a clean positional mapping.
  For these, fall back to "propagate all" — better to over-report than under-report.
- This may reduce finding count. Run `cargo test real_world` and update expectations
  for any findings that correctly disappear.

**Dependencies**: Phase 9 (summary model must exist first)

---

### Phase 11 — Wire call graph topo ordering into pass 2

**Category**: core correctness

**Why**: The call graph SCC analysis is already computed in `callgraph.rs` (with
`topo_scc_callee_first` ordering) but is `#[allow(dead_code)]`. Pass 2 analyses files
in arbitrary parallel order, meaning callee summaries may be incomplete when callers
are analysed. Wiring topo ordering ensures callees are fully analysed before callers.

**Goals**:
- Use `CallGraphAnalysis::topo_scc_callee_first` to order pass 2 file analysis
- Remove `#[allow(dead_code)]` annotations from call graph fields

**Files to touch**:
- `src/commands/scan.rs` — `scan_filesystem()` pass 2 section (lines 384-410)
- `src/callgraph.rs` — remove dead_code annotations

**Implementation tasks**:
1. In `scan_filesystem()`, capture `call_graph` and `cg_analysis` outside the block
   (currently they're dropped at line 382).
2. Use `cg_analysis.topo_scc_callee_first` to determine which `FuncKey`s should be
   analysed first. Map SCCs → files: for each SCC in topo order, collect the set of
   files containing those functions.
3. Process files in SCC order: files whose functions have no callees first, then files
   whose callees are all resolved, etc. Within an SCC, process in parallel (they're
   mutually recursive — ordering doesn't help).
4. Files not in the call graph (no functions found) can be processed in any order
   (append to the end).
5. Remove `#[allow(dead_code)]` from `topo_scc_callee_first`, `node_to_scc`, and
   other call graph fields now in use.

**Test tasks**:
- All existing tests pass
- New integration test: create a two-file fixture where file A has a source function
  and file B calls it as a sink. Verify that topo ordering ensures A's summary is
  available when B is analysed.
- `cargo test real_world` — verify no regressions

**Definition of done**:
- Pass 2 uses topo ordering
- `#[allow(dead_code)]` removed from used call graph fields
- All tests pass

**Risks / gotchas**:
- This converts pass 2 from fully parallel to partially ordered. Files within the same
  SCC can still be parallel. Files in different SCCs must be sequential (callee SCC
  before caller SCC). This may slightly reduce parallelism but improves correctness.
- The indexed path (`scan_with_index_parallel`) should get the same treatment. Start
  with `scan_filesystem` only; leave `scan_with_index_parallel` as a follow-up if this
  works well.
- If the call graph is very flat (few inter-file calls), ordering has little effect
  and parallelism is preserved.

**Dependencies**: None (call graph already computed; this just uses it)

---

### Phase 12 — Fix JS two-level solve stale seed

**Category**: core correctness

**Why**: In `analyse_js_two_level()`, `global_seed` is computed once from the top-level
convergence state and never updated. If function A modifies a global variable and
function B reads it, B sees the pre-A value. This causes false negatives in JS/TS
codebases where global state mutation is common.

**Goals**:
- Make the two-level solve iterative: after analysing all functions, check if any
  function's side effects would change the top-level state
- If so, re-run affected functions with the updated state
- Cap iterations to prevent divergence (e.g., max 3 rounds)

**Files to touch**:
- `src/taint/mod.rs` — `analyse_js_two_level()`

**Implementation tasks**:
1. After Level 2 (all functions analysed), collect the "exit states" from each function
   solve. Extract any variables written by functions that are also in the global seed.
2. Join all function exit states with the original top-level converged state.
3. If the joined state differs from the original `global_seed`, re-run Level 2 with
   the updated seed. Collect new events.
4. Repeat until stable or max 3 iterations reached.
5. Merge all events from all rounds (dedup by sink+source as already done).

**Test tasks**:
- New unit test: `let x = "safe"; function leak() { x = getenv("SECRET"); } function use_it() { sink(x); } leak(); use_it();`
  → must detect taint flow from `getenv` to `sink` via global `x`
- New unit test: verify that the solve converges in ≤3 iterations on typical code
- Existing JS/TS taint tests pass unchanged
- `cargo test` passes

**Definition of done**:
- `analyse_js_two_level()` iterates until seed stabilises (max 3 rounds)
- Inter-function global taint flows are detected
- All tests pass

**Risks / gotchas**:
- Each iteration re-analyses all functions. With max 3 rounds and typical function
  counts, this is 3× the work. Profile on real fixtures to ensure acceptable performance.
- The scope filter ensures functions only see their own scope's nodes, so re-running
  is safe (no cross-function pollution within a single solve).
- If a function writes to a variable that another function also writes to, the join
  produces a conservative union (correct but may add taint that wasn't there before).

**Dependencies**: None

---

### Phase 13 — Add state analysis fixtures for Python and JS

**Category**: evaluation

**Why**: State analysis (resource lifecycle) is tested only on C fixtures (19 files).
The README claims state analysis for all languages, but there are zero Python, JS, or
Rust resource lifecycle test fixtures.

**Goals**:
- Add resource lifecycle test fixtures for Python and JavaScript
- Verify the state analysis engine works correctly for these languages
- Identify any language-specific gaps in resource pair definitions

**Files to touch**:
- `tests/fixtures/state/` — new `*.py` and `*.js` files
- `tests/state_tests.rs` — new test functions
- `src/state/transfer.rs` — may need new `ResourcePair` entries for Python/JS patterns

**Implementation tasks**:
1. Create Python fixtures:
   - `python_file_open_no_close.py` — `f = open("x"); f.read()` (no close → leak)
   - `python_file_open_close.py` — `f = open("x"); f.read(); f.close()` (clean)
   - `python_double_close.py` — `f = open("x"); f.close(); f.close()` (double close)
   - `python_with_statement.py` — `with open("x") as f: f.read()` (clean — context
     manager; may not be detected depending on CFG modelling of `with`)
2. Create JavaScript fixtures:
   - `js_fs_open_no_close.js` — `const fd = fs.openSync("x"); fs.readSync(fd)` (leak)
   - `js_fs_open_close.js` — `const fd = fs.openSync("x"); fs.closeSync(fd)` (clean)
3. Add corresponding test functions in `tests/state_tests.rs`
4. If resource pairs are missing (e.g., Python `open`/`close`, JS `openSync`/`closeSync`),
   add them to the appropriate resource pair definitions in `src/state/transfer.rs`

**Test tasks**:
- New fixtures produce expected state findings (leak, double-close) or no findings (clean)
- `cargo test state` passes
- `cargo test` passes

**Definition of done**:
- At least 4 Python + 2 JS state analysis fixtures
- Test functions covering each fixture
- Resource pairs added if needed
- All tests pass

**Risks / gotchas**:
- Python's `with` statement is a context manager that guarantees cleanup. The CFG may
  not model this correctly (no special `with` handling in `cfg.rs`). If so, document
  this as a known limitation in the test expectations.
- Node.js uses both sync and async file APIs. Start with sync (`openSync`/`closeSync`)
  which maps cleanly to the resource lifecycle model.

**Dependencies**: None

---

### Phase 14 — Express.js framework rule pack

**Category**: rule depth

**Why**: Express.js is the most popular Node.js web framework. Currently JS/TS rules
have basic `req.body`/`req.query` sources and `eval`/`innerHTML` sinks, but no
framework-aware modelling of Express middleware, route handlers, response sinks, or
common middleware patterns.

**Goals**:
- Add comprehensive Express.js source/sink/sanitizer rules
- Add test fixtures demonstrating Express-specific taint flows

**Files to touch**:
- `src/labels/javascript.rs` — new rules
- `src/labels/typescript.rs` — mirror JS rules
- `tests/fixtures/real_world/javascript/taint/` — new Express fixtures
- `tests/fixtures/real_world/typescript/taint/` — new Express fixtures

**Implementation tasks**:
1. Add Express.js **sources** (if not already present):
   - `req.body`, `req.query`, `req.params` (already present — verify)
   - `req.hostname`, `req.ip`, `req.path`, `req.protocol`, `req.url`
   - `req.get` (header access), `req.header`
2. Add Express.js **sinks**:
   - `res.send`, `res.json`, `res.render` — XSS sinks (`Cap::HTML_ESCAPE`)
   - `res.redirect` — open redirect / SSRF (`Cap::SSRF`)
   - `res.sendFile` — path traversal (`Cap::FILE_IO`)
   - `res.set`, `res.header` — header injection (`Cap::HTML_ESCAPE`)
3. Add Express.js **sanitizers**:
   - `express-validator` patterns: `body().trim().escape()`, `validationResult`
   - `helmet` middleware (header hardening — mark as sanitizer for header injection)
4. Add `xss` and `sanitize-html` as sanitizer matchers
5. Create 2 Express taint fixtures per language (JS + TS):
   - `express_xss.js`: `req.query.name` → `res.send(name)` (XSS)
   - `express_redirect.js`: `req.query.url` → `res.redirect(url)` (open redirect)

**Test tasks**:
- New fixtures produce taint findings
- Existing JS/TS tests unchanged
- `cargo test` passes

**Definition of done**:
- 8+ new Express-specific rules in JS and TS label files
- 4 new test fixtures (2 JS + 2 TS)
- All tests pass

**Risks / gotchas**:
- Express response methods (`res.send`, `res.json`) are called on the `res` object,
  which is the second parameter to route handlers. The taint engine doesn't track
  method receivers (see Phase 19), so `res.send(tainted)` is detected via the
  argument, not the receiver. This is fine for these sinks.
- `res.render` takes a template name and data object. Only the data argument is
  dangerous. Without per-argument sink tracking, the template name argument may
  trigger false positives. Note this in fixture expectations.

**Dependencies**: Phase 6 (uses `Cap::SSRF` for redirect sinks)

---

### Phase 14.5 — Per-Rule Case-Sensitive Matching

**Category**: matcher precision

**Why**: All label matching was case-insensitive (ASCII `eq_ignore_ascii_case`). This
prevented distinguishing case-significant identifiers like Django's `request.GET` vs
`request.get`. Before adding framework rule packs, the matcher needed per-rule opt-in
for exact case matching without changing any existing behavior.

**What was done**:
- Added `case_sensitive: bool` field to `LabelRule`, `RuntimeLabelRule`, and
  `ConfigLabelRule` (all default to `false` at construction sites)
- Added parameterized helpers `ends_with_cs()`, `starts_with_cs()`, `match_suffix_cs()`
  that branch on the flag
- Updated all 4 matching loops in `classify()` and `match_config_sanitizer()` in
  `guards.rs` to use the new helpers
- Threaded `case_sensitive` through `build_lang_rules()` so config-specified case
  sensitivity propagates to runtime rules
- `#[serde(default)]` on `ConfigLabelRule.case_sensitive` for backwards-compatible
  deserialization
- Removed old `ends_with_ignore_case`, `starts_with_ignore_case`, `match_suffix`
  (replaced by parameterized versions)
- 4 new unit tests covering default case-insensitive, exact match, prefix, and
  suffix boundary behavior

**Files changed**: `src/labels/mod.rs`, `src/utils/config.rs`,
`src/cfg_analysis/guards.rs`, all 10 language rule files (`case_sensitive: false`
on every existing `LabelRule`)

**Dependencies**: None (pure additive, no behavior change for existing rules)

---

### Phase 15 — Flask/Django framework rule pack

**Category**: rule depth

**Why**: Flask and Django are the two most popular Python web frameworks. Current
Python rules have basic `request.args`/`request.form` sources but no framework-specific
sinks or ORM-aware patterns.

**Goals**:
- Add Flask/Django source/sink/sanitizer rules
- Add test fixtures

**Files to touch**:
- `src/labels/python.rs` — new rules
- `tests/fixtures/real_world/python/taint/` — new Flask/Django fixtures

**Implementation tasks**:
1. Add Flask **sources** (verify existing, add missing):
   - `request.args`, `request.form`, `request.json` (likely present)
   - `request.files`, `request.data`, `request.values`, `request.environ`
   - `request.url`, `request.base_url`, `request.host`
2. Add Flask **sinks**:
   - `render_template_string` — SSTI / code injection (`Cap::CODE_EXEC`)
   - `make_response` — XSS if raw HTML (`Cap::HTML_ESCAPE`)
   - `redirect` — open redirect (`Cap::SSRF`)
   - `send_file`, `send_from_directory` — path traversal (`Cap::FILE_IO`)
3. Add Django **sources**:
   - `request.GET`, `request.POST`, `request.META`, `request.body`
   - `request.FILES`, `request.COOKIES`
4. Add Django **sinks**:
   - `HttpResponse` — XSS (`Cap::HTML_ESCAPE`)
   - `mark_safe` — explicitly marks string as safe (actually a dangerous operation
     if called on user input — this is a sink, not a sanitizer)
   - `cursor.execute` with string formatting — SQL injection (`Cap::SQL_QUERY`)
5. Add **sanitizers**:
   - `bleach.clean` — HTML sanitizer
   - `markupsafe.escape` — HTML escaping
   - `django.utils.html.escape` — Django's escape
6. Create 2 fixtures:
   - `flask_ssti.py`: `request.args.get("name")` → `render_template_string(name)` (SSTI)
   - `django_sqli.py`: `request.GET["q"]` → `cursor.execute("SELECT * WHERE " + q)` (SQLi)

**Test tasks**:
- New fixtures produce taint findings
- Existing Python tests unchanged
- `cargo test` passes

**Definition of done**:
- 10+ new Flask/Django rules in Python label file
- 2+ new test fixtures
- All tests pass

**Risks / gotchas**:
- Django's ORM (`Model.objects.filter()`) is safe by default. Only raw SQL via
  `cursor.execute` or `.raw()` is vulnerable. Don't flag ORM usage.
- Flask's `render_template` (not `render_template_string`) uses Jinja2 auto-escaping
  and is generally safe. Only `render_template_string` is dangerous.

**Dependencies**: Phase 6 (uses `Cap::SQL_QUERY`, `Cap::CODE_EXEC`, `Cap::SSRF`)

---

### Phase 16 — Expand JS/TS DOM and browser API sinks

**Category**: rule depth

**Why**: JS/TS browser API coverage is minimal (only `eval`, `innerHTML`,
`child_process`). Missing: `document.write`, `location.assign`, `postMessage`,
`window.open`, `fetch` (as SSRF), `WebSocket`, `setAttribute` for event handlers.

**Goals**:
- Add browser DOM API sinks
- Add Node.js API sinks beyond child_process
- Add test fixtures

**Files to touch**:
- `src/labels/javascript.rs` — new sink rules
- `src/labels/typescript.rs` — mirror
- `tests/fixtures/real_world/javascript/taint/` — new fixtures

**Implementation tasks**:
1. Add DOM **sinks** (XSS — `Cap::HTML_ESCAPE`):
   - `document.write`, `document.writeln`
   - `outerHTML` (assignment)
   - `insertAdjacentHTML`
   - `setAttribute` (when setting `href`, `src`, `onload`, etc.)
   - `DOMParser.parseFromString` (if injecting user HTML)
2. Add navigation **sinks** (open redirect — `Cap::SSRF`):
   - `location.assign`, `location.replace`, `window.open`
3. Add message **sinks** (data leak):
   - `postMessage` — potential cross-origin data leak (`Cap::HTML_ESCAPE`)
4. Add Node.js **sinks**:
   - `fs.writeFileSync`, `fs.writeFile` — path traversal (`Cap::FILE_IO`)
   - `net.createConnection` — SSRF (`Cap::SSRF`)
5. Create 2 test fixtures:
   - `dom_xss.js`: user input → `document.write()` (DOM XSS)
   - `open_redirect.js`: user input → `location.assign()` (redirect)

**Test tasks**:
- New fixtures produce taint findings
- Existing tests unchanged
- `cargo test` passes

**Definition of done**:
- 8+ new DOM/browser API sink rules in JS and TS
- 2+ new test fixtures
- All tests pass

**Risks / gotchas**:
- `setAttribute` is only dangerous for certain attributes (`href`, `src`, `onload`,
  etc.). Without argument inspection, all `setAttribute` calls would be flagged.
  Start by labelling it as a sink and accept some false positives; refine later with
  per-argument analysis (Phase 10).

**Dependencies**: Phase 6 (uses `Cap::SSRF` for navigation sinks)

---

### Phase 16.5 — Argument-sensitive sink modeling

**Category**: precision

**Why**: Some APIs are only dangerous when a specific argument value selects a risky
mode, attribute, or behavior. Nyx currently models sinks at the callee level only, so
APIs like `setAttribute(name, value)` would be treated as sinks for *all* calls if
added naively. That would create noisy findings such as flagging
`setAttribute("class", user_input)` the same way as `setAttribute("href", user_input)`.

This phase adds **argument-sensitive sink activation** so a call is only treated as a
sink when specific constant argument values indicate danger.

**Goals**:
- Add support for sink activation gated by constant argument values
- Model `setAttribute(name, value)` precisely enough to avoid broad false positives
- Keep the implementation narrow and explicit — no general symbolic reasoning
- Add regression tests for both dangerous and harmless attribute names

**Files to touch**:
- `src/labels/mod.rs` — extend rule metadata to support optional argument gating
- `src/taint/transfer.rs` and/or classification path — activate sink behavior only when
  the gating condition matches
- `src/cfg.rs` — ensure call nodes expose enough constant-argument information to
  inspect specific argument positions
- `src/labels/javascript.rs` — add `setAttribute` using the new gated sink model
- `src/labels/typescript.rs` — mirror JS
- `src/taint/tests.rs` and/or `tests/fixtures/real_world/javascript/taint/` —
  dangerous vs harmless `setAttribute` cases

**Implementation tasks**:

1. **Add explicit sink-gating metadata**
   Extend label rules with a small optional structure for argument-sensitive activation,
   for example:
    - argument index to inspect
    - list of dangerous constant string values
    - optional prefix matching for patterns like `on*`

   Keep this narrowly scoped to constant string argument checks only.

2. **Capture constant argument values**
   In CFG call-node construction, preserve enough information to inspect whether a
   given argument is a constant string literal and what its normalized value is.
   Do not attempt interprocedural constant propagation in this phase.

3. **Gate sink activation in taint transfer**
   When a callee matches a gated sink rule:
    - if the specified argument is a matching dangerous constant, apply sink behavior
    - if the specified argument is a non-dangerous constant, do not apply sink behavior
    - if the specified argument is unknown / non-constant, choose a conservative policy:
      either still treat it as a sink, or defer that branch with a documented note

   Prefer a documented conservative policy over silent under-reporting.

4. **Add `setAttribute` with explicit dangerous attribute names**
   Add `setAttribute` as a gated sink for cases such as:
    - `href`
    - `src`
    - `action`
    - `formaction`
    - `srcdoc`
    - any `on*` event handler attribute

   Do **not** treat harmless attributes such as `class`, `id`, `title`, `aria-*`,
   or `data-*` as sinks.

5. **Add regression tests**
   Add positive cases:
    - `el.setAttribute("href", user_input)` → finding
    - `el.setAttribute("src", user_input)` → finding
    - `el.setAttribute("onclick", user_input)` → finding

   Add negative cases:
    - `el.setAttribute("class", user_input)` → no finding
    - `el.setAttribute("id", user_input)` → no finding
    - `el.setAttribute("data-name", user_input)` → no finding

   Add one unknown case and document the intended conservative behavior:
    - `el.setAttribute(attr_name, user_input)`

**Test tasks**:
- New unit / fixture tests prove dangerous attribute names trigger findings
- Harmless attribute names do not trigger findings
- Existing JS/TS tests continue to pass
- `cargo test` passes

**Definition of done**:
- Nyx can model sinks whose dangerousness depends on constant argument values
- `setAttribute` is supported without broad false positives
- Dangerous DOM attribute names are covered explicitly
- All tests pass

**Risks / gotchas**:
- This is a precision feature, so be careful not to silently suppress true positives
  for unknown dynamic attribute names. Prefer conservative behavior and document it.
- Keep this phase narrowly scoped to constant string argument gating. Do not expand it
  into full symbolic execution or general path reasoning.
- Other APIs may benefit later (`postMessage`, template/render mode arguments, etc.),
  but this phase should focus on `setAttribute` and the reusable mechanism.

**Dependencies**:
- Phase 16 — broad DOM/browser sink expansion lands first
- Phase 10 — per-argument taint propagation is already in place, which reduces
  ambiguity around call argument positions

---

### Phase 16.6 — Argument-role-aware sink modeling

**Category**: precision

**Why**: Phase 16.5 added argument-sensitive sink activation: a call can become a sink
only when a specific argument value indicates danger. That solved the first half of
APIs like `setAttribute(name, value)`.

But some APIs need a second layer of precision: one argument selects whether the call
is dangerous, while a different argument is the actual tainted payload. Without this,
Nyx still treats all call arguments as equally sink-relevant once the sink activates.

This phase adds **argument-role-aware sink modeling** so sink activation and payload
selection can be modeled independently.

**Goals**:
- Add a reusable mechanism for APIs where:
    - one argument controls sink activation
    - a different argument carries the tainted payload
- Keep the implementation narrow and explicit
- Refine `setAttribute(name, value)` so only the value argument is treated as payload
- Add `DOMParser.parseFromString(input, mimeType)` using the same mechanism
- Preserve conservative behavior for dynamic / unknown activation arguments

**Files to touch**:
- `src/labels/mod.rs` — extend `SinkGate` to include payload argument positions
- `src/cfg.rs` — store per-node payload-argument metadata for gated sinks
- `src/taint/transfer.rs` — restrict sink taint checks to payload args when configured
- `src/labels/javascript.rs` — refine `setAttribute`, add `parseFromString`
- `src/labels/typescript.rs` — mirror JS
- `tests/fixtures/real_world/javascript/taint/` — add/update gated sink fixtures
- `src/labels/mod.rs` tests — extend gated-sink unit coverage

**Implementation tasks**:

1. **Extend gated sink metadata with payload arguments**
   Add a `payload_args` field to `SinkGate`:
    - specifies which argument positions carry the tainted payload
    - empty slice means all arguments are payloads (backward-compatible default)

2. **Thread payload argument info through classification**
   Update `classify_gated_sink()` to return both:
    - the sink label
    - the configured payload argument positions

3. **Store payload argument info on CFG nodes**
   Extend `NodeInfo` with optional sink-payload metadata so later taint transfer can
   restrict sink checking to the intended argument positions.

4. **Restrict sink taint checks to payload args**
   In taint transfer:
    - if a node has `sink_payload_args` and positional `arg_uses` are available,
      only those argument positions should be checked for taint
    - if positional argument data is unavailable, fall back to all arguments
      conservatively

5. **Refine `setAttribute(name, value)`**
   Keep the activation logic from Phase 16.5:
    - activation argument: arg 0
    - dangerous values: `href`, `src`, `action`, `formaction`, `srcdoc`
    - dangerous prefixes: `on`

   Add payload-role logic:
    - payload argument: arg 1 only

   This ensures:
    - `setAttribute("href", user_input)` → finding
    - `setAttribute("href", "https://example.com")` → no finding
    - `setAttribute("class", user_input)` → no finding

6. **Add `parseFromString(input, mimeType)`**
   Add as a gated sink:
    - callee matcher: `parseFromString`
    - activation argument: arg 1 (MIME type)
    - dangerous values: `text/html`, `application/xhtml+xml`
    - payload argument: arg 0

   This ensures:
    - `parseFromString(user_input, "text/html")` → finding
    - `parseFromString(user_input, "text/xml")` → no finding
    - `parseFromString("<p>safe</p>", "text/html")` → no finding

7. **Add regression tests**
   Extend unit and fixture coverage for:
    - dangerous selector + tainted payload → finding
    - safe selector + tainted payload → no finding
    - dangerous selector + constant payload → no finding
    - dynamic selector / MIME type → conservative finding
    - payload argument positions are returned correctly by gated classification

**Test tasks**:
- `setAttribute` dangerous attributes fire only when arg 1 is tainted
- harmless `setAttribute` attributes do not fire
- `parseFromString` fires for dangerous MIME types only
- constant payloads do not create findings even when activation arg is dangerous
- existing JS/TS tests continue to pass
- `cargo test` passes

**Definition of done**:
- Nyx can model APIs where sink activation and sink payload are different arguments
- `setAttribute(name, value)` is modeled precisely
- `parseFromString(input, mimeType)` is supported with MIME-type gating
- All tests pass

**Risks / gotchas**:
- This is still a conservative static model. Dynamic selector arguments should prefer
  documented conservative behavior over silent suppression.
- Keep this phase narrowly scoped to explicit constant-argument role modeling.
  Do not expand into full symbolic execution, type inference, or general API semantics.
- `application/xhtml+xml` is intentionally treated as dangerous under the chosen
  browser/DOM threat model; document that choice in fixture or changelog notes.

**Dependencies**:
- Phase 16.5 — argument-sensitive sink activation exists already
- Phase 10 — per-argument taint propagation is already in place

---

### Phase 17 — Model try/catch in CFG: Java and JavaScript

**Category**: core correctness

**Why**: Exception-based control flow is pervasive in Java and JavaScript. Without it,
the scanner misses all exception-path vulnerabilities and produces false negatives on
finally-based cleanup. This is the largest CFG correctness gap.

**Goals**:
- Add `Kind::Try`, `Kind::Catch`, `Kind::Finally` to the Kind enum in `labels/mod.rs`
- Handle `try_statement` / `try_expression` in `build_sub()` in `cfg.rs`
- Create exception edges from call nodes inside try blocks to catch entry nodes
- Model finally blocks as running on both normal and exception paths

**Files to touch**:
- `src/labels/mod.rs` — add `Try`, `Catch`, `Finally` to `Kind` enum
- `src/labels/java.rs` — map `try_statement`, `catch_clause`, `finally_clause` to new Kinds
- `src/labels/javascript.rs` — map `try_statement`, `catch_clause`, `finally_clause`
- `src/labels/typescript.rs` — same
- `src/cfg.rs` — add `try_statement` handling in `build_sub()`

**Implementation tasks**:
1. Add to `Kind` enum: `Try`, `Catch`, `Finally`
2. In language KINDS maps:
   - Java: `"try_statement" => Kind::Try`, `"catch_clause" => Kind::Catch`,
     `"finally_clause" => Kind::Finally`
   - JS/TS: same node names (tree-sitter uses identical names)
3. In `cfg.rs` `build_sub()`, add a match arm for `Kind::Try`:
   - Build the try body as a sub-CFG
   - Build the catch body as a sub-CFG
   - Build the finally body (if present) as a sub-CFG
   - Add normal flow edge: try body → finally entry (or exit if no finally)
   - Add exception edge: from each call node inside the try body → catch entry
     (conservative: any call might throw)
   - Add normal flow edge: catch exit → finally entry (if present)
   - Add edge: finally exit → outer next node
4. Mark exception edges with a new `EdgeKind::Exception` (or reuse `EdgeKind::False`
   for simplicity — the catch block is the "false" path where the try didn't succeed)
5. Ensure the `entry` and `exit` of the try/catch compound are connected correctly

**Test tasks**:
- New unit test: try/catch with source in try and sink in catch → taint should NOT
  flow (source throws before reaching sink assignment)
- New unit test: try/catch with source before try and sink in finally → taint SHOULD
  flow (finally always runs)
- New unit test: try/catch with resource open in try and close in finally → no leak
- Existing tests pass unchanged
- `cargo test` passes

**Definition of done**:
- `try_statement` handled in CFG construction for Java and JS/TS
- Exception edges from calls to catch blocks
- Finally blocks on both paths
- New tests pass
- All existing tests pass

**Risks / gotchas**:
- This is the largest single change in the plan. The try/catch modelling is inherently
  complex. Start with a simple model: every call in a try block has an exception edge
  to catch. This is over-conservative (not every call throws) but sound.
- Don't try to model checked vs unchecked exceptions in Java. Treat all calls as
  potentially throwing.
- Python's try/except has different syntax (`except` vs `catch`). Defer Python to a
  follow-up phase — focus on Java and JS first.
- Go doesn't have try/catch (uses `defer`/`recover`). Skip Go.

**Dependencies**: None (but should be done after Phases 9-10 so test expectations are
stable before this larger change)

---

### Phase 18 — Model try/catch in taint transfer

**Category**: core correctness

**Why**: Phase 17 added try/catch edges to the CFG. This phase ensures the taint
transfer function correctly handles exception edges — specifically, that taint state
on exception edges reflects the state at the throwing call, not at the end of the try
block.

**Goals**:
- Ensure taint transfer correctly propagates state along exception edges
- Handle catch clause parameter binding (the caught exception variable)
- Handle finally cleanup semantics in taint

**Files to touch**:
- `src/taint/transfer.rs` — handle `EdgeKind::Exception` (if added) or the exception
  edge semantics
- `src/cfg.rs` — ensure `NodeInfo` for catch clause binds the exception variable

**Implementation tasks**:
1. If Phase 17 used `EdgeKind::Exception` (new variant):
   - In `transfer.rs` `apply()`, when edge is `Exception`, propagate the state as-is
     from the throwing call node to the catch entry
   - The caught exception variable (if any) should be marked as tainted with
     `Cap::all()` + `SourceKind::Unknown` (exception objects may contain user data)
2. If Phase 17 reused `EdgeKind::False`:
   - No transfer changes needed (False edges already propagate state)
   - Still need to handle catch parameter binding
3. For catch parameters:
   - In `cfg.rs`, when building the catch body, create a synthetic assignment node
     that defines the catch variable (e.g., `catch (err)` → defines `err`)
   - Mark the catch variable as potentially tainted (conservative)
4. For finally blocks:
   - State at finally entry is the join of normal-path state and exception-path state
   - The standard worklist join already handles this correctly

**Test tasks**:
- New test: `try { let x = source(); } catch(e) { sink(e.message); }` → should
  detect taint (exception may carry source data)
- New test: `try { let x = source(); sink(x); } catch(e) { /* no sink */ }` → taint
  finding in try block (normal path)
- Existing tests pass
- `cargo test` passes

**Definition of done**:
- Exception edges propagate taint correctly
- Catch variables are conservatively tainted
- Finally blocks receive joined state from both paths
- All tests pass

**Risks / gotchas**:
- Conservatively tainting catch variables may increase false positives. This is the
  safe default. Refinement (tracking which specific exceptions carry tainted data)
  is a future improvement.
- The interaction between exception edges and predicate tracking needs care. Exception
  paths should not carry predicate state from conditions inside the try block.

**Dependencies**: Phase 17 (CFG must have try/catch edges first)

---

### Phase 19 — Method receiver taint propagation

**Category**: core correctness

**Why**: `tainted_obj.method()` doesn't propagate taint through the receiver. In `cfg.rs`,
only `info.uses` (arguments) are collected; the receiver object is not tracked. This
causes false negatives on method chains like `tainted_response.send(data)`.

**Goals**:
- Track the method receiver as an implicit first use in call nodes
- Propagate receiver taint through method calls

**Files to touch**:
- `src/cfg.rs` — when building a method call node, add the receiver to `uses`
- `src/taint/transfer.rs` — no changes needed if receiver is in `uses` (existing
  `collect_uses_taint` handles it)

**Implementation tasks**:
1. In `cfg.rs`, in the call node construction for method calls (`Kind::CallMethod`):
   - Extract the receiver expression text (the object before `.method()`)
   - Add it as the first element of `info.uses`
   - Adjust parameter indices accordingly (receiver is implicit param 0)
2. For chained calls (`a.b().c()`), only extract the immediate receiver (`a.b()` result
   → but this is a call return, not a variable). For simple cases (`obj.method()`),
   extract `obj`.
3. Be conservative: only extract receiver for simple identifier receivers (`obj.method()`),
   not complex expressions (`getObj().method()`).

**Test tasks**:
- New unit test: `let x = source(); x.dangerous_method()` → receiver `x` is in uses,
  taint propagates to the call's return value
- New unit test: `let x = source(); safe_obj.method(x)` → argument `x` is tainted
  (existing behaviour, no change)
- Existing tests pass (verify no new findings from receiver tracking)
- `cargo test` passes

**Definition of done**:
- Method call receivers added to `info.uses` for `CallMethod` nodes
- Receiver taint propagates through method calls
- All tests pass

**Risks / gotchas**:
- This may increase findings. Some of these will be true positives (good), some may
  be false positives (e.g., `tainted_string.length` — the length is an int, not
  tainted). Without type awareness, we can't distinguish. Accept this trade-off.
- Only handle simple identifier receivers initially. Complex receiver expressions
  (function calls, member access chains) can be added later.
- `info.uses` ordering matters for per-argument propagation (Phase 10). Make sure the
  receiver is consistently at index 0 or is clearly separated from parameter uses.

**Dependencies**: None (but best done after Phase 10 so per-argument model is in place)

---

### Phase 19.5 — Multi-label classification for taint labels

**Category**: core correctness

**Why**: Nyx’s current label classification model returns only the **first matching
label** for a callee. This is too restrictive for real APIs, because some functions
legitimately behave as more than one thing at once. For example:

- `file_get_contents` in PHP can act as a **Source** (its return value contains data)
  and also as an **SSRF Sink** (its URL argument can trigger an outbound request)
- `readObject` in Java can act as a **Source-like producer of attacker-controlled data**
  and also as a **DESERIALIZE Sink**
- future framework wrappers may need to behave as **Sink + Sanitizer** or
  **Source + Sink** depending on usage

As long as classification is single-label, the rule base is forced into awkward
tradeoffs, and later vulnerability modeling (especially SSRF and deserialization)
remains artificially shallow.

This phase upgrades the core classification interface so a single API can carry
multiple labels safely and deterministically.

**Goals**:
- Replace single-label classification with **multi-label classification**
- Allow a callee to return multiple matching labels in stable order
- Update taint analysis to consume multiple labels without changing existing semantics
  for single-label rules
- Add regression coverage for dual-label APIs like PHP `file_get_contents` and
  Java `readObject`
- Keep the implementation narrow: classification + taint consumption only

**Files to touch**:
- `src/labels/mod.rs` — classification API and helpers
- `src/taint/transfer.rs` — consume multiple labels at call sites
- `src/labels/php.rs` — verify dual-label rules like `file_get_contents`
- `src/labels/java.rs` — verify dual-label rules like `readObject`
- `tests/` — new unit tests and/or fixture updates for multi-label behaviour
- `tests/fixtures/real_world/{lang}/taint/*.expect.json` — update expectations if
  previously-shadowed findings now correctly appear

**Implementation tasks**:

1. **Replace first-match classification with all-match classification**
    - Introduce a new classification helper that returns **all matching labels** for a
      callee rather than a single `Option<DataLabel>`.
    - Preserve rule order from the label file so results remain deterministic.
    - Keep the old single-label helper only if needed for compatibility, but migrate
      taint analysis to the new multi-label path.

2. **Update taint transfer to consume multiple labels**
    - At call handling sites in `src/taint/transfer.rs`, process all matching labels:
        - apply `Source(...)` behaviour
        - apply `Sink(...)` behaviour
        - apply `Sanitizer(...)` behaviour
    - Ensure the behaviours compose safely for the same callee:
        - a call may generate taint on its return value
        - also check its arguments as a sink
        - also strip caps if it is a sanitizer
    - Preserve existing behaviour for APIs that only have one label.

3. **Add dual-label regression cases**
    - PHP:
        - `file_get_contents(url)` with tainted URL should be able to act as an SSRF sink
        - `x = file_get_contents(url)` should still act as a source for returned data
    - Java:
        - `readObject` should remain compatible with existing patterns while also being
          available as `Sink(Cap::DESERIALIZE)`
    - Add targeted unit tests or real-world fixture assertions for both cases.

4. **Audit label files for existing shadowed cases**
    - Search for functions that currently have multiple intended semantics but are
      blocked by first-match behaviour.
    - At minimum verify:
        - PHP `file_get_contents`
        - Java `readObject`
    - If additional shadowed cases exist and are clearly correct, leave the rules in
      place and let this phase unlock them. Do not broaden rule coverage here.

5. **Update expectations where correct new findings appear**
    - Some fixtures may now produce `taint-unsanitised-flow` findings that were
      previously impossible due to label shadowing.
    - If the new finding is correct, promote it into the relevant `.expect.json`.
    - Do not suppress newly-correct findings just to keep counts unchanged.

**Test tasks**:
- Add unit test: single-label API still behaves exactly as before
- Add unit test: dual-label API can act as both Source and Sink in one call path
- Add regression test: PHP `file_get_contents` no longer loses SSRF sink behaviour
- Add regression test: Java `readObject` dual-label case is handled deterministically
- `cargo test` must pass
- Run relevant targeted fixture suites (`php`, `java`, `ssrf`, `deser`) and update
  expect files where correct findings now appear

**Definition of done**:
- Classification API returns all matching labels in stable order
- Taint transfer correctly applies multiple labels at a call site
- PHP `file_get_contents` no longer loses SSRF sink behaviour because of first-match shadowing
- Java `readObject` can coexist as both source-like and sink-like semantics
- Existing single-label rules behave unchanged
- All tests pass

**Risks / gotchas**:
- This touches a core engine interface. Keep the change minimal and tightly tested.
- Order must remain deterministic even when multiple labels match.
- Do not silently change non-taint consumers of classification unless required.
- A multi-label call can both create and consume taint; apply behaviours carefully so
  one does not accidentally erase another.
- This phase is about classification semantics only. Do NOT bundle in validator
  recognition, framework expansion, or broader SSRF work.

**Dependencies**:
- Phase 7 / 8 benefit from this change, but this phase can be implemented after they
  land and before later semantic-completion work
- Best placed before deep SSRF semantic completion and before final Phase 2 readiness assessment

--- 

### Phase 20 — Short-circuit evaluation in CFG

**Category**: core correctness

**Why**: Boolean operators (`&&`, `||`) are parsed as single condition nodes. The CFG
doesn't model that in `if (guard && sink(x))`, the guard prevents `sink(x)` from
executing when guard is false. This causes false negatives where guards appear to
cover dangerous operations but the CFG doesn't respect short-circuit semantics.

**Goals**:
- Split `&&` and `||` conditions into separate CFG nodes with short-circuit edges
- Model: `a && b` → evaluate `a`; if false, skip `b`; if true, evaluate `b`
- Model: `a || b` → evaluate `a`; if true, skip `b`; if false, evaluate `b`

**Files to touch**:
- `src/cfg.rs` — condition handling in `build_sub()` for `Kind::If`

**Implementation tasks**:
1. In `build_sub()` If handling, before creating the condition node:
    - Check if the condition expression contains `&&` or `||` operators
    - Use tree-sitter to identify `binary_expression` children with `&&`/`||` operators
2. For `a && b`:
    - Create node for `a` with True/False edges
    - True edge → node for `b`
    - False edge of `a` → False branch of the If (short-circuit)
    - True/False edges of `b` → normal If True/False branches
3. For `a || b`:
    - Create node for `a`
    - True edge of `a` → True branch (short-circuit)
    - False edge of `a` → node for `b`
    - True/False edges of `b` → normal If True/False branches
4. Handle nested operators: `a && b && c` → left-to-right chaining
5. Only apply this to the top-level condition of If/While/For — don't split
   conditions inside assignments or other expressions

**Test tasks**:
- New test: `if (input != null && sink(input))` — `sink` should only be reachable
  when input is not null (predicate tracked on True edge of null check)
- New test: `if (is_safe(x) || validate(x))` — both validation paths should mark
  the True branch as validated
- Existing tests pass (verify that existing If conditions without `&&`/`||` are
  unaffected)
- `cargo test` passes

**Definition of done**:
- `&&` and `||` in conditions create separate CFG nodes with short-circuit edges
- Predicate tracking works correctly on each sub-condition
- All tests pass

**Risks / gotchas**:
- This changes the CFG structure for many conditions. Existing tests that assert
  specific CFG shapes may need updating.
- Tree-sitter's representation of `&&`/`||` varies by language. In most languages,
  it's `binary_expression` with `&&` operator. Verify for Java, Go, Python (`and`/`or`
  keywords), Ruby (`&&`/`and`).
- Nested/complex conditions (`a && (b || c) && d`) should be handled recursively.
  Start with non-nested cases and extend.
- This is a medium-sized change but affects a critical path. Test thoroughly.

**Dependencies**: None (but should be done after Phases 9-18 to minimize test churn)

---

### Phase 21 — Evaluation benchmark corpus

**Category**: evaluation

**Why**: Without a published evaluation, every claim about precision and recall is
unverifiable. This phase creates a curated corpus of known vulnerabilities with ground
truth so every subsequent change can be measured.

**Goals**:
- Create a benchmark corpus of 50 known vulnerability patterns across 5 languages
  (JS, Python, Java, Go, PHP)
- Each pattern is a minimal reproducible code snippet with ground truth annotation
- Patterns drawn from OWASP Top 10, CWE database, and common real-world CVE patterns
- Support automated scoring: precision, recall, F1

**Files to touch**:
- `tests/benchmark/` — new directory
- `tests/benchmark/corpus/{lang}/{vuln_class}/` — test case files
- `tests/benchmark/ground_truth.json` — expected findings per file
- `tests/benchmark_test.rs` — automated scoring harness

**Implementation tasks**:
1. Create benchmark directory structure:
   ```
   tests/benchmark/
     corpus/
       javascript/ (10 cases)
       python/ (10 cases)
       java/ (10 cases)
       go/ (10 cases)
       php/ (10 cases)
     ground_truth.json
   ```
2. For each language, create 10 minimal vulnerability patterns:
   - 2× SQL injection (one with concatenation, one with format string)
   - 2× Command injection (one direct, one indirect via variable)
   - 1× XSS (reflected user input)
   - 1× SSRF (user-controlled URL)
   - 1× Path traversal (user-controlled file path)
   - 1× Deserialization (if applicable to language)
   - 1× Code injection (eval with user input)
   - 1× Safe variant (same pattern but properly sanitised — should NOT trigger)
3. Create `ground_truth.json` mapping each file to expected findings:
   ```json
   {
     "javascript/sqli_concat.js": {
       "expected_rule": "taint-unsanitised-flow",
       "expected_severity": "HIGH",
       "expected_line_range": [5, 10],
       "is_vulnerable": true
     },
     "javascript/sqli_safe.js": {
       "expected_rule": null,
       "is_vulnerable": false
     }
   }
   ```
4. Create `tests/benchmark_test.rs`:
   - Load all corpus files
   - Run Nyx on each file in taint mode
   - Compare findings to ground truth
   - Compute: true positives, false positives, false negatives, true negatives
   - Compute: precision, recall, F1
   - Print summary table
   - Fail test if precision < 0.5 or recall < 0.3 (initial thresholds, to be
     tightened over time)

**Test tasks**:
- Benchmark test runs and produces scores
- Score thresholds are met (adjust thresholds if initial scores are different)
- `cargo test benchmark` passes
- `cargo test` passes (benchmark tests should be behind a feature flag or
  `#[ignore]` to not slow down normal test runs)

**Definition of done**:
- 50 benchmark corpus files across 5 languages
- Ground truth JSON with expected findings
- Automated scoring harness
- Baseline precision/recall numbers recorded

**Risks / gotchas**:
- Initial scores may be low. That's fine — this is a measurement, not a goal. The
  purpose is to establish a baseline for measuring improvement.
- Creating good minimal vulnerability patterns requires security expertise. Base them
  on well-known patterns from OWASP testing guides.
- Mark the benchmark test as `#[ignore]` by default so it doesn't slow CI. Run it
  explicitly with `cargo test benchmark -- --ignored`.

**Dependencies**: Phases 4-8 (cap fixes and new vulnerability classes should be in
place for meaningful measurement)

---

### Phase 22 — Run benchmark and publish baseline numbers

**Category**: evaluation

**Why**: Phase 20 created the benchmark. This phase runs it, records the baseline
numbers, and documents them for future comparison.

**Goals**:
- Run the benchmark suite
- Record precision, recall, F1 per language and overall
- Record per-vulnerability-class scores
- Document in a file that can be diffed over time

**Files to touch**:
- `tests/benchmark/RESULTS.md` — new file with baseline numbers
- `tests/benchmark_test.rs` — may need adjustments based on initial run

**Implementation tasks**:
1. Run `cargo test benchmark -- --ignored --nocapture` to get full output
2. Record results in `tests/benchmark/RESULTS.md`:
   ```markdown
   # Nyx Benchmark Results

   ## Baseline (Phase 21, date)
   | Metric | Score |
   |--------|-------|
   | Overall Precision | X% |
   | Overall Recall | X% |
   | Overall F1 | X% |

   ### Per Language
   | Language | TP | FP | FN | TN | Precision | Recall |
   ...

   ### Per Vulnerability Class
   | Class | TP | FP | FN | Precision | Recall |
   ...
   ```
3. If any benchmark cases are clearly wrong (ground truth error), fix them
4. Set test threshold to 5% below current scores (so future regressions are caught)

**Test tasks**:
- Benchmark test passes with documented thresholds
- `cargo test` passes

**Definition of done**:
- Baseline numbers recorded in `tests/benchmark/RESULTS.md`
- Thresholds set in test harness
- All tests pass

**Risks / gotchas**:
- Results may be humbling. Document honestly.

**Dependencies**: Phase 20

---

### Phase 23 — README and docs claims audit

**Category**: product credibility

**Why**: Several README claims are stronger than what the implementation substantiates.
A skeptical security engineer reading the README should find every claim backed by
evidence.

**Goals**:
- Soften or qualify claims that exceed evidence
- Add missing qualifications (state analysis opt-in, interop requires manual setup)
- Remove or qualify the unsubstantiated "rust-lang/rust in ~1s" performance claim
- Add benchmark results reference
- Make README sound more human

**Files to touch**:
- `README.md`
- `docs/configuration.md` — note state analysis opt-in
- `docs/detectors/patterns.md` — add confidence level definitions

**Implementation tasks**:
1. In `README.md`:
   - Change the "~1s for rust-lang/rust" claim to something like "typically scans
     large codebases in seconds on modern hardware" or add "(informal measurement,
     AST-only mode)" qualification
   - Add "(opt-in)" footnote to state-analysis capabilities in the feature table
   - Qualify cross-language interop: "via explicit interop edge configuration"
   - Add a link to benchmark results if Phase 21 is complete
2. In `docs/configuration.md`:
   - Add section explaining how to enable state analysis
   - Document `scanner.enable_state_analysis = true`
3. In `docs/detectors/patterns.md`:
   - Define `Confidence::High`, `Confidence::Medium`, `Confidence::Low`
   - Explain what confidence means for consumers (filtering, prioritisation)
4. Fix the author email typo in `Cargo.toml` if still present (`exmaple` → `example`)

**Test tasks**:
- `cargo test` passes (no code changes)
- Manual review: README claims match implementation

**Definition of done**:
- All README claims qualified or backed by evidence
- Docs updated
- Cargo.toml metadata fixed
- No code changes

**Risks / gotchas**:
- Softening claims may feel like a step backward, but it builds trust. A tool that
  under-promises and over-delivers is more credible than one that over-promises.

**Dependencies**: Phase 21 (benchmark results to reference)

---

### Phase 24 — Expand Go rule depth

**Category**: rule depth

**Why**: Go has the best existing rule set (11 rules, good http.Request chains) but
is missing SSRF sinks, template security model, and crypto patterns.

**Goals**:
- Add SSRF sinks, crypto weak-algorithm sinks, and template injection patterns
- Bring Go to 18+ rules

**Files to touch**:
- `src/labels/go.rs`
- `tests/fixtures/real_world/go/taint/` — new fixtures

**Implementation tasks**:
1. Add SSRF sinks: `http.Get`, `http.Post`, `http.NewRequest`, `net.Dial`, `net.DialTimeout`
2. Add crypto sinks: `md5.New`, `sha1.New`, `des.NewCipher`, `rc4.NewCipher`
   as `Sink(Cap::CRYPTO)` — using weak crypto with any input is a finding
3. Add template sinks: `template.HTML` (marks string as safe — dangerous if user input),
   `template.JS`, `template.CSS`
4. Add sanitizers: `filepath.Clean` (already present?), `url.PathEscape`
5. Create 2 fixtures: `go_ssrf.go`, `go_weak_crypto.go`

**Test tasks**:
- New fixtures produce findings
- Existing Go tests unchanged
- `cargo test` passes

**Definition of done**:
- 7+ new Go rules
- 2+ new fixtures
- All tests pass

**Risks / gotchas**:
- `template.HTML` is actually a type conversion in Go, not a function call. Tree-sitter
  may parse it as a call expression or a type conversion. Verify with tree-sitter
  playground.

**Dependencies**: Phase 6 (uses `Cap::SSRF`, `Cap::CRYPTO`)

---

### Phase 25 — Expand Java rule depth (Spring, JPA, logging)

**Category**: rule depth

**Why**: Java is widely used in enterprise and currently has 8 rules with only Servlet
API support. Missing: Spring Boot, JPA/Hibernate, Java logging format injection,
JNDI injection.

**Goals**:
- Add Spring Boot source/sink patterns
- Add JPA/Hibernate patterns
- Add logging format injection
- Add JNDI injection

**Files to touch**:
- `src/labels/java.rs`
- `tests/fixtures/real_world/java/taint/` — new fixtures

**Implementation tasks**:
1. Add Spring **sources**:
   - `@RequestParam` handling → method parameters (this is annotation-based; the
     tree-sitter approach would match the method call pattern, not the annotation.
     Instead, add common accessor patterns)
   - `request.getParameter` (already present)
   - `@RequestBody` → method parameter (tree-sitter may not see annotations easily;
     skip for now)
2. Add Spring **sinks**:
   - `jdbcTemplate.query`, `jdbcTemplate.update` — SQL (`Cap::SQL_QUERY`)
   - `RestTemplate.getForObject`, `RestTemplate.exchange` — SSRF (`Cap::SSRF`)
3. Add JPA **sinks**:
   - `entityManager.createNativeQuery` — SQL injection (`Cap::SQL_QUERY`)
   - `entityManager.createQuery` with string concat — SQL injection
4. Add logging **sinks**:
   - `logger.info`, `logger.warn`, `logger.error` with format injection (`Cap::FMT_STRING`)
   - `String.format` — format string (`Cap::FMT_STRING`)
5. Add JNDI **sinks**:
   - `InitialContext.lookup`, `Context.lookup` — JNDI injection (`Cap::CODE_EXEC`)
6. Create 2 fixtures: `spring_sqli.java`, `jndi_injection.java`

**Test tasks**:
- New fixtures produce findings
- Existing Java tests unchanged
- `cargo test` passes

**Definition of done**:
- 8+ new Java rules
- 2+ new fixtures
- All tests pass

**Risks / gotchas**:
- Spring annotations (`@RequestParam`, `@RequestBody`) are not easily matched by
  tree-sitter function call patterns. The current approach matches method names, not
  annotations. This is a fundamental limitation. Consider adding annotation-based
  matching as a future enhancement.
- Log4Shell (CVE-2021-44228) was a logging format string vulnerability. Adding
  `logger.info` as a sink with `Cap::FMT_STRING` would detect this class of issue
  when user input flows to log messages.

**Dependencies**: Phase 6 (uses `Cap::SQL_QUERY`, `Cap::SSRF`, `Cap::CODE_EXEC`)

---

### Phase 26 — Expand Ruby rule depth (Rails, ERB)

**Category**: rule depth

**Why**: Ruby currently has the weakest rule set (6 rules, no Rails framework coverage,
bare function names). Rails is the dominant Ruby web framework.

**Goals**:
- Add Rails source/sink/sanitizer patterns
- Add ERB template injection patterns
- Bring Ruby from 6 to 14+ rules

**Files to touch**:
- `src/labels/ruby.rs`
- `tests/fixtures/real_world/ruby/taint/` — new fixtures

**Implementation tasks**:
1. Add Rails **sources**:
   - `params` (already present — verify)
   - `params.require`, `params.permit` (these are sanitizers in Rails' strong params model!)
   - `request.headers`, `request.body`, `request.url`, `request.referrer`
   - `cookies`, `session`
2. Add Rails **sinks**:
   - `render html:` — XSS (`Cap::HTML_ESCAPE`)
   - `render inline:` — template injection (`Cap::CODE_EXEC`)
   - `redirect_to` — open redirect (`Cap::SSRF`)
   - `send_file`, `send_data` — path traversal (`Cap::FILE_IO`)
   - `ActiveRecord.where` with string — SQL injection (`Cap::SQL_QUERY`)
   - `ActiveRecord.find_by_sql` — SQL injection
   - `constantize` — code injection (`Cap::CODE_EXEC`)
3. Add **sanitizers**:
   - `html_safe` is NOT a sanitizer (it marks string as safe, which is dangerous)
   - `ERB::Util.html_escape`, `CGI.escape`, `Rack::Utils.escape_html`
   - `params.require(...).permit(...)` — strong params (partial sanitiser)
4. Create 2 fixtures: `rails_sqli.rb`, `rails_redirect.rb`

**Test tasks**:
- New fixtures produce findings
- Existing Ruby tests unchanged
- `cargo test` passes

**Definition of done**:
- 8+ new Ruby rules
- 2+ new fixtures
- All tests pass

**Risks / gotchas**:
- `params.permit` is a complex concept. In Rails, it whitelists specific keys but
  doesn't sanitise values. It reduces attack surface but doesn't eliminate
  vulnerability. Model as a sanitizer with limited scope.
- `html_safe` is a common Rails footgun. It should be labelled as a sink
  (`Sink(Cap::HTML_ESCAPE)`) because calling it on user input creates an XSS.

**Dependencies**: Phase 5 (receiver-qualified call fix needed for Rails patterns like
`ActiveRecord.where`, `Net::HTTP.get`), Phase 6 (uses new cap bits)

---

### Phase 27 — Constant-argument sink suppression

**Category**: precision

**Why**: Many false positives come from sinks called with hardcoded constant arguments:
`subprocess.call(["ls", "-la"])`, `exec.Command("echo", "hello")`. These are not
vulnerable because the arguments are not attacker-controlled. The existing constant
detection (Python tests reference it) should be generalised.

**Goals**:
- Detect when a sink's arguments are all string/integer literals
- Suppress taint findings for constant-argument sinks
- Keep the finding if ANY argument has taint flow

**Files to touch**:
- `src/cfg.rs` — add `is_constant: bool` field to `NodeInfo` for call nodes
- `src/taint/transfer.rs` — skip sink check when all arguments are constants
- `src/cfg_analysis/` — use constant detection in structural analysis

**Implementation tasks**:
1. In `cfg.rs`, when building a call node:
   - Check each argument child node in tree-sitter
   - If all arguments are `string`, `number`, `true`, `false`, `null`, or `none`
     literal nodes, set `is_constant: true` on the NodeInfo
   - If any argument is an identifier, call, or complex expression, set `is_constant: false`
2. In `taint/transfer.rs`, in the sink check section:
   - If `info.is_constant` is true and no `info.uses` variables are tainted, skip
     emitting `SinkReached` event
3. In cfg_analysis unguarded-sink detection:
   - Skip constant-argument sinks (they're not exploitable regardless of auth state)

**Test tasks**:
- Verify existing `python_constant_subprocess_no_finding` test still passes
- New test: `Command::new("echo").arg("hello")` → no finding (constant)
- New test: `Command::new(user_input).arg("hello")` → finding (tainted)
- New test: `system("ls -la")` → no finding (constant)
- `cargo test` passes

**Definition of done**:
- Constant-argument detection in CFG construction
- Taint findings suppressed for constant-only sink calls
- CFG structural findings suppressed for constant-only sinks
- All tests pass

**Risks / gotchas**:
- One-hop constant binding (`let cmd = "ls"; system(cmd)`) is harder to detect. The
  existing `python_one_hop_constant_binding_no_finding` test handles this via taint
  analysis (no taint source → no finding). This phase focuses on the simpler case.
- Don't suppress if the constant is user-controllable through other means (e.g.,
  template literals in JS with interpolation). Check for `template_string` in JS
  and exclude those from "constant" classification.

**Dependencies**: None

---

### Phase 28 — Scan path deduplication refactor

**Category**: refactor

**Why**: `src/commands/scan.rs` (1,514 lines) has two separate scan paths
(`scan_filesystem` and `scan_with_index_parallel`) with duplicated orchestration
logic for pass 1, call graph building, and pass 2. This duplication increases
maintenance burden and makes it easy for one path to diverge from the other.

**Goals**:
- Extract shared orchestration logic into helper functions
- Reduce `scan.rs` by ~200 lines
- Ensure both paths behave identically

**Files to touch**:
- `src/commands/scan.rs` — refactor into shared helpers

**Implementation tasks**:
1. Extract `fn build_global_summaries(summaries: Vec<FuncSummary>) -> GlobalSummaries`
   — shared summary merging logic
2. Extract `fn build_and_analyse_call_graph(summaries: &GlobalSummaries) -> CallGraphAnalysis`
   — shared call graph construction and analysis
3. Extract `fn post_process_diags(diags: &mut Vec<Diag>, cfg: &Config)` — shared
   ranking, confidence, and truncation logic
4. Update both `scan_filesystem` and `scan_with_index_parallel` to use shared helpers
5. Verify identical output on test fixtures

**Test tasks**:
- Run `cargo test` with both indexed and non-indexed modes — same findings
- `cargo test real_world` passes
- `cargo test` passes
- Run the benchmark test to verify no performance regression

**Definition of done**:
- Shared helpers extracted
- Both scan paths use them
- `scan.rs` reduced in size
- All tests pass
- `cargo clippy` clean

**Risks / gotchas**:
- The two paths have slightly different data flow (indexed path reads from DB, non-indexed
  reads from memory). The helpers should be parameterised over the summary source, not
  tightly coupled to either path.
- Don't refactor the entire file at once. Start with the three helpers above and see if
  the structure becomes clearer.

**Dependencies**: Phase 3 (ast.rs duplication should be cleaned first to establish
the pattern)

---

### Phase 29 — Re-run benchmark and measure improvement

**Category**: evaluation

**Why**: After all the correctness, precision, and rule depth improvements, measure
the impact. This validates whether the work made a meaningful difference.

**Goals**:
- Re-run the benchmark from Phase 20
- Compare precision, recall, F1 to the Phase 21 baseline
- Document improvement per language and per vulnerability class
- Identify remaining gaps

**Files to touch**:
- `tests/benchmark/RESULTS.md` — add new measurement section

**Implementation tasks**:
1. Run `cargo test benchmark -- --ignored --nocapture`
2. Record results alongside Phase 21 baseline
3. Compute deltas (improvement/regression per metric)
4. Identify remaining worst-performing areas
5. Update test thresholds to lock in improvements (prevent regression)

**Test tasks**:
- Benchmark test passes with updated thresholds
- `cargo test` passes

**Definition of done**:
- Updated results in `tests/benchmark/RESULTS.md` with before/after comparison
- Test thresholds updated
- Remaining gaps documented

**Risks / gotchas**:
- Some improvements may have unexpected side effects (fixing recall may hurt precision
  or vice versa). Document these trade-offs.

**Dependencies**: Phases 1-28 (ideally all prior phases complete, but can run at any
point to measure incremental progress)

---

### Phase 30 — SSRF semantic completion

**Category**: rule depth

**Why**: Initial SSRF support (Phase 7) and SSRF modeling hardening (Phase 7B)
established credible baseline coverage, and Phase 23 enables APIs to carry multiple
labels where needed. However, SSRF support is still not semantically complete.

Remaining limitations include:
- common **SSRF validation patterns** (allowlists, hostname checks, scheme checks,
  localhost/internal-IP blocking) are not recognised as sanitisation
- framework and wrapper coverage is still uneven across JS/TS, Python, Java, Go,
  Ruby, and PHP
- request-builder and helper-function flows remain shallower than direct one-hop sinks
- SSRF precision and recall have improved, but are not yet measured as a dedicated
  vulnerability class with benchmark-quality fixtures

This phase completes SSRF as a mature vulnerability class by focusing on validator
recognition, wrapper depth, benchmark-quality testing, and honest documentation of
remaining static-analysis limits.

**Goals**:
- Recognise a small, explicit set of **SSRF validation / sanitisation patterns**
- Deepen SSRF coverage in high-value frameworks and wrappers
- Add benchmark-quality positive and negative SSRF fixtures
- Measure SSRF precision/recall independently from overall taint
- Document the remaining boundaries of static SSRF detection honestly

**Files to touch**:
- `src/labels/javascript.rs` — SSRF wrapper/sanitizer additions
- `src/labels/typescript.rs` — mirror JS additions
- `src/labels/python.rs` — SSRF wrapper/sanitizer additions
- `src/labels/java.rs` — SSRF wrapper/sanitizer additions
- `src/labels/go.rs` — SSRF wrapper/sanitizer additions
- `src/labels/ruby.rs` — SSRF wrapper/sanitizer additions
- `src/labels/php.rs` — SSRF wrapper/sanitizer additions
- `src/taint/transfer.rs` — SSRF sanitizer / validation semantics
- `tests/fixtures/real_world/{lang}/taint/` — new SSRF precision fixtures
- `tests/benchmark/corpus/{lang}/ssrf/` — SSRF benchmark cases
- `tests/benchmark/ground_truth.json` — SSRF benchmark expectations
- `tests/benchmark/RESULTS.md` — SSRF subsection with measured results
- `docs/` or `README.md` — brief note on SSRF scope and known limits if appropriate

**Implementation tasks**:

1. **Add SSRF-specific validator recognition**
   Add a small, explicit, conservative set of SSRF validators/sanitizers. Do NOT try
   to infer arbitrary user-defined validation logic.

   Recognise patterns such as:
    - **Allowlist / membership checks**
        - `host in ALLOWED_HOSTS`
        - `ALLOWED_HOSTS.includes(host)`
        - `allowed.contains(host)`
    - **Scheme restrictions**
        - `parsed.scheme == "https"`
        - explicit rejection of non-http/https schemes
    - **Localhost / internal-network blocking**
        - rejections for `localhost`, `127.0.0.1`, `::1`
        - obvious private-range checks when already expressed in source
    - **Structured URL parse + host validation**
        - `urlparse(url).hostname`
        - `new URL(url).hostname`
        - `URI.parse(url).host`

   Apply sanitizer semantics only when:
    - the validation dominates the request path
    - the validated variable is the same destination that reaches the sink
    - the logic is explicit and narrow enough to be trusted

   If dominance or variable identity is unclear, do not suppress the finding.

2. **Deepen framework and wrapper SSRF coverage**
   Extend SSRF beyond raw client calls for the highest-value ecosystems.

   Add or verify coverage for:
    - **JavaScript / TypeScript**
        - `axios(...)`, `axios.request(...)`
        - `node-fetch`
        - `got(...)`
        - `undici.request(...)`
    - **Python**
        - `requests.request(...)`
        - `httpx.post(...)`, `httpx.request(...)`
        - framework proxy/helper patterns where the URL flows to a request call
    - **Java**
        - `HttpClient.sendAsync(...)`
        - additional `RestTemplate` execution forms
        - request-builder flows where URL creation happens before execution
    - **Go**
        - `http.NewRequestWithContext(...)`
        - `client.Do(req)`
    - **Ruby**
        - `Net::HTTP.start`
        - `HTTParty.post`
        - Rails redirect/proxy wrapper patterns where appropriate
    - **PHP**
        - `curl_init(url)` execution paths in addition to `curl_exec`
        - retain dual-label APIs now unlocked by Phase 23

   Prefer execution-point sinks and clearly URL-bearing APIs over broad ambiguous names.

3. **Add benchmark-quality SSRF fixtures**
   Create a focused SSRF corpus covering both recall and precision.

   Add at least:
    - **6 positive fixtures**
        - direct tainted URL → HTTP client
        - multi-hop URL concatenation
        - parsed URL host forwarded after unsafe validation
        - request-builder / object-construction flow
        - wrapper/helper function flow
        - dual-label API case
    - **6 negative fixtures**
        - hardcoded URL
        - safe allowlist host check
        - safe scheme enforcement
        - localhost/private-IP rejection before request
        - ambiguous non-network API usage that should not count as SSRF
        - safe wrapper/helper with validated destination

   Spread these across at least JS/TS, Python, Java, Go, PHP, and one of Ruby/Rust.

4. **Add SSRF benchmark measurement**
   Extend the benchmark corpus with an SSRF-specific subsection:
    - `tests/benchmark/corpus/{lang}/ssrf/*.ext`
    - vulnerable and non-vulnerable cases with ground truth
    - enough cases to measure SSRF precision/recall independently from overall taint

   Record:
    - SSRF true positives
    - SSRF false positives
    - SSRF false negatives
    - SSRF precision / recall / F1
      in `tests/benchmark/RESULTS.md`.

5. **Document remaining SSRF boundaries**
   After implementation, explicitly document what still remains out of scope, such as:
    - arbitrary custom validator inference
    - deep alias/heap-sensitive request-object propagation
    - DNS-resolution-aware internal IP blocking
    - network reachability or runtime-only safety properties
    - async/network semantics beyond static taint flow

**Test tasks**:
- Add unit tests for SSRF sanitizer recognition:
    - allowlist-validated host should suppress SSRF where dominance is clear
    - unvalidated or partially validated host should still produce a finding
- `NYX_TEST_FIXTURE=ssrf NYX_TEST_VERBOSE=1 cargo test real_world_fixture_suite -- --nocapture`
  should pass with improved SSRF precision and recall
- `cargo test benchmark -- --ignored --nocapture` should include SSRF-specific metrics
- `cargo test` must pass for the full suite

**Definition of done**:
- At least a small explicit set of SSRF validators is recognised
- Framework/wrapper SSRF coverage is deeper in the top ecosystems
- New SSRF positive and negative fixtures are committed and passing
- SSRF benchmark metrics are recorded and show measurable improvement over the
  post-Phase-29 baseline
- Remaining SSRF limitations are documented honestly

**Risks / gotchas**:
- Validator recognition can easily become unsound if it tries to infer too much.
  Restrict it to a small explicit set of patterns with clear dominance.
- Wrapper functions may look like ordinary calls. Prefer precise, high-value wrappers
  over broad generic matching.
- Do not suppress SSRF findings unless the validation logic is clearly tied to the
  same destination variable that reaches the sink.
- This phase improves SSRF maturity substantially, but it is still static analysis;
  it should not claim dynamic URL safety or network reachability guarantees.

**Dependencies**:
- Phase 7
- Phase 19.5 — multi-label classification should be complete before dual-label SSRF cases are relied on
- Phase 20 / 21 / 29 — benchmark infrastructure and baseline measurements should exist
---

### Phase 31 — Phase 2 readiness assessment

**Category**: evaluation

**Why**: Before beginning dynamic analysis work, formally assess whether the static
engine is ready to build on. This phase produces a go/no-go recommendation.

**Goals**:
- Review benchmark numbers from Phase 29
- Review remaining soft misses in real-world test suite
- Review the list of known false-positive sources and false-negative sources
- Assess: is the static engine trustworthy enough that dynamic analysis would build
  on a solid foundation?

**Files to touch**:
- `docs/PHASE2_READINESS.md` — new assessment document

**Implementation tasks**:
1. Compile all quality metrics:
   - Benchmark precision/recall/F1
   - Real-world suite: hard passes, soft misses, unexpected findings
   - Negative test suite: false positive rate
   - Coverage: vulnerability classes × languages
2. List remaining known issues (from earlier phases and audit)
3. Write assessment:
   - What's ready
   - What's not ready
   - Recommended pre-Phase 2 work (if any)
   - Recommended Phase 2 entry point (which language/vuln class to start with)
4. Produce go/no-go recommendation

**Test tasks**:
- No code changes; document only

**Definition of done**:
- `docs/PHASE2_READINESS.md` exists with honest assessment
- Clear recommendation on whether to proceed with Phase 2

**Risks / gotchas**:
- The answer might be "not yet". That's fine. The purpose is honest assessment.

**Dependencies**: Phase 29
