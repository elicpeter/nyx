# Language Maturity Matrix

Nyx supports ten languages, but support depth is not uniform. This page gives an
honest per-language picture so you can calibrate expectations before depending
on Nyx for a given stack.

The classifications here are grounded in three concrete signals:

1. **Rule depth** — how many distinct source / sanitizer / sink matchers exist
   for the language in `src/labels/<lang>.rs`, and how many vulnerability
   classes (Cap bits) those matchers cover.
2. **Benchmark results** — rule-level precision / recall / F1 on the 262-case
   corpus in [`tests/benchmark/RESULTS.md`](../tests/benchmark/RESULTS.md),
   last measured 2026-04-20 with scanner version 0.5.0.
3. **Known weak spots** — FPs and FNs the maintainers have deliberately left
   in the benchmark rather than suppressed, documented release-by-release in
   `RESULTS.md`.

All parser integrations use tree-sitter and are stable; parsing is not a
differentiator between tiers. The differentiators are rule depth, cross-file
confidence, and modeled idioms.

---

## Tier Summary

| Tier | Languages | What to expect |
|------|-----------|----------------|
| **Stable** | Python, JavaScript, TypeScript | Deep rule sets, gated sinks (argument-role-aware), framework detection, extensive fixtures, and the bulk of advanced-analysis (SSA, context-sensitivity, symbolic execution) coverage. Safe to depend on in CI gates. |
| **Beta** | Go, Java, Ruby, PHP | Solid mid-depth rule sets with known narrower class coverage. No gated sinks yet. Cross-file flows work; some idioms (variable-typed method receivers, framework context, string interpolation) are incomplete. Usable in CI, but review FP/FN lists before tightening gates. |
| **Experimental** | C, C++, Rust | Narrow rule sets relative to first-class languages. Known, documented weak spots. Appropriate for spot-checks and contribution but not yet recommended as a sole SAST dependency. |

---

## Per-Language Detail

### Stable tier

#### Python — 100% P / 100% R / 100% F1 *(29-case corpus)*

- **Rule depth**: 5 source families, 7 sanitizer families, 21 sink matchers
  spanning HTML, URL, Shell, SQL, Code, SSRF, File I/O, and Deserialization.
- **Framework context**: Flask, Django, argparse source matchers; `flask_request`
  import-alias support.
- **Advanced analysis**: gated sinks (`Popen`, `subprocess.run/call` with
  activation-arg awareness), most SSA-equivalence and symbolic-execution
  fixtures target Python.
- **Fixtures**: 125 under `tests/fixtures/` plus 30 benchmark cases.
- **Blind spots**: f-string interpolation is not explicitly modeled as a
  distinct taint-producing construct; string-formatting flows are caught by
  the general concatenation path.

#### JavaScript — 93.8% P / 100% R / 96.8% F1 *(27-case corpus)*

- **Rule depth**: 3 source families, 10 sanitizer families, 24 sink matchers
  spanning HTML, URL, JSON, Shell, SQL, Code, SSRF, and File I/O.
- **Advanced analysis**: gated sinks (`setAttribute`, `parseFromString`),
  two-level SSA solve for top-level + per-function scopes (`analyse_ssa_js_two_level`),
  prefix-locked SSRF suppression via StringFact.
- **Framework context**: Express, Koa, Fastify (via in-file import scan when
  `package.json` is absent).
- **Fixtures**: 238 under `tests/fixtures/` — the largest corpus of any
  language.
- **Blind spots**: template literals are lowered through concatenation rather
  than modeled as a first-class taint operator; dynamic property access
  (`obj[user]`) is conservatively treated.

#### TypeScript — 100% P / 100% R / 100% F1 *(35-case corpus, most recent measurement)*

- **Rule depth**: Shares the JS ruleset (3 sources, 10 sanitizers, 24 sinks)
  plus TS-specific grammar handling.
- **Advanced analysis**: TSX and JSX grammars wired as of 2026-04-20;
  discriminated-union narrowing, generic erasure, decorator flow, and
  interface dispatch are all validated against adversarial type-system
  stressors.
- **Framework context**: Fastify detection via `detect_in_file_frameworks`
  (import-driven, no `package.json` required).
- **Fixtures**: 39 test fixtures plus 35 benchmark cases.
- **Blind spots**: 0 known open weak spots as of 2026-04-20. `as any` casts
  and `any`-typed flows are handled conservatively (treated as tainted).

### Beta tier

#### Go — 94.1% P / 100% R / 97.0% F1 *(28-case corpus)*

- **Rule depth**: 4 source families, 4 sanitizer families, 9 sink matchers
  covering HTML, URL, Shell, SQL, SSRF, Crypto, and File I/O.
- **Framework context**: Gin, Echo source matchers.
- **Known gaps**: no gated sinks, no deserialization class, allowlist
  early-return patterns in path-pruning benchmark cases still produce FPs
  (`go-pathprune-safe-001`). `fmt.Sprintf` is deliberately not a sink.

#### Java — 92.9% P / 100% R / 96.3% F1 *(23-case corpus)*

- **Rule depth**: 3 source families, 8 sanitizer families, 10 sink matchers
  covering HTML, URL, Shell, SQL, Code, SSRF, and Deserialization.
- **Framework context**: Spring, JPA, Hibernate ORM rules; JNDI injection
  sinks.
- **Known gaps**: no gated sinks. Variable-receiver method calls
  (`client.send(...)` vs `HttpClient.send(...)`) rely on type-qualified
  resolution from receiver-type inference; flows where the receiver type
  cannot be inferred are missed (`java-ssrf-002` historically persisted as
  FN; closed via type facts but fragile on unusual builder chains).

#### Ruby — 100% P / 92.3% R / 96.0% F1 *(24-case corpus)*

- **Rule depth**: 3 source families, 7 sanitizer families, 15 sink matchers
  covering HTML, Shell, SQL, Code, SSRF, File I/O, and Deserialization.
- **Framework context**: Rails helpers (`sanitize_sql`, `permit`, `require`).
- **Known gaps**: string interpolation inside shell and SQL strings is
  recognized structurally but not modeled as a distinct operator.
  `begin/rescue/ensure` exception-edge wiring is documented as deferred
  (structurally incompatible with `build_try()`). One FN persists on an
  interprocedural taint propagation case due to rule-ID mismatch, not a
  missed flow (`rb-interproc-001`).

#### PHP — 86.7% P / 100% R / 92.9% F1 *(24-case corpus)*

- **Rule depth**: 3 source families (`$_GET`, `$_POST`, `$_REQUEST`
  superglobals), 7 sanitizer families, 10 sink matchers covering HTML, URL,
  Shell, SQL, Code, SSRF, File I/O, and Deserialization.
- **Known gaps**: no gated sinks. Limited framework context (Laravel raw
  methods only). Interprocedural sanitizer-wrapping case
  (`php-interproc-safe-001`) persists as FP. `echo` language-construct
  detection is wired but its inner-argument propagation is narrower than
  function-call sinks.

### Experimental tier

#### C — 85.7% P / 100% R / 92.3% F1 *(20-case corpus)*

- **Rule depth**: 3 source families, **2** sanitizer families (prefix-based
  only), 5 sink matchers spanning Shell, File, SSRF, and Format-String.
- **Known gaps**: no framework rules, no gated sinks. Path-validation via
  `strstr()` is not recognized as a guard (`c-safe-006`). Forward-declared
  sanitizers are not tracked (`c-safe-008`). Structural taint chains
  involving `fgets` → array → `system` have rule-ID matching issues
  (`c-cmdi-004`).

#### C++ — 80.0% P / 100% R / 88.9% F1 *(20-case corpus)*

- **Rule depth**: Clones the C ruleset (3 sources, 2 sanitizers, 5 sinks) and
  adds `std::cin` / `std::getline` sources.
- **Known gaps**: same sanitizer-recognition gaps as C; additionally the
  `c_str()` method breaks taint chains (`cpp-cmdi-003`), complex socket
  setup (`connect()`) is not detected (`cpp-ssrf-002`), lambdas and
  nested-class handling are not modeled, and container operations
  (`std::vector`, `std::string` methods) are not taint-aware.

#### Rust — 76.0% P / 100% R / 86.4% F1 *(31-case adversarial corpus)*

- **Rule depth**: 6 source families, **2** sanitizer families (prefix and
  type-coercion), 11 sink matchers covering HTML, Shell, SQL, SSRF,
  Deserialization, and File I/O. Extensive framework source coverage
  (Axum, Actix, Rocket) — the most of any language on the source side.
- **Recent additions (2026-04-20)**: new SQL class (`rusqlite`, `sqlx`,
  `diesel`, `postgres`), new Deserialization class (`serde_yaml`,
  `bincode`, `rmp_serde`, `ciborium`, `ron`, `toml`), expanded file I/O
  (`fs::remove_file/dir/rename/copy`), `reqwest` SSRF builder chain.
- **Known gaps (6 FPs persist on adversarial safe cases)**:
  - `rs-safe-003`: structural `cfg-unguarded-sink` fires when a tainted
    variable is *declared* in scope but not used in the sink — intentional
    for high-risk sinks.
  - `rs-safe-007`: `.replace("..", "")` chains are not credited as
    path-traversal sanitizers (conservative).
  - `rs-safe-008`: negative-validation return pattern
    (`if input.contains(";") { return; }`) not modeled.
  - `rs-safe-009`: match-arm guards don't surface as `StmtKind::If`, so
    `classify_condition` never sees the character-class validation.
  - `rs-safe-010`: `HashMap::get(key).copied().unwrap_or(literal)` not
    modeled as a static-lookup sanitizer.
  - `rs-safe-011`: `cfg-unguarded-sink` structural detector has no access
    to type facts, so `parse::<u16>()` type-narrowing doesn't suppress the
    structural finding on `Command::new(...).arg(port.to_string())`.
- **Not yet covered**: unsafe FFI / `std::mem::transmute` (no rules), Tokio
  `process::Command` async variants (not distinguished from sync),
  `hyper` / `surf` / `ureq` SSRF clients (reqwest family only), and Rocket /
  Actix positive cases (rules exist but no benchmark fixtures yet).

---

## How the tiers were assigned

A language lands in **Stable** when all three hold:

- Rule set covers ≥ 8 vulnerability classes with both source and sink
  matchers, and at least one class has argument-role-aware gating.
- Benchmark F1 ≥ 95% on a corpus of ≥ 25 cases.
- Advanced analysis (SSA lowering, context-sensitivity, symbolic-execution)
  is exercised by fixtures for the language.

A language lands in **Beta** when benchmark F1 ≥ 90% but at least one of the
Stable criteria fails — usually narrower cap coverage or absence of gated
sinks.

A language lands in **Experimental** when rule depth is clearly narrower
(≤ 5 sinks and ≤ 2 sanitizers), or benchmark F1 < 90%, or documented weak
spots require engine changes rather than rule additions to close.

---

## What this means for you

- **CI gates**: safe to set strict `--fail-on HIGH` gates on Stable-tier
  languages. On Beta-tier, expect occasional FP triage; the weak-spot lists
  above tell you exactly what to skim for. On Experimental-tier, treat Nyx
  findings as a starting point for manual review rather than authoritative.
- **Rule contributions**: the shortest path to raising a language's tier is
  contributing sink matchers and gated-sink registrations. Label files live
  at `src/labels/<lang>.rs`; benchmark cases live at
  `tests/benchmark/corpus/<lang>/`.
- **Scope planning**: if your primary stack is C, C++, or Rust, Nyx will
  surface real findings, but you should budget for review time and consider
  combining Nyx with a language-specific tool (e.g. `cargo-audit`,
  `clang-tidy`) until those tiers mature.

The benchmark thresholds in `tests/benchmark_test.rs` are deliberately set
~5 pp below current baselines so any drop in a language's F1 fails CI. Tier
promotions require sustained benchmark performance, not just rule additions.
