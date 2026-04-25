# Language Maturity Matrix

Nyx supports ten languages, but support depth is not uniform. This page gives an
honest per-language picture so you can calibrate expectations before depending
on Nyx for a given stack.

The classifications here are grounded in three concrete signals:

1. **Rule depth**: how many distinct source / sanitizer / sink matchers exist
   for the language in `src/labels/<lang>.rs`, and how many vulnerability
   classes (Cap bits) those matchers cover.
2. **Benchmark results**: rule-level precision / recall / F1 on the 368-case
   corpus in
   [`tests/benchmark/RESULTS.md`](https://github.com/elicpeter/nyx/blob/master/tests/benchmark/RESULTS.md),
   last measured 2026-04-25 with scanner version 0.5.0.
3. **Known weak spots**: FPs and FNs the maintainers have deliberately left
   in the benchmark rather than suppressed, plus structural engine
   limitations the corpus does not stress, documented release-by-release in
   [`RESULTS.md`](https://github.com/elicpeter/nyx/blob/master/tests/benchmark/RESULTS.md).

As of 2026-04-25 the synthetic corpus has effectively saturated: nine of ten
languages report rule-level F1 = 100.0% and Ruby reports 96.3% (one FN on an
interprocedural SQLi case). Aggregate rule-level P=1.000, R=0.995, F1=0.997.
That means F1 alone no longer differentiates tiers — the differentiators are
**rule depth**, **gated-sink coverage**, and **structural idioms the corpus
does not fully stress** (pointer aliasing in C/C++, dynamic dispatch,
framework-specific context). All parser integrations use tree-sitter and are
stable; parsing is not a differentiator.

---

## Tier Summary

| Tier | Languages | F1 | What to expect |
|------|-----------|----|----------------|
| **Stable** | Python, JavaScript, TypeScript | 100% | Deep rule sets, gated sinks (argument-role-aware), framework detection, extensive fixtures, and the bulk of advanced-analysis (SSA two-level solve, context-sensitivity, symbolic execution, abstract interpretation) coverage. Safe to depend on in CI gates. |
| **Beta** | Go, Java, PHP, Ruby, Rust | 96.3% – 100% | Solid mid-depth rule sets with narrower cap coverage and **no gated sinks**. Cross-file flows work; some idioms (variable-typed method receivers, framework context, string interpolation, match-arm guards) are partially modeled. Usable in CI; review FP/FN lists before tightening gates. |
| **Preview** | C, C++ | 100% on synthetic corpus | The engine **structurally cannot model** pointer aliasing, function pointer / callback dispatch, array-element taint, or (C++) STL container flows. Rule-level scores against a corpus of obvious unsafe-API uses look perfect; that is not the same as a clean audit. Pair with clang-tidy, Clang Static Analyzer, or Infer. |

---

## Per-Language Detail

### Stable tier

#### Python: 100% P / 100% R / 100% F1 *(42-case corpus)*

- **Rule depth**: 5 source families, 7 sanitizer families, 21 sink matchers
  spanning HTML, URL, Shell, SQL, Code, SSRF, File I/O, and Deserialization.
- **Framework context**: Flask, Django, argparse source matchers; `flask_request`
  import-alias support.
- **Advanced analysis**: gated sinks (`Popen`, `subprocess.run/call` with
  activation-arg awareness), most SSA-equivalence and symbolic-execution
  fixtures target Python.
- **Fixtures**: 125 under `tests/fixtures/` plus 42 benchmark cases.
- **Blind spots**: f-string interpolation is not explicitly modeled as a
  distinct taint-producing construct; string-formatting flows are caught by
  the general concatenation path.

#### JavaScript: 100% P / 100% R / 100% F1 *(37-case corpus)*

- **Rule depth**: 3 source families, 10 sanitizer families, 24 sink matchers
  spanning HTML, URL, JSON, Shell, SQL, Code, SSRF, and File I/O.
- **Advanced analysis**: gated sinks (`setAttribute`, `parseFromString`),
  two-level SSA solve for top-level + per-function scopes
  (`analyse_ssa_js_two_level`), prefix-locked SSRF suppression via
  StringFact, abstract-interpretation interval tracking.
- **Framework context**: Express, Koa, Fastify (via in-file import scan when
  `package.json` is absent).
- **Fixtures**: 238 under `tests/fixtures/`; the largest fixture set of any
  language.
- **Blind spots**: template literals are lowered through concatenation rather
  than modeled as a first-class taint operator; dynamic property access
  (`obj[user]`) is conservatively treated.

#### TypeScript: 100% P / 100% R / 100% F1 *(42-case corpus)*

- **Rule depth**: Shares the JS ruleset (3 sources, 10 sanitizers, 24 sinks)
  plus TS-specific grammar handling.
- **Advanced analysis**: TSX and JSX grammars wired;
  discriminated-union narrowing, generic erasure, decorator flow, and
  interface dispatch are all validated against adversarial type-system
  stressors.
- **Framework context**: Fastify detection via `detect_in_file_frameworks`
  (import-driven, no `package.json` required).
- **Fixtures**: 39 test fixtures plus 42 benchmark cases.
- **Blind spots**: `as any` casts and `any`-typed flows are handled
  conservatively (treated as tainted).

### Beta tier

#### Go: 100% P / 100% R / 100% F1 *(36-case corpus)*

- **Rule depth**: 4 source families, 4 sanitizer families, 9 sink matchers
  covering HTML, URL, Shell, SQL, SSRF, Crypto, and File I/O.
- **Framework context**: Gin, Echo source matchers.
- **Known gaps**: no gated sinks, no deserialization class. `fmt.Sprintf` is
  deliberately not a sink. Rule-level F1 is 100% on the synthetic corpus,
  but cap coverage is narrower than the Stable tier and argument-role-aware
  sink modeling is not yet implemented for Go — production CI gates may
  surface FPs the corpus does not exercise.

#### Java: 100% P / 100% R / 100% F1 *(33-case corpus)*

- **Rule depth**: 3 source families, 8 sanitizer families, 10 sink matchers
  covering HTML, URL, Shell, SQL, Code, SSRF, and Deserialization.
- **Framework context**: Spring, JPA, Hibernate ORM rules; JNDI injection
  sinks.
- **Known gaps**: no gated sinks. Variable-receiver method calls
  (`client.send(...)` vs `HttpClient.send(...)`) rely on type-qualified
  resolution from receiver-type inference; flows where the receiver type
  cannot be inferred are conservatively over-tainted on unusual builder
  chains.

#### PHP: 100% P / 100% R / 100% F1 *(33-case corpus)*

- **Rule depth**: 3 source families (`$_GET`, `$_POST`, `$_REQUEST`
  superglobals), 7 sanitizer families, 10 sink matchers covering HTML, URL,
  Shell, SQL, Code, SSRF, File I/O, and Deserialization.
- **Known gaps**: no gated sinks. Limited framework context (Laravel raw
  methods only). `echo` language-construct detection is wired but its
  inner-argument propagation is narrower than function-call sinks.

#### Ruby: 100% P / 92.9% R / 96.3% F1 *(30-case corpus, 1 FN)*

- **Rule depth**: 3 source families, 7 sanitizer families, 15 sink matchers
  covering HTML, Shell, SQL, Code, SSRF, File I/O, and Deserialization.
- **Framework context**: Rails helpers (`sanitize_sql`, `permit`, `require`).
- **Known gaps**: string interpolation inside shell and SQL strings is
  recognized structurally but not modeled as a distinct operator.
  `begin/rescue/ensure` exception-edge wiring is documented as deferred
  (structurally incompatible with `build_try()`). The single open FN is
  `rb-interproc-001` — interprocedural SQL flow that fires
  `cfg-unguarded-sink` instead of the expected taint rule (rule-ID
  mismatch, not a missed flow).

#### Rust: 100% P / 100% R / 100% F1 *(59-case adversarial corpus)*

Rust holds the largest per-language adversarial corpus and was promoted
from Experimental to Beta in the 2026-04-25 measurement after the PathFact
landings closed every previously-open `rs-safe-*` regression.

- **Rule depth**: 6 source families, **2** sanitizer families (prefix and
  type-coercion), 11 sink matchers covering HTML, Shell, SQL, SSRF,
  Deserialization, and File I/O. Extensive framework source coverage
  (Axum, Actix, Rocket); the most of any language on the source side. The
  narrow sanitizer count is the primary reason Rust is not in the Stable
  tier — engine-side path/typed sanitizer recognition (PathFact) compensates,
  but the ruleset itself is shallow.
- **Recent additions**: SQL class (`rusqlite`, `sqlx`, `diesel`,
  `postgres`), Deserialization class (`serde_yaml`, `bincode`,
  `rmp_serde`, `ciborium`, `ron`, `toml`), expanded file I/O
  (`fs::remove_file/dir/rename/copy`), `reqwest` SSRF builder chain.
- **Closed by recent PathFact landings**
  (`src/abstract_interp/path_domain.rs` + per-return-path PathFact entries
  on `SsaFuncSummary`): `rs-safe-007` (`.replace("..","")` sanitiser),
  `rs-safe-008` (negative-validation return), `rs-safe-009` (match-arm
  guards via condition lifting), `rs-safe-010` (static-map lookup),
  `rs-safe-012` (`.contains("..")` + `.starts_with('/')` rejection),
  `rs-safe-014` (Option-returning user sanitiser), `rs-safe-015`
  (`Path::new(p).is_absolute()` typed rejection), `rs-safe-016`
  (cross-function `.contains("..")` rejection), and CVE patches
  `CVE-2018-20997`, `CVE-2022-36113`, `CVE-2024-24576`.
- **Not yet covered**: unsafe FFI / `std::mem::transmute` (no rules), Tokio
  `process::Command` async variants (not distinguished from sync),
  `hyper` / `surf` / `ureq` SSRF clients (reqwest family only).

### Preview tier

C and C++ remain **Preview** despite reporting 100% rule-level F1 on the
synthetic corpus. The corpus exercises obvious unsafe-API uses
(`system`, `sprintf`, `strcpy`, `getenv` → exec); it does not stress the
constructs the engine **structurally cannot model**. A clean report on a
real C or C++ codebase should not be read as a clean audit. Pair Nyx with
clang-tidy, the Clang Static Analyzer, or Infer for production use.

**Not modeled** (common to both C and C++):

- Pointer aliasing. Taint through `*p`, `p->field`, arbitrary pointer
  arithmetic, and aliased writes are not tracked.
- Function pointers and callback dispatch. Indirect calls through
  `void (*fn)(char *)` resolve to no callee.
- Array-element taint. Writes to `buf[i]` do not propagate taint to `buf`
  in the general case.
- STL container operations (C++ only). `std::vector`, `std::map`,
  `std::string` methods are not taint-aware; `c_str()` breaks taint chains.
- Lambdas and nested classes (C++ only).
- Complex socket setup (C++ only): `connect()` builder chains are not
  detected.

#### C: 100% P / 100% R / 100% F1 *(27-case corpus)*

- **Rule depth**: 3 source families, **2** sanitizer families (prefix-based
  only), 5 sink matchers spanning Shell, File, SSRF, and Format-String.
- **Known gaps**: no framework rules, no gated sinks. The structural
  limitations listed above are the dominant concern; rule additions alone
  will not lift this language out of the Preview tier.

#### C++: 100% P / 100% R / 100% F1 *(27-case corpus)*

- **Rule depth**: Clones the C ruleset (3 sources, 2 sanitizers, 5 sinks) and
  adds `std::cin` / `std::getline` sources.
- **Known gaps**: same sanitizer-recognition gaps as C, plus the
  C++-specific structural gaps (STL containers, `c_str()`, `connect()`,
  lambdas, nested classes) listed above.

---

## How the tiers were assigned

Because rule-level F1 has saturated for nine of ten languages, the tier
boundaries are drawn primarily on **rule depth** and **engine coverage of
real-world idioms** rather than on benchmark scores alone.

A language lands in **Stable** when all three hold:

- Rule set covers ≥ 8 vulnerability classes with both source and sink
  matchers, and at least one class has argument-role-aware **gated-sink**
  modeling (e.g. `setAttribute("href", url)` only flags href-like attrs).
- Benchmark F1 ≥ 95% on a corpus of ≥ 25 cases.
- Advanced analysis (SSA lowering, context-sensitivity, symbolic execution,
  abstract interpretation) is exercised by fixtures for the language.

A language lands in **Beta** when benchmark F1 ≥ 95% on a meaningful corpus
but at least one Stable criterion fails — typically the absence of gated
sinks, or sanitizer rule depth narrow enough that the engine compensates
structurally rather than via the ruleset.

A language lands in **Preview** when the engine **structurally cannot
model** constructs that are pervasive in typical codebases for that language
(pointer aliasing, function pointers, array-element taint, STL containers
for C/C++). Synthetic-corpus F1 is not a reliable signal for Preview-tier
languages: a clean report can coexist with large structural blind spots.

(The previous **Experimental** tier was retired in the 2026-04-25
measurement when Rust's adversarial corpus reached 100% F1; no language
currently sits in that tier.)

---

## What this means for you

- **CI gates**: safe to set strict `--fail-on HIGH` gates on Stable-tier
  languages. On Beta-tier, expect occasional FP triage on production code
  (the synthetic corpus does not cover every framework idiom); the
  weak-spot lists above tell you what to skim for. On Preview-tier, treat
  Nyx findings as a starting point for manual review rather than
  authoritative — the structural blind spots (pointer aliasing, function
  pointers, STL flows) mean a clean report does not disclose what the
  engine cannot see.
- **Rule contributions**: the shortest path to raising a language's tier is
  contributing sink matchers and gated-sink registrations. Label files live
  at `src/labels/<lang>.rs`; benchmark cases live at
  `tests/benchmark/corpus/<lang>/`.
- **Scope planning**: if your primary stack is C or C++, Nyx will surface
  real findings on obvious unsafe-API uses, but budget for review time and
  combine Nyx with `clang-tidy` or the Clang Static Analyzer. Rust is now
  Beta-tier and suitable as a CI gate; pair with `cargo-audit` for
  dependency CVEs.

The benchmark thresholds in `tests/benchmark_test.rs` are deliberately set
~5 pp below current baselines so any drop in a language's F1 fails CI. Tier
promotions require sustained benchmark performance, not just rule additions.
