# Nyx Benchmark Results

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
