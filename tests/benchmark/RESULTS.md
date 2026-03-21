# Nyx Benchmark Results

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
