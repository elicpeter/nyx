# Nyx Benchmark Results

## Baseline (Phase 22, 2026-03-21)

Scanner version: 0.4.0
Analysis mode: Full (taint + AST patterns + state analysis)
Corpus: 95 cases (55 vulnerable, 40 safe)

### Overall Metrics

| Level | TP | FP | FN | TN | Precision | Recall | F1 |
|-------|----|----|----|----|-----------|--------|----|
| File-level | 50 | 30 | 5 | 10 | 62.5% | 90.9% | 74.1% |
| Rule-level | 49 | 30 | 6 | 10 | 62.0% | 89.1% | 73.1% |

### Per Language (rule-level)

| Language | TP | FP | FN | TN | Precision | Recall | F1 |
|----------|----|----|----|----|-----------|--------|----|
| Go | 11 | 8 | 0 | 0 | 57.9% | 100.0% | 73.3% |
| Java | 10 | 7 | 1 | 1 | 58.8% | 90.9% | 71.4% |
| JavaScript | 9 | 4 | 2 | 4 | 69.2% | 81.8% | 75.0% |
| PHP | 10 | 4 | 1 | 4 | 71.4% | 90.9% | 80.0% |
| Python | 9 | 7 | 2 | 1 | 56.2% | 81.8% | 66.7% |

### Per Vulnerability Class (rule-level)

| Class | TP | FP | FN | Precision | Recall | F1 |
|-------|----|----|----|-----------|---------|----|
| cmdi | 9 | 0 | 2 | 100.0% | 81.8% | 90.0% |
| code_injection | 7 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| deser | 4 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| fmt_string | 1 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| path_traversal | 6 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| sqli | 11 | 0 | 0 | 100.0% | 100.0% | 100.0% |
| ssrf | 4 | 0 | 2 | 100.0% | 66.7% | 80.0% |
| xss | 7 | 0 | 2 | 100.0% | 77.8% | 87.5% |

### False Negatives (missed vulnerabilities)

| Case | File | Notes |
|------|------|-------|
| java-ssrf-002 | java/ssrf/SsrfHttpClient.java | HttpClient SSRF not detected |
| js-cmdi-001 | javascript/cmdi/cmdi_direct.js | exec() command injection missed |
| js-cmdi-002 | javascript/cmdi/cmdi_indirect.js | Indirect exec() command injection missed |
| php-xss-001 | php/xss/xss_reflected.php | Reflected XSS via echo not detected |
| py-ssrf-001 | python/ssrf/ssrf_requests.py | Rule mismatch (file-level TP, rule-level FN) |
| py-xss-002 | python/xss/xss_template_string.py | Template string XSS not detected |

### False Positives (safe code flagged)

30 of 40 safe cases were incorrectly flagged as vulnerable. The FP rate is
dominated by the scanner not yet recognizing sanitization, reassignment, and
validation patterns in safe code. This is the primary area for improvement.

| Language | Safe cases | TN | FP | TN rate |
|----------|-----------|----|----|---------|
| Go | 8 | 0 | 8 | 0% |
| Java | 8 | 1 | 7 | 12.5% |
| JavaScript | 8 | 4 | 4 | 50.0% |
| PHP | 8 | 4 | 4 | 50.0% |
| Python | 8 | 1 | 7 | 12.5% |

### Thresholds

Regression thresholds are set 5 percentage points below baseline scores.
These are enforced in `tests/benchmark_test.rs`.

| Metric | Baseline | Threshold |
|--------|----------|-----------|
| Rule-level Precision | 62.0% | 57.0% |
| Rule-level Recall | 89.1% | 84.1% |
| Rule-level F1 | 73.1% | 68.1% |
