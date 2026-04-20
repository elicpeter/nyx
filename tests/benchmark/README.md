# Nyx Benchmark Evaluation Framework

## Corpus philosophy

The benchmark corpus is a curated set of ~262 minimal synthetic files (8-20 lines each) across 10 languages: JavaScript, TypeScript, Python, Java, Go, PHP, Ruby, Rust, C, and C++. Each file contains exactly one vulnerability (positive case) or demonstrates a specific safe pattern (negative case).

Design principles:
- **One vuln per file**: isolates the detection signal from noise.
- **Analogue cases allowed**: when a language lacks a specific sink (e.g., JS has no SQL_QUERY sink), we use an equivalent sink (e.g., `eval()`) to test the same dataflow concept. These are tagged `equivalence_tier: "analogue"`.
- **Semantic truth**: `is_vulnerable` reflects whether the code *is* vulnerable, independent of whether the current scanner detects it. This means some FNs are expected and acceptable.
- **Not full CWE coverage**: the corpus tests the vulnerability classes Nyx targets, not every possible CWE.

## Scoring modes

### Mode 1: File-Level Presence (coarsest)
Does the scanner produce *any* security finding for this file?
- TP: vulnerable file with at least one security finding
- FP: safe file with any security finding
- FN: vulnerable file with no security findings
- TN: safe file with no security findings

### Mode 2: Vuln-Class Scoring
Groups cases by `vuln_class` and computes precision/recall/F1 per class. Shows which vulnerability categories are strong or weak.

### Mode 3: Rule-Level Scoring
Checks whether the *correct* rule fired:
- TP: a finding matches `expected_rule_ids` or `allowed_alternative_rule_ids`
- FP: safe file with any security finding, OR `forbidden_rule_ids` matched on a vulnerable file
- FN: vulnerable file where no expected/alternative rule matched

Rule matching: exact match first, then substring fallback.

### Mode 4: Location-Aware Scoring
When `expected_sink_lines` is present, checks that a matching finding falls within ±2 lines of the expected sink location. Falls back to Mode 3 when no line info is specified.

## What metrics mean and don't mean

- **Precision** measures false positive rate — how often a flagged file truly has a vulnerability.
- **Recall** measures detection rate — how many real vulnerabilities the scanner catches.
- **F1** is the harmonic mean, balancing precision and recall.

Caveats:
- Scores on synthetic micro-benchmarks don't predict real-world performance.
- `equivalence_tier: "analogue"` cases may inflate or deflate metrics depending on whether the proxy sink behaves like the real one.
- `equivalence_tier: "language_specific"` cases have no cross-language equivalent and are scored independently.
- Some FNs are *expected* (e.g., interprocedural safe flows the scanner doesn't yet track).

## How to run

```bash
# Full benchmark (all 246 cases)
cargo test benchmark_evaluation -- --ignored --nocapture

# Filter by language (python, typescript, javascript, java, go, php, ruby, rust, c, cpp)
NYX_BENCH_LANG=typescript cargo test benchmark_evaluation -- --ignored --nocapture

# Filter by vulnerability class
NYX_BENCH_CLASS=sqli cargo test benchmark_evaluation -- --ignored --nocapture

# Single case
NYX_BENCH_CASE=js-sqli-001 cargo test benchmark_evaluation -- --ignored --nocapture

# Only positive (vulnerable) cases
NYX_BENCH_POSITIVE_ONLY=1 cargo test benchmark_evaluation -- --ignored --nocapture

# Only negative (safe) cases
NYX_BENCH_NEGATIVE_ONLY=1 cargo test benchmark_evaluation -- --ignored --nocapture

# Filter by tag
NYX_BENCH_TAG=express cargo test benchmark_evaluation -- --ignored --nocapture
```

## How to add a new case

1. Create a corpus file in `corpus/{language}/{vuln_class}/filename.ext` (8-20 lines, one vulnerability or safe pattern).
2. Add a case entry to `ground_truth.json` with all required fields.
3. Run the benchmark: `cargo test benchmark_evaluation -- --ignored --nocapture`
4. Verify the outcome matches your expectation.

## How to fix a case

If a case outcome is unexpected:
1. Investigate the root cause — is the scanner wrong, or is the ground truth wrong?
2. If the scanner is wrong, fix the scanner (not the ground truth).
3. If the ground truth is wrong (e.g., wrong expected_rule_ids), update it with justification.
4. Never auto-normalize ground truth to match scanner output.

## How to regenerate results

Run the benchmark. `results/latest.json` is overwritten each time:

```bash
cargo test benchmark_evaluation -- --ignored --nocapture
```

## Regression and trend tracking

Compare `latest.json` across commits to track directional improvement:
- Rule IDs may evolve as the scanner improves.
- Focus on precision/recall trends, not absolute numbers.
- The first run establishes the baseline; no hard thresholds are enforced initially.
