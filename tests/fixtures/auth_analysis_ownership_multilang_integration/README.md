# auth_analysis_ownership_multilang_integration

## Purpose
Realistic Multi-language auth integration (ownership checks) fixture used as a multi-file scan regression.

## Expectations
- **required**: `js.auth.missing_ownership_check` (≥1), `py.auth.missing_ownership_check` (≥1), `rb.auth.missing_ownership_check` (≥1), `go.auth.missing_ownership_check` (≥1), `java.auth.missing_ownership_check` (≥1), `rs.auth.missing_ownership_check` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=8, max_high=8

## Why `noise_budget` stays
Realistic apps produce a natural mix of true-positive findings plus minor framework/helper noise. `noise_budget` is a loose upper bound that guards against precision regressions without requiring an exact per-finding pin. The `required_findings` list captures the must-fire truth set; anything new within the budget is permitted variance.
