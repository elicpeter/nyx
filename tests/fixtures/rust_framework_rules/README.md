# rust_framework_rules

## Purpose
Realistic Rust framework rules corpus fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥4)
- **forbidden**: (none)
- **noise_budget**: max_total=10, max_high=10

## Why `noise_budget` stays
Realistic apps produce a natural mix of true-positive findings plus minor framework/helper noise. `noise_budget` is a loose upper bound that guards against precision regressions without requiring an exact per-finding pin. The `required_findings` list captures the must-fire truth set; anything new within the budget is permitted variance.
