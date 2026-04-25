# mixed_project

## Purpose
Realistic Multi-language realistic project fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥10), `js.code_exec.eval` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=40, max_high=20

## Why `noise_budget` stays
Realistic apps produce a natural mix of true-positive findings plus minor framework/helper noise. `noise_budget` is a loose upper bound that guards against precision regressions without requiring an exact per-finding pin. The `required_findings` list captures the must-fire truth set; anything new within the budget is permitted variance.
