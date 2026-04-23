# flask_app

## Purpose
Realistic Flask/Python web app fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥8), `py.code_exec.eval` (≥1), `py.code_exec.exec` (≥2), `state-unauthed-access` (≥5)
- **forbidden**: (none)
- **noise_budget**: max_total=50, max_high=25

## Why `noise_budget` stays
Realistic apps produce a natural mix of true-positive findings plus minor framework/helper noise. `noise_budget` is a loose upper bound that guards against precision regressions without requiring an exact per-finding pin. The `required_findings` list captures the must-fire truth set; anything new within the budget is permitted variance.
