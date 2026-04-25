# rust_web_app

## Purpose
Realistic Rust Axum/Actix-style web app fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥4), `rs.quality.unsafe_block` (≥1), `state-unauthed-access` (≥3)
- **forbidden**: (none)
- **noise_budget**: max_total=45, max_high=15

## Why `noise_budget` stays
Realistic apps produce a natural mix of true-positive findings plus minor framework/helper noise. `noise_budget` is a loose upper bound that guards against precision regressions without requiring an exact per-finding pin. The `required_findings` list captures the must-fire truth set; anything new within the budget is permitted variance.
