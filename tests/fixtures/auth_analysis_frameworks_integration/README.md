# auth_analysis_frameworks_integration

## Purpose
Realistic Framework auth integration (mixed) fixture used as a multi-file scan regression.

## Expectations
- **required**: `js.auth.admin_route_missing_admin_check` (≥1), `js.auth.missing_ownership_check` (≥1), `js.auth.partial_batch_authorization` (≥1), `js.auth.token_override_without_validation` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=8, max_high=8

## Why `noise_budget` stays
Realistic apps produce a natural mix of true-positive findings plus minor framework/helper noise. `noise_budget` is a loose upper bound that guards against precision regressions without requiring an exact per-finding pin. The `required_findings` list captures the must-fire truth set; anything new within the budget is permitted variance.
