# auth_analysis_rust_frameworks_integration

## Purpose
Realistic Rust framework auth integration fixture used as a multi-file scan regression.

## Expectations
- **required**: `rs.auth.admin_route_missing_admin_check` (≥1), `rs.auth.missing_ownership_check` (≥1), `rs.auth.partial_batch_authorization` (≥1), `rs.auth.stale_authorization` (≥1), `rs.auth.token_override_without_validation` (≥1)
- **forbidden**: `rs.auth.`
- **noise_budget**: max_total=8, max_high=8

## Why `noise_budget` stays
Realistic apps produce a natural mix of true-positive findings plus minor framework/helper noise. `noise_budget` is a loose upper bound that guards against precision regressions without requiring an exact per-finding pin. The `required_findings` list captures the must-fire truth set; anything new within the budget is permitted variance.
