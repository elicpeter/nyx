# auth_analysis_admin_multilang_integration

## Purpose
Realistic Multi-language auth integration (admin ownership) fixture used as a multi-file scan regression.

## Expectations
- **required**: `js.auth.admin_route_missing_admin_check` (≥1), `py.auth.admin_route_missing_admin_check` (≥1), `rb.auth.admin_route_missing_admin_check` (≥1), `go.auth.admin_route_missing_admin_check` (≥1), `java.auth.admin_route_missing_admin_check` (≥1), `rs.auth.admin_route_missing_admin_check` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=8, max_high=8

## Why `noise_budget` stays
Realistic apps produce a natural mix of true-positive findings plus minor framework/helper noise. `noise_budget` is a loose upper bound that guards against precision regressions without requiring an exact per-finding pin. The `required_findings` list captures the must-fire truth set; anything new within the budget is permitted variance.
