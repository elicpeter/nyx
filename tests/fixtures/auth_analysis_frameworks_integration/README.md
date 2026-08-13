# auth_analysis_frameworks_integration

## Purpose
Realistic Framework auth integration (mixed) fixture used as a multi-file scan regression.

## Expectations
- **required**: `js.auth.admin_route_missing_admin_check` (≥1), `js.auth.missing_ownership_check` (≥1), `js.auth.partial_batch_authorization` (≥1), `js.auth.token_override_without_validation` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=8, max_high=8
