# auth_analysis_ruby_frameworks_integration

## Purpose
Realistic Ruby framework auth integration fixture used as a multi-file scan regression.

## Expectations
- **required**: `rb.auth.admin_route_missing_admin_check` (≥1), `rb.auth.missing_ownership_check` (≥1), `rb.auth.partial_batch_authorization` (≥1), `rb.auth.stale_authorization` (≥1), `rb.auth.token_override_without_validation` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=12, max_high=12
