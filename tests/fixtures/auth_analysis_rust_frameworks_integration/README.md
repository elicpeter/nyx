# auth_analysis_rust_frameworks_integration

## Purpose
Realistic Rust framework auth integration fixture used as a multi-file scan regression.

## Expectations
- **required**: `rs.auth.admin_route_missing_admin_check` (≥1), `rs.auth.missing_ownership_check` (≥1), `rs.auth.partial_batch_authorization` (≥1), `rs.auth.stale_authorization` (≥1), `rs.auth.token_override_without_validation` (≥1)
- **forbidden**: `rs.auth.`
- **noise_budget**: max_total=8, max_high=8
