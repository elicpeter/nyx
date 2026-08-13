# auth_analysis_python_frameworks_integration

## Purpose
Realistic Python framework auth integration fixture used as a multi-file scan regression.

## Expectations
- **required**: `py.auth.admin_route_missing_admin_check` (≥1), `py.auth.missing_ownership_check` (≥1), `py.auth.partial_batch_authorization` (≥1), `py.auth.stale_authorization` (≥1), `py.auth.token_override_without_validation` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=10, max_high=10
