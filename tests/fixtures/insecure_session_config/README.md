# insecure_session_config

## Purpose
Realistic Realistic session-config app fixture used as a multi-file scan regression.

## Expectations
- **required**: `js.config.insecure_session_httponly` (≥1), `js.secrets.hardcoded_secret` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=15, max_high=2

## Why `noise_budget` stays
Realistic apps produce a natural mix of true-positive findings plus minor framework/helper noise. `noise_budget` is a loose upper bound that guards against precision regressions without requiring an exact per-finding pin. The `required_findings` list captures the must-fire truth set; anything new within the budget is permitted variance.
