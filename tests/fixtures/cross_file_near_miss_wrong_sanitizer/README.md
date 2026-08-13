# cross_file_near_miss_wrong_sanitizer

## Purpose
Near-miss: wrong sanitizer applied; the flow should still fire.

## Expectations
- **required**: `taint-unsanitised-flow` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=15, max_high=8
