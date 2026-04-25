# inline_cache_origin_attribution

## Purpose
Inline-cache origin attribution regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥2)
- **forbidden**: (none)
- **noise_budget**: max_total=8, max_high=6

## Why `noise_budget` stays
`required_findings` pins the specific flow this fixture was authored to assert. `noise_budget` remains as a secondary upper-bound guard so a future regression that floods this small fixture with spurious findings will trip the test.
