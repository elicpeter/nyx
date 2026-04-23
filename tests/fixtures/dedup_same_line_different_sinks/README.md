# dedup_same_line_different_sinks

## Purpose
Dedup: same-line different sinks kept distinct.

## Expectations
- **required**: `taint-unsanitised-flow` (≥2)
- **forbidden**: (none)
- **noise_budget**: max_total=10, max_high=5

## Why `noise_budget` stays
`required_findings` pins the specific flow this fixture was authored to assert. `noise_budget` remains as a secondary upper-bound guard so a future regression that floods this small fixture with spurious findings will trip the test.
