# cross_file_param_sink_precision

## Purpose
Per-parameter sink precision; only payload args taint.

## Expectations
- **required**: `py.cmdi` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=5, max_high=3

## Why `noise_budget` stays
`required_findings` pins the specific flow this fixture was authored to assert. `noise_budget` remains as a secondary upper-bound guard so a future regression that floods this small fixture with spurious findings will trip the test.
