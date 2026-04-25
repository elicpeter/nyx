# cross_file_alias_mutating_helper

## Purpose
Cross-file alias that mutates a helper-owned container; pins transitive taint through mutation.

## Expectations
- **required**: `py.cmdi` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=20, max_high=10

## Why `noise_budget` stays
`required_findings` pins the specific flow this fixture was authored to assert. `noise_budget` remains as a secondary upper-bound guard so a future regression that floods this small fixture with spurious findings will trip the test.
