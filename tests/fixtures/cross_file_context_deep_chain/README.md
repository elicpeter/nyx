# cross_file_context_deep_chain

## Purpose
Context-sensitive taint across a deep call chain.

## Expectations
- **required**: `py.cmdi` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=10, max_high=6

## Why `noise_budget` stays
`required_findings` pins the specific flow this fixture was authored to assert. `noise_budget` remains as a secondary upper-bound guard so a future regression that floods this small fixture with spurious findings will trip the test.
