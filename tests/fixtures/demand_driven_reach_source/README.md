# demand_driven_reach_source

## Purpose
Demand-driven backwards: reaches source.

## Expectations
- **required**: `taint-unsanitised-flow` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=4, max_high=2

## Why `noise_budget` stays
`required_findings` pins the specific flow this fixture was authored to assert. `noise_budget` remains as a secondary upper-bound guard so a future regression that floods this small fixture with spurious findings will trip the test.
