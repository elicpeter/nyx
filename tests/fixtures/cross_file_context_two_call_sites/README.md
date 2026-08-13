# cross_file_context_two_call_sites

## Purpose
Same callee invoked from two call sites with different taint shapes.

## Expectations
- **required**: `taint-unsanitised-flow` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=10, max_high=6
