# cross_file_alias_returned_alias

## Purpose
Cross-file flow where an aliased container is returned; pins taint through return value.

## Expectations
- **required**: `taint-unsanitised-flow` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=15, max_high=8
