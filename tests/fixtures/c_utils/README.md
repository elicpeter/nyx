# c_utils

## Purpose
Realistic C CLI/utilities collection fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥4), `c.memory.strcpy` (≥1), `c.memory.strcat` (≥1), `c.memory.sprintf` (≥4), `c.memory.gets` (≥1), `c.memory.scanf_percent_s` (≥1), `c.cmdi.system` (≥3), `cfg-unguarded-sink` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=50, max_high=20
