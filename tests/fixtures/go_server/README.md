# go_server

## Purpose
Realistic Go HTTP server fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥4), `go.cmdi.exec_command` (≥3), `cfg-unguarded-sink` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=25, max_high=10
