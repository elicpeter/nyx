# flask_app

## Purpose
Realistic Flask/Python web app fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥8), `py.code_exec.eval` (≥1), `py.code_exec.exec` (≥2), `state-unauthed-access` (≥5)
- **forbidden**: (none)
- **noise_budget**: max_total=50, max_high=25
