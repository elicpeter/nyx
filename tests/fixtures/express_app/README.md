# express_app

## Purpose
Realistic Express.js web app fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥6), `js.code_exec.eval` (≥1), `js.xss.document_write` (≥1), `js.code_exec.settimeout_string` (≥1), `js.xss.cookie_write` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=25, max_high=15
