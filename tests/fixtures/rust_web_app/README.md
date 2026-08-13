# rust_web_app

## Purpose
Realistic Rust Axum/Actix-style web app fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥4), `rs.quality.unsafe_block` (≥1), `state-unauthed-access` (≥3)
- **forbidden**: (none)
- **noise_budget**: max_total=45, max_high=15
