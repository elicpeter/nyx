# weak_hash_password

## Purpose
Weak hash applied to password.

## Expectations
- **required**: `js.crypto.weak_hash` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=10, max_high=5

## Why `noise_budget` stays
`required_findings` pins the specific flow this fixture was authored to assert. `noise_budget` remains as a secondary upper-bound guard so a future regression that floods this small fixture with spurious findings will trip the test.
