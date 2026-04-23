# java_service

## Purpose
Realistic Java Spring-style service fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥2), `java.cmdi.runtime_exec` (≥2), `java.reflection.class_forname` (≥1), `cfg-unguarded-sink` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=20, max_high=12

## Why `noise_budget` stays
Realistic apps produce a natural mix of true-positive findings plus minor framework/helper noise. `noise_budget` is a loose upper bound that guards against precision regressions without requiring an exact per-finding pin. The `required_findings` list captures the must-fire truth set; anything new within the budget is permitted variance.
