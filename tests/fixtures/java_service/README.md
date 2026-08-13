# java_service

## Purpose
Realistic Java Spring-style service fixture used as a multi-file scan regression.

## Expectations
- **required**: `taint-unsanitised-flow` (≥2), `java.cmdi.runtime_exec` (≥2), `java.reflection.class_forname` (≥1), `cfg-unguarded-sink` (≥1)
- **forbidden**: (none)
- **noise_budget**: max_total=20, max_high=12
