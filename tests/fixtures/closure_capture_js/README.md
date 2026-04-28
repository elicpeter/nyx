# closure_capture_js — regression guard

## Intended flow
`makeHandler` captures `process.env.USER_INPUT` in a closure and returns an
arrow function that sinks it via `child_process.exec`.  The expected
finding is `taint-unsanitised-flow` from the env source to the exec sink.

## Status
Closure-capture taint detection through the arrow boundary is now
supported.  This fixture pins the intended flow so future regressions
fail loudly.

The Python sibling (`tests/fixtures/closure_capture_py`) was the
reference for parity; both languages now produce the expected finding.
