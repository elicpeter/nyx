# closure_capture_ts — regression guard

## Intended flow
`makeHandler` captures `process.env.USER_INPUT` in a closure and returns
a typed arrow function that sinks it via `child_process.exec`.  The
expected finding is `taint-unsanitised-flow` from the env source to the
exec sink.

## Status
Closure-capture taint detection through the arrow boundary is now
supported on the TypeScript path — parity with the JS sibling
(`closure_capture_js`).  This fixture pins the intended flow so future
regressions fail loudly.
