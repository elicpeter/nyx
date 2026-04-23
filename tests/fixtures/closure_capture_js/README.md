# closure_capture_js — known gap

## Intended flow
`makeHandler` captures `process.env.USER_INPUT` in a closure and returns an
arrow function that sinks it via `child_process.exec`.  The intended
finding is `taint-unsanitised-flow` from the env source to the exec sink.

## Current engine behaviour
The scanner produces **no** taint finding for this fixture — the arrow
function's capture of `tainted` is not tracked across the closure
boundary.

## Why this expectation is codified as a `forbidden_findings` entry
The fixture codifies current (possibly wrong) behaviour so that:

1. CI does not flake on the broken case today.
2. A future engine improvement that starts producing the finding will
   make the `forbidden_findings` assertion fail, forcing whoever lands
   that improvement to update `expectations.json` and delete this
   README.

The Python sibling (`tests/fixtures/closure_capture_py`) *does* produce
the intended finding, which demonstrates that the gap is a JS/TS
pipeline issue rather than a general closure-capture limitation.
