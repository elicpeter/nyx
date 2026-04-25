# closure_capture_ts — known gap

## Intended flow
`makeHandler` captures `process.env.USER_INPUT` in a closure and returns
a typed arrow function that sinks it via `child_process.exec`.  The
intended finding is `taint-unsanitised-flow` from the env source to the
exec sink.

## Current engine behaviour
The scanner produces **no** taint finding for this fixture.  This
parallels the JS sibling (`closure_capture_js`) — the TS fixture exists
to ensure the TypeScript grammar path does not regress independently
when the JS gap is eventually closed.

## Why this expectation is codified as a `forbidden_findings` entry
The fixture codifies current (possibly wrong) behaviour so that:

1. CI does not flake on the broken case today.
2. A future engine improvement that starts producing the finding will
   make the `forbidden_findings` assertion fail, forcing whoever lands
   that improvement to update `expectations.json` and delete this
   README.
