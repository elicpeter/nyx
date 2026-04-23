# container_taint_js — container-element taint regression

## Flow
`items.push(process.env.INPUT)` stores a tainted string into an array,
then `require('child_process').exec(items[0])` reads it back via
subscript and sinks it through exec.

## Current engine behaviour
The scanner surfaces a `taint-unsanitised-flow` finding for the
intra-file case, so the required expectation locks that coverage in.

Cross-function container identity is expected to extend this handling
to cross-file container flows.  Those are out of scope for this
fixture.
