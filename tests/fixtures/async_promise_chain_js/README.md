# async_promise_chain_js — known gap

## Intended flow
A promise chain reads `process.env.PREFIX` inside the second `.then`
callback, concatenates it with fetched text, and sinks the result via
`child_process.exec` from the third callback.  The intended finding is
`taint-unsanitised-flow` from the env source to the exec sink.

## Current engine behaviour
The scanner produces **no** taint finding for this fixture.  Tracking
taint across chained promise callbacks requires reasoning about the
promise resolution value returned from each arrow, which the engine
does not model today.

## Why this expectation is codified as a `forbidden_findings` entry
The fixture asserts current behaviour so a future improvement that
closes the gap — e.g. promise resolution modelling or coarser
callback return propagation — must update `expectations.json` and
delete this README.
