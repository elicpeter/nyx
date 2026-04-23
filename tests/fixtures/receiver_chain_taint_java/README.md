# receiver_chain_taint_java — tainted receiver through no-arg chain

## Flow
`System.getenv("INPUT")` is the source; `tainted.trim().toLowerCase()`
is a chain of zero-arg builder-style methods on the tainted receiver;
`Runtime.getRuntime().exec(result)` is the sink.

## Why this fixture exists
Pins the receiver-fallback behaviour for zero-arg method calls on a
tainted receiver.  Neither `trim()` nor `toLowerCase()` takes arguments,
so the engine's zero-arg receiver-seeding path in
`inline_analyse_callee` / `collect_args_taint` is the only way the taint
reaches `result`.  The fixture guards against a regression if container
or heap-aliasing changes accidentally disturb the receiver-only flow.

Expected finding: `taint-unsanitised-flow` from `System.getenv` to
`Runtime.exec`.
