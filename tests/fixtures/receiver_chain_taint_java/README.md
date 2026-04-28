# receiver_chain_taint_java

Tainted receiver flowing through a zero-arg method chain.

## Flow

- Source: `System.getenv("INPUT")`
- Chain: `tainted.trim().toLowerCase()` (zero-arg builder methods on the tainted receiver)
- Sink: `Runtime.getRuntime().exec(result)`

Neither `trim()` nor `toLowerCase()` takes arguments, so the engine's zero-arg receiver-seeding path in `inline_analyse_callee` / `collect_args_taint` is the only way taint reaches `result`. Regression guard against container or heap-aliasing changes that disturb receiver-only flow.

Expected finding: `taint-unsanitised-flow` from `System.getenv` to `Runtime.exec`.
