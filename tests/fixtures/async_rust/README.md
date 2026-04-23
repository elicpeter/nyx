# async_rust — Rust async flow regression

## Flow
`fetch_and_exec` reads `CMD` from the environment and passes it to
`tokio::process::Command::new("sh").arg("-c").arg(&cmd)`.  The intended
finding is `taint-unsanitised-flow` from the env source to the Tokio
process-spawn sink.

## Note on `docs/language-maturity.md`
The maturity doc previously listed Tokio process variants as a known
gap for Rust.  As of Phase 8 the engine actually does surface this
flow, so the fixture is codified with `required_findings` and will
regression-guard that coverage going forward.  If the maturity doc
still claims this gap, it should be updated alongside any future
refactor that reopens it.
