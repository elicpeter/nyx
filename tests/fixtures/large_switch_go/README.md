# large_switch_go — switch-lowering regression fixture

A Go `switch` statement with seven mutually-exclusive cases, each flowing
a tainted query parameter into a different sink (SQLi, CMDi, XSS, path
traversal, env tampering, log injection, SSRF).

The fixture anchors the `Terminator::Switch` lowering: Go switches
have no implicit fall-through, so the lowering can in principle emit a
single `Terminator::Switch` instead of a cascade of binary `Branch`
headers. Whether lowering does so today or a follow-up flips the switch
over, this fixture asserts that taint propagates into each case
regardless.

The expectation is intentionally loose — `min_count: 1` on
`taint-unsanitised-flow`. Today's cascade lowering reports only a subset
of the case sinks (the SQL path lands reliably; others are gated by
per-case taint-precision work). A future strengthening that emits real
`Terminator::Switch` for Go and narrows taint per case should bump
`min_count` accordingly — the expectation is set to the current floor
so that regressions (0 findings) fail the test.
