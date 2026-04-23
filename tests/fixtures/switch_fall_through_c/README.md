# switch_fall_through_c — switch fall-through regression fixture

A C `switch` with explicit fall-through between cases. The
`Terminator::Switch` lowering is the structured representation for
mutually exclusive dispatch (Go switch, Java arrow-switch, Rust
match). C / C++ / classic-Java switches with fall-through keep the
cascaded `Branch` lowering because their cases are *not* mutually
exclusive — entering `case 1` may also execute `case 2`'s body when
there's no intervening `break`.

This fixture exercises that cascade contract: when `mode == 1`, taint
reaches `system(user)` by *falling through* to `case 2`. The cascade
preserves that flow; a regression that prematurely folded C switches
into `Terminator::Switch` would sever it, because Switch targets are
exclusive-by-contract.

The expectation is a single `taint-unsanitised-flow` (min_count 1) —
present-day lowering produces findings on at least one fall-through
sink, and a tighter lowering that discovers additional ones is
welcome.
