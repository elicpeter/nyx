// JS/TS pass-2 convergence fixture.
//
// Two handler-style functions share one global:
//
//   seed_handler     : writes `globalG1 = process.env.USER_INPUT`
//   finalize_handler : reads `globalG1`, calls `child_process.exec(globalG1)`
//
// Why this requires multiple pass-2 iterations
// ---------------------------------------------
// The source lives inside `seed_handler`, not at the top-level, so
// pass-1 (lexical containment from toplevel downward) starts every
// non-toplevel body with an empty seed.  Pass-2 combines helper exit
// states into a shared seed and re-runs helpers with the enlarged
// seed:
//
//   round 0 : combine `{globalG1}` from `seed_handler` into the seed
//             → seed grows from `{}` to `{globalG1}`; re-run
//             `finalize_handler` with the enlarged seed produces
//             the taint-to-sink finding.
//   round 1 : combined seed is stable (re-running `finalize_handler`
//             does not publish new globals); the loop converges.
//
// Under the default safety cap of 64 this converges and the finding
// is reported.  Under a cap of `2` (`rounds == 1`) the loop still
// reports the finding (from round 0's re-run) but the convergence
// check never fires — so the finding is tagged with
// `InFileFixpointCapped`.

var globalG1;

function seed_handler(req, res) {
    globalG1 = process.env.USER_INPUT;
}

function finalize_handler(req, res) {
    require('child_process').exec(globalG1);
}
