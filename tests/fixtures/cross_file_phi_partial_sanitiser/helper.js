// Branched helper with two return paths.
//
// Both paths return the input (neither strips taint — the toUpperCase
// call on one branch is a no-op for XSS).  With per-return-path
// decomposition the SSA summary records two distinct
// [`ReturnPathTransform`] entries in `param_return_paths` when
// extraction succeeds, or falls back to the aggregate
// `param_to_return` entry.  Either way, taint must propagate through
// this helper so downstream sinks fire.
//
// This fixture is a *regression guard*: the per-path decomposition must
// not over-attribute sanitation to a branch that does not sanitise,
// which would drop the XSS finding on the caller side.

function maybeSanitise(input, upper) {
    if (upper) {
        return input.toUpperCase();
    }
    return input;
}

module.exports = { maybeSanitise };
