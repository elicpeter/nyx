// Phase CF-6 fixture: helper returns its argument unchanged.
//
// At the summary level this is `param_to_return: [(0, Identity)]` —
// already captured by pre-CF-6 analysis.  CF-6 additionally records a
// `Param(0) → Return` alias edge so the caller's heap points-to set is
// threaded through the call, not just the taint cap.
function passthrough(x) {
    return x;
}

module.exports = { passthrough };
