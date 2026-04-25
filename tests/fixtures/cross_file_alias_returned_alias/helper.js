// Points-to alias fixture: helper returns its argument unchanged.
//
// At the summary level this is `param_to_return: [(0, Identity)]` —
// already captured by the taint-cap summary.  The points-to channel
// additionally records a `Param(0) → Return` alias edge so the
// caller's heap points-to set is threaded through the call, not just
// the taint cap.
function passthrough(x) {
    return x;
}

module.exports = { passthrough };
