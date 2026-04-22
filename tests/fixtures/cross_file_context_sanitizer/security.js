// Cross-file sanitizer: delegates to the `xss` library, which is a
// registered HTML_ESCAPE sanitiser in the JS label rules.  The
// wrapping function itself is user-defined, so resolution must go
// through either the cross-file SSA summary (StripBits(HTML_ESCAPE))
// or the CF-2 inline path to clear the taint.

const xss = require('xss');

function xssSafe(s) {
    return xss(String(s));
}

module.exports = { xssSafe };
