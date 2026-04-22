// Caller for CF-4 partial-sanitiser fixture.
//
// User input flows through a cross-file helper whose two return paths
// have different transforms (StripBits(HTML_ESCAPE) vs Identity).
// The caller passes `false` so the raw path fires — the XSS sink must
// still fire because at least one return path is Identity.  CF-4's
// per-return-path decomposition is additive: it preserves per-path
// data in the summary without changing the aggregate-level result
// here.  The fixture is a regression guard against over-eager
// sanitation attribution when `param_return_paths` is present.

const { maybeSanitise } = require('./helper');

function renderComment(req) {
    const input = req.query.content;
    const forwarded = maybeSanitise(input, false);
    document.write(forwarded);
}

module.exports = { renderComment };
