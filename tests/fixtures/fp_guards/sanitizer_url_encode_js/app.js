// FP GUARD — sanitizer edge case (URL encoding with unicode).
//
// User input is percent-encoded via encodeURIComponent before being
// interpolated into a fetch URL.  URL_ENCODE covers SSRF and other
// URL-context sinks, so no taint-unsanitised-flow should fire even
// when the tainted value contains unicode / spaces / other chars that
// would otherwise flag as structural.
//
// Expected: NO taint-unsanitised-flow finding.

async function lookup(req) {
    const q = req.query.q;                   // taint source
    const encoded = encodeURIComponent(q);   // URL_ENCODE sanitiser
    const resp = await fetch("https://api.example.internal/search?q=" + encoded);
    return resp.json();
}

module.exports = { lookup };
