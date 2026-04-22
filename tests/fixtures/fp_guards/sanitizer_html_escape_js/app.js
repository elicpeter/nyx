// FP GUARD — sanitizer edge case (DOMPurify HTML escape).
//
// User input flows through DOMPurify.sanitize (a known HTML_ESCAPE
// sanitiser) before reaching document.write.  The HTML-escape cap
// must cover this path so no taint-unsanitised-flow surfaces, even
// though document.write is itself one of the broadest XSS sinks.
//
// Expected: NO taint-unsanitised-flow finding.

const DOMPurify = require("dompurify");

function render(req) {
    const raw = req.query.name;             // taint source
    const safe = DOMPurify.sanitize(raw);   // HTML_ESCAPE sanitiser
    document.write("<p>" + safe + "</p>");
}

module.exports = { render };
