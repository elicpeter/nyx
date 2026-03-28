const { sanitizeHtml } = require('./security');

/**
 * SAFE: user input is sanitised through an HTML_ESCAPE sanitiser
 * (defined in security.js) before being written to innerHTML.
 *
 * The cross-file sanitiser propagation should suppress the XSS finding.
 * No taint-unsanitised-flow should be reported.
 */
function renderComment(req) {
    const input = req.query.content;  // taint source
    const clean = sanitizeHtml(input); // cross-file HTML_ESCAPE sanitiser
    document.write(clean);             // HTML sink — but taint is neutralised
}
