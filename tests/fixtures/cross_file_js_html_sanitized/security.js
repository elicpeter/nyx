const xss = require('xss');

/**
 * HTML_ESCAPE sanitiser wrapper.
 *
 * Delegates to the `xss` library, which is a registered HTML_ESCAPE
 * sanitiser in Nyx's JavaScript label rules.  Any tainted string passed
 * through this function has its HTML_ESCAPE taint capability neutralised.
 */
function sanitizeHtml(input) {
    return xss(input);
}

module.exports = { sanitizeHtml };
