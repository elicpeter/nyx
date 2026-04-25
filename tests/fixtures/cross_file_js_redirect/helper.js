/**
 * Passthrough helper — returns its first argument unchanged.
 * The cross-file summary should show param 0 → return (propagates_taint).
 */
function safeRedirect(target, fallback) {
    return target || fallback;
}

module.exports = { safeRedirect };
