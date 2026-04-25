/**
 * Session state module.
 *
 * Two distinct module-level variables are maintained:
 *   - `lastUser`  — set externally with user-supplied data (potentially tainted)
 *   - `defaultQuery` — a hard-coded, constant SQL query string
 *
 * Critically, `getDefaultQuery()` returns `defaultQuery`, which is never
 * assigned any user-supplied value.  A precise field/variable-level taint
 * analysis should recognise that `defaultQuery` remains clean even after
 * `setLastUser()` stores tainted data.
 *
 * NEAR MISS — TRUE NEGATIVE:
 *   A coarse analysis that marks the whole module as tainted once any write
 *   occurs would produce a false positive.  A precise analysis should produce
 *   no taint-unsanitised-flow finding for the pool.query() call in app.js.
 */

let lastUser = '';
const defaultQuery = 'SELECT 1';  // constant — never tainted

function setLastUser(user) {
    lastUser = user; // tainted value stored in lastUser, NOT in defaultQuery
}

function getDefaultQuery() {
    return defaultQuery; // returns the constant — not lastUser
}

module.exports = { setLastUser, getDefaultQuery };
