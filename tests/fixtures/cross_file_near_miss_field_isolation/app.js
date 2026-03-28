const { Pool } = require('pg');
const { setLastUser, getDefaultQuery } = require('./session');

const pool = new Pool();

/**
 * NEAR MISS — TRUE NEGATIVE.
 *
 * req.query.user is stored in the `lastUser` variable inside session.js via
 * setLastUser().  However, the SQL query executed by pool.query() comes from
 * getDefaultQuery(), which returns the *constant* string 'SELECT 1' — a
 * variable that is completely independent of lastUser.
 *
 * Expected outcome: NO taint-unsanitised-flow finding.
 *
 * A false positive here would indicate that Nyx is not tracking variable
 * identity precisely enough when data crosses file boundaries through a module
 * with multiple distinct state variables.
 */
async function handleRequest(req) {
    setLastUser(req.query.user);    // taint → session.lastUser
    const q = getDefaultQuery();    // reads session.defaultQuery (constant)
    await pool.query(q);            // SAFE: q is the hard-coded 'SELECT 1'
}

module.exports = { handleRequest };
