// Callback-alias caller: resolves a cross-file sink wrapper
// through a two-hop local alias chain before invoking it with tainted
// data.  The engine's callback-binding table is name-keyed, so the
// alias chain `g → f → dangerous` tests whether the resolver walks
// local assignments transitively.
const helpers = require('./helpers.js');

function run() {
    const f = helpers.dangerous;
    const g = f;
    g(process.env.INPUT); // VULN (if alias chain resolves)
}

module.exports = { run };
