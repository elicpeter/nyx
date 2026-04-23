// Callback-alias fixture: exports a sink wrapper.  The caller
// aliases the exported function twice (`const f = dangerous; const g = f;`)
// and invokes it through the second alias, stressing the engine's
// name-keyed callback-binding resolution.

const child_process = require('child_process');

function dangerous(x) {
    child_process.exec(x); // SINK
}

module.exports = { dangerous };
