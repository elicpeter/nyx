const { execSync } = require('child_process');
// Renamed import: `getInput` is imported as `fetchUserCmd`.
// This exercises Nyx's alias-tracking for CommonJS destructuring.
const { getInput: fetchUserCmd } = require('./source');

/**
 * VULN: req.query.cmd is user-controlled input (source) that flows through
 * fetchUserCmd() — an alias for getInput() defined in source.js — and then
 * directly to execSync() (shell execution sink) with no sanitisation.
 */
function handleRequest(req) {
    const cmd = fetchUserCmd(req.query.cmd); // taint flows through renamed binding
    execSync(cmd);                           // SINK: unsanitised command execution
}
