const { execSync } = require('child_process');
// Renamed import: `getInput` is imported as `fetchUserCmd`.
// This exercises Nyx's alias-tracking for CommonJS destructuring.
const { getInput: fetchUserCmd } = require('./source');

/**
 * VULN: fetchUserCmd() returns a user-controlled value (process.env.USER_CMD)
 * and that value is passed directly to execSync() — a shell execution sink.
 * No sanitisation occurs between source and sink.
 */
function handleRequest() {
    const cmd = fetchUserCmd(); // taint flows through renamed binding
    execSync(cmd);              // SINK: unsanitised command execution
}

handleRequest();
