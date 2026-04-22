// Points-to alias caller: reads tainted request data, sends it
// through the cross-file passthrough helper, and uses the result as
// a shell command.  Passthrough returns its argument unchanged, so
// the finding must fire even though the taint never leaves the
// caller's value space.
const { passthrough } = require('./helper');
const { exec } = require('child_process');

function handle(req, res) {
    const userInput = req.query.cmd;
    const result = passthrough(userInput);
    exec(result);   // VULN: tainted shell command
}

module.exports = { handle };
