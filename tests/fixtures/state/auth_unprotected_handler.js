const { exec } = require('child_process');

function handle_request(req) {
    // No auth check — should trigger state-unauthed-access
    exec(req.body.cmd);
}
