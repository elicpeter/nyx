const { exec } = require('child_process');

function handle_request(req) {
    ensureAuthenticated(req);
    exec(req.body.cmd);
}
